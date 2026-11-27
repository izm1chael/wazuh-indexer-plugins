// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.TemporalAdmission.*;
import static com.wazuh.wade.TemporalPromotion.*;
public final class TemporalReleaseFlowTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("t","cluster","AGENT","001");private static final Rule R=new Rule("t","r");private static final String INDEX=".ds-wazuh-events-v5-auth-000001",SHADOW="f".repeat(64);
    private static int checks;
    private static Instant t(int n){return T.plusSeconds(n);}
    private static Definition d(String version,String outcome){return new Definition("t","r",version,CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000,List.of(new Stage("a",Map.of("event.kind","event","event.outcome","failure")),new Stage("b",Map.of("event.kind","event","event.outcome",outcome))));}
    private static Row row(String id,int n,String outcome){return new Row(INDEX,"uuid",id,"001",t(n),t(n),Map.of("event.kind",List.of("event"),"event.outcome",List.of(outcome)));}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|IllegalStateException|SecurityException e){checks++;}}
    private static final class Backend implements IndexWindowStore.Backend {
        final Map<String,IndexWindowStore.Document> docs=new HashMap<>();boolean lose;
        public IndexWindowStore.Document get(String index,String id){return docs.get(index+id);}
        public boolean create(String index,String id,Map<String,Object> body){if(docs.putIfAbsent(index+id,new IndexWindowStore.Document(id,0,1,body))!=null)return false;if(lose&&index.equals(IndexWindowStore.PUBLICATIONS)){lose=false;throw new IllegalStateException("ack lost");}return true;}
        public boolean replace(String index,String id,long seq,long term,Map<String,Object> body){var old=get(index,id);if(old==null||old.sequence()!=seq||old.primaryTerm()!=term)return false;docs.put(index+id,new IndexWindowStore.Document(id,seq+1,term,body));return true;}
    }
    public static void main(String[] args){
        var a=d("1","success");var b=d("2","other");Backend backend=new Backend();var registry=new IndexTemporalRegistry(backend,R,true);var ra=new Revision(a,"author");var rb=new Revision(b,"author");
        check(registry.provision(ra)&&!registry.provision(ra),"inactive baseline create-only");check(registry.register(rb)&&registry.register(rb),"immutable registration");reject(()->registry.register(new Revision(d("2","different"),"author")));
        check(new IndexTemporalRegistry(backend,R,false).resolve(R,b.policy().version()).equals(rb),"registry reopen");reject(()->new IndexTemporalRegistry(backend,R,false).register(rb));
        List<Row> source=List.of(row("a",1,"failure"),row("b",2,"success"),row("c",21,"failure"),row("d",22,"success"),row("e",23,"other"));
        InventorySource inventory=request->new Inventory(true,List.of(new Partition(INDEX,"uuid",S,t(-10),request.end())));
        Reader reader=(partition,from,to,limit)->new Batch(true,source.stream().filter(x->!x.occurred().isBefore(from)&&x.occurred().isBefore(to)).toList());
        Clock replayClock=Clock.fixed(t(40),ZoneOffset.UTC);var replay=new PairedTemporalReplay((actor,x,y,c)->{if(!actor.equals("reviewer"))throw new SecurityException();},inventory,reader,replayClock);
        var report=replay.run("reviewer",a,b,List.of(new PairedTemporalReplay.Case("a".repeat(64),S,T,t(10),t(10),PairedTemporalReplay.Label.BENIGN,false,"c".repeat(64)),new PairedTemporalReplay.Case("b".repeat(64),S,t(20),t(30),t(30),PairedTemporalReplay.Label.MALICIOUS,true,"d".repeat(64))),1,1);
        check(report.rows().get(0).champion()==PairedTemporalReplay.Outcome.MATCH&&report.rows().get(0).challenger()==PairedTemporalReplay.Outcome.NO_MATCH&&report.rows().get(1).challenger()==PairedTemporalReplay.Outcome.MATCH,"actual replay quality");
        if(args.length==1&&args[0].equals("--cohort")){System.out.println(report.cohortJson());return;}
        var gate=new TemporalPromotion(R,registry,registry,(actor,rule,action)->{if(!Set.of("reviewer","operator").contains(actor))throw new SecurityException();},new Evidence(){public PairedTemporalReplay.Report verifiedReport(Rule rule,String receipt,String shadow){if(!receipt.equals(report.receipt())||!shadow.equals(SHADOW))throw new SecurityException();return report;}public void requireCurrent(Rule rule,Approval approval,Instant now){if(!approval.replayReceipt().equals(report.receipt())||!approval.shadowReceipt().equals(SHADOW))throw new SecurityException();}},replayClock,true,1,1);
        check(gate.approve("reviewer",0,report.receipt(),SHADOW,Duration.ofMinutes(1))&&!registry.load(R).active(),"approval no activation");check(gate.activate("operator",1)&&registry.load(R).active(),"explicit activation");check(new IndexTemporalRegistry(backend,R,true).load(R).champion().equals(b.policy().version()),"active pointer persisted");
        var admission=new TemporalAdmission(gate,inventory,reader);var windows=new IndexWindowStore(backend,S,true);var jobs=new IndexTemporalJobs(backend,S,true);var job=new TemporalJobRunner.Job(S,b.policy(),Duration.ofSeconds(10),Duration.ZERO,Duration.ofMinutes(1),t(20));
        check(jobs.provision(job),"job provision");
        class MutableClock extends Clock {Instant now=t(40);public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){if(!zone.equals(ZoneOffset.UTC))throw new IllegalArgumentException();return this;}public Instant instant(){return now;}}
        var clock=new MutableClock();var service=new WindowService((actor,request,permission)->{if(!actor.equals("worker"))throw new SecurityException();},admission,admission,windows,windows,clock);
        var runner=new TemporalJobRunner((actor,j)->{if(!actor.equals("worker"))throw new SecurityException();},jobs,service,windows,clock);backend.lose=true;
        reject(()->runner.tick("worker",job,Duration.ofSeconds(5),false));check(jobs.load(job).checkpoint().equals(t(20)),"ack loss checkpoint held");clock.now=t(46);
        check(runner.tick("worker",job,Duration.ofSeconds(5),false)==TemporalJobRunner.Result.ADVANCED,"recover and commit");check(jobs.load(job).checkpoint().equals(t(30))&&backend.docs.keySet().stream().filter(x->x.startsWith(IndexWindowStore.PUBLICATIONS)).count()==1,"one publication durable protocol");
        reject(()->gate.resolve(new Request(S,a.policy(),t(20),t(30),t(46))));
        var raw=backend.get(IndexTemporalRegistry.INDEX,R.keyDigest());var corrupt=new HashMap<>(raw.body());corrupt.put("payload_digest","0".repeat(64));backend.docs.put(IndexTemporalRegistry.INDEX+R.keyDigest(),new IndexWindowStore.Document(raw.id(),raw.sequence(),raw.primaryTerm(),corrupt));reject(()->registry.load(R));
        System.out.println("WADE release flow checks passed: "+checks);
    }
}
