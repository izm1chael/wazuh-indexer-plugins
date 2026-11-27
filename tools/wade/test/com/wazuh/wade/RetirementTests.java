// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.TemporalPromotion.*;
public final class RetirementTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");private static int checks;
    private static void check(boolean b,String why){if(!b)throw new AssertionError(why);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(SecurityException|IllegalStateException|IllegalArgumentException e){checks++;}}
    public static void main(String[] args){
        var scope=new Scope("t","cluster","AGENT","001");var rule=new Rule("t","r");var def=new TemporalAdmission.Definition("t","r","1",CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000,List.of(new TemporalAdmission.Stage("a",Map.of("event.kind","event","event.outcome","failure")),new TemporalAdmission.Stage("b",Map.of("event.kind","event","event.outcome","success"))));
        var p=def.policy();var request=new Request(scope,p,T,T.plusSeconds(10),T.plusSeconds(11));Clock clock=Clock.fixed(T.plusSeconds(20),ZoneOffset.UTC);
        State[] active={new State(rule.keyDigest(),1,p.version(),true,null,"a".repeat(64))};boolean[] deny={false},drain={false},fail={false},conflict={false};int[] reads={0};
        var registry=new States(){public State load(Rule r){return active[0];}public boolean compareAndSet(Rule r,State a,State b){if(conflict[0]||!a.equals(active[0]))return false;active[0]=b;return true;}};
        var gate=new TemporalPromotion(rule,registry,(r,d)->new Revision(def,"author"),(a,r,o)->{if(deny[0])throw new SecurityException();},new Evidence(){public PairedTemporalReplay.Report verifiedReport(Rule r,String x,String y){throw new AssertionError();}public void requireCurrent(Rule r,Approval a,Instant n){throw new AssertionError();}},clock,true,1,1);
        Map<String,Envelope> docs=new HashMap<>();Map<String,Pending> delivered=new HashMap<>();var store=new Store(){public Envelope load(String k){return docs.get(k);}public boolean compareAndSet(String k,Envelope a,Envelope b){if(conflict[0]||!docs.getOrDefault(k,Envelope.initial(k)).equals(a))return false;docs.put(k,b);return true;}};
        var service=new WindowService((actor,r,o)->{if(!scope.equals(r.scope())||o==Permission.DRAIN&&!drain[0])throw new SecurityException();},gate::resolve,r->{reads[0]++;return new Snapshot(r,r.lookback(),r.end(),true,List.of(new CrossWindowCorrelation.Event(scope.canonical(),"a",T,T,Set.of("a")),new CrossWindowCorrelation.Event(scope.canonical(),"b",T.plusSeconds(1),T.plusSeconds(1),Set.of("b"))));},store,(r,pending)->{delivered.putIfAbsent(pending.publication().id(),pending);if(fail[0])throw new IllegalStateException("lost ack");},clock);
        check(service.execute("worker",request)==WindowService.Status.STAGED,"existing staged output");deny[0]=true;reject(()->gate.deactivate("operator",1));deny[0]=false;
        reject(()->gate.deactivate("operator",0));conflict[0]=true;check(!gate.deactivate("operator",1)&&active[0].active(),"CAS conflict");conflict[0]=false;
        check(gate.deactivate("operator",1)&&!active[0].active()&&active[0].pending()==null,"explicit deactivate");reject(()->gate.resolve(request));reject(()->service.execute("worker",request));check(reads[0]==1,"no post-retirement read");
        reject(()->service.drain("worker",request));check(delivered.isEmpty(),"separate drain permission");drain[0]=true;fail[0]=true;reject(()->service.drain("operator",request));check(docs.get(request.windowKey()).pending()!=null&&delivered.size()==1,"failed drain retains pending");fail[0]=false;
        conflict[0]=true;check(service.drain("operator",request)==WindowService.Status.CONFLICT,"drain ack CAS conflict");conflict[0]=false;
        check(service.drain("operator",request)==WindowService.Status.RECOVERED&&docs.get(request.windowKey()).pending()==null&&delivered.size()==1,"recover exact publication");
        check(service.drain("operator",request)==WindowService.Status.NO_CHANGE&&reads[0]==1,"no new evaluation");reject(()->gate.deactivate("operator",2));
        System.out.println("WADE retirement checks passed: "+checks);
    }
}
