// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.IndexReplayEvidence.*;
import static com.wazuh.wade.PairedTemporalReplay.*;
import static com.wazuh.wade.TemporalAdmission.*;
import static com.wazuh.wade.TemporalPromotion.*;
import static com.wazuh.wade.WindowService.Scope;
public final class IndexReplayEvidenceTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Rule RULE=new Rule("t","r");private static final Scope S=new Scope("t","cluster","AGENT","001");private static final String IDX=".ds-wazuh-events-v5-auth-000001";
    private static final String A="a".repeat(64),B="b".repeat(64);private static int checks;
    private static Instant t(int n){return T.plusSeconds(n);}
    private static Definition def(String version,String outcome){return new Definition("t","r",version,CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000,List.of(new Stage("a",Map.of("event.kind","event","event.outcome","failure")),new Stage("b",Map.of("event.kind","event","event.outcome",outcome))));}
    private static final Definition D=def("1","success"),C=def("2","other");
    private static Row row(int n,String o){return new Row(IDX,"uuid",Integer.toString(n),"001",t(n),t(n),Map.of("event.kind",List.of("event"),"event.outcome",List.of(o)));}
    private static Case item(String id,int start,Label label){return new Case(id.repeat(64),S,t(start),t(start+10),t(start+10),label,label==Label.MALICIOUS,"f".repeat(64));}
    private static void check(boolean b,String m){if(!b)throw new AssertionError(m);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected failure");}catch(IllegalArgumentException|IllegalStateException|SecurityException e){checks++;}}
    private static final class Fake implements IndexWindowStore.Backend {
        final Map<String,IndexWindowStore.Document> rows=new HashMap<>();public IndexWindowStore.Document get(String idx,String id){return rows.get(id);}public boolean create(String idx,String id,Map<String,Object> body){return rows.putIfAbsent(id,new IndexWindowStore.Document(id,0,1,body))==null;}public boolean replace(String idx,String id,long seq,long term,Map<String,Object> body){var d=get(idx,id);if(d==null||d.sequence()!=seq||d.primaryTerm()!=term)return false;rows.put(id,new IndexWindowStore.Document(id,seq+1,term,body));return true;}
    }
    public static void main(String[] args){
        Fake backend=new Fake();class Mutable extends Clock {Instant now=t(100);public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now;}}var clock=new Mutable();
        var rows=List.of(row(1,"failure"),row(2,"success"),row(21,"failure"),row(22,"success"),row(23,"other"),row(41,"failure"),row(42,"success"),row(61,"failure"),row(62,"success"),row(63,"other"));
        var replay=new PairedTemporalReplay((a,b,c,d)->{},r->new Inventory(true,List.of(new Partition(IDX,"uuid",S,t(-10),r.end()))),(p,from,to,limit)->new Batch(true,rows.stream().filter(x->!x.occurred().isBefore(from)&&x.occurred().isBefore(to)).toList()),clock);
        boolean[] denied={false};IndexReplayEvidence.Authority auth=(r,k,o,a,n,report,cases)->{if(denied[0])throw new SecurityException("denied");};
        var store=new IndexReplayEvidence(backend,RULE,replay,auth,clock,Duration.ofSeconds(20),true,1,1);
        var first=List.of(item("1",0,Label.BENIGN),item("2",20,Label.MALICIOUS));var second=List.of(item("3",40,Label.BENIGN),item("4",60,Label.MALICIOUS));
        String r=store.capture("reviewer",Kind.REPLAY,A,D,C,first,1,1),s=store.capture("reviewer",Kind.SHADOW,B,D,C,second,1,1);
        check(backend.rows.size()==2&&store.verifiedReport(RULE,r,s).receipt().equals(r),"persisted actual paired evidence");
        check(store.capture("reviewer",Kind.REPLAY,A,D,C,first,1,1).equals(r)&&backend.rows.size()==2,"idempotent capture");
        var reopened=new IndexReplayEvidence(backend,RULE,replay,auth,clock,Duration.ofSeconds(20),false,1,1);check(reopened.verifiedReport(RULE,r,s).receipt().equals(r),"reopen");
        reject(()->reopened.revoke(Kind.SHADOW,s));reject(()->store.verifiedReport(new Rule("other","r"),r,s));
        reject(()->store.verifiedReport(RULE,s,r));reject(()->store.capture("reviewer",Kind.REPLAY,B,D,C,first,1,1));
        var overlapped=List.of(item("1",40,Label.BENIGN),item("5",60,Label.MALICIOUS));String o=store.capture("reviewer",Kind.SHADOW,B,D,C,overlapped,1,1);reject(()->store.verifiedReport(RULE,r,o));
        var strict=new IndexReplayEvidence(backend,RULE,replay,auth,clock,Duration.ofSeconds(20),true,2,2);reject(()->strict.verifiedReport(RULE,r,s));
        denied[0]=true;reject(()->store.verifiedReport(RULE,r,s));denied[0]=false;
        var approval=new Approval(D.policy().version(),C.policy().version(),r,s,"reviewer","author",t(130));store.requireCurrent(RULE,approval,t(101));checks++;
        clock.now=t(120);reject(()->store.verifiedReport(RULE,r,s));clock.now=t(101);
        check(store.revoke(Kind.SHADOW,s)&&store.revoke(Kind.SHADOW,s),"revocation idempotent");reject(()->store.requireCurrent(RULE,approval,t(101)));reject(()->store.capture("reviewer",Kind.SHADOW,B,D,C,second,1,1));
        var entry=backend.rows.entrySet().stream().filter(e->e.getValue().body().get("receipt").equals(r)).findFirst().orElseThrow();var doc=entry.getValue();var bad=new HashMap<>(doc.body());bad.put("payload_digest","0".repeat(64));backend.rows.put(entry.getKey(),new IndexWindowStore.Document(doc.id(),doc.sequence(),doc.primaryTerm(),bad));reject(()->store.verifiedReport(RULE,r,s));
        System.out.println("WADE persistent evidence checks passed: "+checks);
    }
}
