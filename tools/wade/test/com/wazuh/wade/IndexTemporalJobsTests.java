// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.TemporalJobRunner.*;
public final class IndexTemporalJobsTests {
    private static int checks;
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|IllegalStateException|SecurityException e){checks++;}}
    private static final class Fake implements IndexWindowStore.Backend {
        final Map<String,IndexWindowStore.Document> data=new HashMap<>();
        public IndexWindowStore.Document get(String index,String id){return data.get(index+id);}
        public boolean create(String index,String id,Map<String,Object> body){return data.putIfAbsent(index+id,new IndexWindowStore.Document(id,0,1,body))==null;}
        public boolean replace(String index,String id,long seq,long term,Map<String,Object> body){var d=get(index,id);if(d==null||d.sequence()!=seq||d.primaryTerm()!=term)return false;data.put(index+id,new IndexWindowStore.Document(id,seq+1,term,body));return true;}
    }
    public static void main(String[] args){
        Instant t=Instant.parse("2026-11-26T00:00:00Z");var scope=new WindowService.Scope("t","cluster","AGENT","001");var p=new CrossWindowCorrelation.Policy("r1",List.of("a","b"),CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000);
        Job j=new Job(scope,p,Duration.ofSeconds(10),Duration.ZERO,Duration.ofMinutes(1),t);Fake f=new Fake();var s=new IndexTemporalJobs(f,scope,true);var disabled=new IndexTemporalJobs(f,scope,false);
        check(s.load(j)==null,"not provisioned");reject(()->disabled.provision(j));check(s.provision(j)&&!s.provision(j),"create only");
        Cursor prior=s.load(j);check(prior.equals(Cursor.initial(j)),"roundtrip initial");
        var lease=new Cursor(j.id(),1,1,t,null,"worker",t.plusSeconds(20),null);check(s.compareAndSet(j,prior,lease),"CAS lease");check(!s.compareAndSet(j,prior,lease),"stale write rejected");
        var done=new Cursor(j.id(),2,1,t.plusSeconds(10),null,null,Instant.MIN,"a".repeat(64));check(s.compareAndSet(j,lease,done),"CAS checkpoint");check(new IndexTemporalJobs(f,scope,true).load(j).equals(done),"reopen");
        reject(()->disabled.compareAndSet(j,done,new Cursor(j.id(),3,2,done.checkpoint(),null,"w",t.plusSeconds(30),done.receipt())));
        reject(()->new IndexTemporalJobs(f,new WindowService.Scope("other","cluster","AGENT","001"),true).load(j));
        var raw=f.get(IndexTemporalJobs.INDEX,j.id());var body=new HashMap<>(raw.body());body.put("unexpected",true);f.data.put(IndexTemporalJobs.INDEX+j.id(),new IndexWindowStore.Document(j.id(),raw.sequence(),1,body));reject(()->s.load(j));
        System.out.println("WADE job document checks passed: "+checks);
    }
}
