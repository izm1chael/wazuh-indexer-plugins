// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.IndexWindowStore.*;

public final class IndexWindowStoreTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("t","inventory","HOST","h");
    private static final CrossWindowCorrelation.Policy P=new CrossWindowCorrelation.Policy("r1",List.of("a","b"),CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000);
    private static int checks;
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|IllegalStateException expected){checks++;}}
    private static final class BackendFake implements Backend {
        final Map<String,Document> data=new HashMap<>();boolean conflict,loseAck;
        private String key(String index,String id){return index+"/"+id;}
        public Document get(String index,String id){return data.get(key(index,id));}
        public boolean create(String index,String id,Map<String,Object> body){if(data.containsKey(key(index,id)))return false;data.put(key(index,id),new Document(id,0,1,body));if(loseAck){loseAck=false;throw new IllegalStateException("ambiguous create");}return true;}
        public boolean replace(String index,String id,long sequence,long term,Map<String,Object> body){var d=get(index,id);if(conflict){conflict=false;return false;}if(d==null||d.sequence()!=sequence||d.primaryTerm()!=term)return false;data.put(key(index,id),new Document(id,sequence+1,term,body));return true;}
        void tamper(String index,String id,String field,Object value){var d=get(index,id);Map<String,Object> b=new HashMap<>(d.body());b.put(field,value);data.put(key(index,id),new Document(id,d.sequence(),d.primaryTerm(),b));}
    }
    public static void main(String[] args){
        BackendFake backend=new BackendFake();var store=new IndexWindowStore(backend,S,true);var disabled=new IndexWindowStore(backend,S,false);
        var request=new Request(S,P,T,T.plusSeconds(10),T.plusSeconds(10));String id=request.windowKey();
        var events=new ArrayList<>(List.of(new CrossWindowCorrelation.Event(S.canonical(),"a",T.minusSeconds(1),T,Set.of("a")),new CrossWindowCorrelation.Event(S.canonical(),"b",T.plusSeconds(1),T.plusSeconds(2),Set.of("b"))));
        var svc=new WindowService((a,r,p)->{},r->{},r->new Snapshot(r,r.lookback(),r.end(),true,events),store,store,Clock.fixed(T.plusSeconds(30),ZoneOffset.UTC));
        check(store.load(id)==null,"not found");check(svc.execute("service",request)==Status.STAGED,"create state and outbox");
        var staged=store.load(id);var pending=staged.pending();String pub=pending.publication().id();
        check(new IndexWindowStore(backend,S,true).load(id).equals(staged),"round trip after reopen");
        reject(()->disabled.deliver(request,pending));reject(()->disabled.compareAndSet(id,staged,new Envelope(staged.token()+1,staged.state(),null)));
        reject(()->new IndexWindowStore(backend,new Scope("other","inventory","HOST","h"),true).load(id));
        backend.loseAck=true;reject(()->svc.execute("service",request));check(store.load(id).pending()!=null&&backend.get(PUBLICATIONS,pub)!=null,"ambiguous create retains outbox");
        backend.conflict=true;check(svc.execute("service",request)==Status.CONFLICT&&store.load(id).pending()!=null,"CAS conflict retains outbox");
        check(svc.execute("service",request)==Status.RECOVERED&&store.load(id).pending()==null,"immutable replay and CAS acknowledgement");
        check(!store.compareAndSet(id,staged,new Envelope(staged.token()+1,staged.state(),null)),"stale expected state rejected");
        store.deliver(request,pending);check(backend.data.size()==2,"already acknowledged retry exact duplicate");
        backend.tamper(PUBLICATIONS,pub,"action","RETRACT");reject(()->store.deliver(request,pending));
        backend.tamper(STATE,id,"payload_digest","0".repeat(64));reject(()->store.load(id));
        System.out.println("WADE Indexer document checks passed: "+checks);
    }
}
