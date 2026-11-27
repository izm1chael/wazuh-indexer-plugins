// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.TemporalAdmission.*;

public final class TemporalAdmissionTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("t","cluster","AGENT","001");
    private static final String INDEX=".ds-wazuh-events-v5-access-management-000001";
    private static final Definition D=new Definition("t","auth-sequence","1",CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),4,1000,List.of(new Stage("failure",Map.of("event.kind","event","event.outcome","failure")),new Stage("success",Map.of("event.kind","event","event.outcome","success"))));
    private static int checks;
    private static Instant t(int n){return T.plusSeconds(n);}
    private static Request request(int cutoff){return new Request(S,D.policy(),T,t(10),t(cutoff));}
    private static Partition part(){return new Partition(INDEX,"uuid",S,t(-10),t(10));}
    private static Row row(String id,int occurred,int available,String outcome){return new Row(INDEX,"uuid",id,"001",t(occurred),t(available),Map.of("event.kind",List.of("event"),"event.outcome",List.of(outcome)));}
    private static void check(boolean b,String msg){if(!b)throw new AssertionError(msg);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|SecurityException e){checks++;}}
    private static final class Fixture {
        Definition approved=D;Inventory inventory=new Inventory(true,List.of(part())); List<Row> rows=new ArrayList<>();int reads;boolean complete=true;
        final TemporalAdmission admission=new TemporalAdmission(r->approved,r->inventory,(p,a,b,l)->{reads++;return new Batch(complete,rows);});
        final Map<String,Envelope> state=new HashMap<>();final Map<String,Pending> outputs=new HashMap<>();
        final Store store=new Store(){public Envelope load(String k){return state.get(k);}public boolean compareAndSet(String k,Envelope a,Envelope b){if(!state.getOrDefault(k,Envelope.initial(k)).equals(a))return false;state.put(k,b);return true;}};
        final WindowService service=new WindowService((a,r,p)->{if(!"service".equals(a))throw new SecurityException();},admission,admission,store,(r,p)->outputs.putIfAbsent(p.publication().id(),p),Clock.fixed(t(30),ZoneOffset.UTC));
    }
    public static void main(String[] args){
        Fixture f=new Fixture();f.rows.add(row("a",-2,-1,"failure"));f.rows.add(row("b",2,11,"success"));
        check(f.service.execute("service",request(10))==Status.NO_CHANGE,"causal negative");
        check(f.service.execute("service",request(11))==Status.STAGED,"actual selected cross-window detection");
        check(f.service.execute("service",request(12))==Status.RECOVERED&&f.outputs.size()==1,"publication delivered");
        check(f.outputs.values().iterator().next().sources().size()==2,"two source refs");
        f.approved=null;int before=f.reads;reject(()->f.service.execute("service",request(13)));check(f.reads==before,"no source on unapproved revision");
        f.approved=new Definition("t","auth-sequence","1",D.mode(),D.span(),4,1000,List.of(new Stage("failure",Map.of("event.kind","event","event.outcome","unknown")),D.stages().get(1)));
        reject(()->f.admission.read(request(13)));check(!f.approved.policy().equals(D.policy()),"selector changes digest");
        f.approved=D;f.inventory=new Inventory(false,List.of(part()));check(!f.admission.read(request(13)).complete()&&f.reads==before,"incomplete inventory no reads");
        f.inventory=new Inventory(true,List.of(part(),new Partition(INDEX+"x","uuid",S,t(-10),t(10))));check(!f.admission.read(request(13)).complete(),"duplicate UUID withheld");
        f.inventory=new Inventory(true,List.of(part()));f.complete=false;check(!f.admission.read(request(13)).complete(),"partial search withheld");f.complete=true;
        f.rows.add(new Row(INDEX,"uuid","c","002",t(3),t(4),Map.of("event.kind",List.of("event"))));check(!f.admission.read(request(13)).complete(),"foreign agent withheld");f.rows.remove(2);
        f.rows.add(new Row(INDEX,"uuid","c","001",t(3),t(4),Map.of("event.kind",List.of("event"))));check(!f.admission.read(request(13)).complete(),"missing selection unknown");f.rows.remove(2);
        f.rows.add(row("a",-2,-1,"failure"));check(!f.admission.read(request(13)).complete(),"duplicate source withheld");f.rows.remove(2);
        f.rows.addAll(List.of(row("c",3,4,"failure"),row("d",4,5,"failure"),row("e",5,6,"failure")));check(!f.admission.read(request(13)).complete(),"aggregate cap withheld");
        reject(()->new Partition("wazuh-events-v5-*","uuid",S,t(-10),t(10)));
        reject(()->new Stage("bad",Map.of("event.kind","event","arbitrary.query","x")));
        System.out.println("WADE temporal admission checks passed: "+checks);
    }
}
