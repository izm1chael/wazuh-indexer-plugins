// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.TemporalAdmission.*;
import static com.wazuh.wade.PairedTemporalReplay.*;
public final class PairedTemporalReplayTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("t","cluster","AGENT","001");
    private static final String INDEX=".ds-wazuh-events-v5-auth-000001";
    private static int checks, reads;private static boolean complete=true,allowed=true;
    private static Instant t(int n){return T.plusSeconds(n);}
    private static Definition def(String version,String outcome){return new Definition("t","r",version,CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),10,1000,List.of(new Stage("a",Map.of("event.kind","event","event.outcome","failure")),new Stage("b",Map.of("event.kind","event","event.outcome",outcome))));}
    private static Row row(String id,int time,int available,String outcome){return new Row(INDEX,"uuid",id,"001",t(time),t(available),Map.of("event.kind",List.of("event"),"event.outcome",List.of(outcome)));}
    private static void check(boolean ok,String msg){if(!ok)throw new AssertionError(msg);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|SecurityException e){checks++;}}
    public static void main(String[] args){
        List<Row> rows=new ArrayList<>(List.of(row("a",-1,0,"failure"),row("b",1,2,"success"),row("c",2,11,"other")));
        var replay=new PairedTemporalReplay((actor,a,b,c)->{if(!allowed)throw new SecurityException();},r->new Inventory(true,List.of(new Partition(INDEX,"uuid",S,t(-10),t(10)))),(p,from,to,limit)->{reads++;return new Batch(complete,rows);},Clock.fixed(t(30),ZoneOffset.UTC));
        var a=def("1","success");var b=def("2","other");var c=new Case("a".repeat(64),S,T,t(10),t(10),Label.BENIGN,false,"c".repeat(64));
        var report=replay.run("analyst",a,b,List.of(c),1,1);
        check(reads==1,"one shared acquisition");check(report.rows().get(0).champion()==Outcome.MATCH&&report.rows().get(0).challenger()==Outcome.NO_MATCH,"actual paired matching and future exclusion");
        check(report.cohortJson().contains("\"champion\":\"MATCH\"")&&!report.cohortJson().contains("uuid"),"dashboard import and no raw source");
        Collections.reverse(rows);check(report.equals(replay.run("analyst",a,b,List.of(c),1,1)),"input order invariant");
        var later=new Case(c.id(),S,T,t(10),t(11),Label.BENIGN,false,c.labelReceipt());check(replay.run("analyst",a,b,List.of(later),1,1).rows().get(0).challenger()==Outcome.MATCH,"late source changes decision");
        check(!report.receipt().equals(replay.run("analyst",a,b,List.of(c),2,1).receipt()),"policy minimum bound");
        complete=false;var bad=replay.run("analyst",a,b,List.of(c),1,1);check(bad.rows().get(0).champion()==Outcome.UNKNOWN&&bad.rows().get(0).challenger()==Outcome.UNKNOWN,"partial source withheld both");complete=true;
        allowed=false;int before=reads;reject(()->replay.run("analyst",a,b,List.of(c),1,1));check(before==reads,"denial before source acquisition");allowed=true;
        reject(()->replay.run("analyst",a,b,List.of(c,c),1,1));reject(()->replay.run("analyst",a,a,List.of(c),1,1));
        rows.add(row("a",-1,0,"failure"));check(replay.run("analyst",a,b,List.of(c),1,1).rows().get(0).champion()==Outcome.UNKNOWN,"duplicate source rejected");
        System.out.println("WADE paired replay checks passed: "+checks);
    }
}
