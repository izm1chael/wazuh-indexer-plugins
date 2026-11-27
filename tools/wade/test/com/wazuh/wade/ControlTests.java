// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;
import static com.wazuh.wade.DetectionQuality.*;

public final class ControlTests {
    private static int checks;
    private static void check(boolean ok,String why) { if(!ok) throw new AssertionError(why); checks++; }
    private static void reject(Runnable r) {
        try { r.run(); throw new AssertionError("expected rejection"); }
        catch (IllegalArgumentException | IllegalStateException expected) { checks++; }
    }
    public static void main(String[] args) {
        Instant t=Instant.parse("2026-11-26T00:00:00Z"); Duration ttl=Duration.ofSeconds(10);
        var s=ExecutionControl.initial("job",t.minusSeconds(60));
        var a=ExecutionControl.acquire(s,0,"a",t,ttl);
        reject(()->ExecutionControl.acquire(a,0,"b",t,ttl));
        reject(()->ExecutionControl.acquire(a,1,"b",t,ttl));
        var b=ExecutionControl.acquire(a,1,"b",t.plusSeconds(10),ttl);
        check(b.fence()==2 && b.checkpoint().equals(s.checkpoint()),"takeover retains checkpoint");
        reject(()->ExecutionControl.complete(b,2,1,"a",t.plusSeconds(11),t,"r"));
        reject(()->ExecutionControl.complete(b,2,2,"b",t.plusSeconds(20),t,"r"));
        reject(()->ExecutionControl.complete(b,2,2,"b",t.plusSeconds(11),s.checkpoint(),"r"));
        reject(()->ExecutionControl.complete(b,2,2,"b",t.plusSeconds(11),t.plusSeconds(12),"r"));
        var c=ExecutionControl.complete(b,2,2,"b",t.plusSeconds(11),t,"r");
        check(c.owner()==null && c.checkpoint().equals(t) && c.receipt().equals("r"),"complete with receipt");
        var d=ExecutionControl.acquire(c,3,"c",t.plusSeconds(12),ttl);
        check(ExecutionControl.abandon(d,4,3,"c",t.plusSeconds(13)).checkpoint().equals(t),"abandon does not advance");
        var healthy=new Source("auth",t,true,true);
        check(coverage(Set.of("auth"),List.of(healthy),t,ttl).health()==Health.COMPLETE,"healthy");
        check(coverage(Set.of("auth","endpoint"),List.of(healthy),t,ttl).health()==Health.UNKNOWN,"missing source");
        check(coverage(Set.of("auth"),List.of(healthy),t.plusSeconds(11),ttl).health()==Health.DEGRADED,"stale");
        check(coverage(Set.of("auth"),List.of(new Source("auth",t,false,true)),t,ttl).health()==Health.DEGRADED,"schema");
        check(coverage(Set.of("auth"),List.of(new Source("auth",t,true,false)),t,ttl).health()==Health.DEGRADED,"partial query");
        check(coverage(Set.of("auth"),List.of(healthy),t.minusSeconds(1),ttl).health()==Health.UNKNOWN,"future heartbeat");
        check(coverage(Set.of("auth"),List.of(healthy,new Source("auth",t,false,true)),t,ttl).health()==Health.UNKNOWN,"conflict");
        var tp=new Case("tp",Label.MALICIOUS,Outcome.MATCH);
        var m=measure(List.of(tp,tp,new Case("fp",Label.BENIGN,Outcome.MATCH),new Case("fn",Label.MALICIOUS,Outcome.NO_MATCH),
            new Case("tn",Label.BENIGN,Outcome.NO_MATCH),new Case("um",Label.MALICIOUS,Outcome.UNKNOWN),new Case("u",Label.UNLABELLED,Outcome.MATCH)));
        check(m.tp()==1 && m.fp()==1 && m.fn()==1 && m.tn()==1,"unique labelled cohort");
        check(m.precision()==0.5 && m.evaluatedRecall()==0.5 && m.conservativeRecall()==1.0/3 && m.labelledCoverage()==0.8,"explicit denominators");
        check(m.unknownMalicious()==1 && m.unlabelled()==1,"unknown and unlabelled visible");
        check(measure(List.of()).precision()==null && measure(List.of()).conservativeRecall()==null,"undefined metrics");
        reject(()->measure(List.of(tp,new Case("tp",Label.BENIGN,Outcome.MATCH))));
        System.out.println("WADE control checks passed: "+checks);
    }
}
