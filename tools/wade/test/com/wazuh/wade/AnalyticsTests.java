// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;

public final class AnalyticsTests {
    private static final Instant T = Instant.parse("2026-11-26T00:00:00Z");
    private static int checks;
    private static void check(boolean ok, String why) { if (!ok) throw new AssertionError(why); checks++; }
    private static TemporalCorrelation.Event event(String id, int t, String... stages) {
        return new TemporalCorrelation.Event("scope", id, T.plusSeconds(t), Set.of(stages));
    }
    private static TemporalCorrelation.Result temporal(TemporalCorrelation.Mode mode, List<TemporalCorrelation.Event> events) {
        return TemporalCorrelation.evaluate(new TemporalCorrelation.Rule(List.of("a", "b"), mode, Duration.ofSeconds(10), 100),
            "scope", T, T.plusSeconds(60), T.plusSeconds(60), true, events);
    }
    private static EntityRisk.Signal signal(String id, String family, String group, int age, double weight) {
        return new EntityRisk.Signal("scope", id, family, group, T.minusSeconds(age), weight, 1, 1);
    }
    private static BehaviourBaseline.Sample sample(String id, int age, double value, boolean approved) {
        return new BehaviourBaseline.Sample(id, T.minusSeconds(age), value, approved);
    }
    public static void main(String[] args) {
        var a = event("a", 0, "a"); var b = event("b", 10, "b");
        var ordered = TemporalCorrelation.Mode.ORDERED; var unordered = TemporalCorrelation.Mode.UNORDERED;
        var match = TemporalCorrelation.Status.MATCH; var no = TemporalCorrelation.Status.NO_MATCH;
        var unknown = TemporalCorrelation.Status.UNKNOWN;
        check(temporal(ordered, List.of(b,a,a)).status() == match, "ordered inclusive span, shuffled duplicates");
        check(temporal(ordered, List.of(event("b",0,"b"),event("a",1,"a"))).status() == no, "reversed ordered");
        check(temporal(unordered, List.of(event("b",0,"b"),event("a",1,"a"))).status() == match, "unordered reversal");
        check(temporal(ordered, List.of(a,event("b",0,"b"))).status() == no, "ties not proof of order");
        check(temporal(unordered, List.of(a,event("b",0,"b"))).status() == match, "unordered equal time");
        check(temporal(ordered, List.of(a,event("b",11,"b"))).status() == no, "outside span");
        check(temporal(unordered, List.of(event("x",0,"a","b"))).status() == no, "distinct evidence");
        check(temporal(unordered, List.of(event("x",0,"a","b"),event("y",1,"a"))).status() == match, "ambiguous assignment backtrack");
        check(temporal(ordered, List.of(a,event("a",1,"a"),b)).status() == unknown, "source conflict");
        check(temporal(ordered, List.of(a,new TemporalCorrelation.Event("other","b",T.plusSeconds(1),Set.of("b")))).status() == unknown, "foreign scope");
        var rule = new TemporalCorrelation.Rule(List.of("a","b"),ordered,Duration.ofSeconds(10),2);
        check(TemporalCorrelation.evaluate(rule,"scope",T,T.plusSeconds(60),T,true,List.of(a,b)).status() == TemporalCorrelation.Status.NOT_READY,"watermark");
        check(TemporalCorrelation.evaluate(rule,"scope",T,T.plusSeconds(60),T.plusSeconds(60),false,List.of(a,b)).status() == unknown,"coverage");
        check(TemporalCorrelation.evaluate(rule,"scope",T,T.plusSeconds(60),T.plusSeconds(60),true,List.of(a,b,a)).status() == unknown,"input bound");
        check(temporal(ordered,List.of(a,b)).equals(temporal(ordered,List.of(b,a,a))),"deterministic evidence");
        var policy = new EntityRisk.Policy("v1",Duration.ofSeconds(60),50,40,100);
        var s1 = signal("s1","auth","g1",0,30); var s2 = signal("s2","auth","g2",0,30);
        var s3 = signal("s3","endpoint","g3",60,40);
        var risk = EntityRisk.project(policy,"scope",T,List.of(s1,s2,s3,s1));
        check(risk.score() == 60 && risk.thresholdMet(),"decay family cap and threshold");
        check(risk.equals(EntityRisk.project(policy,"scope",T,List.of(s3,s2,s1))),"risk deterministic");
        check(EntityRisk.project(policy,"scope",T,List.of(s1,signal("s4","endpoint","g1",0,35))).score() == 35,"cross-family duplicate evidence");
        check(EntityRisk.project(policy,"scope",T,List.of()).score() == 0,"empty risk ledger");
        try { EntityRisk.project(policy,"scope",T,List.of(signal("future","auth","g",-1,20))); throw new AssertionError("future risk"); }
        catch (IllegalArgumentException expected) { checks++; }
        try { EntityRisk.project(policy,"scope",T,List.of(s1,signal("s1","auth","g1",0,40))); throw new AssertionError("conflict"); }
        catch (IllegalArgumentException expected) { checks++; }
        var bp = new BehaviourBaseline.Policy(3,10,3,1);
        var h = List.of(sample("a",3,10,true),sample("b",2,10,true),sample("c",1,11,true),sample("bad",4,1000,false));
        check(BehaviourBaseline.evaluate(bp,T,10,true,h).status() == BehaviourBaseline.Status.NORMAL,"normal and contaminated excluded");
        check(BehaviourBaseline.evaluate(bp,T,20,true,h).status() == BehaviourBaseline.Status.ANOMALOUS,"anomaly with zero MAD floor");
        check(BehaviourBaseline.evaluate(bp,T,20,true,h).samples() == 3,"training admission");
        check(BehaviourBaseline.evaluate(bp,T,20,false,h).status() == BehaviourBaseline.Status.UNKNOWN,"coverage");
        check(BehaviourBaseline.evaluate(bp,T,20,true,List.of(h.get(0),h.get(0))).reason().equals("WARMUP"),"dedup warmup");
        check(BehaviourBaseline.evaluate(bp,T,20,true,List.of(sample("future",0,10,true))).reason().equals("NON_CAUSAL_SAMPLE"),"strict historical boundary");
        check(BehaviourBaseline.evaluate(bp,T,20,true,List.of(h.get(0),sample("a",3,12,true))).reason().equals("CONFLICTING_SAMPLE"),"conflicting history");
        System.out.println("WADE analytics checks passed: " + checks);
    }
}
