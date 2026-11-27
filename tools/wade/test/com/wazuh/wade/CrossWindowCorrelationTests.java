// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;
import static com.wazuh.wade.CrossWindowCorrelation.*;

public final class CrossWindowCorrelationTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static int checks;
    private static Instant t(int n){return T.plusSeconds(n);}
    private static Event e(String id,int time,int available,String... stages){return new Event("scope",id,t(time),t(available),Set.of(stages));}
    private static Policy p(Mode mode){return new Policy("rule-v1",List.of("a","b"),mode,Duration.ofSeconds(10),100,10000);}
    private static Window w(int start,int end){return new Window(t(start),t(end),t(end),t(start-10),t(end),true);}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    public static void main(String[] args){
        var a=e("a",-3,-2,"a"); var b=e("b",3,4,"b"); var policy=p(Mode.ORDERED);
        var r=evaluate(policy,"scope",w(0,10),List.of(a,b));
        check(r.status()==Status.MATCH && r.sources().equals(List.of("a","b")),"cross-boundary witness");
        check(r.equals(evaluate(policy,"scope",w(0,10),List.of(b,a,a))),"deterministic deduplication");
        check(evaluate(policy,"scope",w(10,20),List.of(a,b)).status()==Status.NO_MATCH,"no repeat in next completion window");
        check(evaluate(policy,"scope",w(0,10),List.of(e("a",-8,-8,"a"),b)).status()==Status.NO_MATCH,"span exceeded");
        check(evaluate(policy,"scope",w(0,10),List.of(e("a",-7,-7,"a"),b)).status()==Status.MATCH,"inclusive span");
        check(evaluate(policy,"scope",w(0,10),List.of(a,e("b",3,11,"b"))).status()==Status.NO_MATCH,"future availability excluded");
        check(evaluate(policy,"scope",new Window(t(0),t(10),t(11),t(-10),t(10),true),List.of(a,e("b",3,11,"b"))).findingId().equals(r.findingId()),"late reevaluation stable ID");
        check(evaluate(policy,"scope",w(0,10),List.of(e("a",3,4,"a"),b)).status()==Status.NO_MATCH,"equal time not order");
        check(evaluate(p(Mode.UNORDERED),"scope",w(0,10),List.of(e("a",3,4,"a"),e("b",-3,-2,"b"))).status()==Status.MATCH,"unordered terminal stage");
        check(evaluate(p(Mode.UNORDERED),"scope",w(0,10),List.of(e("x",3,4,"a","b"))).status()==Status.NO_MATCH,"distinct sources");
        check(evaluate(policy,"scope",new Window(t(0),t(10),t(10),t(-9),t(10),true),List.of(a,b)).reason().equals("INCOMPLETE_LOOKBACK"),"coverage gap");
        check(evaluate(policy,"scope",new Window(t(0),t(10),t(10),t(-10),t(9),true),List.of(a,b)).status()==Status.NOT_READY,"watermark");
        check(evaluate(policy,"scope",w(0,10),List.of(a,e("a",-2,-1,"a"),b)).reason().equals("CONFLICTING_SOURCE"),"conflicting source");
        check(evaluate(policy,"scope",w(0,10),List.of(new Event("other","a",t(-3),t(-2),Set.of("a")),b)).reason().equals("SCOPE_MISMATCH"),"foreign scope");
        check(evaluate(new Policy("r",List.of("a","b"),Mode.ORDERED,Duration.ofSeconds(10),100,1),"scope",w(0,10),List.of(a,b)).reason().equals("WORK_LIMIT"),"budget");
        check(evaluate(policy,"scope",w(0,10),List.of(a,e("old",-1,0,"b"),b)).sources().equals(List.of("a","b")),"older match does not hide new completion");
        check(evaluate(policy,"scope",w(0,10),List.of(a,e("b",10,10,"b"))).status()==Status.NO_MATCH,"half-open completion window");
        check(evaluate(policy,"scope",w(0,10),List.of(a,b,e("other",2,3,"irrelevant"))).findingId().equals(r.findingId()),"stable logical ID");
        check(!evaluate(policy,"scope",w(0,10),List.of(a,b,e("other",2,3,"irrelevant"))).receipt().equals(r.receipt()),"receipt binds admitted snapshot");
        System.out.println("WADE cross-window checks passed: "+checks);
    }
}
