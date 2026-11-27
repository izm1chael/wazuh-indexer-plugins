// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;

public final class FeatureHistoryTests {
    private static final Instant T = Instant.parse("2026-11-26T00:00:00Z");
    private static int checks;
    private static void check(boolean ok,String message) { if (!ok) throw new AssertionError(message); checks++; }
    private static FeatureHistory.Feature feature(String receipt,int start,double value,boolean approved) {
        Instant s=T.plusSeconds(start), e=s.plusSeconds(10);
        return new FeatureHistory.Feature("scope","v1","count",s,e,e,approved?e:null,value,true,receipt.repeat(64));
    }
    public static void main(String[] args) {
        var p=new BehaviourBaseline.Policy(3,20,3,1);
        var a=feature("a",-30,10,true); var b=feature("b",-20,10,true); var c=feature("c",-10,11,true);
        var current=feature("d",0,20,false); var future=feature("e",10,100,true);
        var r=FeatureHistory.behaviour(p,current,T.plusSeconds(10),List.of(a,b,c,future));
        check(r.result().status()==BehaviourBaseline.Status.ANOMALOUS && r.result().samples()==3,"causal baseline");
        check(r.receipts().size()==4 && !r.receipts().contains(future.receipt()),"admitted receipts only");
        check(r.equals(FeatureHistory.behaviour(p,current,T.plusSeconds(10),List.of(c,b,a,a))),"order and exact duplicate invariant");
        check(FeatureHistory.behaviour(p,current,T,List.of(a,b,c)).result().status()==BehaviourBaseline.Status.UNKNOWN,"unavailable current");
        check(FeatureHistory.behaviour(p,current,T.plusSeconds(10),List.of(a,b,feature("f",-15,10,true))).result().reason().equals("OVERLAPPING_HISTORY"),"overlap withheld");
        var late=new FeatureHistory.Feature("scope","v1","count",c.start(),c.end(),c.available(),T.plusSeconds(1),c.value(),true,c.receipt());
        check(FeatureHistory.behaviour(p,current,T.plusSeconds(10),List.of(a,b,late)).result().samples()==2,"future approval excluded");
        var foreign=new FeatureHistory.Feature("other","v1","count",a.start(),a.end(),a.available(),a.approved(),a.value(),true,a.receipt());
        check(FeatureHistory.behaviour(p,current,T.plusSeconds(10),List.of(foreign)).result().reason().equals("FEATURE_SCOPE_MISMATCH"),"foreign scope");
        var policy=new EntityRisk.Policy("1",Duration.ofSeconds(60),40,60,10);
        var signal=new EntityRisk.Signal("scope","s","auth","group",T.minusSeconds(60),100,1,1);
        var observed=new FeatureHistory.Signal(signal,T.minusSeconds(30),"a".repeat(64));
        var withheld=new FeatureHistory.Signal(new EntityRisk.Signal("scope","s2","auth","other",T,100,1,1),T.plusSeconds(1),"b".repeat(64));
        var risk=FeatureHistory.risk(policy,"scope",T,true,List.of(observed,withheld,observed));
        check(risk.projection().score()==50 && risk.projection().thresholdMet() && risk.receipts().size()==1,"causal risk projection");
        check(FeatureHistory.risk(policy,"scope",T,false,List.of(observed)).projection()==null,"incomplete ledger no risk number");
        check(FeatureHistory.risk(policy,"other",T,true,List.of(observed)).projection()==null,"foreign ledger withheld");
        check(FeatureHistory.risk(policy,"scope",T,true,List.of(observed,new FeatureHistory.Signal(signal,T,"c".repeat(64)))).projection()==null,"conflicting signal withheld");
        System.out.println("WADE feature checks passed: "+checks);
    }
}
