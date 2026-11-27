// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import static com.wazuh.wade.FindingReconciliation.*;

public final class FindingReconciliationTests {
    private static final String KEY="a".repeat(64), ID="b".repeat(64), E1="c".repeat(64), E2="d".repeat(64), R="e".repeat(64);
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static int checks;
    private static Decision match(int t,String evidence){return new Decision(KEY,T.plusSeconds(t),Outcome.MATCH,R,ID,evidence);}
    private static Decision no(int t){return new Decision(KEY,T.plusSeconds(t),Outcome.NO_MATCH,R,null,null);}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|IllegalStateException expected){checks++;}}
    public static void main(String[] args){
        var initial=State.initial(KEY);
        var negative=apply(initial,0,no(1));
        check(negative.state().revision()==1 && negative.publication()==null,"negative high-water");
        var create=apply(negative.state(),1,match(2,E1));
        check(create.action()==Action.CREATE && create.state().status()==Status.ACTIVE,"late match create");
        check(create.equals(apply(negative.state(),1,match(2,E1))),"deterministic retry");
        check(apply(create.state(),2,match(2,E1)).state().equals(create.state()),"same cutoff idempotence");
        reject(()->apply(create.state(),1,match(3,E2)));
        reject(()->apply(create.state(),2,match(1,E2)));
        reject(()->apply(create.state(),2,match(2,E2)));
        var unchanged=apply(create.state(),2,match(3,E1));
        check(unchanged.state().revision()==3 && unchanged.publication()==null,"same evidence no duplicate publication");
        var amend=apply(unchanged.state(),3,match(4,E2));
        check(amend.action()==Action.AMEND && !amend.publication().id().equals(create.publication().id()),"new evidence amendment");
        var unknown=apply(amend.state(),4,new Decision(KEY,T.plusSeconds(5),Outcome.UNKNOWN,null,null,null));
        check(unknown.action()==Action.WITHHELD && unknown.state().equals(amend.state()),"unknown never retracts");
        var retract=apply(amend.state(),4,no(6));
        check(retract.action()==Action.RETRACT && retract.state().status()==Status.RETRACTED && retract.publication().findingId().equals(ID),"complete negative retracts same logical finding");
        var repeated=apply(retract.state(),5,no(7));
        check(repeated.action()==Action.NONE && repeated.publication()==null,"no duplicate retraction");
        var restore=apply(repeated.state(),6,match(8,E1));
        check(restore.action()==Action.RESTORE && restore.state().status()==Status.ACTIVE && restore.state().findingId().equals(ID),"restore identity");
        reject(()->apply(restore.state(),7,new Decision(KEY,T.plusSeconds(9),Outcome.MATCH,R,"f".repeat(64),E1)));
        reject(()->apply(restore.state(),7,new Decision("f".repeat(64),T.plusSeconds(9),Outcome.NO_MATCH,R,null,null)));
        check(apply(restore.state(),7,new Decision(KEY,T.plusSeconds(9),Outcome.NOT_READY,null,null,null)).state().equals(restore.state()),"not ready holds");
        var policy=new CrossWindowCorrelation.Policy("r-v1",List.of("a","b"),CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),10,1000);
        var w1=new CrossWindowCorrelation.Window(T,T.plusSeconds(10),T.plusSeconds(10),T.minusSeconds(10),T.plusSeconds(10),true);
        var w2=new CrossWindowCorrelation.Window(T,T.plusSeconds(10),T.plusSeconds(11),T.minusSeconds(10),T.plusSeconds(10),true);
        var w3=new CrossWindowCorrelation.Window(T,T.plusSeconds(10),T.plusSeconds(12),T.minusSeconds(10),T.plusSeconds(10),true);
        var a=new CrossWindowCorrelation.Event("scope","a",T.minusSeconds(1),T,Set.of("a"));
        var b=new CrossWindowCorrelation.Event("scope","b",T.plusSeconds(1),T.plusSeconds(11),Set.of("b"));
        var first=evaluateCrossWindow(policy,"scope",w1,List.of(a,b));
        var negativeWindow=apply(State.initial(first.windowKey()),0,first);
        var late=evaluateCrossWindow(policy,"scope",w2,List.of(a,b));
        var positiveWindow=apply(negativeWindow.state(),1,late);
        check(positiveWindow.action()==Action.CREATE,"actual late cross-window finding");
        var repeatedWindow=evaluateCrossWindow(policy,"scope",w3,List.of(a,b));
        check(!repeatedWindow.receipt().equals(late.receipt()) && repeatedWindow.evidenceDigest().equals(late.evidenceDigest()),"separate snapshot and evidence digests");
        check(apply(positiveWindow.state(),2,repeatedWindow).action()==Action.NONE,"actual replay does not republish unchanged evidence");
        check(evaluateCrossWindow(policy,"other",w2,List.of(a,b)).outcome()==Outcome.UNKNOWN,"actual cross-window scope mismatch withheld");
        System.out.println("WADE reconciliation checks passed: "+checks);
    }
}
