// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/** Pure late-evidence decision state machine. Persist state and publication intent atomically. */
public final class FindingReconciliation {
    private FindingReconciliation() {}
    public enum Outcome { MATCH, NO_MATCH, UNKNOWN, NOT_READY }
    public enum Status { NEVER_MATCHED, ACTIVE, RETRACTED }
    public enum Action { NONE, CREATE, AMEND, RETRACT, RESTORE, WITHHELD }
    public record Decision(String windowKey, Instant asOf, Outcome outcome, String receipt, String findingId, String evidenceDigest) {
        public Decision {
            hex(windowKey); Objects.requireNonNull(asOf); Objects.requireNonNull(outcome);
            if (outcome==Outcome.MATCH || outcome==Outcome.NO_MATCH) hex(receipt);
            else if (receipt!=null) hex(receipt);
            if (outcome==Outcome.MATCH) { hex(findingId); hex(evidenceDigest); }
            else if (findingId!=null || evidenceDigest!=null) throw new IllegalArgumentException("unexpected finding");
        }
    }
    public record State(String windowKey, long revision, Instant evaluatedAt, Decision last, Status status, String findingId, String evidenceDigest) {
        public State {
            hex(windowKey); Objects.requireNonNull(status);
            if (revision<0 || (revision==0)!=(last==null) || (last==null)!=(evaluatedAt==null)) throw new IllegalArgumentException("invalid state");
            if (last!=null && (!windowKey.equals(last.windowKey()) || !evaluatedAt.equals(last.asOf())
                || (last.outcome()!=Outcome.MATCH && last.outcome()!=Outcome.NO_MATCH))) throw new IllegalArgumentException("invalid last decision");
            if (status==Status.NEVER_MATCHED) {
                if (findingId!=null || evidenceDigest!=null || (last!=null && last.outcome()==Outcome.MATCH)) throw new IllegalArgumentException("invalid empty finding");
            } else {
                hex(findingId); hex(evidenceDigest);
                if (last==null || (status==Status.ACTIVE && (last.outcome()!=Outcome.MATCH || !findingId.equals(last.findingId()) || !evidenceDigest.equals(last.evidenceDigest())))
                    || (status==Status.RETRACTED && last.outcome()!=Outcome.NO_MATCH)) throw new IllegalArgumentException("invalid finding state");
            }
        }
        public static State initial(String key) { return new State(key,0,null,null,Status.NEVER_MATCHED,null,null); }
    }
    public record Publication(String id, Action action, String windowKey, long revision, String findingId,
                              String evidenceDigest, String receipt, Instant asOf) {}
    public record Transition(State state, Action action, Publication publication) {}
    public static Decision evaluateCrossWindow(CrossWindowCorrelation.Policy p,String scope,CrossWindowCorrelation.Window w,List<CrossWindowCorrelation.Event> events) {
        String key=CrossWindowCorrelation.logicalKey(p,scope,w);
        var result=CrossWindowCorrelation.evaluate(p,scope,w,events);
        return new Decision(key,w.asOf(),Outcome.valueOf(result.status().name()),result.receipt(),result.findingId(),result.evidenceDigest());
    }
    public static Transition apply(State old,long expectedRevision,Decision d) {
        Objects.requireNonNull(old); Objects.requireNonNull(d);
        if (!old.windowKey().equals(d.windowKey())) throw new IllegalArgumentException("foreign window");
        if (old.revision()!=expectedRevision) throw new IllegalStateException("stale revision");
        if (d.outcome()==Outcome.UNKNOWN || d.outcome()==Outcome.NOT_READY) return new Transition(old,Action.WITHHELD,null);
        if (old.evaluatedAt()!=null) {
            if (d.asOf().isBefore(old.evaluatedAt())) throw new IllegalStateException("stale evaluation");
            if (d.asOf().equals(old.evaluatedAt())) {
                if (!d.equals(old.last())) throw new IllegalStateException("conflicting evaluation at same cutoff");
                return new Transition(old,Action.NONE,null);
            }
        }
        long revision=Math.incrementExact(old.revision());
        Status status=old.status(); Action action=Action.NONE;
        String id=old.findingId(), evidence=old.evidenceDigest();
        if (d.outcome()==Outcome.MATCH) {
            if (id!=null && !id.equals(d.findingId())) throw new IllegalStateException("logical finding identity changed");
            action=switch(status) {
                case NEVER_MATCHED -> Action.CREATE;
                case RETRACTED -> Action.RESTORE;
                case ACTIVE -> Objects.equals(evidence,d.evidenceDigest())?Action.NONE:Action.AMEND;
            };
            status=Status.ACTIVE; id=d.findingId(); evidence=d.evidenceDigest();
        } else if (status==Status.ACTIVE) {
            status=Status.RETRACTED; action=Action.RETRACT;
        }
        State next=new State(old.windowKey(),revision,d.asOf(),d,status,id,evidence);
        Publication output=null;
        if (action!=Action.NONE) {
            String outputId=hash("wade-reconcile-v1",old.windowKey(),Long.toString(revision),action.name(),id,evidence,d.receipt(),d.asOf().toString());
            output=new Publication(outputId,action,old.windowKey(),revision,id,evidence,d.receipt(),d.asOf());
        }
        return new Transition(next,action,output);
    }
    private static void hex(String s) {
        if (s==null || !s.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid digest");
    }
    private static String hash(String... fields) {
        try {
            MessageDigest d=MessageDigest.getInstance("SHA-256");
            for (String s:fields) { byte[] b=s.getBytes(StandardCharsets.UTF_8); d.update(ByteBuffer.allocate(4).putInt(b.length).array()); d.update(b); }
            return HexFormat.of().formatHex(d.digest());
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
