// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Immutable reference state machine. A durable adapter must apply transitions with CAS. */
public final class ExecutionControl {
    private ExecutionControl() {}
    public record State(String job, long revision, long fence, String owner, Instant expires,
                        Instant checkpoint, String receipt) {
        public State {
            key(job); Objects.requireNonNull(expires); Objects.requireNonNull(checkpoint);
            if (revision < 0 || fence < 0 || (owner == null && !expires.equals(Instant.MIN)))
                throw new IllegalArgumentException("invalid state");
            if (owner != null) key(owner);
            if (receipt != null) key(receipt);
        }
    }
    public static State initial(String job, Instant checkpoint) {
        return new State(job,0,0,null,Instant.MIN,checkpoint,null);
    }
    public static State acquire(State s, long revision, String owner, Instant now, Duration ttl) {
        revision(s,revision); key(owner); Objects.requireNonNull(now); Objects.requireNonNull(ttl);
        if (ttl.isZero() || ttl.isNegative() || ttl.compareTo(Duration.ofHours(1)) > 0)
            throw new IllegalArgumentException("invalid lease duration");
        if (s.owner() != null && now.isBefore(s.expires())) throw new IllegalStateException("active lease");
        return new State(s.job(),Math.incrementExact(s.revision()),Math.incrementExact(s.fence()),owner,
            now.plus(ttl),s.checkpoint(),s.receipt());
    }
    /** Receipt must attest that all outputs through the checkpoint have been durably committed. */
    public static State complete(State s, long revision, long fence, String owner, Instant now,
                                 Instant checkpoint, String receipt) {
        revision(s,revision); lease(s,fence,owner,now); key(receipt); Objects.requireNonNull(checkpoint);
        if (!checkpoint.isAfter(s.checkpoint()) || checkpoint.isAfter(now))
            throw new IllegalArgumentException("invalid checkpoint");
        return new State(s.job(),Math.incrementExact(s.revision()),s.fence(),null,Instant.MIN,checkpoint,receipt);
    }
    public static State abandon(State s, long revision, long fence, String owner, Instant now) {
        revision(s,revision); lease(s,fence,owner,now);
        return new State(s.job(),Math.incrementExact(s.revision()),s.fence(),null,Instant.MIN,s.checkpoint(),s.receipt());
    }
    private static void revision(State s,long expected) {
        if (s.revision() != expected) throw new IllegalStateException("stale revision");
    }
    private static void lease(State s,long fence,String owner,Instant now) {
        key(owner); Objects.requireNonNull(now);
        if (s.fence() != fence || !owner.equals(s.owner()) || !now.isBefore(s.expires()))
            throw new IllegalStateException("stale lease");
    }
    private static void key(String s) {
        if (s == null || s.isBlank() || s.length() > 1024) throw new IllegalArgumentException("invalid key");
    }
}
