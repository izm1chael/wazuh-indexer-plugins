// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.util.Objects;

/** Immutable promotion policy. Receipts and principal permissions must be verified by an adapter. */
public final class RuleLifecycle {
    private RuleLifecycle() {}
    public enum Stage { DRAFT, VALIDATED, SHADOW, APPROVED, ACTIVE, RETIRED }
    public enum Action { VALIDATE, START_SHADOW, APPROVE, ACTIVATE, RETIRE }
    public record Revision(String tenant,String ruleId,String version,String digest,String author,Stage stage,long sequence) {
        public Revision {
            key(tenant); key(ruleId); key(version); key(author); sha(digest); Objects.requireNonNull(stage);
            if(sequence<0) throw new IllegalArgumentException("invalid sequence");
        }
    }
    public record Evidence(String digest,String receipt,boolean passed) {
        public Evidence { sha(digest); key(receipt); }
    }
    public static Revision transition(Revision r,long expected,Action action,String actor,boolean authorized,
                                      Evidence evidence,boolean productionEnabled) {
        Objects.requireNonNull(r); Objects.requireNonNull(action); key(actor);
        if(!authorized) throw new IllegalStateException("unauthorized");
        if(expected!=r.sequence()) throw new IllegalStateException("stale revision");
        Stage next=switch(action) {
            case VALIDATE -> { require(r,Stage.DRAFT,evidence); yield Stage.VALIDATED; }
            case START_SHADOW -> { require(r,Stage.VALIDATED,evidence); yield Stage.SHADOW; }
            case APPROVE -> {
                require(r,Stage.SHADOW,evidence);
                if(actor.equals(r.author())) throw new IllegalStateException("independent approver required");
                yield Stage.APPROVED;
            }
            case ACTIVATE -> {
                require(r,Stage.APPROVED,evidence);
                if(!productionEnabled) throw new IllegalStateException("activation disabled");
                yield Stage.ACTIVE;
            }
            case RETIRE -> {
                if(r.stage()!=Stage.ACTIVE) throw new IllegalStateException("not active");
                require(r,Stage.ACTIVE,evidence); yield Stage.RETIRED;
            }
        };
        return new Revision(r.tenant(),r.ruleId(),r.version(),r.digest(),r.author(),next,Math.incrementExact(r.sequence()));
    }
    private static void require(Revision r,Stage stage,Evidence e) {
        if(r.stage()!=stage || e==null || !e.passed() || !r.digest().equals(e.digest()))
            throw new IllegalStateException("missing or mismatched gate evidence");
    }
    private static void key(String x) {
        if(x==null||x.isBlank()||x.length()>1024) throw new IllegalArgumentException("invalid key");
    }
    private static void sha(String x) {
        if(x==null||!x.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid digest");
    }
}
