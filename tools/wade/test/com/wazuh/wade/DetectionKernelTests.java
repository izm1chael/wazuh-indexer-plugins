// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Instant;
import java.util.List;
import static com.wazuh.wade.DetectionKernel.*;

/** Dependency-free executable regression suite; throws on failure even without -ea. */
public final class DetectionKernelTests {
    private static final Instant START = Instant.parse("2026-11-26T00:00:00Z");
    private static final Window WINDOW = new Window(START, START.plusSeconds(60));
    private static final Scope SCOPE = new Scope("tenant-a", "user", "alice");
    private static final Rule COUNT = new Rule("r", "1", Mode.EVENT_COUNT, 2, 8);
    private static final Rule DISTINCT = new Rule("d", "1", Mode.DISTINCT_VALUE_COUNT, 2, 8);
    private static int passed;

    private static Evidence event(String id, long second, String value) {
        return new Evidence(SCOPE, new Source("events", id), START.plusSeconds(second), value);
    }

    private static Evaluation run(Rule rule, List<Evidence> events) {
        return evaluate(rule, SCOPE, WINDOW, WINDOW.end(), Coverage.COMPLETE, events);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }

    public static void main(String[] args) {
        Evidence a = event("a", 0, "host-a");
        Evidence b = event("b", 59, "host-b");
        Evidence c = event("c", 60, "host-c");
        check(run(COUNT, List.of()).status() == Status.NO_MATCH, "empty complete window");
        check(run(COUNT, List.of(a, a)).status() == Status.NO_MATCH, "duplicates cannot inflate");
        check(run(COUNT, List.of(a, c)).status() == Status.NO_MATCH, "half-open boundary");
        Finding first = run(COUNT, List.of(a, b)).finding();
        check(first != null && first.observedCount() == 2, "threshold and inclusive start");
        check(first.equals(run(COUNT, List.of(b, a, a)).finding()), "order and duplicate invariant");
        Finding expanded = run(COUNT, List.of(a, b, event("late", 30, "host-c"))).finding();
        check(first.id().equals(expanded.id()), "stable logical finding across late replay");
        check(!first.evidenceDigest().equals(expanded.evidenceDigest()), "changed evidence digest");
        check(!first.id().equals(run(new Rule("r", "2", Mode.EVENT_COUNT, 2, 8), List.of(a,b)).finding().id()), "version isolation");
        check(run(DISTINCT, List.of(a, event("x", 1, "host-a"))).status() == Status.NO_MATCH, "distinct count");
        check(run(DISTINCT, List.of(a, b)).status() == Status.MATCH, "distinct match");
        check(run(DISTINCT, List.of(a, event("x", 2, null))).status() == Status.UNKNOWN, "missing field");
        check(run(COUNT, List.of(a, event("a", 1, "host-a"))).status() == Status.UNKNOWN, "conflicting source");
        check(evaluate(COUNT, SCOPE, WINDOW, START, Coverage.COMPLETE, List.of(a,b)).status() == Status.NOT_READY, "open window");
        check(evaluate(COUNT, SCOPE, WINDOW, WINDOW.end(), Coverage.UNKNOWN, List.of(a,b)).status() == Status.UNKNOWN, "missing coverage");
        Evidence foreign = new Evidence(new Scope("tenant-b", "user", "alice"), b.source(), b.eventTime(), b.distinctValue());
        check(run(COUNT, List.of(a, foreign)).status() == Status.UNKNOWN, "scope isolation");
        check(run(new Rule("tiny", "1", Mode.EVENT_COUNT, 1, 1), List.of(a,b)).status() == Status.UNKNOWN, "input limit");
        check(run(COUNT, List.of(a, event("pre", -1, "host-b"))).status() == Status.NO_MATCH, "before window");
        check(first.sources().size() == 2 && first.sources().get(0).equals(a.source()), "ordered provenance");
        try { first.sources().clear(); throw new AssertionError("mutable sources"); }
        catch (UnsupportedOperationException expected) { passed++; }
        try { new Rule("r", "1", Mode.EVENT_COUNT, 0, 8); throw new AssertionError("invalid rule"); }
        catch (IllegalArgumentException expected) { passed++; }
        System.out.println("WADE kernel checks passed: " + passed);
    }
}
