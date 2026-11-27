// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/** Bounded reference correlation over pre-matched, authorized events, not a Sigma parser. */
public final class TemporalCorrelation {
    private TemporalCorrelation() {}
    public enum Mode { ORDERED, UNORDERED }
    public enum Status { MATCH, NO_MATCH, UNKNOWN, NOT_READY }
    public record Rule(List<String> stages, Mode mode, Duration span, int maxInputs) {
        public Rule {
            stages = List.copyOf(stages);
            Objects.requireNonNull(mode); Objects.requireNonNull(span);
            if (stages.size() < 2 || stages.size() > 16 || new HashSet<>(stages).size() != stages.size()
                || stages.stream().anyMatch(s -> !valid(s)) || span.isZero() || span.isNegative()
                || span.compareTo(Duration.ofDays(31)) > 0 || maxInputs < stages.size() || maxInputs > 10000)
                throw new IllegalArgumentException("invalid temporal rule");
        }
    }
    public record Event(String scope, String source, Instant time, Set<String> stages) {
        public Event {
            if (!valid(scope) || !valid(source)) throw new IllegalArgumentException("invalid event key");
            Objects.requireNonNull(time); stages = Set.copyOf(stages);
            if (stages.size() > 16 || stages.stream().anyMatch(s -> !valid(s)))
                throw new IllegalArgumentException("invalid stage set");
        }
    }
    public record Result(Status status, String reason, List<Event> evidence) {
        public Result { evidence = List.copyOf(evidence); }
    }
    private static boolean valid(String s) { return s != null && !s.isBlank() && s.length() <= 1024; }
    private static Result empty(Status s, String why) { return new Result(s, why, List.of()); }

    public static Result evaluate(Rule rule, String scope, Instant start, Instant end,
                                  Instant watermark, boolean complete, List<Event> inputs) {
        Objects.requireNonNull(rule); Objects.requireNonNull(start); Objects.requireNonNull(end);
        Objects.requireNonNull(watermark); Objects.requireNonNull(inputs);
        if (!valid(scope) || !start.isBefore(end) || Duration.between(start, end).compareTo(Duration.ofDays(31)) > 0)
            throw new IllegalArgumentException("invalid window/scope");
        if (inputs.size() > rule.maxInputs()) return empty(Status.UNKNOWN, "INPUT_LIMIT");
        Map<String, Event> unique = new HashMap<>();
        for (Event e : inputs) {
            if (!scope.equals(e.scope())) return empty(Status.UNKNOWN, "SCOPE_MISMATCH");
            if (e.time().isBefore(start) || !e.time().isBefore(end)) continue;
            Event previous = unique.putIfAbsent(e.source(), e);
            if (previous != null && !previous.equals(e)) return empty(Status.UNKNOWN, "CONFLICTING_SOURCE");
        }
        if (watermark.isBefore(end)) return empty(Status.NOT_READY, "WINDOW_OPEN");
        if (!complete) return empty(Status.UNKNOWN, "INCOMPLETE_COVERAGE");
        List<Event> events = unique.values().stream().sorted(Comparator.comparing(Event::time)
            .thenComparing(Event::source)).toList();
        // Bound ambiguous matching cost: at most 16 stages, 10k candidates and 250k search steps.
        int[] budget = {250000};
        for (int left = 0; left < events.size(); left++) {
            if (--budget[0] < 0) return empty(Status.UNKNOWN, "WORK_LIMIT");
            Event first = events.get(left);
            if (rule.mode() == Mode.ORDERED && !first.stages().contains(rule.stages().get(0))) continue;
            List<Event> chosen = new ArrayList<>();
            Set<String> used = new HashSet<>();
            if (match(rule, events, left, first.time(), 0, chosen, used, budget))
                return new Result(Status.MATCH, "TEMPORAL_MATCH", chosen);
            if (budget[0] < 0) return empty(Status.UNKNOWN, "WORK_LIMIT");
        }
        return empty(Status.NO_MATCH, "NO_SEQUENCE");
    }

    private static boolean match(Rule rule, List<Event> events, int from, Instant anchor, int stage,
                                 List<Event> chosen, Set<String> used, int[] budget) {
        if (stage == rule.stages().size()) return true;
        for (int i = from; i < events.size(); i++) {
            if (--budget[0] < 0) return false;
            Event e = events.get(i);
            if (Duration.between(anchor, e.time()).compareTo(rule.span()) > 0) break;
            if (!e.stages().contains(rule.stages().get(stage)) || used.contains(e.source())) continue;
            // Equal timestamps do not prove ordering; require strictly increasing event time.
            if (rule.mode() == Mode.ORDERED && !chosen.isEmpty()
                && !e.time().isAfter(chosen.get(chosen.size() - 1).time())) continue;
            chosen.add(e); used.add(e.source());
            int next = rule.mode() == Mode.ORDERED ? i + 1 : from;
            if (match(rule, events, next, anchor, stage + 1, chosen, used, budget)) return true;
            chosen.remove(chosen.size() - 1); used.remove(e.source());
            if (budget[0] < 0) return false;
        }
        return false;
    }
}
