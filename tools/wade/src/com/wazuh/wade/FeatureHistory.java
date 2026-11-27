// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;

/** Causal, scoped input contracts for risk and behavioural projections. No live storage. */
public final class FeatureHistory {
    private FeatureHistory() {}
    public record Feature(String scope, String version, String name, Instant start, Instant end,
                          Instant available, Instant approved, double value, boolean complete, String receipt) {
        public Feature {
            key(scope); key(version); key(name); hex(receipt);
            Objects.requireNonNull(start); Objects.requireNonNull(end); Objects.requireNonNull(available);
            if (!start.isBefore(end) || available.isBefore(end) || (approved != null && approved.isBefore(available))
                || !Double.isFinite(value) || Math.abs(value) > 1e12) throw new IllegalArgumentException("invalid feature");
        }
    }
    public record Signal(EntityRisk.Signal value, Instant available, String receipt) {
        public Signal {
            Objects.requireNonNull(value); Objects.requireNonNull(available); hex(receipt);
            if (available.isBefore(value.observed())) throw new IllegalArgumentException("invalid signal availability");
        }
    }
    public record Behaviour(BehaviourBaseline.Result result, List<String> receipts) {
        public Behaviour { receipts = List.copyOf(receipts); }
    }
    public record Risk(String status, EntityRisk.Projection projection, List<String> receipts) {
        public Risk { receipts = List.copyOf(receipts); }
    }
    public static Behaviour behaviour(BehaviourBaseline.Policy policy, Feature current, Instant asOf, List<Feature> history) {
        Objects.requireNonNull(policy); Objects.requireNonNull(current); Objects.requireNonNull(asOf);
        if (!current.complete() || current.available().isAfter(asOf)) return unknown("CURRENT_UNAVAILABLE");
        if (history.size() > policy.maxSamples()) return unknown("INPUT_LIMIT");
        Map<String,Feature> unique = new TreeMap<>();
        for (Feature f : history) {
            if (!f.scope().equals(current.scope()) || !f.version().equals(current.version()) || !f.name().equals(current.name()))
                return unknown("FEATURE_SCOPE_MISMATCH");
            if (!f.complete() || f.approved() == null || f.approved().isAfter(current.start())) continue;
            if (f.end().isAfter(current.start()) || !Duration.between(f.start(),f.end()).equals(Duration.between(current.start(),current.end())))
                return unknown("INCOMPATIBLE_WINDOW");
            Feature old = unique.putIfAbsent(f.receipt(), f);
            if (old != null && !old.equals(f)) return unknown("CONFLICTING_RECEIPT");
        }
        List<Feature> ordered = unique.values().stream().sorted(Comparator.comparing(Feature::start)).toList();
        Instant end = null;
        List<BehaviourBaseline.Sample> samples = new ArrayList<>();
        for (Feature f : ordered) {
            if (end != null && f.start().isBefore(end)) return unknown("OVERLAPPING_HISTORY");
            end = f.end();
            samples.add(new BehaviourBaseline.Sample(f.receipt(), f.start(), f.value(), true));
        }
        var result = BehaviourBaseline.evaluate(policy,current.start(),current.value(),true,samples);
        List<String> receipts = new ArrayList<>(); receipts.add(current.receipt());
        ordered.forEach(f -> receipts.add(f.receipt()));
        return new Behaviour(result,receipts);
    }
    public static Risk risk(EntityRisk.Policy policy, String scope, Instant asOf, boolean ledgerComplete, List<Signal> history) {
        Objects.requireNonNull(policy); key(scope); Objects.requireNonNull(asOf);
        if (!ledgerComplete || history.size() > policy.maxSignals()) return new Risk("UNKNOWN",null,List.of());
        Map<String,Signal> visible = new TreeMap<>();
        for (Signal s : history) {
            if (!scope.equals(s.value().scope())) return new Risk("UNKNOWN",null,List.of());
            if (s.available().isAfter(asOf)) continue;
            Signal old = visible.putIfAbsent(s.value().id(),s);
            if (old != null && !old.equals(s)) return new Risk("UNKNOWN",null,List.of());
        }
        var projection = EntityRisk.project(policy,scope,asOf,visible.values().stream().map(Signal::value).toList());
        return new Risk("COMPLETE",projection,visible.values().stream().map(Signal::receipt).toList());
    }
    private static Behaviour unknown(String reason) {
        return new Behaviour(new BehaviourBaseline.Result(BehaviourBaseline.Status.UNKNOWN,reason,0,null,null,null),List.of());
    }
    private static void key(String s) {
        if (s == null || s.isBlank() || s.length() > 1024) throw new IllegalArgumentException("invalid key");
    }
    private static void hex(String s) {
        if (s == null || !s.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid receipt");
    }
}
