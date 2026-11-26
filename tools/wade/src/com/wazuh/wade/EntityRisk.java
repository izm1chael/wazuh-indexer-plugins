// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/** Pure, explainable point-in-time risk projection. Scores are not probabilities. */
public final class EntityRisk {
    private EntityRisk() {}
    public record Policy(String version, Duration halfLife, double threshold, double familyCap, int maxSignals) {
        public Policy {
            key(version); Objects.requireNonNull(halfLife);
            if (halfLife.compareTo(Duration.ofSeconds(1)) < 0 || halfLife.compareTo(Duration.ofDays(365)) > 0
                || !bounded(threshold, 100) || threshold == 0 || !bounded(familyCap, 100)
                || familyCap == 0 || maxSignals < 1 || maxSignals > 10000)
                throw new IllegalArgumentException("invalid risk policy");
        }
    }
    public record Signal(String scope, String id, String family, String evidenceGroup, Instant observed,
                         double weight, double confidence, double criticality) {
        public Signal {
            key(scope); key(id); key(family); key(evidenceGroup); Objects.requireNonNull(observed);
            if (!bounded(weight, 100) || !bounded(confidence, 1) || !bounded(criticality, 2))
                throw new IllegalArgumentException("invalid signal weights");
        }
    }
    public record Contribution(String family, String evidenceGroup, String signalId, double points) {}
    public record Projection(String version, Instant asOf, double score, boolean thresholdMet,
                             List<Contribution> contributions) {
        public Projection { contributions = List.copyOf(contributions); }
    }
    private static boolean bounded(double x, double max) { return Double.isFinite(x) && x >= 0 && x <= max; }
    private static void key(String s) {
        if (s == null || s.isBlank() || s.length() > 1024) throw new IllegalArgumentException("invalid key");
    }
    public static Projection project(Policy policy, String scope, Instant asOf, List<Signal> signals) {
        Objects.requireNonNull(policy); key(scope); Objects.requireNonNull(asOf); Objects.requireNonNull(signals);
        if (signals.size() > policy.maxSignals()) throw new IllegalArgumentException("signal limit");
        Map<String, Signal> byId = new HashMap<>();
        Map<String, Contribution> groups = new TreeMap<>();
        for (Signal signal : signals) {
            if (!scope.equals(signal.scope())) throw new IllegalArgumentException("scope mismatch");
            if (signal.observed().isAfter(asOf)) throw new IllegalArgumentException("future signal");
            Signal old = byId.putIfAbsent(signal.id(), signal);
            if (old != null && !old.equals(signal)) throw new IllegalArgumentException("conflicting signal");
            if (old != null) continue;
            double age = Duration.between(signal.observed(), asOf).toMillis() / 1000.0;
            double decay = Math.pow(0.5, age / (policy.halfLife().toMillis() / 1000.0));
            double points = Math.min(100, signal.weight() * signal.confidence() * signal.criticality() * decay);
            Contribution c = new Contribution(signal.family(), signal.evidenceGroup(), signal.id(), points);
            groups.merge(signal.evidenceGroup(), c, (a,b) -> a.points() > b.points() ||
                (a.points() == b.points() && a.signalId().compareTo(b.signalId()) <= 0) ? a : b);
        }
        Map<String, Double> familyTotals = new TreeMap<>();
        List<Contribution> admitted = new ArrayList<>();
        for (Contribution c : groups.values()) {
            double current = familyTotals.getOrDefault(c.family(), 0.0);
            double points = Math.min(c.points(), Math.max(0, policy.familyCap() - current));
            familyTotals.put(c.family(), current + points);
            admitted.add(new Contribution(c.family(), c.evidenceGroup(), c.signalId(), points));
        }
        double score = Math.min(100, familyTotals.values().stream().mapToDouble(Double::doubleValue).sum());
        return new Projection(policy.version(), asOf, score, score >= policy.threshold(), admitted);
    }
}
