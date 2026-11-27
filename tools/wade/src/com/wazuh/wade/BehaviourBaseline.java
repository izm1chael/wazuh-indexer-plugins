// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Instant;
import java.util.*;

/** Robust, point-in-time baseline for one pre-scoped numeric feature; no automatic learning. */
public final class BehaviourBaseline {
    private BehaviourBaseline() {}
    public enum Status { NORMAL, ANOMALOUS, UNKNOWN }
    public record Sample(String id, Instant observed, double value, boolean approvedForTraining) {
        public Sample {
            if (id == null || id.isBlank() || id.length() > 1024 || !valid(value))
                throw new IllegalArgumentException("invalid sample");
            Objects.requireNonNull(observed);
        }
    }
    public record Policy(int minSamples, int maxSamples, double zThreshold, double scaleFloor) {
        public Policy {
            if (minSamples < 3 || maxSamples < minSamples || maxSamples > 10000 || !valid(zThreshold)
                || zThreshold <= 0 || !valid(scaleFloor) || scaleFloor <= 0)
                throw new IllegalArgumentException("invalid baseline policy");
        }
    }
    public record Result(Status status, String reason, int samples, Double median, Double mad, Double robustZ) {}
    private static boolean valid(double x) { return Double.isFinite(x) && Math.abs(x) <= 1e12; }
    public static Result evaluate(Policy p, Instant asOf, double observed, boolean complete, List<Sample> history) {
        Objects.requireNonNull(p); Objects.requireNonNull(asOf); Objects.requireNonNull(history);
        if (!valid(observed)) throw new IllegalArgumentException("invalid observation");
        if (!complete) return unknown("INCOMPLETE_COVERAGE", 0);
        if (history.size() > p.maxSamples()) return unknown("INPUT_LIMIT", 0);
        Map<String, Sample> unique = new HashMap<>();
        for (Sample s : history) {
            if (!s.observed().isBefore(asOf)) return unknown("NON_CAUSAL_SAMPLE", 0);
            Sample old = unique.putIfAbsent(s.id(), s);
            if (old != null && !old.equals(s)) return unknown("CONFLICTING_SAMPLE", 0);
        }
        double[] values = unique.values().stream().filter(Sample::approvedForTraining).mapToDouble(Sample::value).sorted().toArray();
        if (values.length < p.minSamples()) return unknown("WARMUP", values.length);
        double median = median(values);
        double[] deviations = Arrays.stream(values).map(v -> Math.abs(v - median)).sorted().toArray();
        double mad = median(deviations);
        double scale = Math.max(p.scaleFloor(), 1.4826 * mad);
        double z = Math.abs(observed - median) / scale;
        if (!Double.isFinite(z)) return unknown("NUMERIC_LIMIT", values.length);
        return new Result(z >= p.zThreshold() ? Status.ANOMALOUS : Status.NORMAL,
            "ROBUST_DEVIATION", values.length, median, mad, z);
    }
    private static Result unknown(String reason, int n) { return new Result(Status.UNKNOWN, reason, n, null, null, null); }
    private static double median(double[] sorted) {
        int mid = sorted.length / 2;
        return sorted.length % 2 == 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
    }
}
