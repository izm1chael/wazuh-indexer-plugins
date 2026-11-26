// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/** Reference telemetry health and labelled replay metrics; no inference from missing data. */
public final class DetectionQuality {
    private DetectionQuality() {}
    public enum Health { COMPLETE, UNKNOWN, DEGRADED }
    public enum Outcome { MATCH, NO_MATCH, UNKNOWN }
    public enum Label { MALICIOUS, BENIGN, UNLABELLED }
    public record Source(String id, Instant heartbeat, boolean schemaValid, boolean queryComplete) {
        public Source { key(id); }
    }
    public record Coverage(Health health,List<String> reasons) {
        public Coverage { reasons = List.copyOf(reasons); }
    }
    public static Coverage coverage(Set<String> required, List<Source> sources, Instant asOf, Duration freshness) {
        Objects.requireNonNull(required); Objects.requireNonNull(sources); Objects.requireNonNull(asOf);
        Objects.requireNonNull(freshness);
        if (required.isEmpty() || required.size() > 256 || sources.size() > 1024 || freshness.isNegative() || freshness.isZero())
            throw new IllegalArgumentException("invalid coverage policy");
        Map<String,Source> byId = new HashMap<>();
        for (Source source : sources) {
            Source prior = byId.putIfAbsent(source.id(),source);
            if (prior != null && !prior.equals(source)) return new Coverage(Health.UNKNOWN,List.of("CONFLICTING_SOURCE"));
        }
        List<String> reasons = new ArrayList<>(); boolean degraded = false;
        for (String id : new TreeSet<>(required)) {
            key(id); Source s = byId.get(id);
            if (s == null || s.heartbeat() == null || s.heartbeat().isAfter(asOf)) { reasons.add(id+":UNKNOWN"); continue; }
            if (!s.schemaValid() || !s.queryComplete() || Duration.between(s.heartbeat(),asOf).compareTo(freshness)>0) {
                reasons.add(id+":DEGRADED"); degraded = true;
            }
        }
        return new Coverage(reasons.isEmpty()?Health.COMPLETE:degraded?Health.DEGRADED:Health.UNKNOWN,reasons);
    }
    public record Case(String id, Label label, Outcome outcome) {
        public Case { key(id); Objects.requireNonNull(label); Objects.requireNonNull(outcome); }
    }
    public record Metrics(int tp,int fp,int tn,int fn,int unknownMalicious,int unknownBenign,int unlabelled,
                          Double precision,Double evaluatedRecall,Double conservativeRecall,Double labelledCoverage) {}
    public static Metrics measure(List<Case> cases) {
        Objects.requireNonNull(cases);
        if (cases.size()>100000) throw new IllegalArgumentException("replay limit");
        Map<String,Case> unique = new HashMap<>();
        for (Case c : cases) {
            Case old = unique.putIfAbsent(c.id(),c);
            if (old != null && !old.equals(c)) throw new IllegalArgumentException("conflicting replay case");
        }
        int tp=0,fp=0,tn=0,fn=0,um=0,ub=0,u=0;
        for (Case c : unique.values()) {
            if (c.label()==Label.UNLABELLED) { u++; continue; }
            if (c.label()==Label.MALICIOUS) {
                switch(c.outcome()) { case MATCH -> tp++; case NO_MATCH -> fn++; case UNKNOWN -> um++; }
            } else {
                switch(c.outcome()) { case MATCH -> fp++; case NO_MATCH -> tn++; case UNKNOWN -> ub++; }
            }
        }
        int evaluated=tp+fp+tn+fn;
        return new Metrics(tp,fp,tn,fn,um,ub,u,ratio(tp,tp+fp),ratio(tp,tp+fn),ratio(tp,tp+fn+um),ratio(evaluated,evaluated+um+ub));
    }
    private static Double ratio(int n,int d) { return d==0?null:(double)n/d; }
    private static void key(String id) {
        if (id==null || id.isBlank() || id.length()>1024) throw new IllegalArgumentException("invalid ID");
    }
}
