/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.setup.incident;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Current-state cohort metrics. This is not a historical as-of reconstruction. */
public final class IncidentMetrics {
    public static final int MAX_RECORDS = 5000;
    private static final Set<String> STATUSES = Set.of("new", "triaging", "active", "closed");
    private static final Set<String> SEVERITIES = Set.of("informational", "low", "medium", "high", "critical");
    private static final Set<String> CLASSIFICATIONS = Set.of("true_positive", "benign_positive", "false_positive", "undetermined", "duplicate");
    private IncidentMetrics() {}

    public record Query(Instant from, Instant until, int triageTargetSeconds, int resolutionTargetSeconds) {
        public Query {
            if (from == null || until == null || !from.isBefore(until) ||
                    from.isBefore(Instant.parse("2000-01-01T00:00:00Z")) ||
                    until.isAfter(Instant.parse("2100-01-01T00:00:00Z")) ||
                    until.isAfter(from.plus(Duration.ofDays(31))) ||
                    triageTargetSeconds < 1 || triageTargetSeconds > 86400 ||
                    resolutionTargetSeconds < 1 || resolutionTargetSeconds > 604800) {
                throw new IllegalArgumentException("Invalid metrics period or SLA targets");
            }
        }
    }

    public static Map<String, Object> summarize(Query query, Instant observedAt, List<Map<String, Object>> records) {
        if (records.size() > MAX_RECORDS || observedAt.isBefore(query.until())) {
            throw new IllegalArgumentException("Incomplete or future metrics cohort");
        }
        var cohortStatuses = counts(STATUSES);
        var classifications = counts(CLASSIFICATIONS);
        var backlogSeverities = counts(SEVERITIES);
        var ages = counts(Set.of("lt_1h", "1h_to_24h", "1d_to_7d", "gte_7d", "unknown"));
        var workload = new TreeMap<String, Integer>();
        var identifiers = new java.util.HashSet<String>();
        var assignment = new Metric(0);
        var triage = new Metric(query.triageTargetSeconds());
        var resolution = new Metric(query.resolutionTargetSeconds());
        var firstClosure = new Metric(0);
        int cohort = 0, backlog = 0, unassigned = 0, reopened = 0, unknownClassification = 0;
        int unknownSeverity = 0, invalidCreated = 0, pendingAudit = 0;
        int openResolutionBreached = 0, openResolutionUnknown = 0, openTriageBreached = 0, openTriageUnknown = 0;
        for (var record : records) {
            if (!(record.get("id") instanceof String id) || !identifiers.add(id)) throw new IllegalArgumentException("Invalid or duplicate incident identity");
            String status = record.get("status") instanceof String value ? value : "";
            if (!STATUSES.contains(status)) throw new IllegalArgumentException("Unknown incident status");
            Instant created = time(record.get("created_at"));
            boolean validCreated = created != null && !created.isAfter(observedAt);
            if (!validCreated) invalidCreated++;
            boolean open = !"closed".equals(status);
            if (open) {
                backlog++;
                Object owner = record.get("owner");
                if (owner == null) unassigned++;
                else if (owner instanceof String name && !name.isBlank()) workload.merge(name, 1, Integer::sum);
                else throw new IllegalArgumentException("Invalid owner");
                String severity = record.get("severity") instanceof String value ? value : "";
                if (SEVERITIES.contains(severity)) backlogSeverities.merge(severity, 1, Integer::sum);
                else unknownSeverity++;
                Long age = duration(created, observedAt, observedAt);
                ages.merge(age == null ? "unknown" : age < 3600000L ? "lt_1h" : age < 86400000L ? "1h_to_24h" :
                        age < 604800000L ? "1d_to_7d" : "gte_7d", 1, Integer::sum);
                if (age == null) openResolutionUnknown++;
                else if (age >= query.resolutionTargetSeconds() * 1000L) openResolutionBreached++;
                if (!"active".equals(status) && record.get("activated_at") == null) {
                    Instant started = time(record.get("triage_started_at"));
                    Long elapsed = duration(started, observedAt, observedAt);
                    if (elapsed == null || !validCreated || started.isBefore(created)) openTriageUnknown++;
                    else if (elapsed >= query.triageTargetSeconds() * 1000L) openTriageBreached++;
                } else if ("active".equals(status) && time(record.get("activated_at")) == null) openTriageUnknown++;
            }
            if (!validCreated || created.isBefore(query.from()) || !created.isBefore(query.until())) continue;
            cohort++;
            cohortStatuses.merge(status, 1, Integer::sum);
            if (record.get("pending_activity") != null) pendingAudit++;
            if (record.get("reopened_at") != null) {
                Instant reopenedAt = time(record.get("reopened_at"));
                if (reopenedAt == null || reopenedAt.isBefore(created) || reopenedAt.isAfter(observedAt)) throw new IllegalArgumentException("Invalid reopen timestamp");
                reopened++;
            }
            assignment.add(created, record.get("first_assigned_at"), observedAt);
            Instant started = time(record.get("triage_started_at"));
            triage.add(started != null && !started.isBefore(created) ? started : null, record.get("activated_at"), observedAt);
            firstClosure.add(created, record.get("first_closed_at"), observedAt);
            // Current closed cohort only; reopened/open incidents do not count as resolved.
            if (!open) {
                resolution.add(created, record.get("closed_at"), observedAt);
                Object closure = record.get("closure");
                Object classification = closure instanceof Map<?, ?> map ? map.get("classification") : null;
                if (classification instanceof String value && CLASSIFICATIONS.contains(value)) classifications.merge(value, 1, Integer::sum);
                else unknownClassification++;
            }
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("scope", "current_state_creation_cohort_and_open_backlog");
        result.put("from", query.from().toString()); result.put("until", query.until().toString());
        result.put("observed_at", observedAt.toString()); result.put("scanned", records.size());
        result.put("cohort_count", cohort); result.put("cohort_statuses", cohortStatuses);
        result.put("reopened_incidents", reopened); result.put("cohort_pending_audit", pendingAudit);
        result.put("invalid_created_records", invalidCreated);
        result.put("classifications", classifications); result.put("unknown_classification", unknownClassification);
        result.put("open_backlog", backlog); result.put("unassigned", unassigned);
        result.put("backlog_severities", backlogSeverities); result.put("unknown_severity", unknownSeverity);
        result.put("backlog_age_buckets", ages);
        result.put("owner_workload", workload.entrySet().stream().map(e -> Map.of("owner", e.getKey(), "open", e.getValue())).toList());
        result.put("open_resolution_breached", openResolutionBreached); result.put("open_resolution_unknown", openResolutionUnknown);
        result.put("open_triage_breached", openTriageBreached); result.put("open_triage_unknown", openTriageUnknown);
        result.put("creation_to_first_assignment", assignment.result());
        result.put("mttt", triage.result()); result.put("mttr", resolution.result()); result.put("creation_to_first_close", firstClosure.result());
        result.put("mtti_available", false);
        return result;
    }

    private static Map<String, Integer> counts(Set<String> keys) {
        var result = new TreeMap<String, Integer>();
        keys.forEach(key -> result.put(key, 0));
        return result;
    }

    private static Instant time(Object value) {
        if (!(value instanceof String text)) return null;
        try { return Instant.parse(text); } catch (RuntimeException e) { return null; }
    }

    private static Long duration(Instant start, Instant end, Instant observedAt) {
        if (start == null || end == null || end.isBefore(start) || end.isAfter(observedAt)) return null;
        try { return Duration.between(start, end).toMillis(); } catch (ArithmeticException e) { return null; }
    }

    private static final class Metric {
        private final int target;
        private final List<Long> samples = new ArrayList<>();
        private int missing, invalid, breached;
        Metric(int target) { this.target = target; }
        void add(Instant start, Object rawEnd, Instant observedAt) {
            if (rawEnd == null) { missing++; return; }
            Long millis = duration(start, time(rawEnd), observedAt);
            if (millis == null) { invalid++; return; }
            samples.add(millis);
            if (target > 0 && millis >= target * 1000L) breached++;
        }
        Map<String, Object> result() {
            var sorted = samples.stream().sorted().toList();
            int n = sorted.size();
            var result = new LinkedHashMap<String, Object>();
            result.put("samples", n); result.put("missing", missing); result.put("invalid", invalid);
            result.put("mean_seconds", n == 0 ? null : sorted.stream().mapToDouble(value -> value / 1000d).average().orElseThrow());
            result.put("p50_seconds", n == 0 ? null : sorted.get((n - 1) / 2) / 1000d);
            result.put("p95_seconds", n == 0 ? null : sorted.get((int) Math.ceil(n * 0.95) - 1) / 1000d);
            if (target > 0) {
                result.put("target_seconds", target); result.put("met", n - breached); result.put("breached", breached);
            }
            return result;
        }
    }
}
