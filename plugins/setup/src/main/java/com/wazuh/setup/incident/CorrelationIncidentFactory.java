/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Internal creation only. No request can supply this aggregate or its provenance. */
final class CorrelationIncidentFactory {
    private CorrelationIncidentFactory() {}

    static Map<String, Object> origin(UUID deployment, CorrelationPlanner.Group group) {
        return CorrelationExecutionLedger.immutableFields(deployment, group);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> create(UUID deployment, CorrelationPlanner.Group group, String actor,
            Instant now, List<FindingCaptureReceipt> receipts) {
        var provenance = origin(deployment, group);
        var expected = group.findings().stream().sorted(Comparator.comparing(FindingReference::index)
                .thenComparing(FindingReference::documentId)).toList();
        if (receipts == null || receipts.size() != expected.size() ||
                receipts.stream().anyMatch(r -> r == null || !actor.equals(r.actor()) ||
                        r.seqNo() < 0 || r.primaryTerm() < 1 || r.sha256() == null || !r.sha256().matches("[a-f0-9]{64}") ||
                        r.capturedAt() == null || Instant.parse(r.capturedAt()).isAfter(now))) {
            throw new IllegalArgumentException("Complete attributed capture receipts required");
        }
        var ordered = receipts.stream().sorted(Comparator.comparing((FindingCaptureReceipt r) -> r.reference().index())
                .thenComparing(r -> r.reference().documentId())).toList();
        if (!expected.equals(ordered.stream().map(FindingCaptureReceipt::reference).toList())) {
            throw new IllegalArgumentException("Capture receipts do not match group membership");
        }
        // No inferred detection severity, no source values in the shared title/description.
        var incident = IncidentMutation.create(Map.of("title", "Correlated findings",
                "description", "Created from a correlation policy; review linked findings and classify.",
                "severity", "informational"), UUID.fromString((String) provenance.get("incident_id")), actor, now);
        var references = expected.stream().map(FindingReference::toMap).toList();
        incident.put("findings", references);
        incident.put("finding_count", references.size());
        incident.put("correlation_origin", provenance);
        var event = new LinkedHashMap<>((Map<String, Object>) incident.get("pending_activity"));
        var changes = new LinkedHashMap<>((Map<String, Object>) event.get("changes"));
        changes.put("findings", change(references));
        changes.put("finding_count", change(references.size()));
        changes.put("correlation_origin", change(provenance));
        changes.put("finding_capture_receipts", change(ordered.stream().map(FindingCaptureReceipt::toMap).toList()));
        event.put("changes", changes);
        incident.put("pending_activity", event);
        return incident;
    }

    private static Map<String, Object> change(Object value) {
        var change = new LinkedHashMap<String, Object>();
        change.put("before", null);
        change.put("after", value);
        return change;
    }

    @SuppressWarnings("unchecked")
    static boolean matches(Map<String, Object> source, Map<String, Object> origin, String actor) {
        return source != null && origin.get("incident_id").equals(source.get("id")) &&
                actor.equals(source.get("created_by")) &&
                source.get("correlation_origin") instanceof Map<?, ?> stored &&
                IncidentRepository.sameEvent(origin, (Map<String, Object>) stored);
    }

    @SuppressWarnings("unchecked")
    static boolean matchesCreationEvent(Map<String, Object> event, Map<String, Object> origin, String actor) {
        if (event == null || !"created".equals(event.get("kind")) || !actor.equals(event.get("actor")) ||
                !(event.get("revision") instanceof Number revision) || revision.longValue() != 1 ||
                !origin.get("incident_id").equals(event.get("incident_id")) ||
                !(origin.get("incident_id") + ":1").equals(event.get("id")) ||
                !(event.get("changes") instanceof Map<?, ?> changes) ||
                !(changes.get("correlation_origin") instanceof Map<?, ?> change) ||
                !(change.get("after") instanceof Map<?, ?> actual)) return false;
        if (!IncidentRepository.sameEvent(origin, (Map<String, Object>) actual)) return false;
        try {
            if (!(changes.get("findings") instanceof Map<?, ?> findingChange) ||
                    !(findingChange.get("after") instanceof List<?> links) ||
                    !(changes.get("finding_capture_receipts") instanceof Map<?, ?> captureChange) ||
                    !(captureChange.get("after") instanceof List<?> captures) ||
                    !(changes.get("finding_count") instanceof Map<?, ?> countChange) ||
                    !(countChange.get("after") instanceof Number count) ||
                    count.longValue() != links.size() || captures.size() != links.size() ||
                    !(origin.get("finding_count") instanceof Number expectedCount) || expectedCount.longValue() != links.size()) return false;
            List<FindingReference> references = links.stream()
                    .map(link -> FindingReference.parse((Map<String, Object>) link)).toList();
            var group = new CorrelationPlanner.Group((String) origin.get("group_key"),
                    UUID.fromString((String) origin.get("policy_id")), ((Number) origin.get("policy_version")).intValue(),
                    Instant.parse((String) origin.get("window_start")), Instant.parse((String) origin.get("window_end")), references);
            var regenerated = CorrelationExecutionLedger.immutableFields(UUID.fromString((String) origin.get("deployment_id")), group);
            if (!IncidentRepository.sameEvent(origin, regenerated)) return false;
            var seen = new java.util.HashSet<FindingReference>();
            for (Object capture : captures) {
                if (!(capture instanceof Map<?, ?> receipt) || !actor.equals(receipt.get("captured_by")) ||
                        !"caller_visible_parsed_source".equals(receipt.get("scope")) ||
                        !"sorted-map-json-v1".equals(receipt.get("serialization")) ||
                        !(receipt.get("sha256") instanceof String digest) || !digest.matches("[a-f0-9]{64}") ||
                        !(receipt.get("seq_no") instanceof Number seq) || seq.longValue() < 0 ||
                        !(receipt.get("primary_term") instanceof Number term) || term.longValue() < 1 ||
                        !(receipt.get("captured_at") instanceof String time) ||
                        Instant.parse(time).truncatedTo(java.time.temporal.ChronoUnit.MILLIS).isAfter(Instant.parse((String) event.get("at")))) return false;
                FindingReference reference = FindingReference.parse((Map<String, Object>) receipt.get("reference"));
                if (!seen.add(reference) || !references.contains(reference)) return false;
            }
            return seen.size() == references.size();
        } catch (RuntimeException e) { return false; }
    }
}
