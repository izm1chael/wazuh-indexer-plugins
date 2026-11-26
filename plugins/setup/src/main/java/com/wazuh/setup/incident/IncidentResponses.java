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

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Approval and manual outcome records only. No executable commands, endpoint calls or dispatch. */
final class IncidentResponses {
    static final int MAX = 50;
    static final Set<String> TYPES = Set.of("investigate_endpoint", "review_containment", "review_indicator_block", "collect_evidence", "scan_vulnerability");
    static final Set<String> STATES = Set.of("requested", "approved", "rejected", "cancelled",
            "reported_completed", "reported_failed", "reported_not_performed", "dispatch_reserved", "manager_accepted", "dispatch_unknown");
    private static final Set<String> FIELDS = Set.of("id", "type", "scope", "reason", "state", "requested_by", "requested_at",
            "decided_by", "decided_at", "decision_reason", "finalized_by", "finalized_at", "final_reason", "execution_verified");
    private IncidentResponses() {}

    static List<Map<String, Object>> project(Map<String, Object> source) {
        if (!(source.getOrDefault("response_requests", List.of()) instanceof List<?> rows) || rows.size() > MAX) {
            throw new IllegalStateException("Invalid response state");
        }
        List<Map<String, Object>> result = new ArrayList<>();
        var seen = new java.util.HashSet<String>();
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> value) || !TYPES.contains(value.get("type")) ||
                    !STATES.contains(value.get("state")) || !Boolean.FALSE.equals(value.get("execution_verified"))) {
                throw new IllegalStateException("Invalid response record");
            }
            var item = new LinkedHashMap<String, Object>();
            for (String field : FIELDS) {
                Object v = value.get(field);
                if (v != null && !(v instanceof String) && !("execution_verified".equals(field) && Boolean.FALSE.equals(v))) {
                    throw new IllegalStateException("Invalid response field");
                }
                item.put(field, v);
            }
            validateStored(source, item, seen);
            result.add(item);
        }
        return result;
    }

    private static void validateStored(Map<String, Object> source, Map<String, Object> row, Set<String> seen) {
        if (!(source.get("id") instanceof String incidentId) || !(source.get("revision") instanceof Number revision) ||
                !(row.get("id") instanceof String id) || !id.startsWith(incidentId + ":") || !seen.add(id)) {
            throw new IllegalStateException("Invalid stored response identity");
        }
        try {
            String suffix = id.substring(incidentId.length() + 1);
            int requestRevision = Integer.parseInt(suffix);
            if (requestRevision < 1 || requestRevision > revision.longValue() || !Integer.toString(requestRevision).equals(suffix)) {
                throw new IllegalStateException("Invalid response revision");
            }
            String requester = text(row.get("requested_by"), 1024);
            java.time.Instant requested = java.time.Instant.parse(text(row.get("requested_at"), 64));
            text(row.get("scope"), 512); text(row.get("reason"), 2048);
            if ("scan_vulnerability".equals(row.get("type"))) scanScope(row.get("scope"));
            else if (Set.of("dispatch_reserved", "manager_accepted", "dispatch_unknown").contains(row.get("state"))) throw new IllegalStateException("Invalid dispatch type");
            boolean noDecision = row.get("decided_by") == null && row.get("decided_at") == null && row.get("decision_reason") == null;
            java.time.Instant decided = null;
            if (!noDecision) {
                String reviewer = text(row.get("decided_by"), 1024);
                decided = java.time.Instant.parse(text(row.get("decided_at"), 64));
                text(row.get("decision_reason"), 2048);
                if (requester.equals(reviewer) || decided.isBefore(requested)) throw new IllegalStateException("Invalid stored decision");
            }
            boolean noFinal = row.get("finalized_by") == null && row.get("finalized_at") == null && row.get("final_reason") == null;
            if (!noFinal) {
                text(row.get("finalized_by"), 1024);
                var finalized = java.time.Instant.parse(text(row.get("finalized_at"), 64));
                text(row.get("final_reason"), 2048);
                if (finalized.isBefore(decided == null ? requested : decided)) throw new IllegalStateException("Invalid stored finalization");
            }
            boolean valid = switch ((String) row.get("state")) {
                case "requested" -> noDecision && noFinal;
                case "approved", "rejected" -> !noDecision && noFinal;
                case "cancelled" -> !noFinal;
                case "reported_completed", "reported_failed", "reported_not_performed" -> !noDecision && !noFinal;
                case "dispatch_reserved", "manager_accepted", "dispatch_unknown" -> !noDecision && !noFinal && "scan_vulnerability".equals(row.get("type")) &&
                        !requester.equals(row.get("finalized_by")) && !row.get("decided_by").equals(row.get("finalized_by"));
                default -> false;
            };
            if (!valid) throw new IllegalStateException("Invalid stored response lifecycle");
        } catch (RuntimeException e) {
            throw new IllegalStateException("Invalid stored response record", e);
        }
    }

    static void requireNoOutstanding(Map<String, Object> source) {
        if (project(source).stream().anyMatch(row -> Set.of("requested", "approved", "dispatch_reserved", "manager_accepted", "dispatch_unknown").contains(row.get("state")))) {
            throw conflict("Resolve or cancel outstanding response requests before closing");
        }
    }

    static String apply(Map<String, Object> next, Map<String, Object> changes, IncidentMutation.Operation operation,
            Map<String, Object> input, String actor, String now, int revision) {
        var rows = project(next);
        Map<String, Object> previous = null;
        Map<String, Object> record = new LinkedHashMap<>();
        String kind;
        if (operation == IncidentMutation.Operation.REQUEST_RESPONSE) {
            exact(input, Set.of("type", "scope", "reason"));
            if (!"triaging".equals(next.get("status")) && !"active".equals(next.get("status"))) throw conflict("Start triage before requesting response");
            if (rows.size() >= MAX) throw conflict("Response request capacity reached");
            String type = text(input.get("type"), 64);
            if (!TYPES.contains(type)) throw invalid("Unknown response intent");
            String scope = text(input.get("scope"), 512);
            String reason = text(input.get("reason"), 2048);
            if ("scan_vulnerability".equals(type)) { scanScope(scope); if (!scope.equals(input.get("scope"))) throw invalid("Exact scan scope required"); }
            if (rows.stream().anyMatch(row -> Set.of("requested", "approved").contains(row.get("state")) &&
                    type.equals(row.get("type")) && scope.equals(row.get("scope")))) throw conflict("Outstanding matching response request");
            record.put("id", next.get("id") + ":" + revision);
            record.put("type", type); record.put("scope", scope); record.put("reason", reason);
            record.put("state", "requested"); record.put("requested_by", actor); record.put("requested_at", now);
            record.put("execution_verified", false);
            for (String field : Set.of("decided_by", "decided_at", "decision_reason", "finalized_by", "finalized_at", "final_reason")) record.put(field, null);
            rows.add(record);
            kind = "response_requested";
        } else {
            exact(input, operation == IncidentMutation.Operation.RECORD_RESPONSE_OUTCOME
                    ? Set.of("response_id", "outcome", "reason") : Set.of("response_id", "reason"));
            String id = text(input.get("response_id"), 64);
            String reason = text(input.get("reason"), 2048);
            int index = -1;
            for (int n = 0; n < rows.size(); n++) if (id.equals(rows.get(n).get("id"))) { index = n; break; }
            if (index < 0) throw conflict("Response request not found");
            previous = rows.get(index);
            record.putAll(previous);
            String state = (String) previous.get("state");
            switch (operation) {
                case APPROVE_RESPONSE:
                case REJECT_RESPONSE:
                    if (!"requested".equals(state)) throw conflict("Response is not awaiting a decision");
                    if (actor.equals(previous.get("requested_by"))) throw new OpenSearchStatusException("Independent reviewer required", RestStatus.FORBIDDEN);
                    boolean approved = operation == IncidentMutation.Operation.APPROVE_RESPONSE;
                    record.put("state", approved ? "approved" : "rejected");
                    record.put("decided_by", actor); record.put("decided_at", now); record.put("decision_reason", reason);
                    kind = approved ? "response_approved" : "response_rejected";
                    break;
                case CANCEL_RESPONSE:
                    if (!Set.of("requested", "approved").contains(state)) throw conflict("Response cannot be cancelled");
                    record.put("state", "cancelled");
                    record.put("finalized_by", actor); record.put("finalized_at", now); record.put("final_reason", reason);
                    kind = "response_cancelled";
                    break;
                case RECORD_RESPONSE_OUTCOME:
                    if (!Set.of("approved", "dispatch_reserved", "manager_accepted", "dispatch_unknown").contains(state)) throw conflict("Approved response required");
                    if ("scan_vulnerability".equals(previous.get("type")) && (actor.equals(previous.get("requested_by")) || actor.equals(previous.get("finalized_by")))) throw new OpenSearchStatusException("Independent scan reconciliation reviewer required", RestStatus.FORBIDDEN);
                    if ("dispatch_reserved".equals(state) && java.time.Instant.parse(now).isBefore(java.time.Instant.parse((String) previous.get("finalized_at")).plusSeconds(900))) throw conflict("Dispatch may still be in flight; reconcile only after stopping runner and waiting fifteen minutes");
                    String outcome = text(input.get("outcome"), 64);
                    if (!Set.of("completed", "failed", "not_performed").contains(outcome)) throw invalid("Unknown manual outcome");
                    record.put("state", "reported_" + outcome);
                    record.put("finalized_by", actor); record.put("finalized_at", now); record.put("final_reason", reason);
                    kind = "response_outcome_reported";
                    break;
                default: throw invalid("Unsupported response operation");
            }
            rows.set(index, record);
        }
        next.put("response_requests", rows);
        var change = new LinkedHashMap<String, Object>();
        change.put("before", previous); change.put("after", record);
        changes.put("response_request", change);
        return kind;
    }

    static String scanScope(Object value) {
        if (!(value instanceof String scope) || !scope.matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:agent:[0-9]{3,8}"))
            throw invalid("Expected manager UUID:agent:exact numeric agent ID");
        if (scope.substring(scope.lastIndexOf(':') + 1).matches("0+")) throw invalid("Manager agent is not eligible");
        return scope;
    }

    static Map<String, Object> dispatch(Map<String, Object> next, Map<String, Object> changes, String id,
            String actor, String now, String manager, Set<String> agents, String outcome) {
        var rows = project(next);
        for (int n = 0; n < rows.size(); n++) {
            var before = rows.get(n);
            if (!id.equals(before.get("id"))) continue;
            if (!"scan_vulnerability".equals(before.get("type"))) throw conflict("Scan request required");
            String scope = scanScope(before.get("scope")), agent = scope.substring(scope.lastIndexOf(':') + 1);
            if (!scope.equals(manager + ":agent:" + agent) || !agents.contains(agent)) throw new OpenSearchStatusException("Scan target not approved", RestStatus.FORBIDDEN);
            var record = new LinkedHashMap<>(before);
            if (outcome == null) {
                if (!"approved".equals(before.get("state")) || actor.equals(before.get("requested_by")) || actor.equals(before.get("decided_by")) ||
                        java.time.Instant.parse(now).isAfter(java.time.Instant.parse((String) before.get("decided_at")).plusSeconds(3600)))
                    throw conflict("Fresh independent scan approval required");
                record.put("state", "dispatch_reserved");
                record.put("final_reason", "Dispatch reserved; execution not verified");
            } else {
                if (!"dispatch_reserved".equals(before.get("state")) || !actor.equals(before.get("finalized_by")) ||
                        !Set.of("manager_accepted", "dispatch_unknown").contains(outcome)) throw conflict("Dispatch reservation unavailable");
                record.put("state", outcome);
                record.put("final_reason", "manager_accepted".equals(outcome) ? "Runner reported manager acknowledgement; execution not verified" :
                        "Runner reported ambiguous dispatch; do not retry automatically");
            }
            record.put("finalized_by", actor); record.put("finalized_at", now);
            rows.set(n, record); next.put("response_requests", rows);
            changes.put("response_request", Map.of("before", before, "after", record));
            changes.put("soar_response_id", Map.of("before", id, "after", id));
            changes.put("soar_state", Map.of("before", before.get("state"), "after", record.get("state")));
            return record;
        }
        throw conflict("Scan request unavailable");
    }

    private static void exact(Map<String, Object> input, Set<String> fields) {
        if (input == null || !input.keySet().equals(fields)) throw invalid("Invalid response fields");
    }
    private static String text(Object value, int max) {
        if (!(value instanceof String text) || text.isBlank() || text.length() > max) throw invalid("Invalid response text");
        return text.trim();
    }
    private static OpenSearchStatusException invalid(String text) { return new OpenSearchStatusException(text, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String text) { return new OpenSearchStatusException(text, RestStatus.CONFLICT); }
}
