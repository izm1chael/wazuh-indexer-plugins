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
import org.opensearch.test.OpenSearchTestCase;
import java.time.Instant;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.UUID;
import static com.wazuh.setup.incident.IncidentMutation.Operation.*;

public class IncidentResponsesTests extends OpenSearchTestCase {
    private static final Instant NOW = Instant.EPOCH;
    private Map<String, Object> apply(Map<String, Object> source, IncidentMutation.Operation op, Map<String, Object> input, String actor) {
        var delivered = new LinkedHashMap<>(source);
        delivered.put("pending_activity", null);
        int rev = (int) source.get("revision");
        return IncidentMutation.apply(delivered, op, input, rev, actor, NOW.plusSeconds(rev));
    }
    private Map<String, Object> triaging() {
        var source = IncidentMutation.create(Map.of("title", "Example", "severity", "high"), UUID.randomUUID(), "analyst", NOW);
        return apply(apply(source, ASSIGN_SELF, Map.of(), "analyst"), START_TRIAGE, Map.of(), "analyst");
    }
    private static final Map<String, Object> INTENT = Map.of("type", "review_containment", "scope", "host under investigation", "reason", "Review evidence");
    private Map<String, Object> requested() { return apply(triaging(), REQUEST_RESPONSE, INTENT, "analyst"); }
    private Map<String, Object> decision(Map<String, Object> source) {
        return Map.of("response_id", IncidentResponses.project(source).get(0).get("id"), "reason", "Reviewed");
    }

    public void testIndependentApprovalAndUnverifiedOutcome() {
        var requested = requested();
        expectThrows(OpenSearchStatusException.class, () -> apply(requested, APPROVE_RESPONSE, decision(requested), "analyst"));
        expectThrows(OpenSearchStatusException.class, () -> apply(requested, REQUEST_RESPONSE, INTENT, "analyst"));
        var approved = apply(requested, APPROVE_RESPONSE, decision(requested), "reviewer");
        assertEquals("approved", IncidentResponses.project(approved).get(0).get("state"));
        assertEquals(false, IncidentResponses.project(approved).get(0).get("execution_verified"));
        var outcome = new LinkedHashMap<>(decision(approved)); outcome.put("outcome", "completed");
        var reported = apply(approved, RECORD_RESPONSE_OUTCOME, outcome, "operator");
        var response = IncidentResponses.project(reported).get(0);
        assertEquals("reported_completed", response.get("state"));
        assertEquals("operator", response.get("finalized_by"));
        assertEquals(false, response.get("execution_verified"));
        assertFalse(IncidentReadService.project(reported).containsKey("response_requests"));
        assertEquals("requested", IncidentResponses.project(requested).get(0).get("state"));
    }

    public void testStoredStateRejectsDuplicateIdentityAndForgedSelfApproval() {
        var requested = requested();
        var row = new LinkedHashMap<>(IncidentResponses.project(requested).get(0));
        var corrupted = new LinkedHashMap<>(requested);
        corrupted.put("response_requests", java.util.List.of(row, row));
        expectThrows(IllegalStateException.class, () -> IncidentResponses.project(corrupted));
        row.put("state", "approved");
        row.put("decided_by", "analyst");
        row.put("decided_at", row.get("requested_at"));
        row.put("decision_reason", "Forged");
        corrupted.put("response_requests", java.util.List.of(row));
        expectThrows(IllegalStateException.class, () -> IncidentResponses.project(corrupted));
    }

    public void testNoCommandsOrForgedExecutionAndClosureGuard() {
        var source = triaging();
        var forged = new LinkedHashMap<>(INTENT); forged.put("command", "arbitrary");
        expectThrows(OpenSearchStatusException.class, () -> apply(source, REQUEST_RESPONSE, forged, "analyst"));
        expectThrows(OpenSearchStatusException.class, () -> apply(source, REQUEST_RESPONSE, INTENT, "other"));
        var requested = apply(source, REQUEST_RESPONSE, INTENT, "analyst");
        var close = Map.<String,Object>of("classification", "true_positive", "reason", "Reviewed");
        expectThrows(OpenSearchStatusException.class, () -> apply(requested, CLOSE, close, "analyst"));
        var cancelled = apply(requested, CANCEL_RESPONSE, decision(requested), "analyst");
        assertEquals("closed", apply(cancelled, CLOSE, close, "analyst").get("status"));
        expectThrows(OpenSearchStatusException.class, () -> apply(cancelled, APPROVE_RESPONSE, decision(cancelled), "reviewer"));
    }
}
