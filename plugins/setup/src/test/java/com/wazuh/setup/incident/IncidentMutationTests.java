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

import org.opensearch.OpenSearchException;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class IncidentMutationTests extends OpenSearchTestCase {
    private static final UUID ID = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");

    private Map<String, Object> create() {
        return IncidentMutation.create(Map.of("title", "Example", "severity", "high"), ID, "creator", NOW);
    }

    private Map<String, Object> delivered(Map<String, Object> record) {
        Map<String, Object> result = new LinkedHashMap<>(record);
        result.put("pending_activity", null);
        return result;
    }

    private Map<String, Object> apply(Map<String, Object> record, IncidentMutation.Operation op, Map<String, Object> input, String actor) {
        return IncidentMutation.apply(delivered(record), op, input, (int) record.get("revision"), actor, NOW.plusSeconds((int) record.get("revision")));
    }

    public void testRejectsForgedServerFields() {
        expectThrows(OpenSearchException.class, () -> IncidentMutation.create(Map.of("title", "x", "severity", "high", "created_by", "admin"), ID, "creator", NOW));
        assertEquals("creator", create().get("created_by"));
        assertNull(create().get("owner"));
    }

    public void testNoSharedOrUnauthenticatedPrincipal() {
        expectThrows(OpenSearchException.class, () -> IncidentPrincipal.requireUserInfo(null));
        expectThrows(OpenSearchException.class, () -> IncidentPrincipal.requireUserInfo("_shared|roles|roles|tenant"));
        assertEquals("auth0|subject", IncidentPrincipal.requireUserInfo("auth0\\|subject|roles|roles|tenant"));
    }

    public void testLifecycleAndOwnerCannotBeSpoofed() {
        var assigned = apply(create(), IncidentMutation.Operation.ASSIGN_SELF, Map.of(), "analyst");
        assertEquals("analyst", assigned.get("owner"));
        assertEquals("creator", assigned.get("created_by"));
        expectThrows(OpenSearchException.class, () -> apply(assigned, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), "other"));
        expectThrows(OpenSearchException.class, () -> apply(assigned, IncidentMutation.Operation.START_TRIAGE, Map.of(), "other"));
        var triage = apply(assigned, IncidentMutation.Operation.START_TRIAGE, Map.of(), "analyst");
        var active = apply(triage, IncidentMutation.Operation.ACTIVATE, Map.of(), "analyst");
        var closed = apply(active, IncidentMutation.Operation.CLOSE, Map.of("classification", "true_positive", "reason", "Verified"), "analyst");
        var reopened = apply(closed, IncidentMutation.Operation.REOPEN, Map.of("reason", "New evidence"), "analyst");
        assertEquals("active", reopened.get("status"));
        assertEquals(closed.get("closed_at"), reopened.get("first_closed_at"));
        assertNull(reopened.get("closed_at"));
        assertEquals(6, reopened.get("revision"));
    }

    public void testReopeningTriageClosureDoesNotInventActivation() {
        var assigned = apply(create(), IncidentMutation.Operation.ASSIGN_SELF, Map.of(), "analyst");
        var triage = apply(assigned, IncidentMutation.Operation.START_TRIAGE, Map.of(), "analyst");
        var closed = apply(triage, IncidentMutation.Operation.CLOSE, Map.of("classification", "false_positive", "reason", "Reviewed"), "analyst");
        var reopened = apply(closed, IncidentMutation.Operation.REOPEN, Map.of("reason", "New evidence"), "analyst");
        assertEquals("triaging", reopened.get("status"));
        assertNull(reopened.get("activated_at"));
        assertEquals(triage.get("triage_started_at"), reopened.get("triage_started_at"));
        var active = apply(reopened, IncidentMutation.Operation.ACTIVATE, Map.of(), "analyst");
        assertNotNull(active.get("activated_at"));
    }

    public void testPendingActivityAndRevisionAreMandatory() {
        var record = create();
        expectThrows(OpenSearchException.class, () -> IncidentMutation.apply(record, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), 1, "analyst", NOW));
        expectThrows(OpenSearchException.class, () -> IncidentMutation.apply(delivered(record), IncidentMutation.Operation.ASSIGN_SELF, Map.of(), 2, "analyst", NOW));
    }

    public void testMetadataEditAuditAndUnknownFields() {
        var assigned = apply(create(), IncidentMutation.Operation.ASSIGN_SELF, Map.of(), "analyst");
        var edited = apply(assigned, IncidentMutation.Operation.EDIT, Map.of("severity", "critical"), "analyst");
        assertEquals("critical", edited.get("severity"));
        assertEquals("high", assigned.get("severity"));
        var activity = (Map<?, ?>) edited.get("pending_activity");
        assertEquals("edit", activity.get("kind"));
        assertEquals(Map.of("before", "high", "after", "critical"), ((Map<?, ?>) activity.get("changes")).get("severity"));
        expectThrows(OpenSearchException.class, () -> apply(assigned, IncidentMutation.Operation.EDIT, Map.of("owner", "other"), "analyst"));
    }
}
