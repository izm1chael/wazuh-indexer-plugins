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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import static com.wazuh.setup.incident.IncidentMutation.Operation.*;

public class IncidentAiFeedbackTests extends OpenSearchTestCase {
    private Map<String,Object> apply(Map<String,Object> source, IncidentMutation.Operation op, Map<String,Object> input, String actor) {
        var delivered = new LinkedHashMap<>(source); delivered.put("pending_activity", null);
        int rev = (int) source.get("revision");
        return IncidentMutation.apply(delivered, op, input, rev, actor, Instant.EPOCH.plusSeconds(rev));
    }
    private Map<String,Object> input(Map<String,Object> source) {
        return Map.of("assessment_id", UUID.randomUUID().toString(), "assessed_revision", source.get("revision"),
            "digest_sha256", "a".repeat(64), "assessment_mode", "agentic_soc", "assessment_rating", "useful", "hypothesis_review", "disagree");
    }
    public void testClosedFeedbackDoesNotChangeClassificationOrResolution() {
        var source = IncidentMutation.create(Map.of("title", "Example", "severity", "high"), UUID.randomUUID(), "analyst", Instant.EPOCH);
        source = apply(source, ASSIGN_SELF, Map.of(), "analyst");
        source = apply(source, START_TRIAGE, Map.of(), "analyst");
        var closed = apply(source, CLOSE, Map.of("classification", "false_positive", "reason", "Investigated"), "analyst");
        var input = input(closed);
        var result = apply(closed, RECORD_AI_FEEDBACK, input, "analyst");
        assertEquals(closed.get("closure"), result.get("closure"));
        assertEquals(closed.get("closed_at"), result.get("closed_at"));
        assertEquals("closed", result.get("status"));
        @SuppressWarnings("unchecked") var event = (Map<String,Object>) result.get("pending_activity");
        assertEquals("ai_feedback_recorded", event.get("kind"));
        assertTrue(IncidentInvestigationService.projectActivity(event).toString().contains("analyst_attestation"));
        var duplicate = new LinkedHashMap<>(input); duplicate.put("assessed_revision", result.get("revision"));
        expectThrows(OpenSearchStatusException.class, () -> apply(result, RECORD_AI_FEEDBACK, duplicate, "analyst"));
        expectThrows(OpenSearchStatusException.class, () -> apply(closed, RECORD_AI_FEEDBACK, input, "other"));
    }
    public void testRejectsStaleAndExtraFields() {
        var created = IncidentMutation.create(Map.of("title", "Example", "severity", "low"), UUID.randomUUID(), "analyst", Instant.EPOCH);
        var assigned = apply(created, ASSIGN_SELF, Map.of(), "analyst");
        expectThrows(OpenSearchStatusException.class, () -> apply(assigned, RECORD_AI_FEEDBACK, input(created), "analyst"));
        var extra = new LinkedHashMap<>(input(assigned)); extra.put("classification", "false_positive");
        expectThrows(OpenSearchStatusException.class, () -> apply(assigned, RECORD_AI_FEEDBACK, extra, "analyst"));
    }
}
