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
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class IncidentEvidenceRegisterTests extends OpenSearchTestCase {
    private static final UUID ID = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final String TARGET = "00000000-0000-4000-8000-000000000002";
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    private static final String SHA = "a".repeat(64);
    private static final Map<String, Object> ARTIFACT = Map.of("type", "log_export", "label", "Export", "sha256", SHA, "custody_reference", "vault-123");

    private Map<String, Object> apply(Map<String, Object> current, IncidentMutation.Operation op, Map<String, Object> input, String actor) {
        var delivered = new LinkedHashMap<>(current); delivered.put("pending_activity", null);
        int revision = (int) delivered.get("revision");
        return IncidentMutation.apply(delivered, op, input, revision, actor, NOW.plusSeconds(revision));
    }

    private Map<String, Object> owned() {
        var created = IncidentMutation.create(Map.of("title", "Example", "severity", "high"), ID, "alice", NOW);
        return apply(created, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), "alice");
    }

    public void testTagsAreCanonicalAndOwnerOnly() {
        var source = owned();
        var updated = apply(source, IncidentMutation.Operation.SET_TAGS, Map.of("tags", List.of("soc", "phishing")), "alice");
        assertEquals(List.of("phishing", "soc"), IncidentEvidenceRegister.storedTags(updated));
        assertEquals(List.of(), IncidentEvidenceRegister.storedTags(source));
        assertEquals(List.of("phishing", "soc"), IncidentReadService.project(updated).get("tags"));
        expectThrows(OpenSearchException.class, () -> apply(updated, IncidentMutation.Operation.SET_TAGS, Map.of("tags", List.of("soc", "phishing")), "alice"));
        expectThrows(OpenSearchException.class, () -> apply(source, IncidentMutation.Operation.SET_TAGS, Map.of("tags", List.of("soc")), "eve"));
        for (var tags : List.of(List.of("a", "a"), List.of("Uppercase"), List.of(""), List.of("bad space"))) {
            expectThrows(OpenSearchException.class, () -> apply(source, IncidentMutation.Operation.SET_TAGS, Map.of("tags", tags), "alice"));
        }
        assertEquals(List.of(), IncidentEvidenceRegister.storedTags(apply(updated, IncidentMutation.Operation.SET_TAGS, Map.of("tags", List.of()), "alice")));
    }

    public void testDirectionalRelationIsAttributedAndRemovedWithAudit() {
        var source = owned();
        var input = Map.<String, Object>of("type", "possible_duplicate", "target_id", TARGET, "reason", "Analyst hypothesis");
        var related = apply(source, IncidentMutation.Operation.ADD_RELATION, input, "alice");
        var row = IncidentEvidenceRegister.relations(related).get(0);
        assertEquals(TARGET, row.get("target_id"));
        assertEquals("alice", row.get("recorded_by"));
        assertEquals("new", related.get("status"));
        assertFalse(IncidentReadService.project(related).containsKey("incident_relations"));
        expectThrows(OpenSearchException.class, () -> apply(related, IncidentMutation.Operation.ADD_RELATION, input, "alice"));
        expectThrows(OpenSearchException.class, () -> apply(source, IncidentMutation.Operation.ADD_RELATION,
                Map.of("type", "related", "target_id", ID.toString(), "reason", "self"), "alice"));
        var removed = apply(related, IncidentMutation.Operation.REMOVE_RELATION, Map.of("relation_id", row.get("id"), "reason", "Incorrect assertion"), "alice");
        assertTrue(IncidentEvidenceRegister.relations(removed).isEmpty());
        assertEquals("incident_relation_removed", ((Map<?, ?>) removed.get("pending_activity")).get("kind"));
        assertEquals(1, IncidentEvidenceRegister.relations(related).size());
    }

    public void testExternalEvidenceWithdrawalPreservesOriginalAndPreventsDuplicate() {
        var source = owned();
        var registered = apply(source, IncidentMutation.Operation.REGISTER_EVIDENCE, ARTIFACT, "alice");
        var row = IncidentEvidenceRegister.evidence(registered).get(0);
        assertEquals(SHA, row.get("sha256"));
        assertEquals("analyst_attested_external_artifact", row.get("origin"));
        assertEquals("recorded", row.get("state"));
        assertFalse(IncidentReadService.project(registered).containsKey("evidence_register"));
        var withdrawn = apply(registered, IncidentMutation.Operation.WITHDRAW_EVIDENCE, Map.of("evidence_id", row.get("id"), "reason", "Wrong export"), "alice");
        var finalRow = IncidentEvidenceRegister.evidence(withdrawn).get(0);
        for (String field : List.of("id", "sha256", "label", "custody_reference", "recorded_by", "recorded_at")) assertEquals(row.get(field), finalRow.get(field));
        assertEquals("withdrawn", finalRow.get("state"));
        assertEquals("alice", finalRow.get("withdrawn_by"));
        assertEquals("recorded", IncidentEvidenceRegister.evidence(registered).get(0).get("state"));
        expectThrows(OpenSearchException.class, () -> apply(withdrawn, IncidentMutation.Operation.REGISTER_EVIDENCE, ARTIFACT, "alice"));
        expectThrows(OpenSearchException.class, () -> apply(withdrawn, IncidentMutation.Operation.WITHDRAW_EVIDENCE, Map.of("evidence_id", row.get("id"), "reason", "Again"), "alice"));
    }

    public void testForgedEvidenceFieldsAndClosedMutationRejected() {
        var source = owned();
        var forged = new LinkedHashMap<>(ARTIFACT); forged.put("recorded_by", "admin");
        expectThrows(OpenSearchException.class, () -> apply(source, IncidentMutation.Operation.REGISTER_EVIDENCE, forged, "alice"));
        var malformed = new LinkedHashMap<>(ARTIFACT); malformed.put("sha256", "x");
        expectThrows(OpenSearchException.class, () -> apply(source, IncidentMutation.Operation.REGISTER_EVIDENCE, malformed, "alice"));
        expectThrows(OpenSearchException.class, () -> apply(source, IncidentMutation.Operation.REGISTER_EVIDENCE, ARTIFACT, "eve"));
        var triage = apply(source, IncidentMutation.Operation.START_TRIAGE, Map.of(), "alice");
        var closed = apply(triage, IncidentMutation.Operation.CLOSE, Map.of("classification", "true_positive", "reason", "Done"), "alice");
        expectThrows(OpenSearchException.class, () -> apply(closed, IncidentMutation.Operation.REGISTER_EVIDENCE, ARTIFACT, "alice"));
    }

    public void testExactTagSearchAndOldRecordCompatibility() {
        var query = new IncidentReadService.Query("all", null, null, "tag:phishing", 25, null, null);
        String search = IncidentReadService.build(query).query().toString();
        assertTrue(search.contains("tags"));
        assertTrue(search.contains("phishing"));
        expectThrows(OpenSearchException.class, () -> new IncidentReadService.Query("all", null, null, "tag:*", 25, null, null));
        assertTrue(IncidentEvidenceRegister.evidence(Map.of()).isEmpty());
        assertTrue(IncidentEvidenceRegister.relations(Map.of()).isEmpty());
        assertTrue(IncidentEvidenceRegister.storedTags(Map.of()).isEmpty());
    }
}
