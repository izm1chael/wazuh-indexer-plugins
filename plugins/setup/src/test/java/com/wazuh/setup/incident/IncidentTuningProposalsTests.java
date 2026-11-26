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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.UUID;
import static com.wazuh.setup.incident.IncidentMutation.Operation.*;

public class IncidentTuningProposalsTests extends OpenSearchTestCase {
    private Map<String, Object> apply(Map<String, Object> source, IncidentMutation.Operation op, Map<String, Object> input, String actor) {
        var delivered = new LinkedHashMap<>(source); delivered.put("pending_activity", null);
        int rev = (int) source.get("revision");
        return IncidentMutation.apply(delivered, op, input, rev, actor, Instant.EPOCH.plusSeconds(rev));
    }
    private Map<String, Object> closed() {
        var source = IncidentMutation.create(Map.of("title", "Example", "severity", "high"), UUID.randomUUID(), "analyst", Instant.EPOCH);
        source = apply(source, ASSIGN_SELF, Map.of(), "analyst");
        source = apply(source, START_TRIAGE, Map.of(), "analyst");
        return apply(source, CLOSE, Map.of("classification", "false_positive", "reason", "Reviewed"), "analyst");
    }
    private List<Map<String, Object>> fixtures(boolean lost) {
        var rows = new ArrayList<Map<String, Object>>();
        for (int i = 0; i < 10; i++) {
            rows.add(Map.of("id", "m"+i, "label", "malicious", "baseline", true, "candidate", !lost || i != 0));
            rows.add(Map.of("id", "b"+i, "label", "benign", "baseline", true, "candidate", i < 2));
        }
        return rows;
    }
    private Map<String, Object> proposal(boolean lost) {
        return Map.of("rule_uuid", UUID.randomUUID().toString(), "baseline_sha256", "a".repeat(64), "candidate_sha256", "b".repeat(64),
                "type", "review_rule_scope", "reason", "External fixture reviewed", "split", "holdout", "rows", fixtures(lost));
    }
    public void testPairedReceiptAndIndependentReview() {
        var closed = closed(); var input = proposal(false);
        var proposed = apply(closed, CREATE_TUNING_PROPOSAL, input, "analyst");
        var item = IncidentTuningProposals.project(proposed).get(0);
        var replay = (Map<?, ?>) item.get("replay");
        assertEquals("eligible_for_human_review", replay.get("gate"));
        assertEquals(8, replay.get("removed_benign"));
        assertFalse(item.containsKey("rows"));
        var decision = Map.of("proposal_id", item.get("id"), "decision", "accepted_for_review", "reason", "Independent review");
        expectThrows(OpenSearchStatusException.class, () -> apply(proposed, REVIEW_TUNING_PROPOSAL, decision, "analyst"));
        var reviewed = apply(proposed, REVIEW_TUNING_PROPOSAL, decision, "reviewer");
        assertEquals("accepted_for_review", IncidentTuningProposals.project(reviewed).get(0).get("state"));
        assertEquals(closed.get("closure"), reviewed.get("closure"));
        assertEquals(closed.get("closed_at"), reviewed.get("closed_at"));
        expectThrows(OpenSearchStatusException.class, () -> apply(reviewed, REVIEW_TUNING_PROPOSAL, decision, "reviewer"));
        expectThrows(OpenSearchStatusException.class, () -> apply(proposed, CREATE_TUNING_PROPOSAL, input, "analyst"));
    }
    public void testRegressionBlocksAcceptanceAndCanonicalHash() {
        var rows = fixtures(true);
        var replay = TuningReplay.evaluate(rows);
        assertEquals("blocked", replay.get("gate"));
        assertEquals(1, replay.get("lost_malicious"));
        java.util.Collections.reverse(rows);
        assertEquals(replay, TuningReplay.evaluate(rows));
        var proposed = apply(closed(), CREATE_TUNING_PROPOSAL, proposal(true), "analyst");
        var item = IncidentTuningProposals.project(proposed).get(0);
        var decision = Map.of("proposal_id", item.get("id"), "decision", "accepted_for_review", "reason", "Reviewed");
        expectThrows(OpenSearchStatusException.class, () -> apply(proposed, REVIEW_TUNING_PROPOSAL, decision, "reviewer"));
    }
    public void testReplayReceiptCannotHideLostSamples() {
        var corrupt = new LinkedHashMap<>(TuningReplay.evaluate(fixtures(true)));
        corrupt.put("lost_malicious", 0);
        expectThrows(IllegalArgumentException.class, () -> TuningReplay.validate(corrupt));
        var rows = fixtures(false); rows.add(rows.get(0));
        expectThrows(IllegalArgumentException.class, () -> TuningReplay.evaluate(rows));
    }
}
