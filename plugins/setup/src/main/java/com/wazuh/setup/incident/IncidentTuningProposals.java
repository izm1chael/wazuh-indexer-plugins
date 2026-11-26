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
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** A durable review of analyst-supplied evidence. No rule patch or deployment permission. */
final class IncidentTuningProposals {
    static final int MAX = 25;
    static final Set<String> TYPES = Set.of("compare_benign_baseline", "review_rule_scope",
            "review_threshold_or_window", "review_duplicate_grouping", "replay_positive_and_negative_tests");
    private static final Set<String> FIELDS = Set.of("id", "rule_uuid", "baseline_sha256", "candidate_sha256", "type", "reason",
            "replay", "state", "proposed_by", "proposed_at", "decided_by", "decided_at", "decision_reason", "evidence_origin");
    private IncidentTuningProposals() {}

    static List<Map<String, Object>> project(Map<String, Object> source) {
        if (!(source.getOrDefault("tuning_proposals", List.of()) instanceof List<?> items) || items.size() > MAX) {
            throw new IllegalStateException("Invalid tuning proposal history");
        }
        var result = new ArrayList<Map<String, Object>>();
        var ids = new HashSet<String>();
        for (Object item : items) {
            try {
                if (!(item instanceof Map<?, ?> row) || !row.keySet().equals(FIELDS)) throw new IllegalArgumentException();
                var projected = new LinkedHashMap<String, Object>();
                for (String key : FIELDS) projected.put(key, row.get(key));
                String id = text(row.get("id"), 64);
                String prefix = source.get("id") + ":";
                if (!id.startsWith(prefix) || !ids.add(id)) throw new IllegalArgumentException();
                int rev = Integer.parseInt(id.substring(prefix.length()));
                if (rev < 1 || rev > (Integer) source.get("revision") || !id.equals(prefix + rev)) throw new IllegalArgumentException();
                identity(row.get("rule_uuid")); hash(row.get("baseline_sha256")); hash(row.get("candidate_sha256"));
                if (row.get("baseline_sha256").equals(row.get("candidate_sha256")) ||
                        !TYPES.contains(row.get("type")) || !"analyst_supplied_paired_holdout".equals(row.get("evidence_origin"))) throw new IllegalArgumentException();
                text(row.get("reason"), 2048);
                String proposer = text(row.get("proposed_by"), 1024);
                Instant at = Instant.parse(text(row.get("proposed_at"), 64));
                Map<String, Object> replay = TuningReplay.validate(row.get("replay"));
                projected.put("replay", replay);
                String state = text(row.get("state"), 64);
                if ("proposed".equals(state)) {
                    if (row.get("decided_by") != null || row.get("decided_at") != null || row.get("decision_reason") != null) throw new IllegalArgumentException();
                } else {
                    if (!Set.of("accepted_for_review", "rejected", "withdrawn").contains(state)) throw new IllegalArgumentException();
                    String reviewer = text(row.get("decided_by"), 1024);
                    if ((!state.equals("withdrawn") && proposer.equals(reviewer)) ||
                            Instant.parse(text(row.get("decided_at"), 64)).isBefore(at)) throw new IllegalArgumentException();
                    text(row.get("decision_reason"), 2048);
                    if ("accepted_for_review".equals(state) && !"eligible_for_human_review".equals(replay.get("gate"))) throw new IllegalArgumentException();
                }
                result.add(projected);
            } catch (RuntimeException e) { throw new IllegalStateException("Invalid stored tuning proposal", e); }
        }
        return result;
    }

    static String apply(Map<String, Object> source, Map<String, Object> changes, IncidentMutation.Operation op,
            Map<String, Object> input, String actor, String at, int newRevision) {
        var rows = project(source);
        Map<String, Object> before = null;
        var record = new LinkedHashMap<String, Object>();
        String kind;
        if (op == IncidentMutation.Operation.CREATE_TUNING_PROPOSAL) {
            exact(input, Set.of("rule_uuid", "baseline_sha256", "candidate_sha256", "type", "reason", "split", "rows"));
            if (!"holdout".equals(input.get("split")) || !TYPES.contains(input.get("type"))) throw invalid("Invalid proposal type or split");
            if (!Set.of("triaging", "active", "closed").contains(source.get("status"))) throw conflict("Triage before proposing tuning");
            if (rows.size() >= MAX) throw conflict("Tuning proposal capacity reached");
            String rule = identity(input.get("rule_uuid"));
            String baseline = hash(input.get("baseline_sha256")), candidate = hash(input.get("candidate_sha256"));
            if (baseline.equals(candidate)) throw invalid("Distinct rule version hashes required");
            String reason = text(input.get("reason"), 2048);
            Map<String, Object> replay;
            try { replay = TuningReplay.evaluate(input.get("rows")); }
            catch (IllegalArgumentException e) { throw invalid("Invalid paired holdout fixture"); }
            if (rows.stream().anyMatch(row -> rule.equals(row.get("rule_uuid")) && baseline.equals(row.get("baseline_sha256")) &&
                    candidate.equals(row.get("candidate_sha256")) && !"withdrawn".equals(row.get("state")))) {
                throw conflict("Matching version proposal already recorded");
            }
            record.put("id", source.get("id") + ":" + newRevision);
            record.put("rule_uuid", rule); record.put("baseline_sha256", baseline); record.put("candidate_sha256", candidate);
            record.put("type", input.get("type")); record.put("reason", reason); record.put("replay", replay);
            record.put("state", "proposed"); record.put("proposed_by", actor); record.put("proposed_at", at);
            record.put("evidence_origin", "analyst_supplied_paired_holdout");
            record.put("decided_by", null); record.put("decided_at", null); record.put("decision_reason", null);
            rows.add(record); kind = "tuning_proposed";
        } else {
            exact(input, op == IncidentMutation.Operation.REVIEW_TUNING_PROPOSAL ?
                    Set.of("proposal_id", "decision", "reason") : Set.of("proposal_id", "reason"));
            String id = text(input.get("proposal_id"), 64), reason = text(input.get("reason"), 2048);
            int index = -1;
            for (int n = 0; n < rows.size(); n++) if (id.equals(rows.get(n).get("id"))) { index = n; break; }
            if (index < 0) throw conflict("Proposal unavailable");
            before = rows.get(index); record.putAll(before);
            if (!"proposed".equals(record.get("state"))) throw conflict("Proposal decision is terminal");
            String state;
            if (op == IncidentMutation.Operation.WITHDRAW_TUNING_PROPOSAL) {
                state = "withdrawn"; kind = "tuning_withdrawn";
            } else {
                if (actor.equals(record.get("proposed_by"))) throw new OpenSearchStatusException("Independent reviewer required", RestStatus.FORBIDDEN);
                Object decision = input.get("decision");
                if (!Set.of("accepted_for_review", "rejected").contains(decision)) throw invalid("Invalid review decision");
                state = (String) decision;
                if ("accepted_for_review".equals(state) &&
                        !"eligible_for_human_review".equals(((Map<?, ?>) record.get("replay")).get("gate"))) {
                    throw conflict("Replay gate blocks acceptance");
                }
                kind = "accepted_for_review".equals(state) ? "tuning_accepted_for_review" : "tuning_rejected";
            }
            record.put("state", state); record.put("decided_by", actor); record.put("decided_at", at); record.put("decision_reason", reason);
            rows.set(index, record);
        }
        source.put("tuning_proposals", rows);
        var change = new LinkedHashMap<String, Object>();
        change.put("before", before); change.put("after", record);
        changes.put("tuning_proposal", change);
        return kind;
    }

    private static void exact(Map<String, Object> input, Set<String> fields) {
        if (input == null || !input.keySet().equals(fields)) throw invalid("Invalid proposal fields");
    }
    private static String text(Object raw, int max) {
        if (!(raw instanceof String value) || value.isBlank() || value.length() > max) throw invalid("Invalid proposal text");
        return value.trim();
    }
    private static String identity(Object raw) {
        if (!(raw instanceof String value) || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) throw invalid("Invalid rule UUID");
        return value;
    }
    private static String hash(Object raw) {
        if (!(raw instanceof String value) || !value.matches("[a-f0-9]{64}")) throw invalid("Invalid rule version hash");
        return value;
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message, RestStatus.CONFLICT); }
}
