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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.UUID;

/** Analyst attestation only; not a signature of provider execution or an authoritative label. */
final class IncidentAiFeedback {
    static final int MAX = 100;
    static final Set<String> FIELDS = Set.of("assessment_id", "assessed_revision", "digest_sha256", "assessment_mode",
            "assessment_rating", "hypothesis_review");
    private IncidentAiFeedback() {}

    static void apply(Map<String, Object> source, Map<String, Object> changes, Map<String, Object> input, int revision) {
        if (input == null || !input.keySet().equals(FIELDS)) throw invalid("Exact feedback fields required");
        String id = uuid(input.get("assessment_id"));
        if (!(input.get("assessed_revision") instanceof Integer assessed) || assessed < 1 || assessed != revision) {
            throw conflict("Assessment revision changed; reassess before recording feedback");
        }
        if (!(input.get("digest_sha256") instanceof String hash) || !hash.matches("[a-f0-9]{64}")) throw invalid("Invalid digest hash");
        String mode = choice(input.get("assessment_mode"), Set.of("ai_review", "agentic_soc"));
        choice(input.get("assessment_rating"), Set.of("useful", "partly_useful", "not_useful"));
        String review = choice(input.get("hypothesis_review"), Set.of("agree", "disagree", "not_reviewed"));
        if ("ai_review".equals(mode) && !"not_reviewed".equals(review)) throw invalid("AI Review has no classification hypothesis");
        Object raw = source.getOrDefault("ai_feedback_ids", List.of());
        if (!(raw instanceof List<?> ids) || ids.size() > MAX) throw new IllegalStateException("Invalid feedback history");
        var seen = new HashSet<String>();
        for (Object item : ids) if (!seen.add(uuid(item))) throw new IllegalStateException("Duplicate stored feedback identity");
        if (seen.contains(id) || ids.size() >= MAX) throw conflict("Assessment already reviewed or feedback capacity reached");
        var next = new ArrayList<>(ids);
        next.add(id);
        source.put("ai_feedback_ids", next);
        for (String field : FIELDS) changes.put(field, change(input.get(field)));
        changes.put("feedback_origin", change("analyst_attestation"));
        // Closure is independently maintained by incident lifecycle, never by AI feedback.
        if ("closed".equals(source.get("status")) && source.get("closure") instanceof Map<?, ?> closure &&
                closure.get("classification") instanceof String classification) {
            changes.put("closure_classification_at_feedback", change(classification));
        }
    }

    private static String uuid(Object value) {
        try {
            if (!(value instanceof String id) || !UUID.fromString(id).toString().equals(id)) throw invalid("Invalid assessment ID");
            return id;
        } catch (IllegalArgumentException e) { throw invalid("Invalid assessment ID"); }
    }
    private static String choice(Object value, Set<String> choices) {
        if (!(value instanceof String s) || !choices.contains(s)) throw invalid("Invalid feedback choice");
        return s;
    }
    private static Map<String, Object> change(Object value) {
        var result = new LinkedHashMap<String, Object>();
        result.put("before", null); result.put("after", value); return result;
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message, RestStatus.CONFLICT); }
}
