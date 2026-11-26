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
import java.util.TreeSet;

/** Bounded analyst-authored investigation metadata. Never copies source findings or retrieves an artifact. */
final class IncidentEvidenceRegister {
    static final int MAX_TAGS = 25, MAX_RELATIONS = 50, MAX_EVIDENCE = 50;
    private static final Set<String> RELATION_TYPES = Set.of("related", "possible_duplicate", "possible_same_campaign");
    private static final Set<String> EVIDENCE_TYPES = Set.of("log_export", "disk_image", "memory_image", "network_capture", "screenshot", "other");
    private static final Set<String> RELATION_FIELDS = Set.of("id", "target_id", "type", "reason", "recorded_by", "recorded_at");
    private static final Set<String> EVIDENCE_FIELDS = Set.of("id", "type", "label", "sha256", "custody_reference", "recorded_by", "recorded_at",
            "state", "withdrawn_by", "withdrawn_at", "withdrawal_reason", "origin");
    private IncidentEvidenceRegister() {}

    static List<String> tags(Object raw) {
        if (!(raw instanceof List<?> list) || list.size() > MAX_TAGS) throw invalid("Invalid tag list");
        var result = new TreeSet<String>();
        for (Object item : list) {
            if (!(item instanceof String tag) || !tag.matches("[a-z0-9][a-z0-9_-]{0,63}") || !result.add(tag)) throw invalid("Invalid or duplicate tag");
        }
        return new ArrayList<>(result);
    }

    static List<String> storedTags(Map<String, Object> source) {
        try { return tags(source.getOrDefault("tags", List.of())); }
        catch (RuntimeException e) { throw new IllegalStateException("Invalid stored incident tags", e); }
    }

    static List<Map<String, Object>> relations(Map<String, Object> source) {
        try {
            var rows = rows(source, "incident_relations", MAX_RELATIONS, RELATION_FIELDS);
            var unique = new HashSet<String>();
            for (var row : rows) {
                String target = uuid(row.get("target_id"));
                if (target.equals(source.get("id")) || !RELATION_TYPES.contains(row.get("type")) || !unique.add(target)) throw invalid("Invalid relation");
                text(row.get("reason"), 1024); attribution(row, "recorded");
            }
            return rows;
        } catch (RuntimeException e) { throw new IllegalStateException("Invalid stored incident relations", e); }
    }

    static List<Map<String, Object>> evidence(Map<String, Object> source) {
        try {
            var rows = rows(source, "evidence_register", MAX_EVIDENCE, EVIDENCE_FIELDS);
            var unique = new HashSet<String>();
            for (var row : rows) {
                if (!EVIDENCE_TYPES.contains(row.get("type")) || !"analyst_attested_external_artifact".equals(row.get("origin"))) throw invalid("Invalid evidence type");
                text(row.get("label"), 256); hash(row.get("sha256")); text(row.get("custody_reference"), 256);
                Instant recorded = attribution(row, "recorded");
                if (!unique.add(row.get("sha256") + ":" + row.get("custody_reference"))) throw invalid("Duplicate evidence identity");
                if ("recorded".equals(row.get("state"))) {
                    if (row.get("withdrawn_by") != null || row.get("withdrawn_at") != null || row.get("withdrawal_reason") != null) throw invalid("Invalid recorded evidence");
                } else if ("withdrawn".equals(row.get("state"))) {
                    if (attribution(row, "withdrawn").isBefore(recorded)) throw invalid("Invalid withdrawal time");
                    text(row.get("withdrawal_reason"), 1024);
                } else throw invalid("Invalid evidence state");
            }
            return rows;
        } catch (RuntimeException e) { throw new IllegalStateException("Invalid stored evidence register", e); }
    }

    private static List<Map<String, Object>> rows(Map<String, Object> source, String field, int max, Set<String> fields) {
        if (!(source.getOrDefault(field, List.of()) instanceof List<?> items) || items.size() > max) throw invalid("Invalid register");
        var result = new ArrayList<Map<String, Object>>();
        var ids = new HashSet<String>();
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> row) || !row.keySet().equals(fields)) throw invalid("Invalid register record");
            String id = text(row.get("id"), 64), prefix = source.get("id") + ":";
            if (!id.startsWith(prefix) || !ids.add(id)) throw invalid("Invalid record identity");
            int rev = Integer.parseInt(id.substring(prefix.length()));
            if (rev < 1 || rev > (Integer) source.get("revision") || !id.equals(prefix + rev)) throw invalid("Invalid record revision");
            var copy = new LinkedHashMap<String, Object>();
            for (String name : fields) copy.put(name, row.get(name));
            result.add(copy);
        }
        return result;
    }

    static String apply(Map<String, Object> next, Map<String, Object> changes, IncidentMutation.Operation operation,
            Map<String, Object> input, String actor, String at, int revision) {
        String id = next.get("id") + ":" + revision;
        switch (operation) {
            case SET_TAGS: {
                exact(input, Set.of("tags"));
                var before = storedTags(next); var after = tags(input.get("tags"));
                if (before.equals(after)) throw conflict("Tags did not change");
                next.put("tags", after); changes.put("tags", change(before, after));
                return "tags_updated";
            }
            case ADD_RELATION: {
                exact(input, Set.of("target_id", "type", "reason"));
                String target = uuid(input.get("target_id"));
                if (target.equals(next.get("id")) || !RELATION_TYPES.contains(input.get("type"))) throw invalid("Invalid incident relation");
                var rows = relations(next);
                if (rows.size() >= MAX_RELATIONS || rows.stream().anyMatch(row -> target.equals(row.get("target_id")))) throw conflict("Relation already exists or capacity reached");
                var row = Map.<String, Object>of("id", id, "target_id", target, "type", input.get("type"),
                        "reason", text(input.get("reason"), 1024), "recorded_by", actor, "recorded_at", at);
                rows.add(row); next.put("incident_relations", rows); changes.put("incident_relation", change(null, row));
                return "incident_relation_added";
            }
            case REMOVE_RELATION: {
                exact(input, Set.of("relation_id", "reason"));
                var rows = relations(next); String key = text(input.get("relation_id"), 64);
                var row = rows.stream().filter(item -> key.equals(item.get("id"))).findFirst().orElseThrow(() -> conflict("Relation unavailable"));
                rows.remove(row); next.put("incident_relations", rows);
                changes.put("incident_relation", change(row, null));
                changes.put("relation_removal_reason", change(null, text(input.get("reason"), 1024)));
                return "incident_relation_removed";
            }
            case REGISTER_EVIDENCE: {
                exact(input, Set.of("type", "label", "sha256", "custody_reference"));
                if (!EVIDENCE_TYPES.contains(input.get("type"))) throw invalid("Invalid evidence type");
                var rows = evidence(next);
                String digest = hash(input.get("sha256")), custody = text(input.get("custody_reference"), 256);
                if (rows.size() >= MAX_EVIDENCE || rows.stream().anyMatch(row -> digest.equals(row.get("sha256")) && custody.equals(row.get("custody_reference")))) throw conflict("Evidence identity already recorded or capacity reached");
                var row = new LinkedHashMap<String, Object>();
                row.put("id", id); row.put("type", input.get("type")); row.put("label", text(input.get("label"), 256));
                row.put("sha256", digest); row.put("custody_reference", custody); row.put("recorded_by", actor); row.put("recorded_at", at);
                row.put("origin", "analyst_attested_external_artifact"); row.put("state", "recorded");
                row.put("withdrawn_by", null); row.put("withdrawn_at", null); row.put("withdrawal_reason", null);
                rows.add(row); next.put("evidence_register", rows); changes.put("evidence_record", change(null, row));
                return "evidence_registered";
            }
            case WITHDRAW_EVIDENCE: {
                exact(input, Set.of("evidence_id", "reason"));
                var rows = evidence(next); String key = text(input.get("evidence_id"), 64);
                var old = rows.stream().filter(item -> key.equals(item.get("id"))).findFirst().orElseThrow(() -> conflict("Evidence unavailable"));
                if (!"recorded".equals(old.get("state"))) throw conflict("Evidence already withdrawn");
                var row = new LinkedHashMap<>(old);
                row.put("state", "withdrawn"); row.put("withdrawn_by", actor); row.put("withdrawn_at", at);
                row.put("withdrawal_reason", text(input.get("reason"), 1024));
                rows.set(rows.indexOf(old), row); next.put("evidence_register", rows);
                changes.put("evidence_record", change(old, row));
                return "evidence_withdrawn";
            }
            default: throw invalid("Unsupported register operation");
        }
    }

    private static Map<String, Object> change(Object before, Object after) {
        var change = new LinkedHashMap<String, Object>(); change.put("before", before); change.put("after", after); return change;
    }
    private static void exact(Map<String, Object> input, Set<String> fields) {
        if (input == null || !input.keySet().equals(fields)) throw invalid("Unexpected register fields");
    }
    private static Instant attribution(Map<String, Object> row, String prefix) {
        text(row.get(prefix + "_by"), 1024); return Instant.parse(text(row.get(prefix + "_at"), 64));
    }
    private static String text(Object raw, int max) {
        if (!(raw instanceof String value) || value.isBlank() || value.length() > max || value.chars().anyMatch(Character::isISOControl)) throw invalid("Invalid register text");
        return value.trim();
    }
    private static String hash(Object raw) {
        if (!(raw instanceof String value) || !value.matches("[a-f0-9]{64}")) throw invalid("Lowercase SHA-256 required");
        return value;
    }
    private static String uuid(Object raw) {
        if (!(raw instanceof String value)) throw invalid("Canonical incident UUID required");
        return IncidentReadService.canonicalId(value).toString();
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message, RestStatus.CONFLICT); }
}
