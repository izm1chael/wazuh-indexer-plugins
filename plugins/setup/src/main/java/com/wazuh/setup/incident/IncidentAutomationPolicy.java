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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Immutable ordered automation rule set. Shared case metadata only, no arbitrary scripts or source reads. */
public final class IncidentAutomationPolicy {
    static final int MAX_RULES = 10, MAX_RECEIPTS = 50;
    static final List<String> SEVERITY = List.of("informational", "low", "medium", "high", "critical");
    static final List<String> PRIORITY = List.of("low", "medium", "high", "urgent");
    static final Set<String> UPDATES = Set.of("assign", "start_triage", "activate", "edit", "attach_finding", "detach_finding", "tags_updated", "reopen", "handover_accepted");
    private static final Set<String> FIELDS = Set.of("policy_id", "policy_version", "rules");
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private IncidentAutomationPolicy() {}

    public record Rule(String id, String trigger, String severity, String status, int minimumFindings,
            boolean unassigned, List<String> requiredTags, String correlationPolicy, Map<String, Object> actions) {
        Map<String, Object> definition() {
            var out = new LinkedHashMap<String, Object>();
            out.put("id", id); out.put("trigger", trigger); out.put("minimum_severity", severity); out.put("status", status);
            out.put("minimum_findings", minimumFindings); out.put("unassigned_only", unassigned); out.put("required_tags", requiredTags);
            out.put("correlation_policy_id", correlationPolicy); out.put("actions", actions);
            return out;
        }
    }
    public record Policy(UUID id, int version, List<Rule> rules) {
        Map<String, Object> definition() {
            return Map.of("policy_id", id.toString(), "policy_version", version, "rules", rules.stream().map(Rule::definition).toList());
        }
        public String fingerprint() {
            try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(definition()))); }
            catch (Exception e) { throw new IllegalStateException("Automation fingerprint unavailable", e); }
        }
    }
    public static Policy parse(Map<?, ?> input) {
        if (input == null || !input.keySet().equals(FIELDS) || !(input.get("policy_id") instanceof String id) ||
                !(input.get("policy_version") instanceof Integer version) || version < 1 ||
                !(input.get("rules") instanceof List<?> items) || items.isEmpty() || items.size() > MAX_RULES) throw invalid("Invalid automation policy");
        UUID uuid = IncidentReadService.canonicalId(id);
        var seen = new HashSet<String>(); var rules = new ArrayList<Rule>();
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> row) || !row.keySet().equals(Set.of("id", "trigger", "minimum_severity", "status",
                    "minimum_findings", "unassigned_only", "required_tags", "correlation_policy_id", "actions"))) throw invalid("Invalid automation rule");
            String key = text(row.get("id"), 64);
            if (!key.matches("[a-z][a-z0-9_-]{0,63}") || !seen.add(key)) throw invalid("Duplicate or invalid automation rule ID");
            String trigger = choice(row.get("trigger"), Set.of("created", "updated"));
            String severity = choice(row.get("minimum_severity"), SEVERITY);
            String status = choice(row.get("status"), Set.of("any_open", "new", "triaging", "active"));
            if (!(row.get("minimum_findings") instanceof Integer minimum) || minimum < 0 || minimum > 1000 ||
                    !(row.get("unassigned_only") instanceof Boolean unassigned) || !(row.get("actions") instanceof Map<?, ?> raw) ||
                    raw.isEmpty() || !Set.of("assign_to", "raise_severity", "raise_priority", "add_tags", "create_task", "apply_playbook").containsAll(raw.keySet()))
                throw invalid("Invalid automation conditions or actions");
            var actions = new LinkedHashMap<String, Object>();
            if (raw.containsKey("assign_to")) {
                String owner = text(raw.get("assign_to"), 1024);
                if ("_shared".equals(owner)) throw invalid("Invalid assignment target");
                actions.put("assign_to", owner);
            }
            if (raw.containsKey("raise_severity")) actions.put("raise_severity", choice(raw.get("raise_severity"), SEVERITY));
            if (raw.containsKey("raise_priority")) actions.put("raise_priority", choice(raw.get("raise_priority"), PRIORITY));
            if (raw.containsKey("add_tags")) {
                var tags = IncidentEvidenceRegister.tags(raw.get("add_tags"));
                if (tags.isEmpty()) throw invalid("Empty tag action");
                actions.put("add_tags", List.copyOf(tags));
            }
            if (raw.containsKey("create_task")) actions.put("create_task", text(raw.get("create_task"), 1024));
            if (raw.containsKey("apply_playbook")) actions.put("apply_playbook", choice(raw.get("apply_playbook"),
                    Set.of("initial_triage", "high_severity_review", "linked_finding_review")));
            String correlation = row.get("correlation_policy_id") == null ? null :
                    IncidentReadService.canonicalId(text(row.get("correlation_policy_id"), 36)).toString();
            rules.add(new Rule(key, trigger, severity, status, minimum, unassigned,
                    List.copyOf(IncidentEvidenceRegister.tags(row.get("required_tags"))), correlation, Map.copyOf(actions)));
        }
        return new Policy(uuid, version, List.copyOf(rules));
    }

    /** Latest delivered event only; superseded events are deliberately not replayed. */
    static Rule match(Policy policy, Map<String, Object> source, Map<String, Object> event) {
        if (source.get("pending_activity") != null || "closed".equals(source.get("status"))) return null;
        if (!(source.get("revision") instanceof Integer revision) || revision < 1 ||
                !source.get("id").equals(event.get("incident_id")) || !Integer.valueOf(revision).equals(event.get("revision")) ||
                !(source.get("id") + ":" + revision).equals(event.get("id")) ||
                !source.get("updated_at").equals(event.get("at")) || !source.get("updated_by").equals(event.get("actor")) ||
                !(event.get("changes") instanceof Map<?, ?>) || !(event.get("kind") instanceof String kind)) throw new IllegalStateException("Automation event identity mismatch");
        String trigger = "created".equals(kind) && revision == 1 ? "created" : UPDATES.contains(kind) ? "updated" : null;
        if (alreadyRecorded(policy, source) || trigger == null) return null;
        int severity = SEVERITY.indexOf(source.get("severity"));
        if (severity < 0 || !(source.get("finding_count") instanceof Integer count) || count < 0 || count > 1000 ||
                !Set.of("new", "triaging", "active").contains(source.get("status"))) throw new IllegalStateException("Invalid automation source metadata");
        var tags = IncidentEvidenceRegister.storedTags(source);
        String correlation = source.get("correlation_origin") instanceof Map<?, ?> origin && origin.get("policy_id") instanceof String id ? id : null;
        for (Rule rule : policy.rules()) {
            if (rule.trigger().equals(trigger) && severity >= SEVERITY.indexOf(rule.severity()) &&
                    ("any_open".equals(rule.status()) || rule.status().equals(source.get("status"))) &&
                    count >= rule.minimumFindings() && (!rule.unassigned() || source.get("owner") == null) &&
                    tags.containsAll(rule.requiredTags()) && (rule.correlationPolicy() == null || rule.correlationPolicy().equals(correlation))) return rule;
        }
        return null;
    }

    static boolean alreadyRecorded(Policy policy, Map<String, Object> source) {
        for (var row : receipts(source)) {
            if (policy.id().toString().equals(row.get("policy_id")) && Integer.valueOf(policy.version()).equals(row.get("policy_version"))) {
                if (!policy.fingerprint().equals(row.get("policy_hash")) ||
                        policy.rules().stream().noneMatch(rule -> rule.id().equals(row.get("rule_id"))))
                    throw new IllegalStateException("Automation receipt policy mismatch");
                return true;
            }
        }
        return false;
    }

    static List<Map<String, Object>> receipts(Map<String, Object> source) {
        if (!(source.getOrDefault("automation_runs", List.of()) instanceof List<?> rows) || rows.size() > MAX_RECEIPTS)
            throw new IllegalStateException("Invalid automation history");
        var seen = new HashSet<String>(); var result = new ArrayList<Map<String, Object>>();
        int prior = 0;
        for (Object item : rows) {
            if (!(item instanceof Map<?, ?> row) || !row.keySet().equals(Set.of("policy_id", "policy_version", "policy_hash",
                    "rule_id", "trigger_revision", "applied_revision", "actor", "at", "changed_fields")) ||
                    !(row.get("policy_id") instanceof String id) || !(row.get("policy_version") instanceof Integer version) || version < 1 ||
                    !(row.get("policy_hash") instanceof String hash) || !hash.matches("[a-f0-9]{64}") ||
                    !(row.get("rule_id") instanceof String rule) || !rule.matches("[a-z][a-z0-9_-]{0,63}") ||
                    !(row.get("trigger_revision") instanceof Integer trigger) || !(row.get("applied_revision") instanceof Integer applied) ||
                    trigger < 1 || applied != trigger + 1 || applied <= prior || applied > (Integer) source.get("revision") ||
                    !(row.get("changed_fields") instanceof Integer fields) || fields < 0 || fields > 7 ||
                    !seen.add(id + ":" + version)) throw new IllegalStateException("Invalid automation receipt");
            IncidentReadService.canonicalId(id); text(row.get("actor"), 1024); Instant.parse(text(row.get("at"), 30));
            prior = applied;
            var copy = new LinkedHashMap<String, Object>(); row.forEach((k, v) -> copy.put((String) k, v)); result.add(copy);
        }
        return result;
    }

    private static String text(Object raw, int max) {
        if (!(raw instanceof String s) || s.isBlank() || s.length() > max || !s.equals(s.trim()) ||
                s.chars().anyMatch(Character::isISOControl)) throw invalid("Invalid automation text");
        return s;
    }
    private static String choice(Object raw, java.util.Collection<String> allowed) {
        if (!(raw instanceof String s) || !allowed.contains(s)) throw invalid("Invalid automation choice");
        return s;
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
}
