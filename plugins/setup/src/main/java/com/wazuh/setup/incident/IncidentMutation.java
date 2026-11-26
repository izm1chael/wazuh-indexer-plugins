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
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Authoritative indexer-side mutation rules. No caller-supplied document, actor, timestamp,
 * activity envelope or index name is accepted. The transport must gate each operation and
 * resolve the principal before elevating privileges. This class performs no I/O.
 */
public final class IncidentMutation {
    public enum Operation {
        CREATE, ASSIGN_SELF, UNASSIGN, START_TRIAGE, ACTIVATE, CLOSE, REOPEN, EDIT, ATTACH_FINDING, DETACH_FINDING, ADD_NOTE, CREATE_TASK, COMPLETE_TASK, REOPEN_TASK, REQUEST_RESPONSE, CANCEL_RESPONSE, APPROVE_RESPONSE, REJECT_RESPONSE, RECORD_RESPONSE_OUTCOME, APPLY_PLAYBOOK, RECORD_AI_FEEDBACK, CREATE_TUNING_PROPOSAL, REVIEW_TUNING_PROPOSAL, WITHDRAW_TUNING_PROPOSAL, OFFER_HANDOVER, ACCEPT_HANDOVER, CANCEL_HANDOVER, SET_TAGS, ADD_RELATION, REMOVE_RELATION, REGISTER_EVIDENCE, WITHDRAW_EVIDENCE
    }

    private static final Set<String> SEVERITY = Set.of("informational", "low", "medium", "high", "critical");
    private static final Set<String> PRIORITY = Set.of("low", "medium", "high", "urgent");
    private static final Set<String> TLP = Set.of("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED");
    private static final Set<String> CLASSIFICATION = Set.of("true_positive", "benign_positive", "false_positive", "undetermined", "duplicate");
    private static final DateTimeFormatter CLOCK = new DateTimeFormatterBuilder().appendInstant(3).toFormatter();

    private IncidentMutation() {}

    public static Map<String, Object> create(Map<String, Object> input, UUID id, String actor, Instant at) {
        only(input, Set.of("title", "description", "severity", "priority", "tlp"));
        requireActor(actor);
        String now = CLOCK.format(at);
        Map<String, Object> incident = new LinkedHashMap<>();
        incident.put("id", id.toString());
        incident.put("title", text(input.get("title"), 1024, "title", false));
        incident.put("description", text(input.getOrDefault("description", ""), 32768, "description", true));
        incident.put("status", "new");
        incident.put("severity", choice(input.get("severity"), SEVERITY, "severity"));
        incident.put("priority", choice(input.getOrDefault("priority", "medium"), PRIORITY, "priority"));
        incident.put("tlp", choice(input.getOrDefault("tlp", "TLP:AMBER"), TLP, "tlp"));
        incident.put("owner", null);
        incident.put("handover", null);
        incident.put("created_by", actor);
        incident.put("updated_by", actor);
        incident.put("created_at", now);
        incident.put("updated_at", now);
        for (String field : Set.of("first_assigned_at", "triage_started_at", "activated_at", "closed_at", "first_closed_at", "reopened_at", "closure")) {
            incident.put(field, null);
        }
        incident.put("findings", List.of());
        incident.put("finding_count", 0);
        incident.put("tags", List.of());
        incident.put("incident_relations", List.of());
        incident.put("evidence_register", List.of());
        incident.put("tasks", List.of());
        incident.put("playbook_runs", List.of());
        incident.put("automation_runs", List.of());
        incident.put("ai_feedback_ids", List.of());
        incident.put("tuning_proposals", List.of());
        incident.put("response_requests", List.of());
        incident.put("revision", 1);
        Map<String, Object> changes = new LinkedHashMap<>();
        incident.forEach((key, value) -> changes.put(key, change(null, value)));
        incident.put("pending_activity", activity(incident, "created", changes));
        return incident;
    }

    public static Map<String, Object> apply(Map<String, Object> current, Operation operation,
            Map<String, Object> input, int expectedRevision, String actor, Instant at) {
        requireActor(actor);
        if (current == null || !(current.get("revision") instanceof Integer revision) ||
                revision < 1 || revision == Integer.MAX_VALUE || revision != expectedRevision) {
            throw conflict("Incident revision changed or invalid");
        }
        if (current.get("pending_activity") != null) throw conflict("Pending activity must be delivered first");
        if (at.isBefore(Instant.parse((String) current.get("updated_at")))) throw invalid("Incident clock moved backwards");
        String now = CLOCK.format(at);
        String status = (String) current.get("status");
        Object owner = current.get("owner");
        if ("closed".equals(status) && operation != Operation.REOPEN && operation != Operation.RECORD_AI_FEEDBACK &&
                operation != Operation.CREATE_TUNING_PROPOSAL && operation != Operation.REVIEW_TUNING_PROPOSAL &&
                operation != Operation.WITHDRAW_TUNING_PROPOSAL) throw conflict("Reopen before modifying");
        Map<String, Object> next = new LinkedHashMap<>(current);
        Map<String, Object> changes = new LinkedHashMap<>();
        String kind;
        switch (operation) {
            case ASSIGN_SELF:
                only(input, Set.of());
                if (owner != null && !actor.equals(owner)) throw conflict("Incident already assigned");
                if (actor.equals(owner)) throw conflict("Assignment did not change");
                set(next, changes, "owner", actor);
                if (current.get("first_assigned_at") == null) set(next, changes, "first_assigned_at", now);
                kind = "assign";
                break;
            case UNASSIGN:
                only(input, Set.of());
                if (!"new".equals(status) || !actor.equals(owner)) throw conflict("Only an owner can return a new incident to the queue");
                if (current.get("handover") != null) throw conflict("Resolve handover first");
                set(next, changes, "owner", null);
                kind = "assign";
                break;
            case OFFER_HANDOVER:
                only(input, Set.of("target", "reason"));
                requireOwner(owner, actor);
                if (current.get("handover") != null) throw conflict("Handover already pending");
                String target = text(input.get("target"), 1024, "target", false);
                if (!target.equals(input.get("target")) || target.equals(actor) || "_shared".equals(target)
                        || target.chars().anyMatch(Character::isISOControl)) throw invalid("Invalid handover target");
                set(next, changes, "handover", Map.of("target", target, "offered_by", actor, "offered_at", now));
                changes.put("handover_target", change(null, target));
                changes.put("handover_reason", change(null, text(input.get("reason"), 8192, "reason", false)));
                kind = "handover_offered";
                break;
            case ACCEPT_HANDOVER:
            case CANCEL_HANDOVER:
                only(input, Set.of("reason"));
                if (!(current.get("handover") instanceof Map<?, ?> offer) ||
                        !(offer.get("target") instanceof String recipient) ||
                        !Objects.equals(offer.get("offered_by"), owner) || owner == null) {
                    throw conflict("No valid pending handover");
                }
                if (operation == Operation.ACCEPT_HANDOVER) {
                    if (!actor.equals(recipient)) throw new OpenSearchStatusException("Handover recipient required", RestStatus.FORBIDDEN);
                    set(next, changes, "owner", actor);
                    kind = "handover_accepted";
                } else {
                    if (!actor.equals(owner) && !actor.equals(recipient)) throw new OpenSearchStatusException("Handover participant required", RestStatus.FORBIDDEN);
                    kind = "handover_cancelled";
                }
                changes.put("handover_target", change(recipient, null));
                changes.put("handover_reason", change(null, text(input.get("reason"), 8192, "reason", false)));
                set(next, changes, "handover", null);
                break;
            case START_TRIAGE:
                only(input, Set.of());
                requireOwner(owner, actor);
                if (!"new".equals(status)) throw conflict("Only new incidents can enter triage");
                set(next, changes, "status", "triaging");
                set(next, changes, "triage_started_at", now);
                kind = "start_triage";
                break;
            case ACTIVATE:
                only(input, Set.of());
                requireOwner(owner, actor);
                if (!"triaging".equals(status)) throw conflict("Start triage before activation");
                set(next, changes, "status", "active");
                set(next, changes, "activated_at", now);
                kind = "activate";
                break;
            case CLOSE:
                only(input, Set.of("classification", "reason"));
                requireOwner(owner, actor);
                if (!"triaging".equals(status) && !"active".equals(status)) throw conflict("Triage before closing");
                if (current.get("handover") != null) throw conflict("Resolve handover before closing");
                IncidentResponses.requireNoOutstanding(current);
                set(next, changes, "status", "closed");
                set(next, changes, "closed_at", now);
                if (current.get("first_closed_at") == null) set(next, changes, "first_closed_at", now);
                set(next, changes, "closure", Map.of("classification", choice(input.get("classification"), CLASSIFICATION, "classification"),
                        "reason", text(input.get("reason"), 8192, "reason", false), "closed_by", actor));
                kind = "close";
                break;
            case REOPEN:
                only(input, Set.of("reason"));
                requireOwner(owner, actor);
                if (!"closed".equals(status)) throw conflict("Only closed incidents can reopen");
                changes.put("reopen_reason", change(null, text(input.get("reason"), 8192, "reason", false)));
                set(next, changes, "status", current.get("activated_at") == null ? "triaging" : "active");
                set(next, changes, "closed_at", null);
                set(next, changes, "closure", null);
                set(next, changes, "reopened_at", now);
                kind = "reopen";
                break;
            case EDIT:
                only(input, Set.of("title", "description", "severity", "priority", "tlp"));
                requireOwner(owner, actor);
                if (input.containsKey("title")) set(next, changes, "title", text(input.get("title"), 1024, "title", false));
                if (input.containsKey("description")) set(next, changes, "description", text(input.get("description"), 32768, "description", true));
                if (input.containsKey("severity")) set(next, changes, "severity", choice(input.get("severity"), SEVERITY, "severity"));
                if (input.containsKey("priority")) set(next, changes, "priority", choice(input.get("priority"), PRIORITY, "priority"));
                if (input.containsKey("tlp")) set(next, changes, "tlp", choice(input.get("tlp"), TLP, "tlp"));
                if (changes.isEmpty()) throw conflict("Incident fields did not change");
                kind = "edit";
                break;
            case ATTACH_FINDING:
            case DETACH_FINDING:
                requireOwner(owner, actor);
                FindingReference reference = FindingReference.parse(input);
                Object storedFindings = current.getOrDefault("findings", List.of());
                if (!(storedFindings instanceof List<?> links)) throw conflict("Invalid finding links");
                List<Object> findings = new ArrayList<>(links);
                boolean exists = findings.contains(reference.toMap());
                if (operation == Operation.ATTACH_FINDING) {
                    if (exists) throw conflict("Finding already attached");
                    if (findings.size() >= 1000) throw conflict("Incident finding limit reached");
                    findings.add(reference.toMap());
                    kind = "attach_finding";
                } else {
                    if (!exists) throw conflict("Finding not attached");
                    findings.remove(reference.toMap());
                    kind = "detach_finding";
                }
                // Store only the reference. A full before/after list would multiply audit storage.
                next.put("findings", findings);
                changes.put("finding", change(operation == Operation.ATTACH_FINDING ? null : reference.toMap(),
                        operation == Operation.ATTACH_FINDING ? reference.toMap() : null));
                set(next, changes, "finding_count", findings.size());
                break;
            case SET_TAGS:
            case ADD_RELATION:
            case REMOVE_RELATION:
            case REGISTER_EVIDENCE:
            case WITHDRAW_EVIDENCE:
                requireOwner(owner, actor);
                kind = IncidentEvidenceRegister.apply(next, changes, operation, input, actor, now, revision + 1);
                break;
            case ADD_NOTE:
                only(input, Set.of("body"));
                // Any authenticated caller with the collaboration action may contribute a note.
                changes.put("note", change(null, text(input.get("body"), 8192, "note", false)));
                kind = "note_added";
                break;
            case CREATE_TASK:
            case COMPLETE_TASK:
            case REOPEN_TASK:
                requireOwner(owner, actor);
                IncidentTasks.apply(next, changes, operation, input, actor, now, revision + 1);
                kind = switch (operation) {
                    case CREATE_TASK -> "task_created";
                    case COMPLETE_TASK -> "task_completed";
                    default -> "task_reopened";
                };
                break;
            case CREATE_TUNING_PROPOSAL:
            case WITHDRAW_TUNING_PROPOSAL:
                requireOwner(owner, actor);
                kind = IncidentTuningProposals.apply(next, changes, operation, input, actor, now, revision + 1);
                break;
            case REVIEW_TUNING_PROPOSAL:
                kind = IncidentTuningProposals.apply(next, changes, operation, input, actor, now, revision + 1);
                break;
            case RECORD_AI_FEEDBACK:
                requireOwner(owner, actor);
                IncidentAiFeedback.apply(next, changes, input, revision);
                kind = "ai_feedback_recorded";
                break;
            case APPLY_PLAYBOOK:
                requireOwner(owner, actor);
                IncidentPlaybooks.apply(next, changes, input, actor, now, revision + 1);
                kind = "playbook_applied";
                break;
            case REQUEST_RESPONSE:
            case CANCEL_RESPONSE:
                requireOwner(owner, actor);
                kind = IncidentResponses.apply(next, changes, operation, input, actor, now, revision + 1);
                break;
            case APPROVE_RESPONSE:
            case REJECT_RESPONSE:
            case RECORD_RESPONSE_OUTCOME:
                kind = IncidentResponses.apply(next, changes, operation, input, actor, now, revision + 1);
                break;
            default:
                throw invalid("Unsupported mutation");
        }
        next.put("updated_by", actor);
        next.put("updated_at", now);
        next.put("revision", revision + 1);
        next.put("pending_activity", activity(next, kind, changes));
        return next;
    }

    /** Internal automation only: never exposed as an ordinary IncidentMutation.Operation. */
    static Map<String, Object> automate(Map<String, Object> current, Map<String, Object> event,
            IncidentAutomationPolicy.Policy policy, String actor, Instant at) {
        requireActor(actor);
        var rule = IncidentAutomationPolicy.match(policy, current, event);
        if (rule == null) throw conflict("Automation trigger no longer eligible");
        int revision = (Integer) current.get("revision");
        if (revision == Integer.MAX_VALUE || at.isBefore(Instant.parse((String) current.get("updated_at"))))
            throw conflict("Invalid automation revision or clock");
        var history = IncidentAutomationPolicy.receipts(current);
        if (history.size() >= IncidentAutomationPolicy.MAX_RECEIPTS) throw conflict("Automation history capacity reached");
        var next = new LinkedHashMap<>(current);
        var changes = new LinkedHashMap<String, Object>();
        var actions = rule.actions();
        String now = CLOCK.format(at);
        if (actions.containsKey("assign_to") && "new".equals(current.get("status")) && current.get("owner") == null &&
                current.get("handover") == null) {
            set(next, changes, "owner", actions.get("assign_to"));
            if (current.get("first_assigned_at") == null) set(next, changes, "first_assigned_at", now);
        }
        for (String field : List.of("severity", "priority")) {
            var order = field.equals("severity") ? IncidentAutomationPolicy.SEVERITY : IncidentAutomationPolicy.PRIORITY;
            if (order.indexOf(current.get(field)) < 0) throw conflict("Invalid incident classification");
            if (actions.containsKey("raise_" + field) && order.indexOf(actions.get("raise_" + field)) > order.indexOf(current.get(field)))
                set(next, changes, field, actions.get("raise_" + field));
        }
        if (actions.containsKey("add_tags")) {
            var tags = new java.util.TreeSet<>(IncidentEvidenceRegister.storedTags(current));
            @SuppressWarnings("unchecked") var additional = (List<String>) actions.get("add_tags");
            tags.addAll(additional);
            set(next, changes, "tags", IncidentEvidenceRegister.tags(new ArrayList<>(tags)));
        }
        if (actions.containsKey("create_task")) {
            IncidentInvestigationService.projectTasks(next);
            IncidentTasks.apply(next, changes, Operation.CREATE_TASK, Map.of("title", actions.get("create_task")), actor, now, revision + 1);
        }
        if (actions.containsKey("apply_playbook")) {
            String template = (String) actions.get("apply_playbook");
            var candidate = IncidentPlaybooks.preview(next).stream().filter(row -> template.equals(row.get("template_id")) &&
                    Integer.valueOf(1).equals(row.get("version"))).findFirst().orElseThrow(() -> conflict("Playbook unavailable"));
            if ("available".equals(candidate.get("state"))) {
                IncidentPlaybooks.apply(next, changes, Map.of("template_id", template, "version", 1), actor, now, revision + 1);
            } else if (!"already_applied".equals(candidate.get("state"))) throw conflict("Automation playbook not eligible or at capacity");
        }
        var receipt = Map.<String, Object>of("policy_id", policy.id().toString(), "policy_version", policy.version(),
                "policy_hash", policy.fingerprint(), "rule_id", rule.id(), "trigger_revision", revision,
                "applied_revision", revision + 1, "actor", actor, "at", now, "changed_fields", changes.size());
        history.add(receipt);
        next.put("automation_runs", history);
        changes.put("automation_receipt", change(null, receipt));
        changes.put("automation_policy_id", change(null, policy.id().toString()));
        changes.put("automation_policy_version", change(null, policy.version()));
        changes.put("automation_rule_id", change(null, rule.id()));
        changes.put("automation_trigger_revision", change(null, revision));
        changes.put("automation_changed_fields", change(null, receipt.get("changed_fields")));
        next.put("updated_by", actor); next.put("updated_at", now); next.put("revision", revision + 1);
        next.put("pending_activity", activity(next, "automation_applied", changes));
        IncidentAutomationPolicy.receipts(next);
        return next;
    }

    private static void only(Map<String, Object> input, Set<String> allowed) {
        if (input == null || !allowed.containsAll(input.keySet())) throw invalid("Unsupported request field");
    }

    private static String text(Object value, int max, String field, boolean allowBlank) {
        if (!(value instanceof String s) || s.length() > max || (!allowBlank && s.isBlank())) throw invalid("Invalid " + field);
        return allowBlank ? s : s.trim();
    }

    private static String choice(Object value, Set<String> choices, String field) {
        if (!(value instanceof String s) || !choices.contains(s)) throw invalid("Invalid " + field);
        return s;
    }

    private static void requireActor(String actor) {
        if (actor == null || actor.isBlank() || actor.length() > 1024 || "_shared".equals(actor)) {
            throw new OpenSearchStatusException("Authenticated incident principal required", RestStatus.UNAUTHORIZED);
        }
    }

    private static void requireOwner(Object owner, String actor) {
        if (!actor.equals(owner)) throw new OpenSearchStatusException("Incident owner required", RestStatus.FORBIDDEN);
    }

    private static void set(Map<String, Object> next, Map<String, Object> changes, String field, Object value) {
        if (!Objects.equals(next.get(field), value)) {
            changes.put(field, change(next.get(field), value));
            next.put(field, value);
        }
    }

    private static Map<String, Object> change(Object before, Object after) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("before", before);
        result.put("after", after);
        return result;
    }

    private static Map<String, Object> activity(Map<String, Object> incident, String kind, Map<String, Object> changes) {
        return Map.of("id", incident.get("id") + ":" + incident.get("revision"),
                "incident_id", incident.get("id"), "revision", incident.get("revision"),
                "kind", kind, "actor", incident.get("updated_by"), "at", incident.get("updated_at"), "changes", changes);
    }

    private static OpenSearchStatusException invalid(String message) {
        return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST);
    }

    private static OpenSearchStatusException conflict(String message) {
        return new OpenSearchStatusException(message, RestStatus.CONFLICT);
    }
}
