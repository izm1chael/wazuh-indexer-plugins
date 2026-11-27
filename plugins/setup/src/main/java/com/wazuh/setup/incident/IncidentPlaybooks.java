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
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Built-in versioned human investigation checklists; no executable action or external I/O. */
final class IncidentPlaybooks {
    private record Template(String id, int version, String title, List<String> tasks) {}
    private static final List<Template> CATALOG = List.of(
        new Template("initial_triage", 1, "Initial incident triage", List.of(
                "Review the detection and available source findings",
                "Identify affected assets and accounts",
                "Assess severity, priority and potential impact",
                "Record the initial assessment and next investigation steps")),
        new Template("high_severity_review", 1, "High-severity investigation", List.of(
                "Confirm the affected scope and business impact",
                "Review evidence for lateral movement or persistence",
                "Assess containment options through the response approval workflow",
                "Document escalation and handover requirements")),
        new Template("linked_finding_review", 1, "Linked finding investigation", List.of(
                "Review each accessible linked finding and its chronology",
                "Identify common entities and ATT&CK techniques",
                "Document corroborating evidence and any unavailable sources",
                "Assess whether findings belong to the same incident"))
    );
    private IncidentPlaybooks() {}

    private static boolean eligible(Template template, Map<String, Object> source) {
        if (!Set.of("triaging", "active").contains(source.get("status")) || source.get("owner") == null) return false;
        return switch (template.id()) {
            case "initial_triage" -> true;
            case "high_severity_review" -> Set.of("high", "critical").contains(source.get("severity"));
            case "linked_finding_review" -> source.get("finding_count") instanceof Number count && count.intValue() > 0;
            default -> false;
        };
    }

    static List<Map<String, Object>> runs(Map<String, Object> source) {
        Object raw = source.getOrDefault("playbook_runs", List.of());
        if (!(raw instanceof List<?> items) || items.size() > 100) throw new IllegalStateException("Invalid playbook history");
        var result = new ArrayList<Map<String, Object>>();
        var seen = new HashSet<String>();
        var usedTasks = new HashSet<String>();
        var tasks = IncidentInvestigationService.projectTasks(source);
        for (Object entry : items) {
            if (!(entry instanceof Map<?, ?> row) || !(row.get("template_id") instanceof String id) ||
                    !id.matches("[a-z][a-z0-9_]{0,63}") || !(row.get("version") instanceof Integer version) || version < 1 ||
                    !(row.get("applied_revision") instanceof Integer rev) || rev < 1 ||
                    !(source.get("revision") instanceof Number sourceRevision) || rev > sourceRevision.longValue() ||
                    !(row.get("applied_by") instanceof String actor) || actor.isBlank() || actor.length() > 1024 ||
                    !(row.get("applied_at") instanceof String at) ||
                    !(row.get("task_ids") instanceof List<?> ids) || ids.isEmpty() || ids.size() > 20 ||
                    !seen.add(id + ":" + version)) throw new IllegalStateException("Invalid playbook receipt");
            java.time.Instant.parse(at);
            for (int n = 0; n < ids.size(); n++) {
                String expected = source.get("id") + ":" + rev + ":" + (n + 1);
                if (!expected.equals(ids.get(n)) || !usedTasks.add(expected) ||
                        tasks.stream().noneMatch(task -> expected.equals(task.get("id")) &&
                                actor.equals(task.get("created_by")) && at.equals(task.get("created_at")))) {
                    throw new IllegalStateException("Invalid playbook task membership");
                }
            }
            result.add(Map.of("template_id", id, "version", version, "applied_revision", rev,
                    "applied_by", actor, "applied_at", at, "task_ids", List.copyOf(ids)));
        }
        return result;
    }

    static List<Map<String, Object>> preview(Map<String, Object> source) {
        var runs = runs(source);
        int size = IncidentInvestigationService.projectTasks(source).size();
        return CATALOG.stream().map(template -> {
            boolean applied = runs.stream().anyMatch(run -> template.id().equals(run.get("template_id")) &&
                    Integer.valueOf(template.version()).equals(run.get("version")));
            boolean matches = eligible(template, source);
            boolean capacity = size + template.tasks().size() <= 100 && runs.size() < 100;
            return Map.<String, Object>of("template_id", template.id(), "version", template.version(), "title", template.title(),
                    "tasks", template.tasks(), "state", applied ? "already_applied" : !matches ? "not_applicable" :
                            !capacity ? "capacity_exceeded" : "available");
        }).toList();
    }

    static void apply(Map<String, Object> next, Map<String, Object> changes, Map<String, Object> input,
            String actor, String at, int revision) {
        if (input == null || !input.keySet().equals(Set.of("template_id", "version")) ||
                !(input.get("template_id") instanceof String id) || !(input.get("version") instanceof Integer version)) {
            throw invalid("Exact template ID and integer version required");
        }
        Template template = CATALOG.stream().filter(t -> t.id().equals(id) && t.version() == version).findFirst()
                .orElseThrow(() -> invalid("Unknown playbook version"));
        var history = runs(next);
        if (!eligible(template, next)) throw conflict("Playbook conditions not met");
        if (history.stream().anyMatch(run -> id.equals(run.get("template_id")) && version.equals(run.get("version")))) {
            throw conflict("Playbook version already applied");
        }
        var tasks = new ArrayList<>(IncidentInvestigationService.projectTasks(next));
        if (tasks.size() + template.tasks().size() > 100 || history.size() >= 100) throw conflict("Insufficient playbook capacity");
        var created = new ArrayList<Map<String, Object>>();
        var ids = new ArrayList<String>();
        for (String title : template.tasks()) {
            var task = new LinkedHashMap<String, Object>();
            String taskId = next.get("id") + ":" + revision + ":" + (ids.size() + 1);
            task.put("id", taskId); task.put("title", title); task.put("status", "open");
            task.put("created_by", actor); task.put("created_at", at);
            task.put("completed_by", null); task.put("completed_at", null);
            ids.add(taskId); created.add(task); tasks.add(task);
        }
        var receipt = Map.<String, Object>of("template_id", id, "version", version, "applied_revision", revision,
                "applied_by", actor, "applied_at", at, "task_ids", List.copyOf(ids));
        history.add(receipt);
        next.put("tasks", tasks);
        next.put("playbook_runs", history);
        var change = new LinkedHashMap<String, Object>();
        change.put("before", null);
        change.put("after", Map.of("receipt", receipt, "created_tasks", created));
        changes.put("playbook", change);
    }

    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message, RestStatus.CONFLICT); }
}
