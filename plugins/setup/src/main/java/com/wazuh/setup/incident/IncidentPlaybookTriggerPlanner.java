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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure, staged planner for a delivered lifecycle event at the current revision.
 * A recommendation is not permission to execute; no scheduler or writer uses this class.
 */
final class IncidentPlaybookTriggerPlanner {
    record Plan(String incidentId, int expectedRevision, String eventId,
            String templateId, int version, String deduplicationKey) {}

    private IncidentPlaybookTriggerPlanner() {}

    static List<Plan> plan(Map<String, Object> source, Map<String, Object> event) {
        if (source == null || event == null || !(source.get("id") instanceof String id) ||
                !(source.get("revision") instanceof Integer revision) || revision < 1 ||
                source.get("pending_activity") != null || !id.equals(event.get("incident_id")) ||
                !Integer.valueOf(revision).equals(event.get("revision")) ||
                !(id + ":" + revision).equals(event.get("id")) ||
                !(event.get("kind") instanceof String kind) || !(event.get("changes") instanceof Map<?, ?> changes) ||
                !(source.get("updated_at") instanceof String updatedAt) || !updatedAt.equals(event.get("at")) ||
                !(source.get("updated_by") instanceof String updatedBy) || !updatedBy.equals(event.get("actor"))) {
            return List.of();
        }
        Set<String> candidates;
        switch (kind) {
            case "start_triage":
                if (!"triaging".equals(source.get("status")) ||
                        !transition(changes, "status", "new", "triaging")) return List.of();
                candidates = Set.of("initial_triage", "high_severity_review", "linked_finding_review");
                break;
            case "activate":
                if (!"active".equals(source.get("status")) ||
                        !transition(changes, "status", "triaging", "active")) return List.of();
                candidates = Set.of("initial_triage", "high_severity_review", "linked_finding_review");
                break;
            case "edit":
                if (!(source.get("severity") instanceof String severity) || !Set.of("high", "critical").contains(severity) ||
                        !(changes.get("severity") instanceof Map<?, ?> severityChange) ||
                        !severity.equals(severityChange.get("after")) ||
                        !(severityChange.get("before") instanceof String before) ||
                        !Set.of("informational", "low", "medium").contains(before)) return List.of();
                candidates = Set.of("high_severity_review");
                break;
            case "attach_finding":
                if (!(source.get("finding_count") instanceof Integer count) || count != 1 ||
                        !transition(changes, "finding_count", 0, 1)) return List.of();
                candidates = Set.of("linked_finding_review");
                break;
            default:
                return List.of();
        }
        var result = new ArrayList<Plan>();
        for (var preview : IncidentPlaybooks.preview(source)) {
            String template = (String) preview.get("template_id");
            int version = (Integer) preview.get("version");
            if (candidates.contains(template) && "available".equals(preview.get("state"))) {
                result.add(new Plan(id, revision, (String) event.get("id"), template, version,
                        id + ":" + template + ":" + version));
            }
        }
        return List.copyOf(result);
    }

    private static boolean transition(Map<?, ?> changes, String field, Object before, Object after) {
        return changes.get(field) instanceof Map<?, ?> change &&
                before.equals(change.get("before")) && after.equals(change.get("after"));
    }
}
