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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded current task state; all transitions are separately preserved in activity. */
final class IncidentTasks {
    private IncidentTasks() {}

    static void apply(Map<String, Object> next, Map<String, Object> changes, IncidentMutation.Operation operation,
            Map<String, Object> input, String actor, String at, int revision) {
        Object stored = next.getOrDefault("tasks", List.of());
        if (!(stored instanceof List<?> existing)) throw conflict("Invalid task state");
        List<Object> tasks = new ArrayList<>(existing);
        if (operation == IncidentMutation.Operation.CREATE_TASK) {
            if (!input.keySet().equals(Set.of("title"))) throw invalid("Task title required");
            if (!(input.get("title") instanceof String title) || title.isBlank() || title.length() > 1024) {
                throw invalid("Invalid task title");
            }
            if (tasks.size() >= 100) throw conflict("Incident task capacity reached");
            Map<String, Object> task = new LinkedHashMap<>();
            task.put("id", next.get("id") + ":" + revision);
            task.put("title", title.trim());
            task.put("status", "open");
            task.put("created_by", actor);
            task.put("created_at", at);
            task.put("completed_by", null);
            task.put("completed_at", null);
            tasks.add(task);
            changes.put("task", change(null, task));
        } else {
            if (!input.keySet().equals(Set.of("task_id")) || !(input.get("task_id") instanceof String id)) {
                throw invalid("Task ID required");
            }
            int found = -1;
            for (int n = 0; n < tasks.size(); n++) {
                if (tasks.get(n) instanceof Map<?, ?> task && id.equals(task.get("id"))) {
                    found = n;
                    break;
                }
            }
            if (found < 0) throw conflict("Task not found");
            @SuppressWarnings("unchecked")
            Map<String, Object> previous = (Map<String, Object>) tasks.get(found);
            Map<String, Object> task = new LinkedHashMap<>(previous);
            boolean complete = operation == IncidentMutation.Operation.COMPLETE_TASK;
            if (!(complete ? "open" : "completed").equals(previous.get("status"))) throw conflict("Invalid task transition");
            task.put("status", complete ? "completed" : "open");
            task.put("completed_by", complete ? actor : null);
            task.put("completed_at", complete ? at : null);
            tasks.set(found, task);
            changes.put("task", change(previous, task));
        }
        next.put("tasks", tasks);
    }

    private static Map<String, Object> change(Object before, Object after) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("before", before);
        result.put("after", after);
        return result;
    }
    private static OpenSearchStatusException invalid(String message) {
        return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST);
    }
    private static OpenSearchStatusException conflict(String message) {
        return new OpenSearchStatusException(message, RestStatus.CONFLICT);
    }
}
