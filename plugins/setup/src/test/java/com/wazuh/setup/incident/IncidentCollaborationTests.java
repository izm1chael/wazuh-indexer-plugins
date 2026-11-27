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
import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.UUID;
import java.time.Instant;
import static com.wazuh.setup.incident.IncidentMutation.Operation.*;

public class IncidentCollaborationTests extends OpenSearchTestCase {
    private Map<String, Object> create() {
        return IncidentMutation.create(Map.of("title", "Example", "severity", "high"), UUID.randomUUID(), "creator", Instant.EPOCH);
    }
    private Map<String, Object> apply(Map<String, Object> previous, IncidentMutation.Operation op, Map<String, Object> input, String actor) {
        var delivered = new LinkedHashMap<>(previous);
        delivered.put("pending_activity", null);
        int revision = (int) delivered.get("revision");
        return IncidentMutation.apply(delivered, op, input, revision, actor, Instant.EPOCH.plusSeconds(revision));
    }
    public void testNoteIsAppendOnlyAuditContentWithServerAttribution() {
        var result = apply(create(), ADD_NOTE, Map.of("body", "Analyst observation"), "reviewer");
        var event = (Map<?, ?>) result.get("pending_activity");
        assertEquals("reviewer", event.get("actor"));
        assertEquals("note_added", event.get("kind"));
        assertEquals("Analyst observation", ((Map<?, ?>) ((Map<?, ?>) event.get("changes")).get("note")).get("after"));
        assertFalse(IncidentInvestigationService.projectActivity((Map<String, Object>) event).toString().contains("Analyst observation"));
        expectThrows(OpenSearchStatusException.class, () -> apply(result, ADD_NOTE, Map.of("body", "x", "actor", "fake"), "reviewer"));
    }
    public void testTaskTransitionsAreOwnerOnlyAndPreserveHistory() {
        var assigned = apply(create(), ASSIGN_SELF, Map.of(), "analyst");
        expectThrows(OpenSearchStatusException.class, () -> apply(assigned, CREATE_TASK, Map.of("title", "Review"), "other"));
        var created = apply(assigned, CREATE_TASK, Map.of("title", "Review"), "analyst");
        var task = (Map<?, ?>) ((List<?>) created.get("tasks")).get(0);
        String id = (String) task.get("id");
        var completed = apply(created, COMPLETE_TASK, Map.of("task_id", id), "analyst");
        var completedTask = (Map<?, ?>) ((List<?>) completed.get("tasks")).get(0);
        assertEquals("completed", completedTask.get("status"));
        assertEquals("analyst", completedTask.get("completed_by"));
        assertEquals("open", task.get("status"));
        expectThrows(OpenSearchStatusException.class, () -> apply(completed, COMPLETE_TASK, Map.of("task_id", id), "analyst"));
        var reopened = apply(completed, REOPEN_TASK, Map.of("task_id", id), "analyst");
        assertEquals("open", ((Map<?, ?>) ((List<?>) reopened.get("tasks")).get(0)).get("status"));
    }
}
