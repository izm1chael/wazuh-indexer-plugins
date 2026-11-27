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
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.UUID;
import static com.wazuh.setup.incident.IncidentMutation.Operation.*;

public class IncidentPlaybooksTests extends OpenSearchTestCase {
    private Map<String, Object> apply(Map<String, Object> source, IncidentMutation.Operation op, Map<String, Object> input, String actor) {
        var delivered = new LinkedHashMap<>(source);
        delivered.put("pending_activity", null);
        int rev = (int) source.get("revision");
        return IncidentMutation.apply(delivered, op, input, rev, actor, Instant.EPOCH.plusSeconds(rev));
    }
    private Map<String, Object> triage(String severity) {
        var incident = IncidentMutation.create(Map.of("title", "Example", "severity", severity), UUID.randomUUID(), "analyst", Instant.EPOCH);
        return apply(apply(incident, ASSIGN_SELF, Map.of(), "analyst"), START_TRIAGE, Map.of(), "analyst");
    }
    private static final Map<String, Object> INITIAL = Map.of("template_id", "initial_triage", "version", 1);

    public void testAtomicApplyAndReceiptThenTaskCompletion() {
        var original = triage("high");
        var updated = apply(original, APPLY_PLAYBOOK, INITIAL, "analyst");
        var tasks = IncidentInvestigationService.projectTasks(updated);
        assertEquals(4, tasks.size());
        assertEquals(0, IncidentInvestigationService.projectTasks(original).size());
        assertEquals(1, IncidentPlaybooks.runs(updated).size());
        assertEquals(tasks.stream().map(task -> task.get("id")).toList(), IncidentPlaybooks.runs(updated).get(0).get("task_ids"));
        assertEquals("playbook_applied", ((Map<?, ?>) updated.get("pending_activity")).get("kind"));
        assertEquals("already_applied", IncidentPlaybooks.preview(updated).get(0).get("state"));
        expectThrows(OpenSearchStatusException.class, () -> apply(updated, APPLY_PLAYBOOK, INITIAL, "analyst"));
        var completed = apply(updated, COMPLETE_TASK, Map.of("task_id", tasks.get(0).get("id")), "analyst");
        assertEquals("completed", IncidentInvestigationService.projectTasks(completed).get(0).get("status"));
        assertEquals(IncidentPlaybooks.runs(updated), IncidentPlaybooks.runs(completed));
    }
    public void testConditionsPermissionsAndNoArbitraryPayload() {
        var low = triage("low");
        assertEquals("not_applicable", IncidentPlaybooks.preview(low).get(1).get("state"));
        expectThrows(OpenSearchStatusException.class, () -> apply(low, APPLY_PLAYBOOK, Map.of("template_id", "high_severity_review", "version", 1), "analyst"));
        expectThrows(OpenSearchStatusException.class, () -> apply(low, APPLY_PLAYBOOK, INITIAL, "other"));
        expectThrows(OpenSearchStatusException.class, () -> apply(low, APPLY_PLAYBOOK, Map.of("template_id", "initial_triage", "version", 1, "tasks", List.of("arbitrary")), "analyst"));
        expectThrows(OpenSearchStatusException.class, () -> apply(low, APPLY_PLAYBOOK, Map.of("template_id", "initial_triage", "version", 2), "analyst"));
    }
    public void testCapacityIsAllOrNothing() {
        var source = triage("high");
        for (int n = 0; n < 97; n++) source = apply(source, CREATE_TASK, Map.of("title", "Task " + n), "analyst");
        final var full = source;
        assertEquals("capacity_exceeded", IncidentPlaybooks.preview(full).get(0).get("state"));
        expectThrows(OpenSearchStatusException.class, () -> apply(full, APPLY_PLAYBOOK, INITIAL, "analyst"));
        assertEquals(97, IncidentInvestigationService.projectTasks(full).size());
        assertTrue(IncidentPlaybooks.runs(full).isEmpty());
    }
}
