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

import org.opensearch.test.OpenSearchTestCase;
import java.util.Map;
import java.util.List;
import java.util.UUID;

public class IncidentCollaborationReadTests extends OpenSearchTestCase {
    public void testNoteQueryIsScopedAndBounded() {
        var query = IncidentInvestigationService.notesQuery(UUID.randomUUID(), 12, 10, 5);
        assertEquals(6, query.size());
        assertTrue(query.query().toString().contains("note_added"));
        assertTrue(query.query().toString().contains("incident_id"));
    }

    public void testNoteAndTaskProjection() {
        var event = Map.<String, Object>of("id", "note", "kind", "note_added", "actor", "analyst",
                "changes", Map.of("note", Map.of("after", "Observation"), "finding", Map.of("after", "secret")));
        assertEquals("Observation", IncidentInvestigationService.projectNote(event).get("body"));
        assertFalse(IncidentInvestigationService.projectNote(event).toString().contains("secret"));
        var tasks = IncidentInvestigationService.projectTasks(Map.of("tasks", List.of(Map.of("id", "task", "title", "Review", "secret", "hidden"))));
        assertEquals("Review", tasks.get(0).get("title"));
        assertFalse(tasks.get(0).containsKey("secret"));
    }
}
