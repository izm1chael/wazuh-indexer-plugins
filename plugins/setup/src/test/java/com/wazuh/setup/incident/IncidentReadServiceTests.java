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

import org.opensearch.OpenSearchException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

public class IncidentReadServiceTests extends OpenSearchTestCase {
    public void testPersonalQueuesRequireAuthenticatedActor() {
        var incoming = new IncidentReadService.Query("handover", null, null, null, 50, null, null);
        var mine = new IncidentReadService.Query("mine", null, null, null, 50, null, null);
        expectThrows(OpenSearchException.class, () -> IncidentReadService.build(incoming));
        expectThrows(OpenSearchException.class, () -> IncidentReadService.build(mine, "_shared"));
        String query = IncidentReadService.build(incoming, "bob").query().toString();
        assertTrue(query.contains("handover.target"));
        assertTrue(query.contains("bob"));
        assertTrue(query.contains("triaging"));
        assertTrue(IncidentReadService.build(mine, "alice").query().toString().contains("alice"));
    }

    public void testOpenQueueIsIndependentOfFindingTime() {
        var query = new IncidentReadService.Query("open", null, null, null, 50, null, null);
        var source = IncidentReadService.build(query);
        assertEquals(51, source.size());
        assertTrue(source.query().toString().contains("triaging"));
        assertFalse(source.query().toString().contains("timestamp"));
    }

    public void testUnassignedAndBoundedPagination() {
        var query = new IncidentReadService.Query("unassigned", "high", null, null, 1, 123L, "00000000-0000-4000-8000-000000000001");
        var source = IncidentReadService.build(query);
        assertEquals(2, source.size());
        assertEquals(2, source.searchAfter().length);
        assertTrue(source.query().toString().contains("must_not"));
        expectThrows(OpenSearchException.class, () -> new IncidentReadService.Query("all", null, null, null, 101, null, null));
        expectThrows(OpenSearchException.class, () -> new IncidentReadService.Query("all", null, null, null, 50, 123L, null));
    }

    public void testHandoverProjectionOmitsUnexpectedFields() {
        var result = IncidentReadService.project(Map.of("owner", "alice", "handover",
                Map.of("target", "bob", "offered_by", "alice", "offered_at", "now", "unexpected", "private")));
        assertEquals(Map.of("target", "bob", "offered_by", "alice", "offered_at", "now"), result.get("handover"));
        expectThrows(IllegalStateException.class, () -> IncidentReadService.project(Map.of("owner", "other", "handover",
                Map.of("target", "bob", "offered_by", "alice", "offered_at", "now"))));
    }

    public void testProjectionNeverLeaksInternalFields() {
        var output = IncidentReadService.project(Map.of("title", "Example", "finding_count", 2,
                "pending_activity", "sensitive", "findings", "sensitive", "unknown", "sensitive"));
        assertTrue(output.containsKey("handover"));
        assertNull(output.remove("handover"));
        assertEquals(Map.of("title", "Example", "finding_count", 2), output);
    }
}
