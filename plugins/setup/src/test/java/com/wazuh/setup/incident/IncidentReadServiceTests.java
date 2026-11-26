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

    public void testProjectionNeverLeaksInternalFields() {
        var output = IncidentReadService.project(Map.of("title", "Example", "finding_count", 2,
                "pending_activity", "sensitive", "findings", "sensitive", "unknown", "sensitive"));
        assertEquals(Map.of("title", "Example", "finding_count", 2), output);
    }
}
