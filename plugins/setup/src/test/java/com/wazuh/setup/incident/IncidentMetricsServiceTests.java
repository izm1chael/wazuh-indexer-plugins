/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import com.wazuh.setup.transport.TransportIncidentMetricsAction;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.test.OpenSearchTestCase;

public class IncidentMetricsServiceTests extends OpenSearchTestCase {
    private static final String INPUT = """
        {"from":"2026-11-26T12:00:00Z","until":"2026-11-26T13:00:00Z","triage_target_seconds":600,"resolution_target_seconds":1200}
        """;
    public void testFixedUnionAndBound() {
        var query = TransportIncidentMetricsAction.parse(INPUT);
        var source = IncidentMetricsService.build(query);
        assertEquals(5001, source.size());
        assertTrue(source.query().toString().contains("created_at"));
        assertTrue(source.query().toString().contains("triaging"));
        assertTrue(source.query().toString().contains("minimum_should_match"));
    }
    public void testStrictInput() {
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentMetricsAction.parse(INPUT.replace("600", "600.5")));
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentMetricsAction.parse(INPUT.replace("600", "0")));
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentMetricsAction.parse(INPUT.replace("600", "600,\"index\":\"*\"")));
    }
}
