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

import com.wazuh.setup.transport.TransportIncidentCorrelationAction;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.test.OpenSearchTestCase;

public class CorrelationPreviewTests extends OpenSearchTestCase {
    private static final String INPUT = """
        {"policy_id":"00000000-0000-4000-8000-000000000001","policy_version":1,
         "rules":["00000000-0000-4000-8000-000000000002"],"window_minutes":15,"minimum_findings":2,
         "from":"2026-11-26T12:00:00Z","until":"2026-11-26T13:00:00Z"}
        """;
    public void testBoundedQueryAndCompleteWindowAlignment() {
        var input = TransportIncidentCorrelationAction.parse(INPUT);
        var source = CorrelationPreviewService.build(input);
        assertEquals(1001, source.size());
        assertTrue(source.query().toString().contains("wazuh.rule.uuid"));
        assertTrue(source.query().toString().contains("@timestamp"));
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentCorrelationAction.parse(INPUT.replace("12:00:00", "12:01:00")));
    }
    public void testStrictRequestNoArbitraryQueryOrCoercion() {
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentCorrelationAction.parse(INPUT.replace("\"policy_version\":1", "\"policy_version\":\"1\"")));
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentCorrelationAction.parse(INPUT.replace("\"policy_version\":1", "\"policy_version\":1,\"index\":\"*\"")));
        expectThrows(OpenSearchStatusException.class, () -> TransportIncidentCorrelationAction.parse(INPUT.replace("\"policy_version\":1", "\"policy_version\":1,\"policy_version\":2")));
    }
}
