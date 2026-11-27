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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.setup.transport.TransportCorrelationPolicyAction;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.test.OpenSearchTestCase;
import java.util.List;

public class CorrelationPolicyStoreTests extends OpenSearchTestCase {
    private static final String INPUT = """
        {"policy_id":"00000000-0000-4000-8000-000000000001","policy_version":1,
        "rules":["00000000-0000-4000-8000-000000000003","00000000-0000-4000-8000-000000000002"],
        "window_minutes":15,"minimum_findings":2}
        """;
    public void testDefinitionIsSortedAndPreviewOnly() throws Exception {
        var policy = TransportCorrelationPolicyAction.parsePolicy(new ObjectMapper().readTree(INPUT));
        var definition = CorrelationPolicyStore.definition(policy);
        assertEquals("preview_only", definition.get("mode"));
        assertEquals(List.of("00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"), definition.get("rules"));
    }
    public void testRejectsCallerSuppliedModeAndActor() throws Exception {
        var mapper = new ObjectMapper();
        expectThrows(OpenSearchStatusException.class, () -> TransportCorrelationPolicyAction.parsePolicy(mapper.readTree(INPUT.replace("\"policy_version\":1", "\"policy_version\":1,\"mode\":\"enabled\""))));
        expectThrows(OpenSearchStatusException.class, () -> TransportCorrelationPolicyAction.parsePolicy(mapper.readTree(INPUT.replace("\"policy_version\":1", "\"policy_version\":1,\"created_by\":\"admin\""))));
    }
}
