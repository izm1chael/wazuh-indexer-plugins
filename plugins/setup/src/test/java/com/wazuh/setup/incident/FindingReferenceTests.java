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

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class FindingReferenceTests extends OpenSearchTestCase {
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    private static final Map<String, Object> FIRST = Map.of("index", ".ds-wazuh-findings-v5-security-000001", "document_id", "first");
    private static final Map<String, Object> SECOND = Map.of("index", ".ds-wazuh-findings-v5-security-000002", "document_id", "first");

    private Map<String, Object> command(Map<String, Object> record, IncidentMutation.Operation operation, Map<String, Object> payload) {
        Map<String, Object> delivered = new LinkedHashMap<>(record);
        delivered.put("pending_activity", null);
        int revision = (int) delivered.get("revision");
        return IncidentMutation.apply(delivered, operation, payload, revision, "analyst", NOW.plusSeconds(revision));
    }

    public void testRejectsWildcardAliasAndArbitraryIndex() {
        for (String index : new String[]{"*", "wazuh-findings-v5-security", ".security-000001", "wazuh-findings-v5-*-000001"}) {
            expectThrows(OpenSearchException.class, () -> new FindingReference(index, "id"));
        }
        expectThrows(OpenSearchException.class, () -> FindingReference.parse(Map.of("index", FIRST.get("index"), "document_id", "id", "source", "forged")));
    }

    public void testMultipleFindingsAndAuditedDetach() {
        var incident = IncidentMutation.create(Map.of("title", "Example", "severity", "high"), UUID.randomUUID(), "analyst", NOW);
        var assigned = command(incident, IncidentMutation.Operation.ASSIGN_SELF, Map.of());
        var first = command(assigned, IncidentMutation.Operation.ATTACH_FINDING, FIRST);
        var second = command(first, IncidentMutation.Operation.ATTACH_FINDING, SECOND);
        assertEquals(2, second.get("finding_count"));
        expectThrows(OpenSearchException.class, () -> command(second, IncidentMutation.Operation.ATTACH_FINDING, FIRST));
        var detached = command(second, IncidentMutation.Operation.DETACH_FINDING, FIRST);
        assertEquals(1, detached.get("finding_count"));
        assertEquals(2, second.get("finding_count"));
        assertEquals("detach_finding", ((Map<?, ?>) detached.get("pending_activity")).get("kind"));
        expectThrows(OpenSearchException.class, () -> command(detached, IncidentMutation.Operation.DETACH_FINDING, FIRST));
    }
}
