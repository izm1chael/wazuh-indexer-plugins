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

public class FindingIntelligenceTests extends OpenSearchTestCase {
    private static final FindingReference REF = new FindingReference(".ds-wazuh-findings-v5-security-000001", "doc");

    public void testAllowlistedNestedAndDottedFieldsOnly() {
        var source = Map.<String, Object>of("@timestamp", "2026-11-26T12:00:00Z",
                "host", Map.of("name", "host01", "ip", List.of("192.0.2.1")),
                "user.name", "alice", "rule", Map.of("id", "123", "title", "Example"),
                "message", "SECRET", "threat", Map.of("technique", List.of(Map.of("id", "T1059"), Map.of("id", "invalid"))));
        var result = FindingIntelligence.project(REF, source);
        assertEquals("123", result.get("rule_id"));
        assertEquals(List.of("T1059"), result.get("techniques"));
        assertTrue(result.get("entities").toString().contains("host01"));
        assertTrue(result.get("entities").toString().contains("alice"));
        assertFalse(result.toString().contains("SECRET"));
        assertFalse(result.toString().contains("invalid"));
    }

    public void testMissingFieldsNeverInventEntitiesOrTimes() {
        var result = FindingIntelligence.project(REF, Map.of("@timestamp", "invalid", "unrelated", "value"));
        assertNull(result.get("timestamp"));
        assertNull(result.get("rule_id"));
        assertEquals(List.of(), result.get("entities"));
    }

    public void testFieldTraversalIsBounded() {
        assertEquals(16, FindingIntelligence.values(Map.of("host.ip", java.util.Collections.nCopies(100, "192.0.2.1")), "host.ip").size());
        assertEquals(List.of(), FindingIntelligence.values(Map.of("user.name", "bad\nname"), "user.name"));
    }
}
