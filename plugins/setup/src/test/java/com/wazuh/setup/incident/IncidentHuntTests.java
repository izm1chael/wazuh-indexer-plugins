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

import com.wazuh.setup.action.IncidentHuntAction;
import com.wazuh.setup.action.IncidentHuntRequest;
import com.wazuh.setup.transport.TransportIncidentHuntAction;
import org.opensearch.OpenSearchException;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class IncidentHuntTests extends OpenSearchTestCase {
    private static final Instant FROM = Instant.parse("2026-11-25T00:00:00Z");
    private static final Instant UNTIL = Instant.parse("2026-11-26T00:00:00Z");
    private static final String AT = "2026-11-25T12:00:00Z";
    private static final FindingReference REF = new FindingReference(".ds-wazuh-findings-v5-security-000001", "doc");
    private static final String JSON = """
            {"field":"source.ip","values":["192.0.2.2","192.0.2.1"],
             "from":"2026-11-25T00:00:00Z","until":"2026-11-26T00:00:00Z"}
            """;

    private IncidentHuntService.Input input() {
        return new IncidentHuntService.Input("source.ip", List.of("192.0.2.2", "192.0.2.1"), FROM, UNTIL);
    }

    public void testFixedPermissionAndRequestParsing() {
        assertEquals("cluster:admin/wazuh/incident/hunt_read", IncidentHuntAction.NAME);
        assertNull(new IncidentHuntRequest(JSON).validate());
        assertNotNull(new IncidentHuntRequest("a".repeat(16385)).validate());
        assertEquals(input(), TransportIncidentHuntAction.parse(JSON));
        for (String invalid : List.of(JSON.replace("source.ip", "_id"), JSON.replace("192.0.2.2", "192.0.2.1"),
                JSON.replace("192.0.2.2", "192.0.2.999"), JSON.replace("192.0.2.2", "192.0.2.0/24"),
                JSON.replace("2026-11-26", "2026-12-26"), JSON.replace("\"field\":", "\"index\":"),
                JSON + "{}", JSON.replace("\"field\":", "\"field\":\"host.name\",\"field\":"))) {
            expectThrows(OpenSearchException.class, () -> TransportIncidentHuntAction.parse(invalid));
        }
    }

    public void testExactTermsAndProjection() {
        var query = IncidentHuntService.build(input());
        assertEquals(101, query.size());
        assertTrue(query.query().toString().contains("terms"));
        assertTrue(query.query().toString().contains("source.ip"));
        assertTrue(query.query().toString().contains("@timestamp"));
        var source = Map.<String, Object>of("@timestamp", AT, "source", Map.of("ip", List.of("192.0.2.1", "192.0.2.5")),
                "secret", "never returned");
        var result = IncidentHuntService.project(input(), REF, source);
        assertEquals(Map.of("index", REF.index(), "document_id", REF.documentId(),
                "timestamp", AT, "matched_values", List.of("192.0.2.1")), result);
        assertEquals(result, IncidentHuntService.project(input(), REF, Map.of("@timestamp", AT, "source.ip", "192.0.2.1")));
    }

    public void testUnconfirmedOrAmbiguousCandidateFailsClosed() {
        for (var source : List.<Map<String, Object>>of(
                Map.of("@timestamp", AT),
                Map.of("@timestamp", AT, "source.ip", "192.0.2.5"),
                Map.of("@timestamp", AT, "source.ip", " 192.0.2.1"),
                Map.of("@timestamp", UNTIL.toString(), "source.ip", "192.0.2.1"),
                Map.of("@timestamp", AT, "source.ip", "192.0.2.1", "source", Map.of("ip", "192.0.2.1")),
                Map.of("@timestamp", AT, "source.ip", java.util.Collections.nCopies(300, "192.0.2.1")))) {
            expectThrows(OpenSearchException.class, () -> IncidentHuntService.project(input(), REF, source));
        }
    }

    public void testHashAndRangeBounds() {
        assertTrue(IncidentHuntService.valid("file.hash.sha256", "a".repeat(64)));
        assertFalse(IncidentHuntService.valid("file.hash.sha256", "a".repeat(63)));
        assertFalse(IncidentHuntService.valid("source.ip", "192.000.2.1"));
        assertFalse(IncidentHuntService.valid("source.ip", "::1"));
        expectThrows(IllegalArgumentException.class, () -> new IncidentHuntService.Input("host.name", List.of("host"), FROM, FROM));
        expectThrows(IllegalArgumentException.class, () -> new IncidentHuntService.Input("host.name", java.util.stream.IntStream.range(0, 21).mapToObj(n -> "host" + n).toList(), FROM, UNTIL));
    }
}
