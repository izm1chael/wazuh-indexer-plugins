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

import com.wazuh.setup.action.IndicatorCatalogAction;
import org.opensearch.OpenSearchException;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class IndicatorCatalogTests extends OpenSearchTestCase {
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    private static final String FROM = "2026-11-25T00:00:00Z";
    private static final String UNTIL = "2026-11-30T00:00:00Z";

    private Map<String, Object> indicator(String type, String value) {
        var input = new LinkedHashMap<String, Object>();
        input.put("type", type); input.put("value", value); input.put("source", "External feed"); input.put("external_id", null);
        input.put("confidence", 75); input.put("tlp", "TLP:AMBER"); input.put("valid_from", FROM); input.put("valid_until", UNTIL);
        return input;
    }

    private Map<String, Object> create() {
        return IndicatorCatalog.add(IndicatorCatalog.empty(), 0, List.of(indicator("ipv4", "192.0.2.1")), "alice", NOW);
    }

    private String id(Map<String, Object> catalog) {
        return (String) IndicatorCatalog.rows(catalog).get(0).get("id");
    }

    public void testSeparateGrantsAndCanonicalIdentity() {
        assertEquals("cluster:admin/wazuh/incident/indicator_read", IndicatorCatalogAction.READ_NAME);
        assertEquals("cluster:admin/wazuh/incident/indicator_write", IndicatorCatalogAction.SAVE_NAME);
        assertEquals("example.org", IndicatorCatalog.definition(indicator("domain", "EXAMPLE.ORG")).get("value"));
        assertEquals("a".repeat(64), IndicatorCatalog.definition(indicator("sha256", "A".repeat(64))).get("value"));
        for (String value : List.of("*.example.org", "example.org.", "192.0.2.1", "K.example.org"))
            expectThrows(OpenSearchException.class, () -> IndicatorCatalog.definition(indicator("domain", value)));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.definition(indicator("ipv4", "192.0.2.0/24")));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.definition(indicator("sha256", "a".repeat(63))));
    }

    public void testAtomicBatchDuplicateAndStaleRevision() {
        var initial = IndicatorCatalog.empty();
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.add(initial, 0,
                List.of(indicator("domain", "example.org"), indicator("domain", "EXAMPLE.ORG")), "alice", NOW));
        assertEquals(0, initial.get("revision"));
        var created = IndicatorCatalog.add(initial, 0, List.of(indicator("ipv4", "192.0.2.1"), indicator("domain", "example.org")), "alice", NOW);
        assertEquals(1, created.get("revision"));
        assertEquals(2, IndicatorCatalog.rows(created).size());
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.add(created, 0, List.of(indicator("ipv4", "192.0.2.2")), "alice", NOW));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.add(created, 1, List.of(indicator("ipv4", "192.0.2.1")), "alice", NOW));
        var forged = indicator("ipv4", "192.0.2.2"); forged.put("created_by", "admin");
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.add(created, 1, List.of(forged), "alice", NOW));
    }

    public void testRevocationRenewalAndExpiryPreserveRecords() {
        var current = create(); String id = id(current);
        var revoked = IndicatorCatalog.revoke(current, 1, id, "Superseded", "bob", NOW.plusSeconds(1));
        assertNull(IndicatorCatalog.rows(current).get(0).get("revoked_at"));
        assertEquals("bob", IndicatorCatalog.rows(revoked).get(0).get("revoked_by"));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.revoke(revoked, 2, id, "Again", "bob", NOW.plusSeconds(2)));
        var renewed = IndicatorCatalog.add(revoked, 2, List.of(indicator("ipv4", "192.0.2.1")), "alice", NOW.plusSeconds(2));
        assertEquals(2, IndicatorCatalog.rows(renewed).size());
        assertNotEquals(id, IndicatorCatalog.rows(renewed).get(1).get("id"));
        var projected = IndicatorCatalog.project(renewed, Instant.parse(UNTIL));
        var rows = (List<?>) projected.get("indicators");
        assertEquals("revoked", ((Map<?, ?>) rows.get(0)).get("state"));
        assertEquals("expired", ((Map<?, ?>) rows.get(1)).get("state"));
    }

    public void testSightingAndWithdrawalWithRevisionConservation() {
        var current = create(); String id = id(current);
        var sight = IndicatorCatalog.sight(current, 1, id, FROM, "External report", 3, "alice", NOW.plusSeconds(1));
        assertEquals(List.of(), IndicatorCatalog.rows(current).get(0).get("sightings"));
        var records = (List<?>) IndicatorCatalog.rows(sight).get(0).get("sightings");
        assertEquals("analyst_attested_external_sighting", ((Map<?, ?>) records.get(0)).get("origin"));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.sight(sight, 2, id, FROM, "External report", 3, "bob", NOW.plusSeconds(2)));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.sight(sight, 2, id, UNTIL, "External report", 3, "bob", NOW.plusSeconds(2)));
        var withdrawn = IndicatorCatalog.withdrawSighting(sight, 2, id, 2, "Incorrect report", "bob", NOW.plusSeconds(2));
        var finalRecord = (Map<?, ?>) ((List<?>) IndicatorCatalog.rows(withdrawn).get(0).get("sightings")).get(0);
        assertEquals(3, finalRecord.get("withdrawn_revision"));
        assertEquals(3, finalRecord.get("count"));
        assertEquals("alice", finalRecord.get("recorded_by"));
        assertEquals("bob", finalRecord.get("withdrawn_by"));
        assertNull(((Map<?, ?>) records.get(0)).get("withdrawn_at"));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.withdrawSighting(withdrawn, 3, id, 2, "Again", "bob", NOW.plusSeconds(3)));
        var gap = new LinkedHashMap<>(withdrawn); gap.put("revision", 4);
        expectThrows(IllegalStateException.class, () -> IndicatorCatalog.rows(gap));
        var corrected = IndicatorCatalog.sight(withdrawn, 3, id, FROM, "External report", 1, "alice", NOW.plusSeconds(3));
        assertEquals(4, corrected.get("revision"));
        assertEquals(2, ((List<?>) IndicatorCatalog.rows(corrected).get(0).get("sightings")).size());
    }

    public void testCapacityAndInvalidMetadata() {
        var tooMany = new ArrayList<Map<String, Object>>();
        for (int i = 1; i <= 21; i++) tooMany.add(indicator("ipv4", "192.0.2." + i));
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.add(IndicatorCatalog.empty(), 0, tooMany, "alice", NOW));
        var bad = indicator("domain", "example.org"); bad.put("confidence", 101);
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.definition(bad));
        bad.put("confidence", 50); bad.put("valid_from", "2026-02-30T00:00:00Z");
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.definition(bad));
        bad.put("valid_from", FROM); bad.put("valid_until", "2026-11-26T00:00:00Z");
        expectThrows(OpenSearchException.class, () -> IndicatorCatalog.add(IndicatorCatalog.empty(), 0, List.of(bad), "alice", NOW));
    }
}
