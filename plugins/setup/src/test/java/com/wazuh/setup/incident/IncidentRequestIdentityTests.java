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
import java.util.Map;
import java.util.UUID;

public class IncidentRequestIdentityTests extends OpenSearchTestCase {
    private static final UUID KEY = UUID.fromString("00000000-0000-4000-8000-000000000001");

    public void testStableActorScopedIdentity() {
        UUID first = IncidentRequestIdentity.incidentId("analyst", KEY);
        assertEquals(first, IncidentRequestIdentity.incidentId("analyst", KEY));
        assertNotEquals(first, IncidentRequestIdentity.incidentId("another", KEY));
        assertNotEquals(first, IncidentRequestIdentity.incidentId("analyst", UUID.randomUUID()));
        assertEquals(KEY, IncidentRequestIdentity.requireKey(KEY.toString()));
        expectThrows(OpenSearchException.class, () -> IncidentRequestIdentity.requireKey("1-1-1-1-1"));
    }

    public void testNormalizedPayloadFingerprintAndReplay() {
        UUID id = IncidentRequestIdentity.incidentId("analyst", KEY);
        var first = IncidentMutation.create(Map.of("title", " Example ", "severity", "high"), id, "analyst", Instant.EPOCH);
        var second = IncidentMutation.create(Map.of("title", "Example", "severity", "high", "priority", "medium"), id, "analyst", Instant.EPOCH.plusSeconds(5));
        String fingerprint = IncidentRequestIdentity.createFingerprint(first);
        assertEquals(fingerprint, IncidentRequestIdentity.createFingerprint(second));
        first.put("create_request_hash", fingerprint);
        assertTrue(IncidentRequestIdentity.matches(first, "analyst", fingerprint));
        assertFalse(IncidentRequestIdentity.matches(first, "other", fingerprint));
        second.put("severity", "low");
        assertFalse(IncidentRequestIdentity.matches(first, "analyst", IncidentRequestIdentity.createFingerprint(second)));
        assertFalse(IncidentReadService.project(first).containsKey("create_request_hash"));
    }
}
