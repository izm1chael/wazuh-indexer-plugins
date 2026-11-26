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

import org.opensearch.test.OpenSearchTestCase;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class CorrelationIncidentFactoryTests extends OpenSearchTestCase {
    private static final UUID DEPLOYMENT = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID POLICY = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final FindingReference A = new FindingReference(".ds-wazuh-findings-v5-security-000001", "a");
    private static final FindingReference B = new FindingReference(".ds-wazuh-findings-v5-security-000001", "b");
    private static final Instant NOW = Instant.EPOCH.plusSeconds(1000);
    private CorrelationPlanner.Group group() {
        return new CorrelationPlanner.Group("a".repeat(64), POLICY, 1, Instant.EPOCH, Instant.EPOCH.plusSeconds(900), List.of(A, B));
    }
    private FindingCaptureReceipt receipt(FindingReference ref, String actor) {
        return FindingCaptureReceipt.create(ref, Map.of("message", "private"), NOW, actor, 1, 1);
    }

    @SuppressWarnings("unchecked")
    public void testDeterministicInitialIncidentAndAudit() {
        var group = group();
        var origin = CorrelationIncidentFactory.origin(DEPLOYMENT, group);
        var source = CorrelationIncidentFactory.create(DEPLOYMENT, group, "automation", NOW, List.of(receipt(B, "automation"), receipt(A, "automation")));
        assertEquals(origin.get("incident_id"), source.get("id"));
        assertEquals(2, source.get("finding_count"));
        assertEquals("new", source.get("status"));
        assertEquals("informational", source.get("severity"));
        assertTrue(CorrelationIncidentFactory.matches(source, origin, "automation"));
        var event = (Map<String, Object>) source.get("pending_activity");
        assertTrue(CorrelationIncidentFactory.matchesCreationEvent(event, origin, "automation"));
        assertFalse(CorrelationIncidentFactory.matchesCreationEvent(event, origin, "other"));
        assertFalse(source.toString().contains("private"));
        assertFalse(IncidentReadService.project(source).containsKey("correlation_origin"));
        assertFalse(IncidentInvestigationService.projectActivity(event).get("changes").toString().contains("finding_capture_receipts"));
    }

    public void testRejectsMissingDuplicateOrForeignActorReceipts() {
        expectThrows(IllegalArgumentException.class, () -> CorrelationIncidentFactory.create(DEPLOYMENT, group(), "automation", NOW, List.of(receipt(A, "automation"))));
        expectThrows(IllegalArgumentException.class, () -> CorrelationIncidentFactory.create(DEPLOYMENT, group(), "automation", NOW, List.of(receipt(A, "automation"), receipt(A, "automation"))));
        expectThrows(IllegalArgumentException.class, () -> CorrelationIncidentFactory.create(DEPLOYMENT, group(), "automation", NOW, List.of(receipt(A, "automation"), receipt(B, "other"))));
    }
}
