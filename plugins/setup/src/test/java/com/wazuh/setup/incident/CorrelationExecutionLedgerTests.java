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

public class CorrelationExecutionLedgerTests extends OpenSearchTestCase {
    private static final UUID DEPLOYMENT = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID POLICY = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final FindingReference A = new FindingReference(".ds-wazuh-findings-v5-security-000001", "a");
    private static final FindingReference B = new FindingReference(".ds-wazuh-findings-v5-security-000001", "b");
    private static final FindingReference C = new FindingReference(".ds-wazuh-findings-v5-security-000001", "c");
    private CorrelationPlanner.Group group(List<FindingReference> refs) {
        return new CorrelationPlanner.Group("a".repeat(64), POLICY, 1, Instant.EPOCH, Instant.EPOCH.plusSeconds(900), refs);
    }
    public void testStableReservationAndMembershipIndependentOfOrder() {
        var first = CorrelationExecutionIdentity.reserve(DEPLOYMENT, group(List.of(A, B)));
        var second = CorrelationExecutionIdentity.reserve(DEPLOYMENT, group(List.of(B, A)));
        assertEquals(first, second);
        assertNotEquals(first.incidentId(), CorrelationExecutionIdentity.reserve(UUID.randomUUID(), group(List.of(A, B))).incidentId());
    }
    public void testLateArrivalChangesMembershipNotIncidentIdentity() {
        var first = CorrelationExecutionIdentity.reserve(DEPLOYMENT, group(List.of(A, B)));
        var changed = CorrelationExecutionIdentity.reserve(DEPLOYMENT, group(List.of(A, B, C)));
        assertEquals(first.id(), changed.id());
        assertEquals(first.incidentId(), changed.incidentId());
        assertNotEquals(first.membershipHash(), changed.membershipHash());
        Map<String, Object> original = CorrelationExecutionLedger.immutableFields(DEPLOYMENT, group(List.of(A, B)));
        assertFalse(CorrelationExecutionLedger.matches(original, CorrelationExecutionLedger.immutableFields(DEPLOYMENT, group(List.of(A, B, C)))));
        assertEquals("reserved", original.get("state"));
        assertFalse(original.containsKey("findings"));
    }
    public void testDuplicateMembershipRejected() {
        expectThrows(IllegalArgumentException.class, () -> CorrelationExecutionIdentity.reserve(DEPLOYMENT, group(List.of(A, A))));
    }
}
