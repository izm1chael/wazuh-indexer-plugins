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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class FindingCaptureReceiptTests extends OpenSearchTestCase {
    private static final FindingReference REF = new FindingReference(".ds-wazuh-findings-v5-security-000001", "document");
    public void testStableFingerprintAndNoRawSource() {
        var first = new LinkedHashMap<String, Object>();
        first.put("z", "private payload");
        first.put("a", Map.of("b", 1));
        var second = new LinkedHashMap<String, Object>();
        second.put("a", Map.of("b", 1));
        second.put("z", "private payload");
        var a = FindingCaptureReceipt.create(REF, first, Instant.EPOCH, "analyst", 3, 1);
        var b = FindingCaptureReceipt.create(REF, second, Instant.EPOCH, "analyst", 3, 1);
        assertEquals(a.sha256(), b.sha256());
        assertNotEquals(a.sha256(), FindingCaptureReceipt.create(REF, Map.of("z", "changed"), Instant.EPOCH, "analyst", 3, 1).sha256());
        assertFalse(a.toMap().toString().contains("private payload"));
        assertEquals("caller_visible_parsed_source", a.toMap().get("scope"));
    }
    public void testReceiptIsAtomicAuditContentAndRedactedFromGeneralActivity() {
        var record = IncidentMutation.create(Map.of("title", "Example", "severity", "high"), UUID.randomUUID(), "analyst", Instant.EPOCH);
        record.put("pending_activity", null);
        var assigned = IncidentMutation.apply(record, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), 1, "analyst", Instant.EPOCH.plusSeconds(1));
        assigned.put("pending_activity", null);
        var attached = IncidentMutation.apply(assigned, IncidentMutation.Operation.ATTACH_FINDING, REF.toMap(), 2, "analyst", Instant.EPOCH.plusSeconds(2));
        var receipt = FindingCaptureReceipt.create(REF, Map.of("message", "private payload"), Instant.EPOCH, "analyst", 3, 1);
        FindingCaptureReceipt.appendToPending(attached, receipt);
        @SuppressWarnings("unchecked")
        var event = (Map<String, Object>) attached.get("pending_activity");
        assertTrue(event.toString().contains(receipt.sha256()));
        assertFalse(IncidentInvestigationService.projectActivity(event).toString().contains(receipt.sha256()));
        assertFalse(attached.toString().contains("private payload"));
    }
}
