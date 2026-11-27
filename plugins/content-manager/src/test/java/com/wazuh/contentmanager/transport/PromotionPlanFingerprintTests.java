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
package com.wazuh.contentmanager.transport;

import org.opensearch.test.OpenSearchTestCase;
import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;

public class PromotionPlanFingerprintTests extends OpenSearchTestCase {
    public void testCanonicalObjectsAndOrderedArrays() {
        var one = new LinkedHashMap<String,Object>();
        one.put("b",List.of(1,2));one.put("a",Map.of("y",2,"x",1));
        var two = new LinkedHashMap<String,Object>();
        two.put("a",Map.of("x",1,"y",2));two.put("b",List.of(1,2));
        String hash=PromotionPlanFingerprint.of(one);
        assertEquals(64,hash.length());
        assertEquals(hash,PromotionPlanFingerprint.of(two));
        two.put("b",List.of(2,1));
        assertNotEquals(hash,PromotionPlanFingerprint.of(two));
        assertTrue(PromotionPlanFingerprint.approved(hash,hash));
        assertFalse(PromotionPlanFingerprint.approved("",hash));
        assertFalse(PromotionPlanFingerprint.approved(null,hash));
        assertFalse(PromotionPlanFingerprint.approved(hash.toUpperCase(java.util.Locale.ROOT),hash));
    }
    public void testApprovalExpiryIsBoundedAndCanonical() {
        var now=java.time.Instant.parse("2026-11-25T12:00:00Z");
        assertTrue(PromotionPlanFingerprint.active("2026-11-25T13:00:00Z",now));
        assertFalse(PromotionPlanFingerprint.active("2026-11-25T13:00:01Z",now));
        assertFalse(PromotionPlanFingerprint.active("2026-11-25T12:00:00Z",now));
        assertFalse(PromotionPlanFingerprint.active("2026-11-25T11:59:59Z",now));
        assertFalse(PromotionPlanFingerprint.active("2026-11-25T12:30:00.000Z",now));
        assertFalse(PromotionPlanFingerprint.active("2026-02-30T12:30:00Z",now));
        assertFalse(PromotionPlanFingerprint.active("",now));
        assertFalse(PromotionPlanFingerprint.active(null,now));
    }
    public void testChangedOldVersionAndApplyPayloadInvalidateApproval() {
        var plan=new LinkedHashMap<String,Object>();
        plan.put("apply",Map.of("rule",Map.of("enabled",true)));
        plan.put("old_versions",Map.of("rule",Map.of("enabled",false)));
        plan.put("delete",List.of());
        String approved=PromotionPlanFingerprint.of(plan);
        plan.put("old_versions",Map.of("rule",Map.of("enabled",true)));
        assertFalse(PromotionPlanFingerprint.approved(approved,PromotionPlanFingerprint.of(plan)));
        plan.put("old_versions",Map.of("rule",Map.of("enabled",false)));
        plan.put("apply",Map.of("rule",Map.of("enabled",false)));
        assertFalse(PromotionPlanFingerprint.approved(approved,PromotionPlanFingerprint.of(plan)));
    }
}
