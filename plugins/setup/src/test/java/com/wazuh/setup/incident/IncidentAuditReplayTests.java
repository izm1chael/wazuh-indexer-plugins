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

public class IncidentAuditReplayTests extends OpenSearchTestCase {
    public void testEquivalentJsonAcrossNumericWrappersAndMapOrder() {
        Map<String, Object> original = Map.of("revision", 1, "changes", Map.of("receipt", Map.of("seq_no", 3L, "primary_term", 1L)));
        Map<String, Object> decoded = Map.of("changes", Map.of("receipt", Map.of("primary_term", 1, "seq_no", 3)), "revision", 1L);
        assertTrue(IncidentRepository.sameEvent(original, decoded));
        assertFalse(IncidentRepository.sameEvent(original, Map.of("revision", 2, "changes", decoded.get("changes"))));
    }
    public void testArrayOrderAndStringTypesRemainSignificant() {
        assertFalse(IncidentRepository.sameEvent(Map.of("items", List.of(1, 2)), Map.of("items", List.of(2, 1))));
        assertFalse(IncidentRepository.sameEvent(Map.of("revision", 1), Map.of("revision", "1")));
        assertFalse(IncidentRepository.sameEvent(Map.of("revision", 1), null));
    }
}
