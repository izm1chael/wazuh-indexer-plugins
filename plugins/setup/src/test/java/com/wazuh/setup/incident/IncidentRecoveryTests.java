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

public class IncidentRecoveryTests extends OpenSearchTestCase {
    public void testBoundedPendingOnlyQuery() {
        var source = IncidentRecovery.build(null);
        assertEquals(25, source.size());
        assertTrue(source.query().toString().contains("pending_activity.id"));
        assertNull(source.searchAfter());
    }

    public void testCursorAdvancesThroughPoisonEvents() {
        String id = "00000000-0000-4000-8000-000000000001";
        var source = IncidentRecovery.build(id);
        assertArrayEquals(new Object[]{id}, source.searchAfter());
    }
}
