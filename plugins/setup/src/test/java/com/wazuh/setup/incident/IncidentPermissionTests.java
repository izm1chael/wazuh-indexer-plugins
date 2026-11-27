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

import java.util.Set;

import com.wazuh.setup.action.IncidentWriteAction.Grant;
import com.wazuh.setup.action.IncidentWriteRequest;
import com.wazuh.setup.incident.IncidentMutation.Operation;

public class IncidentPermissionTests extends OpenSearchTestCase {
    public void testEveryOperationHasExactlyOneGrant() {
        for (Operation operation : Operation.values()) {
            int count = 0;
            for (Grant grant : Grant.values()) if (grant.permits(operation)) count++;
            assertEquals(operation.name(), 1, count);
        }
        assertFalse(Grant.ASSIGN.permits(Operation.CLOSE));
        assertFalse(Grant.UPDATE.permits(Operation.REOPEN));
        assertFalse(Grant.CREATE.permits(Operation.EDIT));
    }

    public void testActionNamesAreDistinct() {
        assertEquals(Grant.values().length, java.util.Arrays.stream(Grant.values()).map(Grant::actionName).distinct().count());
    }

    public void testRequestValidation() {
        String id = "00000000-0000-4000-8000-000000000001";
        assertNull(new IncidentWriteRequest(Operation.CREATE, null, 0, "{}").validate());
        assertNotNull(new IncidentWriteRequest(Operation.CREATE, id, 0, "{}").validate());
        assertNull(new IncidentWriteRequest(Operation.CLOSE, id, 2, "{}").validate());
        assertNotNull(new IncidentWriteRequest(Operation.CLOSE, id, 0, "{}").validate());
        assertNotNull(new IncidentWriteRequest(Operation.CLOSE, "1-1-1-1-1", 2, "{}").validate());
        assertNotNull(new IncidentWriteRequest(Operation.CREATE, null, 0, "a".repeat(262145)).validate());
    }
}
