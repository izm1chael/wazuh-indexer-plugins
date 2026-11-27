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
import java.util.UUID;
import com.wazuh.setup.action.IncidentReadRequest;

public class IncidentInvestigationTests extends OpenSearchTestCase {
    private static final String ID = "00000000-0000-4000-8000-000000000001";

    public void testActivityRedactsFindingReferencesAndUnknownChanges() {
        var event = IncidentInvestigationService.projectActivity(Map.of("id", ID + ":2", "kind", "attach_finding",
                "changes", Map.of("finding", Map.of("after", "secret"), "description", Map.of("after", "secret"),
                "status", Map.of("before", "new", "after", "triaging"), "owner", Map.of("after", Map.of("secret", "value")))));
        assertEquals(Map.of("status", Map.of("before", "new", "after", "triaging")), event.get("changes"));
        assertFalse(event.toString().contains("secret"));
    }

    public void testActivityQueryScopedToIncidentAndRevision() {
        var source = IncidentInvestigationService.activityQuery(UUID.fromString(ID), 12, 10, 5);
        assertEquals(6, source.size());
        assertTrue(source.query().toString().contains(ID));
        assertTrue(source.query().toString().contains("revision"));
    }

    public void testViewRequestValidation() {
        assertNull(new IncidentReadRequest(ID, null, IncidentReadRequest.View.ACTIVITY, 50, 0, 0).validate());
        assertNull(new IncidentReadRequest(ID, null, IncidentReadRequest.View.FINDINGS, 25, 25, 4).validate());
        assertNotNull(new IncidentReadRequest(ID, null, IncidentReadRequest.View.FINDINGS, 25, 25, 0).validate());
        assertNotNull(new IncidentReadRequest(ID, null, IncidentReadRequest.View.FINDINGS, 26, 0, 0).validate());
        assertNotNull(new IncidentReadRequest(ID, null, IncidentReadRequest.View.ACTIVITY, 101, 0, 0).validate());
    }
}
