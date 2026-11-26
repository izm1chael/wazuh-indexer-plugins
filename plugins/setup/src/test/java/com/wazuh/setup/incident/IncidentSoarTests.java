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

import org.opensearch.OpenSearchStatusException;
import org.opensearch.test.OpenSearchTestCase;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class IncidentSoarTests extends OpenSearchTestCase {
    private static final UUID ID = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final String MANAGER = "00000000-0000-4000-8000-000000000002";
    private static final String SCOPE = MANAGER + ":agent:001";
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    private static Map<String,Object> delivered(Map<String,Object> source) {
        var copy = new LinkedHashMap<>(source); copy.put("pending_activity", null); return copy;
    }
    private Map<String,Object> command(Map<String,Object> source, IncidentMutation.Operation op, Map<String,Object> input, String actor, int seconds) {
        return delivered(IncidentMutation.apply(source, op, input, (Integer) source.get("revision"), actor, NOW.plusSeconds(seconds)));
    }
    private Map<String,Object> approved() {
        var created = delivered(IncidentMutation.create(Map.of("title","Scan test","severity","high"), ID,"analyst",NOW));
        var owned = command(created, IncidentMutation.Operation.ASSIGN_SELF, Map.of(),"analyst",1);
        var triage = command(owned, IncidentMutation.Operation.START_TRIAGE, Map.of(),"analyst",2);
        var request = command(triage, IncidentMutation.Operation.REQUEST_RESPONSE,
                Map.of("type","scan_vulnerability","scope",SCOPE,"reason","Investigate"),"analyst",3);
        return command(request, IncidentMutation.Operation.APPROVE_RESPONSE, Map.of("response_id", ID+":4","reason","Reviewed"),"reviewer",4);
    }
    private Map<String,Object> dispatch(Map<String,Object> source, String actor, int seconds, String manager, Set<String> agents, String outcome) {
        return IncidentMutation.dispatchScan(source,(Integer)source.get("revision"),ID+":4",actor,NOW.plusSeconds(seconds),manager,agents,outcome);
    }
    public void testIndependentFreshApprovalAndExactTarget() {
        var source = approved();
        expectThrows(OpenSearchStatusException.class, () -> dispatch(source,"analyst",5,MANAGER,Set.of("001"),null));
        expectThrows(OpenSearchStatusException.class, () -> dispatch(source,"reviewer",5,MANAGER,Set.of("001"),null));
        expectThrows(OpenSearchStatusException.class, () -> dispatch(source,"runner",3605,MANAGER,Set.of("001"),null));
        expectThrows(OpenSearchStatusException.class, () -> dispatch(source,"runner",5,MANAGER,Set.of("002"),null));
        expectThrows(OpenSearchStatusException.class, () -> dispatch(source,"runner",5,ID.toString(),Set.of("001"),null));
        for (String scope : Set.of("all", MANAGER+":agent:000", MANAGER+":agent:001,002", MANAGER+":agent:001/")) {
            expectThrows(OpenSearchStatusException.class, () -> IncidentResponses.scanScope(scope));
        }
    }
    public void testOneShotReservationAndUnverifiedReport() {
        var source = approved();
        var reserved = dispatch(source,"runner",5,MANAGER,Set.of("001"),null);
        assertEquals("approved",IncidentResponses.project(source).get(0).get("state"));
        assertNotNull(reserved.get("pending_activity"));
        var current = delivered(reserved);
        assertEquals("dispatch_reserved",IncidentResponses.project(current).get(0).get("state"));
        expectThrows(OpenSearchStatusException.class, () -> dispatch(current,"runner",6,MANAGER,Set.of("001"),null));
        expectThrows(OpenSearchStatusException.class, () -> dispatch(current,"other",6,MANAGER,Set.of("001"),"manager_accepted"));
        expectThrows(OpenSearchStatusException.class, () -> IncidentResponses.requireNoOutstanding(current));
        var report = delivered(dispatch(current,"runner",6,MANAGER,Set.of("001"),"manager_accepted"));
        var record = IncidentResponses.project(report).get(0);
        assertEquals("manager_accepted",record.get("state")); assertEquals(false,record.get("execution_verified"));
        expectThrows(OpenSearchStatusException.class, () -> IncidentResponses.requireNoOutstanding(report));
        var resolved = command(report, IncidentMutation.Operation.RECORD_RESPONSE_OUTCOME,
                Map.of("response_id",ID+":4","outcome","completed","reason","Manually reviewed"),"reviewer",7);
        IncidentResponses.requireNoOutstanding(resolved);
        assertEquals(false,IncidentResponses.project(resolved).get(0).get("execution_verified"));
    }
    public void testUnknownReservationCannotBeImmediatelyReconciledOrCancelled() {
        var reserved = delivered(dispatch(approved(),"runner",5,MANAGER,Set.of("001"),null));
        expectThrows(OpenSearchStatusException.class, () -> command(reserved, IncidentMutation.Operation.CANCEL_RESPONSE,
                Map.of("response_id",ID+":4","reason","Cancel"),"analyst",6));
        expectThrows(OpenSearchStatusException.class, () -> command(reserved, IncidentMutation.Operation.RECORD_RESPONSE_OUTCOME,
                Map.of("response_id",ID+":4","outcome","not_performed","reason","Inspect"),"reviewer",6));
        var unknown = delivered(dispatch(reserved,"runner",6,MANAGER,Set.of("001"),"dispatch_unknown"));
        expectThrows(OpenSearchStatusException.class, () -> command(unknown, IncidentMutation.Operation.RECORD_RESPONSE_OUTCOME,
                Map.of("response_id",ID+":4","outcome","not_performed","reason","Inspect"),"runner",7));
    }
}
