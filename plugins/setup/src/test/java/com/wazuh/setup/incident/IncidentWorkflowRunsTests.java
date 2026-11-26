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

import com.wazuh.setup.action.IncidentWriteAction.Grant;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.test.OpenSearchTestCase;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class IncidentWorkflowRunsTests extends OpenSearchTestCase {
    private static final UUID ID = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final String MANAGER = "00000000-0000-4000-8000-000000000002";
    private static final String SCOPE = MANAGER + ":agent:001";
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");
    private static final String OWNER = "analyst";
    private static final String RUN = ID + ":4", RESPONSE = ID + ":6", REVIEW = ID + ":9";

    private Map<String,Object> delivered(Map<String,Object> source) {
        var copy = new LinkedHashMap<>(source); copy.put("pending_activity",null); return copy;
    }
    private Map<String,Object> change(Map<String,Object> source, IncidentMutation.Operation op, Map<String,Object> input, String actor) {
        int rev = (Integer) source.get("revision");
        return delivered(IncidentMutation.apply(source,op,input,rev,actor,NOW.plusSeconds(rev)));
    }
    private Map<String,Object> base() {
        var created = delivered(IncidentMutation.create(Map.of("title","Workflow test","severity","high"),ID,OWNER,NOW));
        var owned = change(created,IncidentMutation.Operation.ASSIGN_SELF,Map.of(),OWNER);
        return change(owned,IncidentMutation.Operation.START_TRIAGE,Map.of(),OWNER);
    }
    private Map<String,Object> start(Map<String,Object> source, String template, String scope) {
        return change(source,IncidentMutation.Operation.START_WORKFLOW,Map.of("template_id",template,"version",1,"scope",scope,"reason","Investigate"),OWNER);
    }
    private Map<String,Object> advance(Map<String,Object> source) {
        return change(source,IncidentMutation.Operation.ADVANCE_WORKFLOW,Map.of("run_id",RUN),OWNER);
    }
    private Map<String,Object> task(Map<String,Object> source,String id) {
        return change(source,IncidentMutation.Operation.COMPLETE_TASK,Map.of("task_id",id),OWNER);
    }
    private Map<String,Object> requested(String template,String scope) { return advance(task(start(base(),template,scope),RUN)); }
    private Map<String,Object> view(Map<String,Object> source) { return IncidentWorkflowRuns.view(source).get(0); }

    public void testEvidenceWorkflowFromStartToCompletion() {
        var initial = start(base(),"evidence_collection","Host review");
        assertEquals("open",view(initial).get("observed_state"));
        assertEquals(false,view(initial).get("can_advance"));
        expectThrows(OpenSearchStatusException.class,() -> advance(initial));
        var prepared = task(initial,RUN);
        assertEquals(true,view(prepared).get("can_advance"));
        var requested = advance(prepared);
        assertEquals("requested",view(requested).get("observed_state"));
        var response = IncidentResponses.project(requested).get(0);
        assertEquals(RESPONSE,response.get("id")); assertEquals("collect_evidence",response.get("type"));
        var approved = change(requested,IncidentMutation.Operation.APPROVE_RESPONSE,Map.of("response_id",RESPONSE,"reason","Reviewed"),"reviewer");
        expectThrows(OpenSearchStatusException.class,() -> advance(approved));
        var outcome = change(approved,IncidentMutation.Operation.RECORD_RESPONSE_OUTCOME,Map.of("response_id",RESPONSE,"outcome","completed","reason","Reviewed artifact"),"reviewer");
        var review = advance(outcome);
        assertEquals("open",view(review).get("observed_state"));
        var finished = advance(task(review,REVIEW));
        assertEquals("terminal",view(finished).get("observed_state"));
        assertEquals(4,((List<?>)view(finished).get("steps")).size());
        assertEquals(false,view(finished).get("can_cancel"));
        IncidentWorkflowRuns.requireNoOutstanding(finished);
        IncidentResponses.requireNoOutstanding(finished);
        expectThrows(OpenSearchStatusException.class,() -> advance(finished));
    }

    public void testScanAcknowledgementDoesNotAdvance() {
        var requested = requested("vulnerability_investigation",SCOPE);
        var approved = change(requested,IncidentMutation.Operation.APPROVE_RESPONSE,Map.of("response_id",RESPONSE,"reason","Reviewed"),"reviewer");
        var reserved = delivered(IncidentMutation.dispatchScan(approved,7,RESPONSE,"runner",NOW.plusSeconds(7),MANAGER,Set.of("001"),null));
        var accepted = delivered(IncidentMutation.dispatchScan(reserved,8,RESPONSE,"runner",NOW.plusSeconds(8),MANAGER,Set.of("001"),"manager_accepted"));
        assertEquals("manager_accepted",view(accepted).get("observed_state"));
        assertEquals(false,view(accepted).get("can_advance"));
        assertEquals(false,view(accepted).get("can_cancel"));
        expectThrows(OpenSearchStatusException.class,() -> advance(accepted));
        expectThrows(OpenSearchStatusException.class,() -> IncidentWorkflowRuns.requireNoOutstanding(accepted));
        var reported = change(accepted,IncidentMutation.Operation.RECORD_RESPONSE_OUTCOME,Map.of("response_id",RESPONSE,"outcome","failed","reason","No execution evidence"),"reviewer");
        var failed = advance(reported);
        assertEquals("terminal",view(failed).get("observed_state"));
        assertEquals(1,IncidentInvestigationService.projectTasks(failed).size());
        IncidentWorkflowRuns.requireNoOutstanding(failed);
    }

    public void testOwnershipCancellationAndGrant() {
        var initial = start(base(),"evidence_collection","Host");
        expectThrows(OpenSearchStatusException.class,() -> start(initial,"evidence_collection","Other"));
        expectThrows(OpenSearchStatusException.class,() -> change(initial,IncidentMutation.Operation.CANCEL_WORKFLOW,Map.of("run_id",RUN,"reason","Stop"),"other"));
        expectThrows(OpenSearchStatusException.class,() -> IncidentWorkflowRuns.requireNoOutstanding(initial));
        var cancelled = change(initial,IncidentMutation.Operation.CANCEL_WORKFLOW,Map.of("run_id",RUN,"reason","Stop"),OWNER);
        IncidentWorkflowRuns.requireNoOutstanding(cancelled);
        assertEquals(1,IncidentInvestigationService.projectTasks(cancelled).size());
        var next = start(cancelled,"evidence_collection","Other");
        assertEquals(2,IncidentWorkflowRuns.runs(next).size());
        assertTrue(Grant.WORKFLOW_OPERATE.permits(IncidentMutation.Operation.START_WORKFLOW));
        assertFalse(Grant.WORKFLOW_OPERATE.permits(IncidentMutation.Operation.APPROVE_RESPONSE));
        assertFalse(Grant.PLAYBOOK_APPLY.permits(IncidentMutation.Operation.ADVANCE_WORKFLOW));
        var waiting = requested("evidence_collection","Host");
        expectThrows(OpenSearchStatusException.class,() -> change(waiting,IncidentMutation.Operation.CANCEL_WORKFLOW,Map.of("run_id",RUN,"reason","Stop"),OWNER));
        var rejected = change(waiting,IncidentMutation.Operation.REJECT_RESPONSE,Map.of("response_id",RESPONSE,"reason","Denied"),"reviewer");
        IncidentWorkflowRuns.requireNoOutstanding(advance(rejected));
    }

    public void testInvalidScopeAndCorruptReferenceFailClosed() {
        expectThrows(OpenSearchStatusException.class,() -> start(base(),"vulnerability_investigation",MANAGER+":agent:000"));
        expectThrows(OpenSearchStatusException.class,() -> start(base(),"unknown","Host"));
        var initial = start(base(),"evidence_collection","Host");
        var corrupt = new LinkedHashMap<>(initial); corrupt.put("tasks",List.of());
        expectThrows(OpenSearchStatusException.class,() -> IncidentWorkflowRuns.runs(corrupt));
        var duplicate = new ArrayList<>(IncidentWorkflowRuns.runs(initial)); duplicate.add(duplicate.get(0));
        corrupt.put("workflow_runs",duplicate);
        expectThrows(OpenSearchStatusException.class,() -> IncidentWorkflowRuns.runs(corrupt));
        var pending = new LinkedHashMap<>(initial); pending.put("pending_activity",Map.of("id","pending"));
        expectThrows(OpenSearchStatusException.class,() -> advance(pending));
    }
}
