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

import com.wazuh.setup.action.IncidentAutomationAction;
import com.wazuh.setup.action.IncidentAutomationRequest;
import com.wazuh.setup.transport.TransportIncidentAutomationAction;
import org.opensearch.OpenSearchException;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class IncidentAutomationTests extends OpenSearchTestCase {
    private static final UUID INCIDENT = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID POLICY = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID ANALYTICS = UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final Instant NOW = Instant.parse("2026-11-26T12:00:00Z");

    private Map<String, Object> rule(String id, String trigger, Map<String, Object> actions) {
        var row = new LinkedHashMap<String, Object>();
        row.put("id", id); row.put("trigger", trigger); row.put("minimum_severity", "informational"); row.put("status", "any_open");
        row.put("minimum_findings", 0); row.put("unassigned_only", false); row.put("required_tags", List.of());
        row.put("correlation_policy_id", null); row.put("actions", actions); return row;
    }

    private IncidentAutomationPolicy.Policy policy(Map<String, Object>... rules) {
        return IncidentAutomationPolicy.parse(Map.of("policy_id", POLICY.toString(), "policy_version", 1, "rules", List.of(rules)));
    }

    private Map<String, Object> fresh() {
        return IncidentMutation.create(Map.of("title", "Example", "severity", "medium"), INCIDENT, "analyst", NOW);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> deliver(Map<String, Object> source) {
        var event = (Map<String, Object>) source.get("pending_activity");
        source.put("pending_activity", null); return event;
    }

    public void testFirstMatchAtomicCreationActionsAndReplay() {
        var source = fresh(); var event = deliver(source);
        var policy = policy(rule("first", "created", Map.of("assign_to", "analyst2", "raise_severity", "high", "raise_priority", "urgent",
                "add_tags", List.of("soc", "escalated"), "create_task", "Review detection")),
                rule("second", "created", Map.of("assign_to", "other")));
        assertEquals("first", IncidentAutomationPolicy.match(policy, source, event).id());
        var next = IncidentMutation.automate(source, event, policy, "runner", NOW.plusSeconds(1));
        assertNull(source.get("owner")); assertEquals(1, source.get("revision")); assertEquals(List.of(), source.get("tasks"));
        assertEquals("analyst2", next.get("owner")); assertEquals("new", next.get("status"));
        assertEquals("high", next.get("severity")); assertEquals("urgent", next.get("priority"));
        assertEquals(List.of("escalated", "soc"), next.get("tags"));
        assertEquals(1, IncidentInvestigationService.projectTasks(next).size());
        assertEquals("runner", next.get("updated_by")); assertEquals(2, next.get("revision"));
        var history = IncidentAutomationPolicy.receipts(next);
        assertEquals(1, history.size()); assertEquals(6, history.get(0).get("changed_fields"));
        assertEquals(policy.fingerprint(), history.get(0).get("policy_hash"));
        assertEquals(1, history.get(0).get("trigger_revision"));
        var applied = deliver(next);
        assertEquals("automation_applied", applied.get("kind"));
        assertEquals("runner", applied.get("actor"));
        assertNull(IncidentAutomationPolicy.match(policy, next, applied));
        assertTrue(IncidentAutomationPolicy.alreadyRecorded(policy, next));
        expectThrows(OpenSearchException.class, () -> IncidentMutation.automate(next, applied, policy, "runner", NOW.plusSeconds(2)));
    }

    public void testOriginConditionAndLatestEventOnly() {
        var source = fresh(); var event = deliver(source);
        var rule = rule("correlated", "created", Map.of("add_tags", List.of("correlated")));
        rule.put("correlation_policy_id", ANALYTICS.toString());
        var policy = policy(rule);
        assertNull(IncidentAutomationPolicy.match(policy, source, event));
        source.put("correlation_origin", Map.of("policy_id", ANALYTICS.toString()));
        assertNotNull(IncidentAutomationPolicy.match(policy, source, event));
        var assigned = IncidentMutation.apply(source, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), 1, "analyst", NOW.plusSeconds(1));
        assertNull(IncidentAutomationPolicy.match(policy, assigned, event)); // pending activity
        var latest = deliver(assigned);
        assertNull(IncidentAutomationPolicy.match(policy, assigned, latest)); // creation superseded
        expectThrows(IllegalStateException.class, () -> IncidentAutomationPolicy.match(policy, assigned, event));
    }

    public void testExistingOwnerAndSeverityNeverOverwritten() {
        var source = fresh(); deliver(source);
        var assigned = IncidentMutation.apply(source, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), 1, "analyst", NOW.plusSeconds(1));
        var event = deliver(assigned);
        var policy = policy(rule("no_downgrade", "updated", Map.of("assign_to", "other", "raise_severity", "low", "raise_priority", "low")));
        var next = IncidentMutation.automate(assigned, event, policy, "runner", NOW.plusSeconds(2));
        assertEquals("analyst", next.get("owner")); assertEquals("medium", next.get("severity")); assertEquals("medium", next.get("priority"));
        assertEquals(0, IncidentAutomationPolicy.receipts(next).get(0).get("changed_fields"));
        assertEquals(3, next.get("revision"));
    }

    public void testTaskAndChecklistTogetherAndBlockedChecklistAtomicity() {
        var source = fresh(); var event = deliver(source);
        var blocked = policy(rule("blocked", "created", Map.of("assign_to", "analyst", "apply_playbook", "initial_triage")));
        expectThrows(OpenSearchException.class, () -> IncidentMutation.automate(source, event, blocked, "runner", NOW.plusSeconds(1)));
        assertNull(source.get("owner")); assertEquals(List.of(), source.get("tasks"));
        var assigned = IncidentMutation.apply(source, IncidentMutation.Operation.ASSIGN_SELF, Map.of(), 1, "analyst", NOW.plusSeconds(1)); deliver(assigned);
        var triage = IncidentMutation.apply(assigned, IncidentMutation.Operation.START_TRIAGE, Map.of(), 2, "analyst", NOW.plusSeconds(2));
        var latest = deliver(triage);
        var policy = policy(rule("triage", "updated", Map.of("create_task", "Custom task", "apply_playbook", "initial_triage")));
        var next = IncidentMutation.automate(triage, latest, policy, "runner", NOW.plusSeconds(3));
        var tasks = IncidentInvestigationService.projectTasks(next);
        assertEquals(5, tasks.size()); assertEquals(5, tasks.stream().map(task -> task.get("id")).distinct().count());
        assertEquals(1, IncidentPlaybooks.runs(next).size()); assertEquals(2, IncidentAutomationPolicy.receipts(next).get(0).get("changed_fields"));
    }

    public void testPolicyValidationFingerprintAndGrants() {
        var a = rule("a", "created", Map.of("add_tags", List.of("b", "a")));
        var b = rule("b", "updated", Map.of("raise_priority", "urgent"));
        assertEquals(policy(a, b).fingerprint(), policy(rule("a", "created", Map.of("add_tags", List.of("a", "b"))), b).fingerprint());
        assertNotEquals(policy(a,b).fingerprint(), policy(b,a).fingerprint());
        expectThrows(OpenSearchException.class, () -> policy(a,a));
        expectThrows(OpenSearchException.class, () -> policy(rule("bad", "created", Map.of("close", true))));
        expectThrows(OpenSearchException.class, () -> policy(rule("bad", "created", Map.of("assign_to", "_shared"))));
        assertEquals("cluster:admin/wazuh/incident/automation_read", IncidentAutomationAction.READ_NAME);
        assertEquals("cluster:admin/wazuh/incident/automation_save", IncidentAutomationAction.SAVE_NAME);
        assertEquals("cluster:admin/wazuh/incident/automation_execute", IncidentAutomationAction.EXECUTE_NAME);
        String hash = policy(a,b).fingerprint();
        assertEquals(hash, TransportIncidentAutomationAction.authorize("runner","runner",POLICY + ":1:" + hash,POLICY,1));
        expectThrows(OpenSearchException.class, () -> TransportIncidentAutomationAction.authorize("other","runner",POLICY + ":1:" + hash,POLICY,1));
        expectThrows(OpenSearchException.class, () -> TransportIncidentAutomationAction.authorize("runner","runner",POLICY + ":1:" + hash,POLICY,2));
        expectThrows(OpenSearchException.class, () -> TransportIncidentAutomationAction.parse("{\"policy_id\":1,\"policy_id\":2}"));
        assertNotNull(new IncidentAutomationRequest("a".repeat(32769)).validate());
    }
}
