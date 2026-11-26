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

import com.wazuh.setup.action.AnalyticsRunAction;
import com.wazuh.setup.action.AnalyticsRunRequest;
import com.wazuh.setup.transport.TransportAnalyticsRunAction;
import org.opensearch.OpenSearchException;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class AnalyticsWindowTests extends OpenSearchTestCase {
    private static final UUID DEPLOYMENT = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID POLICY = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID RULE = UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final Instant FROM = Instant.parse("2026-11-26T12:00:00Z");
    private static final Instant UNTIL = FROM.plusSeconds(900);
    private static final Instant NOW = UNTIL.plusSeconds(120);
    private static final CorrelationPlanner.Policy DEFINITION = new CorrelationPlanner.Policy(POLICY, 1, Set.of(RULE), 15, 2);
    private static final AnalyticsWindow.Key KEY = new AnalyticsWindow.Key(DEPLOYMENT, POLICY, 1, FROM, UNTIL);
    private static final String JSON = "{\"policy_id\":\"" + POLICY + "\",\"policy_version\":1,\"from\":\"" + FROM + "\",\"until\":\"" + UNTIL + "\"}";

    private CorrelationPreviewService.Versioned candidate(String id, String agent, long seqNo) {
        var ref = new FindingReference(".ds-wazuh-findings-v5-security-000001", id);
        return new CorrelationPreviewService.Versioned(new CorrelationPlanner.Candidate(ref, "cluster", agent, RULE, FROM.plusSeconds(1)), seqNo, 1);
    }
    private CorrelationPreviewService.Scan scan(List<CorrelationPreviewService.Versioned> versions) {
        return new CorrelationPreviewService.Scan(CorrelationPlanner.plan(DEFINITION,
                versions.stream().map(CorrelationPreviewService.Versioned::candidate).toList(), FROM, UNTIL), versions);
    }

    public void testStrictClosedWindowAndActivation() {
        assertEquals("cluster:admin/wazuh/incident/analytics_execute", AnalyticsRunAction.EXECUTE_NAME);
        assertEquals("cluster:admin/wazuh/incident/analytics_read", AnalyticsRunAction.READ_NAME);
        assertNull(new AnalyticsRunRequest(JSON).validate());
        assertNotNull(new AnalyticsRunRequest("a".repeat(4097)).validate());
        var window = TransportAnalyticsRunAction.parse(JSON);
        assertEquals(POLICY, window.policy()); assertEquals(FROM, window.from());
        TransportAnalyticsRunAction.authorize("runner", "runner", POLICY + ":1", window);
        for (String approved : List.of("", POLICY + ":2", POLICY + ":01", POLICY + ":1," + POLICY + ":1", POLICY + ":1,")) {
            expectThrows(OpenSearchException.class, () -> TransportAnalyticsRunAction.authorize("runner", "runner", approved, window));
        }
        expectThrows(OpenSearchException.class, () -> TransportAnalyticsRunAction.authorize("other", "runner", POLICY + ":1", window));
        expectThrows(OpenSearchException.class, () -> TransportAnalyticsRunAction.parse(JSON.replace("\"policy_version\":1", "\"policy_version\":1,\"actor\":\"runner\"")));
        expectThrows(OpenSearchException.class, () -> TransportAnalyticsRunAction.parse(JSON.replace("\"policy_version\":1", "\"policy_version\":1,\"policy_version\":1")));
        expectThrows(OpenSearchException.class, () -> TransportAnalyticsRunAction.parse(JSON + "{}"));
        assertEquals(FROM, AnalyticsWindow.input(KEY, DEFINITION, NOW).from());
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.input(KEY, DEFINITION, NOW.minusSeconds(1)));
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.input(KEY, DEFINITION, NOW.plusSeconds(8 * 86400)));
        var misaligned = new AnalyticsWindow.Key(DEPLOYMENT, POLICY, 1, FROM.plusSeconds(1), UNTIL.plusSeconds(1));
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.input(misaligned, DEFINITION, NOW.plusSeconds(1)));
    }

    public void testPlanIdentityAndLateArrival() {
        var a = candidate("a", "agent", 1); var b = candidate("b", "agent", 2); var below = candidate("c", "other", 3);
        var plan = AnalyticsWindow.plan(KEY, scan(List.of(a, b, below)));
        assertEquals(3, plan.findings()); assertEquals(1, plan.groups()); assertEquals(1, plan.belowThreshold());
        assertEquals(plan, AnalyticsWindow.plan(KEY, scan(List.of(below, b, a))));
        assertNotEquals(plan.digest(), AnalyticsWindow.plan(KEY, scan(List.of(candidate("a", "agent", 9), b, below))).digest());
        assertNotEquals(plan.digest(), AnalyticsWindow.plan(KEY, scan(List.of(a, b, below, candidate("d", "other", 4)))).digest());
        assertEquals(0, AnalyticsWindow.plan(KEY, scan(List.of())).groups());
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.plan(KEY, scan(List.of(a, a))));
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.plan(KEY, scan(List.of(candidate("a", "agent", -1)))));
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.plan(KEY, scan(List.of(candidate("a", "", 1)))));
    }

    public void testGroupBudgetAndSavedPolicy() {
        var candidates = new ArrayList<CorrelationPreviewService.Versioned>();
        for (int i = 0; i < 21; i++) {
            candidates.add(candidate("a" + i, "agent" + i, 1));
            candidates.add(candidate("b" + i, "agent" + i, 2));
        }
        expectThrows(IllegalArgumentException.class, () -> AnalyticsWindow.plan(KEY, scan(candidates)));
        assertEquals(DEFINITION, AnalyticsExecutionService.policy(CorrelationPolicyStore.definition(DEFINITION), POLICY, 1));
        var changed = new LinkedHashMap<>(CorrelationPolicyStore.definition(DEFINITION)); changed.put("mode", "enabled");
        expectThrows(IllegalStateException.class, () -> AnalyticsExecutionService.policy(changed, POLICY, 1));
    }

    public void testReceiptValidationAndCountConservation() {
        var plan = AnalyticsWindow.plan(KEY, scan(List.of(candidate("a", "agent", 1), candidate("b", "agent", 2))));
        var source = new LinkedHashMap<>(plan.fields("runner")); source.put("state", "reserved"); source.put("recorded_at", NOW.toString());
        AnalyticsRunStore.validate(KEY, source, "reserved");
        var invalid = new LinkedHashMap<>(source); invalid.put("group_count", 2);
        expectThrows(OpenSearchException.class, () -> AnalyticsRunStore.validate(KEY, invalid, "reserved"));
        invalid.put("group_count", 1); invalid.put("recorded_at", UNTIL.toString());
        expectThrows(OpenSearchException.class, () -> AnalyticsRunStore.validate(KEY, invalid, "reserved"));
        expectThrows(OpenSearchException.class, () -> AnalyticsRunStore.validate(KEY, source, "completed"));
    }
}
