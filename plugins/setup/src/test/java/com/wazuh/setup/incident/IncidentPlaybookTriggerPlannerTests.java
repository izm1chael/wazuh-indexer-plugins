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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static com.wazuh.setup.incident.IncidentMutation.Operation.*;

public class IncidentPlaybookTriggerPlannerTests extends OpenSearchTestCase {
    private Map<String, Object> delivered(Map<String, Object> source) {
        var next = new LinkedHashMap<>(source);
        next.put("pending_activity", null);
        return next;
    }
    private Map<String, Object> apply(Map<String, Object> source, IncidentMutation.Operation op, Map<String, Object> input) {
        int rev = (int) source.get("revision");
        return IncidentMutation.apply(delivered(source), op, input, rev, "analyst", Instant.EPOCH.plusSeconds(rev));
    }
    private Map<String, Object> triaging(String severity) {
        var incident = IncidentMutation.create(Map.of("title", "Example", "severity", severity), UUID.randomUUID(), "analyst", Instant.EPOCH);
        return apply(apply(incident, ASSIGN_SELF, Map.of()), START_TRIAGE, Map.of());
    }
    @SuppressWarnings("unchecked")
    private Map<String, Object> event(Map<String, Object> source) { return (Map<String, Object>) source.get("pending_activity"); }

    public void testTriageProducesStableApplicablePlansOnlyAfterDelivery() {
        var source = triaging("high");
        var event = event(source);
        assertTrue(IncidentPlaybookTriggerPlanner.plan(source, event).isEmpty());
        var plans = IncidentPlaybookTriggerPlanner.plan(delivered(source), event);
        assertEquals(List.of("initial_triage", "high_severity_review"), plans.stream().map(IncidentPlaybookTriggerPlanner.Plan::templateId).toList());
        assertEquals(plans, IncidentPlaybookTriggerPlanner.plan(delivered(source), event));
        assertEquals(source.get("id") + ":initial_triage:1", plans.get(0).deduplicationKey());
        var applied = apply(source, APPLY_PLAYBOOK, Map.of("template_id", "initial_triage", "version", 1));
        assertTrue(IncidentPlaybookTriggerPlanner.plan(delivered(applied), event).isEmpty());
        var active = apply(applied, ACTIVATE, Map.of());
        assertEquals(List.of("high_severity_review"), IncidentPlaybookTriggerPlanner.plan(delivered(active), event(active)).stream()
                .map(IncidentPlaybookTriggerPlanner.Plan::templateId).toList());
    }
    public void testEscalationAndForeignEventRejection() {
        var source = triaging("medium");
        var edited = apply(source, EDIT, Map.of("severity", "critical"));
        var plans = IncidentPlaybookTriggerPlanner.plan(delivered(edited), event(edited));
        assertEquals(1, plans.size());
        assertEquals("high_severity_review", plans.get(0).templateId());
        var forged = new LinkedHashMap<>(event(edited));
        forged.put("incident_id", UUID.randomUUID().toString());
        assertTrue(IncidentPlaybookTriggerPlanner.plan(delivered(edited), forged).isEmpty());
        forged = new LinkedHashMap<>(event(edited));
        forged.put("changes", Map.of("severity", Map.of("before", "high", "after", "critical")));
        assertTrue(IncidentPlaybookTriggerPlanner.plan(delivered(edited), forged).isEmpty());
    }
}
