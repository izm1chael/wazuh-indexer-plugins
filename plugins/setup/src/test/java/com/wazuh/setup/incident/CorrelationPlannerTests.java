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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class CorrelationPlannerTests extends OpenSearchTestCase {
    private static final Instant START = Instant.parse("2026-11-26T12:00:00Z");
    private static final UUID RULE = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID POLICY = UUID.fromString("00000000-0000-4000-8000-000000000002");

    private CorrelationPlanner.Policy policy() { return new CorrelationPlanner.Policy(POLICY, 1, Set.of(RULE), 15, 2); }
    private CorrelationPlanner.Candidate finding(String id, String cluster, String agent, UUID rule, int seconds) {
        return new CorrelationPlanner.Candidate(new FindingReference(".ds-wazuh-findings-v5-security-000001", id),
                cluster, agent, rule, START.plusSeconds(seconds));
    }
    private CorrelationPlanner.Preview plan(List<CorrelationPlanner.Candidate> candidates) {
        return CorrelationPlanner.plan(policy(), candidates, START, START.plusSeconds(3600));
    }

    public void testOrderIndependentGroupingAndDeduplication() {
        var a = finding("a", "cluster", "001", RULE, 5);
        var b = finding("b", "cluster", "001", RULE, 60);
        var first = plan(List.of(a, b, a));
        var second = plan(List.of(b, a));
        assertEquals(first.eligible(), second.eligible());
        assertEquals(1, first.duplicateInputs());
        assertEquals(2, first.eligible().get(0).findings().size());
        assertEquals(START, first.eligible().get(0).windowStart());
    }

    public void testNoCrossClusterAgentRuleOrWindowGrouping() {
        var a = finding("a", "cluster", "001", RULE, 5);
        var b = finding("b", "other", "001", RULE, 60);
        var c = finding("c", "cluster", "002", RULE, 60);
        var d = finding("d", "cluster", "001", RULE, 900);
        var e = finding("e", "cluster", "001", UUID.randomUUID(), 60);
        var f = finding("f", null, "001", RULE, 60);
        var result = plan(List.of(a, b, c, d, e, f));
        assertEquals(List.of(), result.eligible());
        assertEquals(4, result.belowThreshold());
        assertEquals(1, result.excludedRule());
        assertEquals(1, result.insufficientIdentity());
    }

    public void testDuplicateConflictingFactsFailRatherThanGuess() {
        expectThrows(IllegalArgumentException.class, () -> plan(List.of(
                finding("a", "cluster", "001", RULE, 0), finding("a", "cluster", "001", RULE, 1))));
    }

    public void testExtractRejectsAmbiguousRuleAndAgentFields() {
        var reference = finding("a", "cluster", "001", RULE, 0).reference();
        var candidate = CorrelationPlanner.extract(reference, Map.of("wazuh.cluster.name", "cluster",
                "wazuh.agent.id", List.of("001", "002"), "wazuh.rule.uuid", RULE.toString(),
                "rule.uuid", UUID.randomUUID().toString(), "@timestamp", START.toString()));
        assertNull(candidate.agent());
        assertNull(candidate.rule());
        assertEquals(START, candidate.at());
    }

    public void testVersionAndWindowArePartOfIdentity() {
        var candidates = List.of(finding("a", "cluster", "001", RULE, 5), finding("b", "cluster", "001", RULE, 10));
        var a = plan(candidates).eligible().get(0);
        var b = CorrelationPlanner.plan(new CorrelationPlanner.Policy(POLICY, 2, Set.of(RULE), 15, 2),
                candidates, START, START.plusSeconds(3600)).eligible().get(0);
        assertNotEquals(a.key(), b.key());
    }
}
