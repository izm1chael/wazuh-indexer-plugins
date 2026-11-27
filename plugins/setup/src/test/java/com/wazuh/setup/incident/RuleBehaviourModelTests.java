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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class RuleBehaviourModelTests extends OpenSearchTestCase {
    private static final Instant DAY=Instant.parse("2026-11-25T00:00:00Z");
    private static final UUID RULE=UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final String INDEX=".ds-wazuh-findings-v5-security-000001";
    private static final RuleBehaviourModel.Input INPUT=new RuleBehaviourModel.Input("user.name","alice",RULE,DAY);
    private static RuleBehaviourModel.Observation row(String id,Instant at){return new RuleBehaviourModel.Observation(new FindingReference(INDEX,id),at);}
    public void testRobustThresholdsAndSparseHistory(){
        var zero=Collections.nCopies(28,0);
        assertEquals("no_observed_activity",RuleBehaviourModel.assess(zero,0).get("classification"));
        assertEquals("newly_observed",RuleBehaviourModel.assess(zero,1).get("classification"));
        var sparse=new ArrayList<>(zero);sparse.set(0,1);
        assertEquals("sparse_baseline",RuleBehaviourModel.assess(sparse,100).get("classification"));
        var regular=Collections.nCopies(28,2);
        assertEquals(5,RuleBehaviourModel.assess(regular,4).get("threshold"));
        assertEquals("within_volume_threshold",RuleBehaviourModel.assess(regular,4).get("classification"));
        assertEquals("elevated_rule_volume",RuleBehaviourModel.assess(regular,5).get("classification"));
        var mixed=new ArrayList<>(Collections.nCopies(14,0));mixed.addAll(Collections.nCopies(14,10));
        var result=RuleBehaviourModel.assess(mixed,20);
        assertEquals(10,result.get("median_times_two"));assertEquals(20,result.get("mad_times_four"));assertEquals(20,result.get("threshold"));
        var half=new ArrayList<>(Collections.nCopies(14,1));half.addAll(Collections.nCopies(14,2));
        assertEquals(3,RuleBehaviourModel.assess(half,5).get("median_times_two"));assertEquals(2,RuleBehaviourModel.assess(half,5).get("mad_times_four"));
        var weekday=new ArrayList<>(Collections.nCopies(28,1));weekday.set(0,40);
        assertEquals(43,RuleBehaviourModel.assess(weekday,42).get("threshold"));
        expectThrows(IllegalArgumentException.class,()->RuleBehaviourModel.assess(Collections.nCopies(28,72),0));
        expectThrows(IllegalArgumentException.class,()->RuleBehaviourModel.assess(zero,-1));
    }
    public void testWindowAndPopulation(){
        INPUT.requireCompleted(INPUT.until().plusSeconds(120));
        expectThrows(IllegalArgumentException.class,()->INPUT.requireCompleted(INPUT.until().plusSeconds(119)));
        expectThrows(IllegalArgumentException.class,()->new RuleBehaviourModel.Input("user.name","alice",RULE,DAY.plusSeconds(1)));
        expectThrows(IllegalArgumentException.class,()->new RuleBehaviourModel.Input("dns.question.name","example.org",RULE,DAY));
        var rows=new ArrayList<RuleBehaviourModel.Observation>();
        rows.add(row("a",INPUT.from()));rows.add(row("b",DAY.minusNanos(1)));
        for(int n=24;n>=0;n--)rows.add(row("comparison-"+n,DAY.plusSeconds(n)));
        var report=RuleBehaviourModel.evaluate(INPUT,rows);
        var assessment=(Map<?,?>)report.get("assessment");
        assertEquals(27,report.get("finding_count"));assertEquals(2,assessment.get("baseline_total"));assertEquals(25,assessment.get("current_count"));
        assertEquals(1,((List<?>)assessment.get("daily_counts")).get(0));assertEquals(1,((List<?>)assessment.get("daily_counts")).get(27));
        var sample=(List<?>)report.get("current_sample");assertEquals(20,sample.size());assertEquals("comparison-0",((Map<?,?>)sample.get(0)).get("document_id"));
        expectThrows(IllegalArgumentException.class,()->RuleBehaviourModel.evaluate(INPUT,List.of(row("a",DAY),row("a",INPUT.from()))));
        expectThrows(IllegalArgumentException.class,()->RuleBehaviourModel.evaluate(INPUT,List.of(row("a",INPUT.until()))));
        expectThrows(IllegalArgumentException.class,()->RuleBehaviourModel.evaluate(INPUT,List.of(row("a",INPUT.from().minusNanos(1)))));
        expectThrows(IllegalArgumentException.class,()->RuleBehaviourModel.evaluate(INPUT,Collections.nCopies(2001,row("a",DAY))));
        var other=new RuleBehaviourModel.Observation(new FindingReference(".ds-wazuh-findings-v5-security-000002","a"),DAY);
        assertEquals(2,RuleBehaviourModel.evaluate(INPUT,List.of(row("a",DAY),other)).get("finding_count"));
    }
}
