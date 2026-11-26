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
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;

public class EntityBehaviourModelTests extends OpenSearchTestCase {
    private static final Instant FROM=Instant.parse("2026-11-25T00:00:00Z"), UNTIL=FROM.plusSeconds(86400);
    private static final String FIELD="user.name", INDEX=".ds-wazuh-findings-v5-security-000001";
    private static final List<String> VALUES=List.of("alice","bob");
    private static Map<String,Object> row(String id,Instant at,List<String> values) {
        return Map.of("index",INDEX,"document_id",id,"timestamp",at.toString(),"matched_values",values);
    }
    private static Map<String,Object> report(Instant from,Instant until,List<Map<String,Object>> rows) {
        return Map.of("scope","caller_visible_findings_exact_terms","field",FIELD,"values",VALUES,
                "from",from.toString(),"until",until.toString(),"rows",rows,"match_count",rows.size());
    }
    public void testThresholdAndSparseHistory() {
        assertEquals("no_observed_activity",EntityBehaviourModel.assess(List.of(0,0,0,0,0,0,0),0).classification());
        assertEquals("newly_observed",EntityBehaviourModel.assess(List.of(0,0,0,0,0,0,0),1).classification());
        assertEquals("sparse_baseline",EntityBehaviourModel.assess(List.of(1,0,0,0,0,0,0),100).classification());
        var regular=List.of(2,2,2,2,2,2,2);
        assertEquals(5,EntityBehaviourModel.assess(regular,4).threshold());
        assertEquals("within_volume_threshold",EntityBehaviourModel.assess(regular,4).classification());
        assertEquals("elevated_volume",EntityBehaviourModel.assess(regular,5).classification());
        assertEquals(20,EntityBehaviourModel.assess(List.of(10,10,10,10,10,10,10),20).threshold());
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.assess(List.of(101,0,0,0,0,0,0),0));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.assess(List.of(100,1,0,0,0,0,0),0));
    }
    public void testCompletedAlignedWindow() {
        EntityBehaviourModel.window(FIELD,VALUES,FROM,UNTIL,UNTIL.plusSeconds(120));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.window(FIELD,VALUES,FROM,UNTIL,UNTIL.plusSeconds(119)));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.window(FIELD,VALUES,FROM.plusSeconds(1),UNTIL.plusSeconds(1),UNTIL.plusSeconds(200)));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.window("file.hash.md5",VALUES,FROM,UNTIL,UNTIL.plusSeconds(120)));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.window(FIELD,List.of("a","b","c","d","e","f"),FROM,UNTIL,UNTIL.plusSeconds(120)));
    }
    public void testExactConservationAndIdentity() {
        Instant start=FROM.minusSeconds(7*86400);
        var history=report(start,FROM,List.of(row("a",start,VALUES),row("b",start.plusSeconds(86400),List.of("alice")),row("c",FROM.minusNanos(1),List.of("alice"))));
        var current=report(FROM,UNTIL,List.of(row("d",FROM,VALUES)));
        var result=EntityBehaviourModel.evaluate(FIELD,VALUES,FROM,UNTIL,history,current);
        assertEquals(List.of(1,1,0,0,0,0,1),result.get(0).get("daily_counts"));
        assertEquals(List.of(1,0,0,0,0,0,0),result.get(1).get("daily_counts"));
        assertEquals(1,result.get(0).get("current_count"));
        assertEquals("sparse_baseline",result.get(1).get("classification"));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.evaluate(FIELD,VALUES,FROM,UNTIL,history,report(FROM,UNTIL,List.of(row("a",FROM,VALUES)))));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.evaluate(FIELD,VALUES,FROM,UNTIL,history,report(FROM,UNTIL,List.of(row("d",UNTIL,VALUES)))));
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.evaluate(FIELD,VALUES,FROM,UNTIL,history,report(FROM,UNTIL,List.of(row("d",FROM,List.of("alice","alice"))))));
        var wrong=new LinkedHashMap<>(history);wrong.put("match_count",4);
        expectThrows(IllegalArgumentException.class,()->EntityBehaviourModel.evaluate(FIELD,VALUES,FROM,UNTIL,wrong,current));
    }
}
