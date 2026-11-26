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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class IncidentEntityInvestigationTests extends OpenSearchTestCase {
    private static final UUID ID=UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final FindingReference A=new FindingReference(".ds-wazuh-findings-v5-security-000001","same");
    private static final FindingReference B=new FindingReference(".ds-wazuh-findings-v5-security-000002","same");
    private static final FindingReference C=new FindingReference(".ds-wazuh-findings-v5-security-000001","other");
    private static final Instant NOW=Instant.parse("2026-11-26T12:00:00Z");
    private static final Map<String,Object> QUERY=Map.of("field","source.ip","values",List.of("192.0.2.3","192.0.2.1"),
            "from","2026-11-25T12:00:00.000Z","until","2026-11-26T12:00:00.000Z");

    private Map<String,Object> source(List<FindingReference> refs) {
        return Map.of("id",ID.toString(),"revision",5,"status","active","severity","high",
                "findings",refs.stream().map(FindingReference::toMap).toList(),"finding_count",refs.size());
    }
    public void testExactPairJoinAndMinimalProjection() {
        var projected=IncidentEntityInvestigationService.project(ID.toString(),source(List.of(A,B,C)),Set.of(A));
        assertEquals(Set.of("id","revision","status","severity","matches"),projected.keySet());
        assertEquals(List.of(A.toMap()),projected.get("matches"));
        expectThrows(OpenSearchStatusException.class,()->IncidentEntityInvestigationService.project(ID.toString(),source(List.of(B)),Set.of(A)));
        expectThrows(OpenSearchStatusException.class,()->IncidentEntityInvestigationService.project(ID.toString(),source(List.of(A,A)),Set.of(A)));
        var wrong=new LinkedHashMap<>(source(List.of(A)));wrong.put("finding_count",2);
        expectThrows(OpenSearchStatusException.class,()->IncidentEntityInvestigationService.project(ID.toString(),wrong,Set.of(A)));
        String query=IncidentEntityInvestigationService.build(Set.of(A,B,C)).toString();
        assertTrue(query.contains("nested"));assertTrue(query.contains("findings.index"));assertTrue(query.contains("findings.document_id"));
    }
    public void testHuntReferencesMustBeUniqueAndComplete() {
        var base=Map.<String,Object>of("scope","caller_visible_findings_exact_terms","rows",List.of(A.toMap(),B.toMap()),"match_count",2);
        assertEquals(Set.of(A,B),IncidentEntityInvestigationService.references(base));
        var bad=new LinkedHashMap<>(base);bad.put("rows",List.of(A.toMap(),A.toMap()));
        expectThrows(OpenSearchStatusException.class,()->IncidentEntityInvestigationService.references(bad));
        bad.put("rows",List.of(A.toMap()));expectThrows(OpenSearchStatusException.class,()->IncidentEntityInvestigationService.references(bad));
        expectThrows(OpenSearchStatusException.class,()->IncidentEntityInvestigationService.build(Set.of()));
    }
    private Map<String,Object> delivered(Map<String,Object> value) {
        var copy=new LinkedHashMap<>(value);copy.put("pending_activity",null);return copy;
    }
    private Map<String,Object> command(Map<String,Object> value,IncidentMutation.Operation op,Map<String,Object> input,String actor) {
        int rev=(Integer)value.get("revision");
        return delivered(IncidentMutation.apply(value,op,input,rev,actor,NOW.plusSeconds(rev)));
    }
    public void testBookmarkSaveWithdrawResaveAndNoResultStorage() {
        var created=delivered(IncidentMutation.create(Map.of("title","Bookmark test","severity","high"),ID,"analyst",NOW));
        var owned=command(created,IncidentMutation.Operation.ASSIGN_SELF,Map.of(),"analyst");
        var input=Map.<String,Object>of("label","Pivot","query",QUERY);
        expectThrows(OpenSearchStatusException.class,()->command(owned,IncidentMutation.Operation.SAVE_HUNT_BOOKMARK,input,"other"));
        var saved=command(owned,IncidentMutation.Operation.SAVE_HUNT_BOOKMARK,input,"analyst");
        var row=IncidentHuntBookmarks.project(saved).get(0);
        assertEquals("saved",row.get("state"));assertEquals(ID+":3",row.get("id"));
        assertEquals(List.of("192.0.2.1","192.0.2.3"),((Map<?,?>)row.get("query")).get("values"));
        assertFalse(row.containsKey("results"));
        expectThrows(OpenSearchStatusException.class,()->command(saved,IncidentMutation.Operation.SAVE_HUNT_BOOKMARK,input,"analyst"));
        var withdrawn=command(saved,IncidentMutation.Operation.WITHDRAW_HUNT_BOOKMARK,Map.of("bookmark_id",row.get("id"),"reason","Superseded"),"analyst");
        assertEquals("withdrawn",IncidentHuntBookmarks.project(withdrawn).get(0).get("state"));
        var again=command(withdrawn,IncidentMutation.Operation.SAVE_HUNT_BOOKMARK,input,"analyst");
        assertEquals(2,IncidentHuntBookmarks.project(again).size());
        var bad=new LinkedHashMap<>(QUERY);bad.put("results",List.of());
        expectThrows(OpenSearchStatusException.class,()->IncidentHuntBookmarks.query(bad));
        bad.remove("results");bad.put("field","arbitrary.field");
        expectThrows(OpenSearchStatusException.class,()->IncidentHuntBookmarks.query(bad));
    }
}
