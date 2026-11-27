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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class BehaviourObservationTests extends OpenSearchTestCase {
    static final Instant DAY=Instant.parse("2026-11-25T00:00:00Z"),NOW=DAY.plusSeconds(86520);
    static final RuleBehaviourModel.Input INPUT=new RuleBehaviourModel.Input("user.name","alice",UUID.fromString("00000000-0000-4000-8000-000000000001"),DAY);
    private Map<String,Object> report(int baseline,int current){
        return Map.of("scope","caller_visible_rule_finding_scan","model","rule_volume_v2","query",INPUT.definition(),
                "actor","publisher","observed_at",NOW.toString(),"coverage","search_complete_telemetry_unverified",
                "finding_count",baseline*28+current,"assessment",RuleBehaviourModel.assess(Collections.nCopies(28,baseline),current),
                "current_sample",List.of(Map.of("document_id","not-persisted")));
    }
    public void testIdentityAndMinimalObservation(){
        assertEquals("7a265b3f73c0a9adf58122bfdd9d2bf0ea1cc1bfa8d0948c3c6ac749d88a06bc",BehaviourObservation.fingerprint(INPUT));
        assertEquals("197591c7-8a01-840e-9b4c-02f888e34dd7",BehaviourObservation.id(INPUT,"publisher").toString());
        var row=BehaviourObservation.create(INPUT,"publisher",report(2,5));
        assertEquals("unreviewed",row.get("state"));assertEquals(1,row.get("revision"));
        assertEquals(false,row.containsKey("current_sample"));
        assertEquals("not_flagged",BehaviourObservation.create(INPUT,"publisher",report(2,4)).get("state"));
        assertEquals("unreviewed",BehaviourObservation.create(INPUT,"publisher",report(0,1)).get("state"));
        assertEquals("not_flagged",BehaviourObservation.create(INPUT,"publisher",report(0,0)).get("state"));
        var bad=new LinkedHashMap<>(row);bad.put("finding_count",99);
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.validate(bad));
        bad.put("finding_count",61);bad.put("id",UUID.randomUUID().toString());
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.validate(bad));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.create(INPUT,"other",report(2,5)));
    }
    public void testReviewAndPromotion(){
        var row=BehaviourObservation.create(INPUT,"publisher",report(2,5));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.review(row,1,"publisher","monitor","reason",NOW));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.review(row,2,"reviewer","monitor","reason",NOW));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.review(row,1,"reviewer","monitor"," ",NOW));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.review(row,1,"reviewer","monitor","reason",NOW.minusSeconds(1)));
        var dismissed=BehaviourObservation.review(row,1,"reviewer","dismissed","Rule noise",NOW);
        assertEquals("dismissed",dismissed.get("state"));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.incidentPayload(dismissed,"reviewer"));
        var monitor=BehaviourObservation.review(row,1,"reviewer","monitor","Observe",NOW);
        assertEquals("monitor",monitor.get("state"));
        var escalated=BehaviourObservation.review(row,1,"reviewer","escalation_requested","Investigate",NOW);
        assertEquals(2,escalated.get("revision"));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.review(escalated,2,"reviewer","monitor","Changed",NOW));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.incidentPayload(escalated,"other"));
        var payload=BehaviourObservation.incidentPayload(escalated,"reviewer");
        assertEquals("informational",payload.get("severity"));assertEquals(row.get("id"),payload.get("request_id"));
        assertEquals(false,((String)payload.get("description")).contains("alice"));
        var id=BehaviourObservation.incidentId(escalated,"reviewer");
        assertEquals("aff3d786-fca1-8bf0-83ea-09be8a066c9f",id.toString());
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.promoted(escalated,"reviewer",UUID.randomUUID(),NOW));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.promoted(escalated,"reviewer",id,NOW.minusSeconds(1)));
        var promoted=BehaviourObservation.promoted(escalated,"reviewer",id,NOW.plusSeconds(1));
        assertEquals("promoted",promoted.get("state"));assertEquals(3,promoted.get("revision"));
        assertEquals(id.toString(),promoted.get("incident_id"));assertEquals(escalated.get("review"),promoted.get("review"));
        assertEquals(row.get("assessment"),promoted.get("assessment"));
        expectThrows(IllegalArgumentException.class,()->BehaviourObservation.incidentPayload(promoted,"reviewer"));
    }
}
