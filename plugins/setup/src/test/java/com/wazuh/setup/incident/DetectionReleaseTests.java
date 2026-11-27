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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DetectionReleaseTests extends OpenSearchTestCase {
    static final String PLAN="a".repeat(64),PACK="b".repeat(64),RULE="00000000-0000-4000-8000-000000000001";
    static final Instant NOW=Instant.parse("2026-11-27T10:00:00Z");
    static final String EXPIRES="2026-11-27T10:30:00Z";
    static Map<String,Object> evidence(){
        var m=Map.ofEntries(Map.entry("positive",10),Map.entry("negative",10),Map.entry("unknown",0),
                Map.entry("lost_positive",0),Map.entry("gained_positive",0),Map.entry("new_false_positive",0),
                Map.entry("removed_false_positive",10),Map.entry("baseline_tp",10),Map.entry("baseline_fp",10),
                Map.entry("baseline_tn",0),Map.entry("baseline_fn",0),Map.entry("candidate_tp",10),
                Map.entry("candidate_fp",0),Map.entry("candidate_tn",10),Map.entry("candidate_fn",0));
        return new LinkedHashMap<>(Map.ofEntries(Map.entry("pack_sha256",PACK),Map.entry("test_sha256",PLAN),
                Map.entry("custom_sha256",PLAN),Map.entry("preview_sha256",PLAN),Map.entry("labels_sha256",PACK),
                Map.entry("integration",RULE),Map.entry("cluster","lab"),Map.entry("space","standard"),Map.entry("dataset","sshd"),
                Map.entry("changed_rules",List.of(RULE)),Map.entry("historical_events",20),Map.entry("prospective_events",20),
                Map.entry("prospective_seconds",86400),Map.entry("historical_metrics",Map.of(RULE,m)),Map.entry("prospective_metrics",Map.of(RULE,m))));
    }
    public void testLifecycleAndIndependence(){
        var s=DetectionRelease.submit(PLAN,evidence(),"author",NOW);
        assertEquals("submitted",s.get("state"));assertEquals(1,s.get("revision"));assertNull(s.get("review"));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.review(s,"author",PACK,"approved","review","deployer",EXPIRES,NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.review(s,"reviewer",PACK,"approved","review","author",EXPIRES,NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.review(s,"reviewer",PACK,"approved","review","reviewer",EXPIRES,NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.review(s,"reviewer",PLAN,"approved","review","deployer",EXPIRES,NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.review(s,"reviewer",PACK,"approved","review","deployer",NOW.plusSeconds(3601).toString(),NOW));
        var a=DetectionRelease.review(s,"reviewer",PACK,"approved","review","deployer",EXPIRES,NOW);
        assertEquals("approved",a.get("state"));assertEquals(2,a.get("revision"));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.reserve(a,PLAN,"reviewer",List.of(RULE),NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.reserve(a,PACK,"deployer",List.of(RULE),NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.reserve(a,PLAN,"deployer",List.of(),NOW));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.reserve(a,PLAN,"deployer",List.of(RULE),Instant.parse(EXPIRES)));
        var r=DetectionRelease.reserve(a,PLAN,"deployer",List.of(RULE),NOW.plusSeconds(1));
        assertEquals("reserved",r.get("state"));assertEquals(3,r.get("revision"));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.reserve(r,PLAN,"deployer",List.of(RULE),NOW.plusSeconds(2)));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.report(r,200,NOW));
        var done=DetectionRelease.report(r,200,NOW.plusSeconds(2));
        assertEquals("native_reported",done.get("state"));assertEquals(4,done.get("revision"));assertEquals(s.get("evidence"),done.get("evidence"));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.report(done,200,NOW.plusSeconds(3)));
        var rejected=DetectionRelease.review(s,"reviewer",PACK,"rejected","not ready",null,null,NOW);
        assertEquals("rejected",rejected.get("state"));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.reserve(rejected,PLAN,"deployer",List.of(RULE),NOW));
    }
    public void testEvidenceConservation(){
        var e=evidence();assertEquals(e,DetectionRelease.evidence(e));
        for(var patch:List.of(Map.of("prospective_seconds",86399),Map.of("historical_events",21),
                Map.of("changed_rules",List.of(RULE,RULE)),Map.of("preview_sha256","invalid"),Map.of("space"," "))){
            var bad=new LinkedHashMap<>(e);bad.putAll(patch);expectThrows(IllegalArgumentException.class,()->DetectionRelease.evidence(bad));
        }
        var bad=new LinkedHashMap<>(e);bad.put("historical_metrics",Map.of(RULE,Map.of("positive",10)));
        expectThrows(IllegalArgumentException.class,()->DetectionRelease.evidence(bad));
    }
}
