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
import java.util.LinkedHashMap;

public class EventBehaviourModelTests extends OpenSearchTestCase {
    static final Instant DAY=Instant.parse("2026-11-25T00:00:00Z");
    static final Instant NOW=DAY.plusSeconds(86520);
    static final String INDEX=".ds-wazuh-events-v5-access-management-000001";
    static final EventBehaviourModel.Input INPUT=new EventBehaviourModel.Input("authentication","lab","standard","sshd","user-1",DAY);
    private static Map<String,Object> event(Instant at,String outcome,String host,String ip,Instant ingested){
        var source=new LinkedHashMap<String,Object>();
        source.put("@timestamp",at.toString());source.put("wazuh.cluster.name","lab");source.put("wazuh.space.name","standard");
        source.put("event.dataset","sshd");source.put("event.category",List.of("authentication"));source.put("user.id","user-1");
        if(outcome!=null)source.put("event.outcome",outcome);
        if(host!=null)source.put("host.id",host);
        if(ip!=null)source.put("source.ip",ip);
        if(ingested!=null)source.put("event.ingested",ingested.toString());
        return source;
    }
    private static EventBehaviourModel.Row row(String id,Instant at,String outcome,String host,String ip,Instant ingested){
        return EventBehaviourModel.project(INPUT,new EventBehaviourModel.Ref(INDEX,id),event(at,outcome,host,ip,ingested));
    }
    public void testAuthenticationAndIngestionConservation(){
        var report=EventBehaviourModel.evaluate(INPUT,List.of(
                row("a",INPUT.from(),"success","host-a","192.0.2.1",INPUT.from().plusSeconds(5)),
                row("b",DAY.minusSeconds(1),"failure","host-a","192.0.2.1",DAY.plusSeconds(121)),
                row("c",DAY,"failure","host-b","192.0.2.2",DAY.minusSeconds(1)),
                row("d",DAY.plusSeconds(1),null,null,"2001:db8::1",null),
                row("e",DAY.plusSeconds(2),"other","host-b","192.0.2.2",NOW.plusSeconds(1))),NOW);
        assertEquals(5,report.get("event_count"));
        var auth=(Map<?,?>)report.get("authentication");
        assertEquals(1,((Map<?,?>)auth.get("success")).get("baseline_total"));
        assertEquals(1,((Map<?,?>)auth.get("failure")).get("baseline_total"));
        assertEquals(1,((Map<?,?>)auth.get("failure")).get("current_count"));
        assertEquals(2,((Map<?,?>)auth.get("unknown")).get("current_count"));
        var rel=(Map<?,?>)report.get("relationship");
        assertEquals(1,rel.get("baseline_distinct"));assertEquals(1,rel.get("comparison_distinct"));
        assertEquals(1,rel.get("comparison_missing"));
        assertEquals(List.of(Map.of("value","host-b","count",2)),rel.get("newly_observed"));
        var source=(Map<?,?>)report.get("source_relationship");
        assertEquals(1,source.get("comparison_missing"));
        assertEquals(List.of(Map.of("value","192.0.2.2","count",2)),source.get("newly_observed"));
        var coverage=(Map<?,?>)report.get("coverage");
        assertEquals(2,coverage.get("ingest_lag_known"));assertEquals(1,coverage.get("ingest_lag_missing"));
        assertEquals(1,coverage.get("ingest_before_event"));assertEquals(1,coverage.get("ingest_after_observation"));
        assertEquals(1,coverage.get("lag_over_120s"));assertEquals(122L,coverage.get("max_lag_seconds"));
    }
    public void testRejectWrongScopeAmbiguityAndDuplicate(){
        var source=event(DAY,"success","host-a","192.0.2.1",DAY);
        var ref=new EventBehaviourModel.Ref(INDEX,"x");
        source.put("event.dataset","other");
        expectThrows(IllegalArgumentException.class,()->EventBehaviourModel.project(INPUT,ref,source));
        source.put("event.dataset","sshd");source.put("event",Map.of("dataset","sshd"));
        expectThrows(IllegalArgumentException.class,()->EventBehaviourModel.project(INPUT,ref,source));
        var first=row("a",DAY,"success","host-a","192.0.2.1",DAY);
        expectThrows(IllegalArgumentException.class,()->EventBehaviourModel.evaluate(INPUT,List.of(first,first),NOW));
        expectThrows(IllegalArgumentException.class,()->EventBehaviourModel.evaluate(INPUT,List.of(first),NOW.minusSeconds(1)));
        expectThrows(IllegalArgumentException.class,()->new EventBehaviourModel.Ref(".ds-wazuh-findings-v5-security-000001","x"));
        expectThrows(IllegalArgumentException.class,()->EventBehaviourModel.project(INPUT,ref,event(INPUT.until(),"success","host-a","192.0.2.1",NOW)));
    }
    public void testProcessAndNetworkSemantics(){
        var process=new EventBehaviourModel.Input("process","lab","standard","sysmon","host-1",DAY);
        var src=new LinkedHashMap<String,Object>();
        src.put("@timestamp",DAY.toString());src.put("wazuh.cluster.name","lab");src.put("wazuh.space.name","standard");
        src.put("event.dataset","sysmon");src.put("event.category",List.of("process"));src.put("event.type",List.of("start"));
        src.put("host.id","host-1");src.put("process.executable","/usr/bin/example");
        var ref=new EventBehaviourModel.Ref(INDEX,"p");
        var report=EventBehaviourModel.evaluate(process,List.of(EventBehaviourModel.project(process,ref,src)),NOW);
        assertEquals(null,report.get("authentication"));
        assertEquals(List.of(Map.of("value","/usr/bin/example","count",1)),((Map<?,?>)report.get("relationship")).get("newly_observed"));
        src.put("event.type",List.of("end"));
        expectThrows(IllegalArgumentException.class,()->EventBehaviourModel.project(process,ref,src));
        var network=new EventBehaviourModel.Input("network","lab","standard","sysmon","host-1",DAY);
        src.put("event.category",List.of("network"));src.put("destination.ip","2001:db8::1");
        report=EventBehaviourModel.evaluate(network,List.of(EventBehaviourModel.project(network,ref,src)),NOW);
        assertEquals(1,((Map<?,?>)report.get("relationship")).get("comparison_missing"));
    }
}
