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

import org.apache.lucene.search.TotalHits;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/** Shared release metadata; no raw events, no caller-selected index, no deployment action. */
public final class DetectionReleaseService {
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;
    public DetectionReleaseService(Client client,ThreadPool pool,Clock clock){this.client=client;this.pool=pool;this.clock=clock;}
    private void require(String actor){
        if(!DetectionRelease.actor(actor).equals(IncidentPrincipal.require(pool.getThreadContext())))
            throw new OpenSearchStatusException("Authenticated release principal required",RestStatus.FORBIDDEN);
    }
    public void submit(String plan,Object evidence,String actor,ActionListener<Map<String,Object>> listener){
        require(actor);
        var row=DetectionRelease.submit(plan,evidence,actor,clock.instant());
        var request=new IndexRequest(DetectionRelease.INDEX).id(plan).source(row,XContentType.JSON).opType(DocWriteRequest.OpType.CREATE);
        write(request,row,listener);
    }
    public void read(String plan,String actor,ActionListener<Map<String,Object>> listener){
        require(actor);get(plan,ActionListener.wrap(stored->listener.onResponse(stored.source()),listener::onFailure));
    }
    public void review(String plan,String actor,String pack,String decision,String reason,Object deployer,Object expires,
                       ActionListener<Map<String,Object>> listener){
        require(actor);
        get(plan,ActionListener.wrap(old->{
            if(!"submitted".equals(old.source().get("state")))throw conflict();
            if(actor.equals(old.source().get("author")))throw new OpenSearchStatusException("Independent release reviewer required",RestStatus.FORBIDDEN);
            var row=DetectionRelease.review(old.source(),actor,pack,decision,reason,deployer,expires,clock.instant());
            var request=new IndexRequest(DetectionRelease.INDEX).id(plan).source(row,XContentType.JSON)
                    .setIfSeqNo(old.seqNo()).setIfPrimaryTerm(old.primaryTerm());
            write(request,row,listener);
        },listener::onFailure));
    }
    public void day(Instant day,String actor,ActionListener<Map<String,Object>> listener){
        require(actor);
        if(day.getNano()!=0||Math.floorMod(day.getEpochSecond(),86400)!=0||day.isBefore(Instant.parse("2000-01-01T00:00:00Z"))||
                day.isAfter(clock.instant()))throw new IllegalArgumentException("Canonical UTC day required");
        var request=new SearchRequest(DetectionRelease.INDEX).source(new SearchSourceBuilder()
                .query(QueryBuilders.rangeQuery("submitted_at").gte(day.toString()).lt(day.plusSeconds(86400).toString()))
                .size(51).trackTotalHits(true).timeout(TimeValue.timeValueSeconds(15)));
        request.allowPartialSearchResults(false);
        try(var ignored=pool.getThreadContext().stashContext()){
            client.search(request,ActionListener.wrap(response->{
                var hits=response.getHits();
                if(response.isTimedOut()||response.getFailedShards()>0||Boolean.TRUE.equals(response.isTerminatedEarly())||
                        hits.getTotalHits()==null||hits.getTotalHits().relation!=TotalHits.Relation.EQUAL_TO||
                        hits.getTotalHits().value!=hits.getHits().length||hits.getHits().length>50)throw conflict();
                var rows=new ArrayList<Map<String,Object>>();var seen=new HashSet<String>();
                for(var hit:hits.getHits()){
                    var row=hit.getSourceAsMap();DetectionRelease.validate(row);
                    Instant at=DetectionRelease.instant(row.get("submitted_at"));
                    if(!DetectionRelease.INDEX.equals(hit.getIndex())||!hit.getId().equals(row.get("id"))||!seen.add(hit.getId())||
                            at.isBefore(day)||!at.isBefore(day.plusSeconds(86400)))throw conflict();
                    rows.add(row);
                }
                rows.sort(java.util.Comparator.comparing((Map<String,Object> row)->(String)row.get("id")));
                listener.onResponse(Map.of("scope","shared_detection_release_metadata","day",day.toString(),"rows",List.copyOf(rows),"count",rows.size()));
            },listener::onFailure));
        }
    }
    private record Stored(Map<String,Object> source,long seqNo,long primaryTerm){}
    private void get(String plan,ActionListener<Stored> listener){
        DetectionRelease.hash(plan);
        try(var ignored=pool.getThreadContext().stashContext()){
            client.get(new GetRequest(DetectionRelease.INDEX,plan),ActionListener.wrap(response->{
                if(!response.isExists()||!DetectionRelease.INDEX.equals(response.getIndex())||!plan.equals(response.getId()))throw conflict();
                var row=response.getSourceAsMap();DetectionRelease.validate(row);
                if(!plan.equals(row.get("id")))throw conflict();
                listener.onResponse(new Stored(row,response.getSeqNo(),response.getPrimaryTerm()));
            },listener::onFailure));
        }
    }
    private void write(IndexRequest request,Map<String,Object> row,ActionListener<Map<String,Object>> listener){
        DetectionRelease.validate(row);request.setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try(var ignored=pool.getThreadContext().stashContext()){
            client.index(request,ActionListener.wrap(response->{
                if(!DetectionRelease.INDEX.equals(response.getIndex())||!row.get("id").equals(response.getId()))throw conflict();
                listener.onResponse(row);
            },listener::onFailure));
        }
    }
    private static OpenSearchStatusException conflict(){
        return new OpenSearchStatusException("Release unavailable, already changed or daily queue exceeds 50 records",RestStatus.CONFLICT);
    }
}
