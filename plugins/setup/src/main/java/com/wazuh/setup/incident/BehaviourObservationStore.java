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
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Fixed private index; only trusted transport/service callers use this store. */
final class BehaviourObservationStore {
    static final String INDEX=".wazuh-behaviour-observations-v1";
    static final int MAX_DAY=50;
    record Stored(Map<String,Object> source,long seqNo,long primaryTerm){}
    private final Client client;
    private final ThreadPool pool;
    BehaviourObservationStore(Client client,ThreadPool pool){this.client=client;this.pool=pool;}
    void get(UUID id,ActionListener<Stored> listener){
        try(ThreadContext.StoredContext ignored=pool.getThreadContext().stashContext()){
            client.get(new GetRequest(INDEX,id.toString()),ActionListener.wrap(response->{
                if(!response.isExists()){listener.onResponse(null);return;}
                if(!INDEX.equals(response.getIndex())||!id.toString().equals(response.getId()))throw conflict();
                var row=response.getSourceAsMap();BehaviourObservation.validate(row);
                if(!id.toString().equals(row.get("id")))throw conflict();
                listener.onResponse(new Stored(row,response.getSeqNo(),response.getPrimaryTerm()));
            },listener::onFailure));
        }
    }
    void create(Map<String,Object> row,ActionListener<Stored> listener){
        BehaviourObservation.validate(row);
        if(!Integer.valueOf(1).equals(row.get("revision")))throw conflict();
        var request=new IndexRequest(INDEX).id((String)row.get("id")).source(row,XContentType.JSON).opType(DocWriteRequest.OpType.CREATE);
        write(request,row,listener);
    }
    void replace(Stored old,Map<String,Object> row,ActionListener<Stored> listener){
        BehaviourObservation.validate(row);
        if(!old.source().get("id").equals(row.get("id"))||
                !Integer.valueOf((Integer)old.source().get("revision")+1).equals(row.get("revision")))throw conflict();
        for(String field:List.of("model","query","actor","observed_at","coverage","finding_count","assessment"))
            if(!old.source().get(field).equals(row.get(field)))throw conflict();
        if((Integer)old.source().get("revision")==2&&!old.source().get("review").equals(row.get("review")))throw conflict();
        var request=new IndexRequest(INDEX).id((String)row.get("id")).source(row,XContentType.JSON)
                .setIfSeqNo(old.seqNo()).setIfPrimaryTerm(old.primaryTerm());
        write(request,row,listener);
    }
    private void write(IndexRequest request,Map<String,Object> row,ActionListener<Stored> listener){
        request.setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try(ThreadContext.StoredContext ignored=pool.getThreadContext().stashContext()){
            client.index(request,ActionListener.wrap(response->listener.onResponse(new Stored(row,response.getSeqNo(),response.getPrimaryTerm())),listener::onFailure));
        }
    }
    void day(Instant day,ActionListener<List<Map<String,Object>>> listener){
        var request=new SearchRequest(INDEX).source(new SearchSourceBuilder().query(QueryBuilders.termQuery("query.day",day.toString()))
                .size(MAX_DAY+1).trackTotalHits(true).timeout(TimeValue.timeValueSeconds(15)));
        request.allowPartialSearchResults(false);
        try(ThreadContext.StoredContext ignored=pool.getThreadContext().stashContext()){
            client.search(request,ActionListener.wrap(response->{
                var hits=response.getHits();
                if(response.isTimedOut()||response.getFailedShards()>0||Boolean.TRUE.equals(response.isTerminatedEarly())||
                        hits.getTotalHits()==null||hits.getTotalHits().relation!=TotalHits.Relation.EQUAL_TO||
                        hits.getTotalHits().value!=hits.getHits().length||hits.getHits().length>MAX_DAY)throw conflict();
                var rows=new ArrayList<Map<String,Object>>();var seen=new HashSet<String>();
                for(var hit:hits.getHits()){
                    var row=hit.getSourceAsMap();BehaviourObservation.validate(row);
                    if(!INDEX.equals(hit.getIndex())||!hit.getId().equals(row.get("id"))||!seen.add(hit.getId())||
                            !day.equals(BehaviourObservation.input(row.get("query")).day()))throw conflict();
                    rows.add(row);
                }
                rows.sort(java.util.Comparator.comparingInt((Map<String,Object> row)->rank(row)).thenComparing(row->(String)row.get("id")));
                listener.onResponse(List.copyOf(rows));
            },listener::onFailure));
        }
    }
    private static int rank(Map<String,Object> row){
        if(!"unreviewed".equals(row.get("state")))return "escalation_requested".equals(row.get("state"))?2:3;
        return "elevated_rule_volume".equals(((Map<?,?>)row.get("assessment")).get("classification"))?0:1;
    }
    static OpenSearchStatusException conflict(){return new OpenSearchStatusException("Observation changed, unavailable or exceeds 50 records for the day",RestStatus.CONFLICT);}
}
