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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/** Caller-visible normalized event stream, not raw messages. */
public final class EventBehaviourService {
    private final Client client;private final ThreadPool pool;private final Clock clock;
    private final Semaphore permits=new Semaphore(1);
    public EventBehaviourService(Client client,ThreadPool pool,Clock clock){this.client=client;this.pool=pool;this.clock=clock;}
    static SearchSourceBuilder build(EventBehaviourModel.Input input){
        var query=QueryBuilders.boolQuery().filter(QueryBuilders.rangeQuery("@timestamp").gte(input.from().toString()).lt(input.until().toString()))
                .filter(QueryBuilders.termQuery("wazuh.cluster.name",input.cluster())).filter(QueryBuilders.termQuery("wazuh.space.name",input.space()))
                .filter(QueryBuilders.termQuery("event.dataset",input.dataset())).filter(QueryBuilders.termQuery(input.field(),input.subject()))
                .filter(QueryBuilders.termQuery("event.category",input.mode()));
        if("process".equals(input.mode()))query.filter(QueryBuilders.termQuery("event.type","start"));
        var fields=new ArrayList<>(java.util.List.of("@timestamp","event.ingested","wazuh.cluster.name","wazuh.space.name","event.dataset","event.category",input.field()));
        switch(input.mode()){
            case "authentication" -> fields.addAll(java.util.List.of("event.outcome","host.id","source.ip"));
            case "process" -> fields.addAll(java.util.List.of("event.type","process.executable"));
            default -> fields.add("destination.ip");
        }
        return new SearchSourceBuilder().query(query).size(EventBehaviourModel.MAX+1).trackTotalHits(true)
                .timeout(TimeValue.timeValueSeconds(15)).fetchSource(fields.toArray(String[]::new),new String[0]);
    }
    public void assess(EventBehaviourModel.Input input,String actor,ActionListener<Map<String,Object>> listener){
        if(!actor.equals(IncidentPrincipal.require(pool.getThreadContext())))throw new OpenSearchStatusException("Caller required",RestStatus.FORBIDDEN);
        input.completed(clock.instant());
        if(!permits.tryAcquire())throw new OpenSearchStatusException("Event profile busy",RestStatus.TOO_MANY_REQUESTS);
        var released=new AtomicBoolean();
        ActionListener<Map<String,Object>> done=ActionListener.wrap(value->{
            if(released.compareAndSet(false,true)){permits.release();listener.onResponse(value);}
        },error->{if(released.compareAndSet(false,true)){permits.release();listener.onFailure(error);}});
        try{
            var request=new SearchRequest("wazuh-events-v5*").source(build(input));
            request.allowPartialSearchResults(false);
            request.indicesOptions(org.opensearch.action.support.IndicesOptions.strictExpandOpen());
            client.search(request,ActionListener.wrap(response->{
                try{
                    var hits=response.getHits();
                    if(response.isTimedOut()||response.getFailedShards()>0||Boolean.TRUE.equals(response.isTerminatedEarly())||
                            hits.getTotalHits()==null||hits.getTotalHits().relation!=TotalHits.Relation.EQUAL_TO||
                            hits.getTotalHits().value!=hits.getHits().length||hits.getHits().length>EventBehaviourModel.MAX)throw incomplete();
                    var rows=new ArrayList<EventBehaviourModel.Row>();
                    for(var hit:hits.getHits())rows.add(EventBehaviourModel.project(input,new EventBehaviourModel.Ref(hit.getIndex(),hit.getId()),hit.getSourceAsMap()));
                    var result=EventBehaviourModel.evaluate(input,rows,clock.instant());result.put("actor",actor);done.onResponse(result);
                }catch(Exception e){done.onFailure(e);}
            },done::onFailure));
        }catch(Exception e){done.onFailure(e);}
    }
    private static OpenSearchStatusException incomplete(){return new OpenSearchStatusException("Event profile unavailable, incomplete or exceeds bounded population",RestStatus.CONFLICT);}
}
