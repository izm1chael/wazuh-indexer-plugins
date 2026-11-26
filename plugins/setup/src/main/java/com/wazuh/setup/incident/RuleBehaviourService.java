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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/** Single bounded original-caller scan; validates every returned row, never elevates privileges. */
public final class RuleBehaviourService {
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;
    private final Semaphore permits=new Semaphore(1);
    public RuleBehaviourService(Client client,ThreadPool pool,Clock clock){
        this.client=client;this.pool=pool;this.clock=clock;
    }
    static SearchSourceBuilder build(RuleBehaviourModel.Input input){
        var rule=QueryBuilders.boolQuery().should(QueryBuilders.termQuery("wazuh.rule.uuid",input.rule().toString()))
                .should(QueryBuilders.termQuery("rule.uuid",input.rule().toString())).minimumShouldMatch(1);
        return new SearchSourceBuilder().query(QueryBuilders.boolQuery()
                .filter(QueryBuilders.rangeQuery("@timestamp").gte(input.from().toString()).lt(input.until().toString()))
                .filter(QueryBuilders.termQuery(input.field(),input.value())).filter(rule))
                .size(RuleBehaviourModel.MAX_HITS+1).trackTotalHits(true).timeout(TimeValue.timeValueSeconds(15))
                .fetchSource(new String[]{"@timestamp",input.field(),"wazuh.rule.uuid","rule.uuid"},new String[0]);
    }
    static RuleBehaviourModel.Observation project(RuleBehaviourModel.Input input,FindingReference reference,Map<String,Object> source){
        var candidate=CorrelationPlanner.extract(reference,source);
        if(!input.rule().equals(candidate.rule())||candidate.at()==null||
                candidate.at().isBefore(input.from())||!candidate.at().isBefore(input.until()))throw incomplete();
        // Reuse the existing strict caller-visible literal extractor on the exact day containing this finding.
        long day=Math.floorDiv(candidate.at().getEpochSecond(),RuleBehaviourModel.DAY)*RuleBehaviourModel.DAY;
        var exact=new IncidentHuntService.Input(input.field(),List.of(input.value()),Instant.ofEpochSecond(day),
                Instant.ofEpochSecond(day+RuleBehaviourModel.DAY));
        var projected=IncidentHuntService.project(exact,reference,source);
        if(!candidate.at().toString().equals(projected.get("timestamp")))throw incomplete();
        return new RuleBehaviourModel.Observation(reference,candidate.at());
    }
    public void assess(RuleBehaviourModel.Input input,String actor,ActionListener<Map<String,Object>> listener){
        if(!actor.equals(IncidentPrincipal.require(pool.getThreadContext())))throw new OpenSearchStatusException("Caller required",RestStatus.FORBIDDEN);
        input.requireCompleted(clock.instant());
        if(!permits.tryAcquire())throw new OpenSearchStatusException("Rule behaviour scan busy",RestStatus.TOO_MANY_REQUESTS);
        var released=new AtomicBoolean();
        ActionListener<Map<String,Object>> done=ActionListener.wrap(value->{
            if(released.compareAndSet(false,true)){permits.release();listener.onResponse(value);}
        },error->{if(released.compareAndSet(false,true)){permits.release();listener.onFailure(error);}});
        try{
            var request=new SearchRequest("wazuh-findings-v5*").source(build(input));
            request.allowPartialSearchResults(false);
            request.indicesOptions(org.opensearch.action.support.IndicesOptions.strictExpandOpen());
            client.search(request,ActionListener.wrap(response->{
                var hits=response.getHits();
                if(response.isTimedOut()||response.getFailedShards()>0||Boolean.TRUE.equals(response.isTerminatedEarly())||
                        hits.getTotalHits()==null||hits.getTotalHits().relation!=TotalHits.Relation.EQUAL_TO||
                        hits.getTotalHits().value!=hits.getHits().length||hits.getHits().length>RuleBehaviourModel.MAX_HITS)throw incomplete();
                var rows=new ArrayList<RuleBehaviourModel.Observation>();
                for(var hit:hits.getHits())rows.add(project(input,new FindingReference(hit.getIndex(),hit.getId()),hit.getSourceAsMap()));
                var report=new java.util.LinkedHashMap<>(RuleBehaviourModel.evaluate(input,rows));
                report.put("actor",actor);
                report.put("observed_at",clock.instant().toString());
                done.onResponse(report);
            },done::onFailure));
        }catch(Exception e){done.onFailure(e);}
    }
    private static OpenSearchStatusException incomplete(){
        return new OpenSearchStatusException("Rule behaviour scan incomplete or exceeds 2000 findings; check visibility or select another entity/rule",RestStatus.CONFLICT);
    }
}
