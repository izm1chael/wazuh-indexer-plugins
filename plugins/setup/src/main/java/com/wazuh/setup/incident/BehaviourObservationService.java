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

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/** Publish only server-generated assessments; independently reviewed escalation uses existing idempotent incident creation. */
public final class BehaviourObservationService {
    public static final String INDEX=BehaviourObservationStore.INDEX;
    private final BehaviourObservationStore store;
    private final RuleBehaviourService scan;
    private final IncidentWriteService incidents;
    private final ThreadPool pool;
    private final Clock clock;
    private final Semaphore publisher=new Semaphore(1);
    public BehaviourObservationService(Client client,ThreadPool pool,RuleBehaviourService scan,IncidentWriteService incidents,Clock clock){
        this.store=new BehaviourObservationStore(client,pool);this.scan=scan;this.incidents=incidents;this.pool=pool;this.clock=clock;
    }
    private void require(String actor){
        if(!actor.equals(IncidentPrincipal.require(pool.getThreadContext())))throw forbidden();
    }
    public static void authorize(String actor,String configured,String approved,RuleBehaviourModel.Input input){
        if(actor==null||actor.isBlank()||!actor.equals(configured)||approved==null||approved.length()>1299)throw forbidden();
        var scopes=new java.util.HashSet<String>();
        for(String hash:approved.split(",",-1))if(!hash.matches("[a-f0-9]{64}")||!scopes.add(hash)||scopes.size()>20)throw forbidden();
        if(!scopes.contains(BehaviourObservation.fingerprint(input)))throw forbidden();
    }
    public void publish(RuleBehaviourModel.Input input,String actor,ActionListener<Map<String,Object>> listener){
        require(actor);input.requireCompleted(clock.instant());
        if(!publisher.tryAcquire())throw new OpenSearchStatusException("Observation publisher busy",RestStatus.TOO_MANY_REQUESTS);
        var released=new AtomicBoolean();
        ActionListener<Map<String,Object>> done=ActionListener.wrap(value->{
            if(released.compareAndSet(false,true)){publisher.release();listener.onResponse(value);}
        },error->{if(released.compareAndSet(false,true)){publisher.release();listener.onFailure(error);}});
        try{
            UUID id=BehaviourObservation.id(input,actor);
            var caller=pool.getThreadContext().newRestorableContext(false);
            store.get(id,ActionListener.wrap(old->{
                if(old!=null){done.onResponse(receipt(old.source(),input,actor));return;}
                if(input.day().isBefore(clock.instant().minusSeconds(7*86400L)))throw BehaviourObservationStore.conflict();
                try(ThreadContext.StoredContext ignored=caller.get()){
                    require(actor);
                    scan.assess(input,actor,ActionListener.wrap(report->{
                        var row=BehaviourObservation.create(input,actor,report);
                        store.create(row,ActionListener.wrap(saved->done.onResponse(receipt(saved.source(),input,actor)),error->{
                            if(ExceptionsHelper.status(error)!=RestStatus.CONFLICT){done.onFailure(error);return;}
                            store.get(id,ActionListener.wrap(existing->{
                                if(existing==null)throw BehaviourObservationStore.conflict();
                                done.onResponse(receipt(existing.source(),input,actor));
                            },done::onFailure));
                        }));
                    },done::onFailure));
                }
            },done::onFailure));
        }catch(Exception e){done.onFailure(e);}
    }
    private static Map<String,Object> receipt(Map<String,Object> row,RuleBehaviourModel.Input input,String actor){
        BehaviourObservation.validate(row);
        if(!actor.equals(row.get("actor"))||!input.definition().equals(row.get("query")))throw BehaviourObservationStore.conflict();
        // The publisher gets only its observation, not another analyst's review.
        return Map.of("id",row.get("id"),"query",row.get("query"),"actor",actor,"model",row.get("model"),
                "observed_at",row.get("observed_at"),"coverage",row.get("coverage"),"finding_count",row.get("finding_count"),
                "assessment",row.get("assessment"),"recorded",true);
    }
    public void day(Instant day,String actor,ActionListener<Map<String,Object>> listener){
        require(actor);
        if(day.getNano()!=0||Math.floorMod(day.getEpochSecond(),86400)!=0||day.isBefore(Instant.parse("2000-01-29T00:00:00Z"))||
                !day.plusSeconds(86400).isBefore(Instant.parse("2100-01-01T00:00:00Z"))||day.plusSeconds(86400).isAfter(clock.instant().minusSeconds(120)))throw new IllegalArgumentException("Completed UTC day required");
        store.day(day,ActionListener.wrap(rows->listener.onResponse(Map.of("scope","shared_soc_observation_metadata","day",day.toString(),
                "rows",rows,"count",rows.size())),listener::onFailure));
    }
    public void review(UUID id,int revision,String actor,String decision,String reason,ActionListener<Map<String,Object>> listener){
        require(actor);
        store.get(id,ActionListener.wrap(old->{
            if(old==null)throw BehaviourObservationStore.conflict();
            if(!Integer.valueOf(revision).equals(old.source().get("revision"))||!"unreviewed".equals(old.source().get("state")))throw BehaviourObservationStore.conflict();
            if(actor.equals(old.source().get("actor")))throw forbidden();
            var next=BehaviourObservation.review(old.source(),revision,actor,decision,reason,clock.instant());
            store.replace(old,next,ActionListener.wrap(saved->listener.onResponse(saved.source()),listener::onFailure));
        },listener::onFailure));
    }
    public void promote(UUID id,int revision,String actor,ActionListener<Map<String,Object>> listener){
        require(actor);
        if(revision!=2)throw BehaviourObservationStore.conflict();
        store.get(id,ActionListener.wrap(old->{
            if(old==null)throw BehaviourObservationStore.conflict();
            var row=old.source();
            if("promoted".equals(row.get("state"))&&actor.equals(((Map<?,?>)row.get("review")).get("actor"))){
                listener.onResponse(row);return;
            }
            if(!"escalation_requested".equals(row.get("state")))throw BehaviourObservationStore.conflict();
            if(!actor.equals(((Map<?,?>)row.get("review")).get("actor")))throw forbidden();
            var payload=BehaviourObservation.incidentPayload(row,actor);
            // Only the immutable escalation reviewer can retry. Existing create service deduplicates the incident by actor+observation ID.
            incidents.create(payload,actor,ActionListener.wrap(result->{
                if(result.activityPending())throw BehaviourObservationStore.conflict();
                UUID incident=UUID.fromString((String)result.incident().get("id"));
                var next=BehaviourObservation.promoted(row,actor,incident,clock.instant());
                store.replace(old,next,ActionListener.wrap(saved->listener.onResponse(saved.source()),error->{
                    if(ExceptionsHelper.status(error)!=RestStatus.CONFLICT){listener.onFailure(error);return;}
                    store.get(id,ActionListener.wrap(existing->{
                        if(existing==null||!"promoted".equals(existing.source().get("state"))||
                                !incident.toString().equals(existing.source().get("incident_id")))throw BehaviourObservationStore.conflict();
                        listener.onResponse(existing.source());
                    },listener::onFailure));
                }));
            },listener::onFailure));
        },listener::onFailure));
    }
    private static OpenSearchStatusException forbidden(){return new OpenSearchStatusException("Behaviour operation principal or scope not approved",RestStatus.FORBIDDEN);}
}
