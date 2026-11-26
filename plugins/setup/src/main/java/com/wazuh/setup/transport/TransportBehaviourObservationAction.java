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
package com.wazuh.setup.transport;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.setup.action.BehaviourObservationAction;
import com.wazuh.setup.action.IncidentHuntRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.BehaviourObservationService;
import com.wazuh.setup.incident.IncidentPrincipal;
import com.wazuh.setup.settings.PluginSettings;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public abstract class TransportBehaviourObservationAction extends HandledTransportAction<IncidentHuntRequest,IncidentReadResponse>{
    private static final ObjectMapper JSON=new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final String operation;
    private final BehaviourObservationService service;
    private final ThreadPool pool;
    private final ClusterService cluster;
    protected TransportBehaviourObservationAction(String operation,String name,TransportService transport,ActionFilters filters,
            BehaviourObservationService service,ThreadPool pool,ClusterService cluster){
        super(name,transport,filters,IncidentHuntRequest::new);this.operation=operation;this.service=service;this.pool=pool;this.cluster=cluster;
    }
    @Override protected void doExecute(Task task,IncidentHuntRequest request,ActionListener<IncidentReadResponse> listener){
        try{
            var settings=cluster.getSettings();
            if(!PluginSettings.INCIDENTS_ENABLED.get(settings)||!PluginSettings.BEHAVIOUR_OBSERVATIONS_ENABLED.get(settings))
                throw new OpenSearchStatusException("Behaviour observation storage disabled",RestStatus.FORBIDDEN);
            String actor=IncidentPrincipal.require(pool.getThreadContext());
            ActionListener<Map<String,Object>> result=ActionListener.wrap(value->listener.onResponse(new IncidentReadResponse(value)),listener::onFailure);
            if("publish".equals(operation)){
                if(!PluginSettings.BEHAVIOUR_ENABLED.get(settings)||!PluginSettings.RULE_BEHAVIOUR_ENABLED.get(settings))
                    throw new OpenSearchStatusException("Rule behaviour analytics disabled",RestStatus.FORBIDDEN);
                var input=TransportRuleBehaviourAction.parse(request.payload());
                BehaviourObservationService.authorize(actor,PluginSettings.BEHAVIOUR_PUBLISHER.get(settings),
                        PluginSettings.BEHAVIOUR_SCOPES.get(settings),input);
                service.publish(input,actor,result);return;
            }
            Map<?,?> body=JSON.readValue(request.payload(),Map.class);
            if(body==null)throw bad();
            if("day".equals(operation)){
                if(!body.keySet().equals(Set.of("day"))||!(body.get("day") instanceof String raw))throw bad();
                Instant day=Instant.parse(raw);if(!day.toString().equals(raw))throw bad();
                service.day(day,actor,result);return;
            }
            Set<String> fields="review".equals(operation)?Set.of("id","expected_revision","decision","reason"):Set.of("id","expected_revision");
            if(!body.keySet().equals(fields)||!(body.get("id") instanceof String raw)||!(body.get("expected_revision") instanceof Integer rev)||rev<1)throw bad();
            UUID id=UUID.fromString(raw);if(!id.toString().equals(raw))throw bad();
            if("review".equals(operation)){
                if(!(body.get("decision") instanceof String decision)||!(body.get("reason") instanceof String reason))throw bad();
                service.review(id,rev,actor,decision,reason,result);
            }else {
                if(!PluginSettings.BEHAVIOUR_PROMOTION_ENABLED.get(settings))
                    throw new OpenSearchStatusException("Behaviour promotion disabled",RestStatus.FORBIDDEN);
                service.promote(id,rev,actor,result);
            }
        }catch(IllegalArgumentException|java.io.IOException e){listener.onFailure(bad());}
        catch(Exception e){listener.onFailure(e);}
    }
    private static OpenSearchStatusException bad(){return new OpenSearchStatusException("Invalid observation command",RestStatus.BAD_REQUEST);}
    public static final class Publish extends TransportBehaviourObservationAction{
        @Inject public Publish(TransportService t,ActionFilters f,BehaviourObservationService s,ThreadPool p,ClusterService c){super("publish",BehaviourObservationAction.PUBLISH_NAME,t,f,s,p,c);}
    }
    public static final class Read extends TransportBehaviourObservationAction{
        @Inject public Read(TransportService t,ActionFilters f,BehaviourObservationService s,ThreadPool p,ClusterService c){super("day",BehaviourObservationAction.READ_NAME,t,f,s,p,c);}
    }
    public static final class Review extends TransportBehaviourObservationAction{
        @Inject public Review(TransportService t,ActionFilters f,BehaviourObservationService s,ThreadPool p,ClusterService c){super("review",BehaviourObservationAction.REVIEW_NAME,t,f,s,p,c);}
    }
    public static final class Promote extends TransportBehaviourObservationAction{
        @Inject public Promote(TransportService t,ActionFilters f,BehaviourObservationService s,ThreadPool p,ClusterService c){super("promote",BehaviourObservationAction.PROMOTE_NAME,t,f,s,p,c);}
    }
}
