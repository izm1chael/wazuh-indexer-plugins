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

import com.wazuh.setup.action.EventBehaviourAction;
import com.wazuh.setup.action.IncidentHuntRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.EventBehaviourService;
import com.wazuh.setup.incident.EventBehaviourModel;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
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

public final class TransportEventBehaviourAction extends HandledTransportAction<IncidentHuntRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON=new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    public static EventBehaviourModel.Input parse(String payload){
        try{
            JsonNode row=JSON.readTree(payload);
            if(row==null||!row.isObject()||row.size()!=6)throw new IllegalArgumentException();
            for(String key:java.util.List.of("mode","cluster","space","dataset","subject","day"))if(!row.has(key)||!row.get(key).isTextual())throw new IllegalArgumentException();
            String rawDay=row.get("day").textValue();
            Instant day=Instant.parse(rawDay);
            if(!day.toString().equals(rawDay))throw new IllegalArgumentException();
            return new EventBehaviourModel.Input(row.get("mode").textValue(),row.get("cluster").textValue(),row.get("space").textValue(),row.get("dataset").textValue(),row.get("subject").textValue(),day);
        }catch(java.io.IOException|RuntimeException e){
            throw new OpenSearchStatusException("Invalid exact event profile parameters",RestStatus.BAD_REQUEST);
        }
    }
    private final EventBehaviourService service;
    private final ThreadPool pool;
    private final ClusterService cluster;
    @Inject public TransportEventBehaviourAction(TransportService transport, ActionFilters filters,
            EventBehaviourService service, ThreadPool pool, ClusterService cluster) {
        super(EventBehaviourAction.NAME, transport, filters, IncidentHuntRequest::new);
        this.service=service; this.pool=pool; this.cluster=cluster;
    }
    @Override protected void doExecute(Task task, IncidentHuntRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings()) || !PluginSettings.BEHAVIOUR_ENABLED.get(cluster.getSettings()) || !PluginSettings.EVENT_BEHAVIOUR_ENABLED.get(cluster.getSettings())) throw new OpenSearchStatusException("Experimental behaviour analytics disabled",RestStatus.FORBIDDEN);
            String actor=IncidentPrincipal.require(pool.getThreadContext());
            service.assess(parse(request.payload()),actor,
                    ActionListener.wrap(value -> listener.onResponse(new IncidentReadResponse(value)),listener::onFailure));
        } catch (Exception e) { listener.onFailure(e); }
    }
}
