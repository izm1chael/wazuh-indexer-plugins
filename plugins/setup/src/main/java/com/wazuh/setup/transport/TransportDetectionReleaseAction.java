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
import com.wazuh.setup.action.DetectionReleaseAction;
import com.wazuh.setup.action.IncidentHuntRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.DetectionRelease;
import com.wazuh.setup.incident.DetectionReleaseService;
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
import java.util.Map;
import java.util.Set;

public abstract class TransportDetectionReleaseAction extends HandledTransportAction<IncidentHuntRequest,IncidentReadResponse>{
    private static final ObjectMapper JSON=new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final String operation;
    private final DetectionReleaseService service;
    private final ThreadPool pool;
    private final ClusterService cluster;
    protected TransportDetectionReleaseAction(String operation,String name,TransportService transport,ActionFilters filters,
            DetectionReleaseService service,ThreadPool pool,ClusterService cluster){
        super(name,transport,filters,IncidentHuntRequest::new);this.operation=operation;this.service=service;this.pool=pool;this.cluster=cluster;
    }
    @Override protected void doExecute(Task task,IncidentHuntRequest request,ActionListener<IncidentReadResponse> listener){
        try{
            if(!PluginSettings.DETECTION_RELEASES_ENABLED.get(cluster.getSettings()))
                throw new OpenSearchStatusException("Detection release ledger disabled",RestStatus.FORBIDDEN);
            String actor=IncidentPrincipal.require(pool.getThreadContext());
            ActionListener<Map<String,Object>> result=ActionListener.wrap(value->listener.onResponse(new IncidentReadResponse(value)),listener::onFailure);
            Map<?,?> raw=JSON.readValue(request.payload(),Map.class);
            switch(operation){
                case "submit" -> {
                    var body=DetectionRelease.exact(raw,Set.of("id","evidence"));
                    service.submit(DetectionRelease.hash(body.get("id")),body.get("evidence"),actor,result);
                }
                case "read" -> {
                    var body=DetectionRelease.exact(raw,Set.of("id"));
                    service.read(DetectionRelease.hash(body.get("id")),actor,result);
                }
                case "day" -> {
                    var body=DetectionRelease.exact(raw,Set.of("day"));
                    service.day(DetectionRelease.instant(body.get("day")),actor,result);
                }
                case "review" -> {
                    var body=DetectionRelease.exact(raw,Set.of("id","expected_revision","pack_sha256","decision","reason","deployer","expires"));
                    if(!Integer.valueOf(1).equals(body.get("expected_revision")))throw new IllegalArgumentException();
                    service.review(DetectionRelease.hash(body.get("id")),actor,DetectionRelease.hash(body.get("pack_sha256")),
                            DetectionRelease.text(body.get("decision"),16),DetectionRelease.text(body.get("reason"),1024),
                            body.get("deployer"),body.get("expires"),result);
                }
                default -> throw new IllegalArgumentException();
            }
        }catch(IllegalArgumentException|java.io.IOException e){listener.onFailure(new OpenSearchStatusException("Invalid release command",RestStatus.BAD_REQUEST));}
        catch(Exception e){listener.onFailure(e);}
    }
    public static final class Submit extends TransportDetectionReleaseAction{
        @Inject public Submit(TransportService t,ActionFilters f,DetectionReleaseService s,ThreadPool p,ClusterService c){super("submit",DetectionReleaseAction.SUBMIT_NAME,t,f,s,p,c);}
    }
    public static final class Read extends TransportDetectionReleaseAction{
        @Inject public Read(TransportService t,ActionFilters f,DetectionReleaseService s,ThreadPool p,ClusterService c){super("read",DetectionReleaseAction.READ_NAME,t,f,s,p,c);}
    }
    public static final class Day extends TransportDetectionReleaseAction{
        @Inject public Day(TransportService t,ActionFilters f,DetectionReleaseService s,ThreadPool p,ClusterService c){super("day",DetectionReleaseAction.DAY_NAME,t,f,s,p,c);}
    }
    public static final class Review extends TransportDetectionReleaseAction{
        @Inject public Review(TransportService t,ActionFilters f,DetectionReleaseService s,ThreadPool p,ClusterService c){super("review",DetectionReleaseAction.REVIEW_NAME,t,f,s,p,c);}
    }
}
