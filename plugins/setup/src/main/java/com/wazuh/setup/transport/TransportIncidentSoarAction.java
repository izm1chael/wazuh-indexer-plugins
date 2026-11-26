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
import com.wazuh.setup.action.IncidentSoarAction;
import com.wazuh.setup.action.IncidentSoarRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IncidentSoarService;
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
import java.util.HashSet;
import java.util.UUID;

public final class TransportIncidentSoarAction extends HandledTransportAction<IncidentSoarRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final IncidentSoarService service;
    private final ThreadPool pool;
    private final ClusterService cluster;
    @Inject public TransportIncidentSoarAction(TransportService transport, ActionFilters filters, IncidentSoarService service, ThreadPool pool, ClusterService cluster) {
        super(IncidentSoarAction.DISPATCH_NAME, transport, filters, IncidentSoarRequest::new);
        this.service = service; this.pool = pool; this.cluster = cluster;
    }
    @Override protected void doExecute(Task task, IncidentSoarRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            var settings = cluster.getSettings();
            if (!PluginSettings.INCIDENTS_ENABLED.get(settings) || !PluginSettings.SOAR_ENABLED.get(settings)) throw forbidden();
            String actor = IncidentPrincipal.require(pool.getThreadContext());
            if (!actor.equals(PluginSettings.SOAR_ACTOR.get(settings))) throw forbidden();
            String manager = uuid(PluginSettings.SOAR_MANAGER.get(settings)).toString();
            Set<String> agents = targets(PluginSettings.SOAR_AGENTS.get(settings));
            Map<?, ?> body;
            try { body = JSON.readValue(request.payload(), Map.class); } catch (Exception e) { throw invalid(); }
            if (body == null || !body.keySet().equals(Set.of("incident_id", "expected_revision", "response_id", "manager_id", "scope", "outcome")) ||
                    !manager.equals(body.get("manager_id")) || !(body.get("expected_revision") instanceof Integer revision) || revision < 1 ||
                    !(body.get("response_id") instanceof String response) || !(body.get("scope") instanceof String scope) || !agents.stream().anyMatch(agent -> scope.equals(manager + ":agent:" + agent))) throw invalid();
            UUID id = uuid(body.get("incident_id"));
            if (!response.startsWith(id + ":") || !response.substring(37).matches("[1-9][0-9]{0,9}")) throw invalid();
            Object outcome = body.get("outcome");
            if (outcome != null && !Set.of("manager_accepted", "dispatch_unknown").contains(outcome)) throw invalid();
            service.dispatch(id, revision, response, scope, actor, manager, agents, (String) outcome,
                    ActionListener.wrap(result -> listener.onResponse(new IncidentReadResponse(result)), listener::onFailure));
        } catch (Exception e) { listener.onFailure(e); }
    }
    static Set<String> targets(String configured) {
        if (configured == null || configured.length() > 1024) throw forbidden();
        var result = new HashSet<String>();
        for (String item : configured.split(",", -1)) {
            if (!item.matches("[0-9]{3,8}") || item.matches("0+") || !result.add(item) || result.size() > 50) throw forbidden();
        }
        return Set.copyOf(result);
    }
    private static UUID uuid(Object value) {
        try { if (!(value instanceof String s)) throw invalid(); UUID id = UUID.fromString(s); if (!id.toString().equals(s)) throw invalid(); return id; }
        catch (RuntimeException e) { throw invalid(); }
    }
    private static OpenSearchStatusException invalid() { return new OpenSearchStatusException("Invalid SOAR dispatch request", RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException forbidden() { return new OpenSearchStatusException("SOAR disabled or principal/target not approved", RestStatus.FORBIDDEN); }
}
