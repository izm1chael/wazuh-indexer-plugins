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
import com.wazuh.setup.action.IncidentAutomationAction;
import com.wazuh.setup.action.IncidentAutomationRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IncidentAutomationPolicy;
import com.wazuh.setup.incident.IncidentAutomationStore;
import com.wazuh.setup.incident.IncidentAutomationService;
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
import java.util.UUID;

public abstract class TransportIncidentAutomationAction extends HandledTransportAction<IncidentAutomationRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final String action;
    private final IncidentAutomationStore store;
    private final IncidentAutomationService service;
    private final ThreadPool pool;
    private final ClusterService cluster;
    protected TransportIncidentAutomationAction(String action, TransportService transport, ActionFilters filters,
            IncidentAutomationStore store, IncidentAutomationService service, ThreadPool pool, ClusterService cluster) {
        super(action, transport, filters, IncidentAutomationRequest::new);
        this.action = action; this.store = store; this.service = service; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IncidentAutomationRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            var settings = cluster.getSettings();
            if (!PluginSettings.INCIDENTS_ENABLED.get(settings)) throw forbidden();
            String actor = IncidentPrincipal.require(pool.getThreadContext());
            Map<?, ?> body = parse(request.payload());
            ActionListener<Map<String, Object>> result = ActionListener.wrap(value -> listener.onResponse(new IncidentReadResponse(value)), listener::onFailure);
            if (IncidentAutomationAction.SAVE_NAME.equals(action)) {
                store.save(IncidentAutomationPolicy.parse(body), actor, result); return;
            }
            if (IncidentAutomationAction.EXECUTE_NAME.equals(action)) {
                if (!PluginSettings.AUTOMATION_ENABLED.get(settings)) throw forbidden();
                exact(body, Set.of("policy_id", "policy_version", "fingerprint", "after"));
                UUID policy = uuid(body.get("policy_id")); int version = version(body);
                String hash = authorize(actor, PluginSettings.AUTOMATION_ACTOR.get(settings), PluginSettings.AUTOMATION_POLICY.get(settings), policy, version);
                if (!hash.equals(body.get("fingerprint"))) throw forbidden();
                UUID after = body.get("after") == null ? null : uuid(body.get("after"));
                service.tick(policy, version, hash, after, actor, result); return;
            }
            if ("policy".equals(body.get("operation"))) {
                exact(body, Set.of("operation", "policy_id", "policy_version"));
                store.read(uuid(body.get("policy_id")), version(body), result);
            } else if ("preview".equals(body.get("operation"))) {
                exact(body, Set.of("operation", "policy_id", "policy_version", "incident_id"));
                service.preview(uuid(body.get("policy_id")), version(body), uuid(body.get("incident_id")), actor, result);
            } else if ("history".equals(body.get("operation"))) {
                exact(body, Set.of("operation", "incident_id"));
                service.history(uuid(body.get("incident_id")), result);
            } else throw invalid();
        } catch (Exception e) { listener.onFailure(e); }
    }

    public static Map<?, ?> parse(String payload) {
        try {
            Map<?, ?> body = JSON.readValue(payload, Map.class);
            if (body == null) throw invalid();
            return body;
        } catch (Exception e) { throw invalid(); }
    }
    public static String authorize(String actor, String configured, String approval, UUID policy, int version) {
        if (actor == null || configured == null || configured.isBlank() || !configured.equals(actor) ||
                approval == null || !approval.matches("[a-f0-9-]{36}:[1-9][0-9]{0,9}:[a-f0-9]{64}")) throw forbidden();
        String prefix = policy + ":" + version + ":";
        if (!approval.startsWith(prefix)) throw forbidden();
        return approval.substring(prefix.length());
    }
    private static int version(Map<?, ?> body) {
        if (!(body.get("policy_version") instanceof Integer n) || n < 1) throw invalid();
        return n;
    }
    private static UUID uuid(Object value) {
        if (!(value instanceof String s)) throw invalid();
        try { UUID id = UUID.fromString(s); if (!id.toString().equals(s)) throw invalid(); return id; }
        catch (RuntimeException e) { throw invalid(); }
    }
    private static void exact(Map<?, ?> body, Set<String> fields) { if (!body.keySet().equals(fields)) throw invalid(); }
    private static OpenSearchStatusException invalid() { return new OpenSearchStatusException("Invalid automation request", RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException forbidden() { return new OpenSearchStatusException("Automation disabled or approval unavailable", RestStatus.FORBIDDEN); }

    public static final class Read extends TransportIncidentAutomationAction {
        @Inject public Read(TransportService transport, ActionFilters filters, IncidentAutomationStore store, IncidentAutomationService service, ThreadPool pool, ClusterService cluster) {
            super(IncidentAutomationAction.READ_NAME, transport, filters, store, service, pool, cluster);
        }
    }
    public static final class Save extends TransportIncidentAutomationAction {
        @Inject public Save(TransportService transport, ActionFilters filters, IncidentAutomationStore store, IncidentAutomationService service, ThreadPool pool, ClusterService cluster) {
            super(IncidentAutomationAction.SAVE_NAME, transport, filters, store, service, pool, cluster);
        }
    }
    public static final class Execute extends TransportIncidentAutomationAction {
        @Inject public Execute(TransportService transport, ActionFilters filters, IncidentAutomationStore store, IncidentAutomationService service, ThreadPool pool, ClusterService cluster) {
            super(IncidentAutomationAction.EXECUTE_NAME, transport, filters, store, service, pool, cluster);
        }
    }
}
