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
import com.wazuh.setup.action.AnalyticsRunAction;
import com.wazuh.setup.action.AnalyticsRunRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.AnalyticsExecutionService;
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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public abstract class TransportAnalyticsRunAction extends HandledTransportAction<AnalyticsRunRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final boolean execute;
    private final AnalyticsExecutionService service;
    private final ThreadPool pool;
    private final ClusterService cluster;

    protected TransportAnalyticsRunAction(boolean execute, TransportService transport, ActionFilters filters,
            AnalyticsExecutionService service, ThreadPool pool, ClusterService cluster) {
        super(execute ? AnalyticsRunAction.EXECUTE_NAME : AnalyticsRunAction.READ_NAME, transport, filters, AnalyticsRunRequest::new);
        this.execute = execute; this.service = service; this.pool = pool; this.cluster = cluster;
    }

    public record Window(UUID policy, int version, Instant from, Instant until) {}

    @Override protected void doExecute(Task task, AnalyticsRunRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            var settings = cluster.getSettings();
            if (!PluginSettings.INCIDENTS_ENABLED.get(settings) || !PluginSettings.ANALYTICS_ENABLED.get(settings)) throw forbidden();
            String actor = IncidentPrincipal.require(pool.getThreadContext());
            UUID deployment;
            try { deployment = uuid(PluginSettings.ANALYTICS_DEPLOYMENT.get(settings)); } catch (RuntimeException e) { throw forbidden(); }
            Window input = parse(request.payload());
            ActionListener<Map<String, Object>> result = ActionListener.wrap(body -> listener.onResponse(new IncidentReadResponse(body)), listener::onFailure);
            if (execute) {
                authorize(actor, PluginSettings.ANALYTICS_ACTOR.get(settings), PluginSettings.ANALYTICS_POLICIES.get(settings), input);
                service.execute(deployment, input.policy(), input.version(), input.from(), input.until(), actor, result);
            } else service.status(deployment, input.policy(), input.version(), input.from(), input.until(), result);
        } catch (Exception e) { listener.onFailure(e); }
    }

    public static void authorize(String actor, String configured, String approved, Window window) {
        if (configured == null || configured.isBlank() || configured.length() > 1024 ||
                !configured.equals(configured.trim()) || !configured.equals(actor) || approved == null || approved.length() > 2048) throw forbidden();
        var policies = new HashSet<String>();
        for (String entry : approved.split(",", -1)) {
            String[] parts = entry.split(":", -1);
            try {
                if (parts.length != 2 || !parts[1].matches("[1-9][0-9]{0,9}")) throw new IllegalArgumentException();
                uuid(parts[0]); int version = Integer.parseInt(parts[1]);
                if (!policies.add(parts[0] + ":" + version) || policies.size() > 20) throw new IllegalArgumentException();
            } catch (RuntimeException e) { throw forbidden(); }
        }
        if (!policies.contains(window.policy() + ":" + window.version())) throw forbidden();
    }

    public static Window parse(String payload) {
        try {
            Map<?, ?> body = JSON.readValue(payload, Map.class);
            if (body == null || !body.keySet().equals(Set.of("policy_id", "policy_version", "from", "until")) ||
                    !(body.get("policy_id") instanceof String id) || !(body.get("policy_version") instanceof Integer version) || version < 1 ||
                    !(body.get("from") instanceof String start) || !(body.get("until") instanceof String end) ||
                    !start.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z") ||
                    !end.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")) throw new IllegalArgumentException();
            Instant from = Instant.parse(start), until = Instant.parse(end);
            if (!from.toString().equals(start) || !until.toString().equals(end) || !from.isBefore(until) ||
                    until.isAfter(from.plusSeconds(86400)) || from.isBefore(Instant.parse("2000-01-01T00:00:00Z")) ||
                    until.isAfter(Instant.parse("2100-01-01T00:00:00Z"))) throw new IllegalArgumentException();
            return new Window(uuid(id), version, from, until);
        } catch (Exception e) { throw new OpenSearchStatusException("Invalid analytics window request", RestStatus.BAD_REQUEST); }
    }

    private static UUID uuid(String value) {
        UUID id = UUID.fromString(value);
        if (!id.toString().equals(value)) throw new IllegalArgumentException();
        return id;
    }
    private static OpenSearchStatusException forbidden() { return new OpenSearchStatusException("Analytics disabled or principal/policy not approved", RestStatus.FORBIDDEN); }

    public static final class Read extends TransportAnalyticsRunAction {
        @Inject public Read(TransportService transport, ActionFilters filters, AnalyticsExecutionService service, ThreadPool pool, ClusterService cluster) {
            super(false, transport, filters, service, pool, cluster);
        }
    }
    public static final class Execute extends TransportAnalyticsRunAction {
        @Inject public Execute(TransportService transport, ActionFilters filters, AnalyticsExecutionService service, ThreadPool pool, ClusterService cluster) {
            super(true, transport, filters, service, pool, cluster);
        }
    }
}
