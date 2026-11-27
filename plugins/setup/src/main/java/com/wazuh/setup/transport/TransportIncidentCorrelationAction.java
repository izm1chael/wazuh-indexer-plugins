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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.setup.action.IncidentCorrelationAction;
import com.wazuh.setup.action.IncidentCorrelationRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.CorrelationPlanner;
import com.wazuh.setup.incident.CorrelationPreviewService;
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

import java.io.IOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public final class TransportIncidentCorrelationAction extends HandledTransportAction<IncidentCorrelationRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final CorrelationPreviewService service;
    private final ThreadPool pool;
    private final ClusterService cluster;

    @Inject
    public TransportIncidentCorrelationAction(TransportService transport, ActionFilters filters,
            CorrelationPreviewService service, ThreadPool pool, ClusterService cluster) {
        super(IncidentCorrelationAction.NAME, transport, filters, IncidentCorrelationRequest::new);
        this.service = service; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IncidentCorrelationRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings())) {
                throw new OpenSearchStatusException("Experimental incidents are disabled", RestStatus.FORBIDDEN);
            }
            IncidentPrincipal.require(pool.getThreadContext());
            CorrelationPreviewService.Input input = parse(request.payload());
            service.preview(input, ActionListener.wrap(value -> listener.onResponse(new IncidentReadResponse(value)), listener::onFailure));
        } catch (Exception e) { listener.onFailure(e); }
    }

    public static CorrelationPreviewService.Input parse(String payload) {
        try {
            JsonNode node = JSON.readTree(payload);
            if (node == null || !node.isObject() || node.size() != 7 ||
                    !node.has("policy_id") || !node.has("policy_version") || !node.has("rules") ||
                    !node.has("window_minutes") || !node.has("minimum_findings") || !node.has("from") || !node.has("until")) {
                throw new IllegalArgumentException();
            }
            JsonNode rules = node.get("rules");
            if (!rules.isArray() || rules.isEmpty() || rules.size() > 100) throw new IllegalArgumentException();
            Set<UUID> ids = new HashSet<>();
            for (JsonNode rule : rules) if (!ids.add(uuid(rule))) throw new IllegalArgumentException();
            var policy = new CorrelationPlanner.Policy(uuid(node.get("policy_id")), integer(node.get("policy_version")),
                    ids, integer(node.get("window_minutes")), integer(node.get("minimum_findings")));
            return new CorrelationPreviewService.Input(policy, Instant.parse(string(node.get("from"))), Instant.parse(string(node.get("until"))));
        } catch (IOException | RuntimeException e) {
            throw new OpenSearchStatusException("Invalid bounded correlation preview parameters", RestStatus.BAD_REQUEST);
        }
    }
    private static String string(JsonNode node) {
        if (node == null || !node.isTextual()) throw new IllegalArgumentException();
        return node.textValue();
    }
    private static UUID uuid(JsonNode node) {
        String value = string(node);
        UUID id = UUID.fromString(value);
        if (!id.toString().equals(value)) throw new IllegalArgumentException();
        return id;
    }
    private static int integer(JsonNode node) {
        if (node == null || !node.isIntegralNumber() || !node.canConvertToInt()) throw new IllegalArgumentException();
        return node.intValue();
    }
}
