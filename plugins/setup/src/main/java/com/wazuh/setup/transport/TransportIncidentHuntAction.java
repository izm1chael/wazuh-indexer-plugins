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
import com.wazuh.setup.action.IncidentHuntAction;
import com.wazuh.setup.action.IncidentHuntRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IncidentHuntService;
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
import java.util.ArrayList;
import java.util.List;

public final class TransportIncidentHuntAction extends HandledTransportAction<IncidentHuntRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final IncidentHuntService service;
    private final ThreadPool pool;
    private final ClusterService cluster;

    @Inject
    public TransportIncidentHuntAction(TransportService transport, ActionFilters filters,
            IncidentHuntService service, ThreadPool pool, ClusterService cluster) {
        super(IncidentHuntAction.NAME, transport, filters, IncidentHuntRequest::new);
        this.service = service; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IncidentHuntRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings())) {
                throw new OpenSearchStatusException("Experimental incidents are disabled", RestStatus.FORBIDDEN);
            }
            IncidentPrincipal.require(pool.getThreadContext());
            IncidentHuntService.Input input = parse(request.payload());
            service.hunt(input, ActionListener.wrap(value -> listener.onResponse(new IncidentReadResponse(value)), listener::onFailure));
        } catch (Exception e) { listener.onFailure(e); }
    }

    public static IncidentHuntService.Input parse(String payload) {
        try {
            JsonNode node = JSON.readTree(payload);
            if (node == null || !node.isObject() || node.size() != 4 ||
                    !node.has("field") || !node.has("values") || !node.has("from") || !node.has("until")) {
                throw new IllegalArgumentException();
            }
            JsonNode values = node.get("values");
            if (!values.isArray() || values.isEmpty() || values.size() > 20) throw new IllegalArgumentException();
            List<String> terms = new ArrayList<>();
            for (JsonNode value : values) terms.add(string(value));
            return new IncidentHuntService.Input(string(node.get("field")), terms,
                    Instant.parse(string(node.get("from"))), Instant.parse(string(node.get("until"))));
        } catch (IOException | RuntimeException e) {
            throw new OpenSearchStatusException("Invalid bounded hunt parameters", RestStatus.BAD_REQUEST);
        }
    }
    private static String string(JsonNode node) {
        if (node == null || !node.isTextual()) throw new IllegalArgumentException();
        return node.textValue();
    }
}
