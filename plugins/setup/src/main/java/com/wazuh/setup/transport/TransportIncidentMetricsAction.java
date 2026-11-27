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
import com.wazuh.setup.action.IncidentMetricsAction;
import com.wazuh.setup.action.IncidentCorrelationRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IncidentMetrics;
import com.wazuh.setup.incident.IncidentMetricsService;
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

public final class TransportIncidentMetricsAction extends HandledTransportAction<IncidentCorrelationRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final IncidentMetricsService service;
    private final ThreadPool pool;
    private final ClusterService cluster;

    @Inject public TransportIncidentMetricsAction(TransportService transport, ActionFilters filters,
            IncidentMetricsService service, ThreadPool pool, ClusterService cluster) {
        super(IncidentMetricsAction.NAME, transport, filters, IncidentCorrelationRequest::new);
        this.service = service; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IncidentCorrelationRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings())) throw new OpenSearchStatusException("Incidents disabled", RestStatus.FORBIDDEN);
            IncidentPrincipal.require(pool.getThreadContext());
            service.report(parse(request.payload()), ActionListener.wrap(body -> listener.onResponse(new IncidentReadResponse(body)), listener::onFailure));
        } catch (Exception e) { listener.onFailure(e); }
    }

    public static IncidentMetrics.Query parse(String payload) {
        try {
            JsonNode node = JSON.readTree(payload);
            if (node == null || !node.isObject() || node.size() != 4 ||
                    !node.has("from") || !node.has("until") || !node.has("triage_target_seconds") ||
                    !node.has("resolution_target_seconds")) throw new IllegalArgumentException();
            return new IncidentMetrics.Query(instant(node.get("from")), instant(node.get("until")),
                    integer(node.get("triage_target_seconds")), integer(node.get("resolution_target_seconds")));
        } catch (Exception e) {
            throw new OpenSearchStatusException("Invalid metrics request", RestStatus.BAD_REQUEST);
        }
    }
    private static Instant instant(JsonNode value) {
        if (value == null || !value.isTextual()) throw new IllegalArgumentException();
        return Instant.parse(value.textValue());
    }
    private static int integer(JsonNode value) {
        if (value == null || !value.isIntegralNumber() || !value.canConvertToInt()) throw new IllegalArgumentException();
        return value.intValue();
    }
}
