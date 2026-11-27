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
import com.wazuh.setup.action.IndicatorCatalogAction;
import com.wazuh.setup.action.IndicatorCatalogRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IndicatorCatalogStore;
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
import java.util.List;
import java.util.Set;

public abstract class TransportIndicatorCatalogAction extends HandledTransportAction<IndicatorCatalogRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final boolean write;
    private final IndicatorCatalogStore store;
    private final ThreadPool pool;
    private final ClusterService cluster;
    protected TransportIndicatorCatalogAction(boolean write, TransportService transport, ActionFilters filters,
            IndicatorCatalogStore store, ThreadPool pool, ClusterService cluster) {
        super(write ? IndicatorCatalogAction.SAVE_NAME : IndicatorCatalogAction.READ_NAME, transport, filters, IndicatorCatalogRequest::new);
        this.write = write; this.store = store; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IndicatorCatalogRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings())) throw new OpenSearchStatusException("Incidents disabled", RestStatus.FORBIDDEN);
            String actor = IncidentPrincipal.require(pool.getThreadContext());
            Map<?, ?> body;
            try { body = JSON.readValue(request.payload(), Map.class); }
            catch (Exception e) { throw invalid(); }
            if (body == null) throw invalid();
            ActionListener<Map<String, Object>> result = ActionListener.wrap(value -> listener.onResponse(new IncidentReadResponse(value)), listener::onFailure);
            if (!write) {
                if (!body.isEmpty()) throw invalid();
                store.read(result); return;
            }
            if (!(body.get("expected_revision") instanceof Integer revision) || revision < 0) throw invalid();
            if ("add".equals(body.get("operation")) && body.keySet().equals(Set.of("operation", "expected_revision", "indicators"))
                    && body.get("indicators") instanceof List<?> entries) {
                store.add(revision, entries, actor, result);
            } else if ("revoke".equals(body.get("operation")) && body.keySet().equals(Set.of("operation", "expected_revision", "id", "reason"))
                    && body.get("id") instanceof String id && body.get("reason") instanceof String reason) {
                store.revoke(revision, id, reason, actor, result);
            } else if ("record-sighting".equals(body.get("operation")) && body.keySet().equals(Set.of("operation", "expected_revision", "id", "observed_at", "source", "count"))
                    && body.get("id") instanceof String id && body.get("observed_at") instanceof String observed &&
                    body.get("source") instanceof String source && body.get("count") instanceof Integer count) {
                store.sight(revision, id, observed, source, count, actor, result);
            } else if ("withdraw-sighting".equals(body.get("operation")) && body.keySet().equals(Set.of("operation", "expected_revision", "id", "sighting_revision", "reason"))
                    && body.get("id") instanceof String id && body.get("sighting_revision") instanceof Integer sightingRevision && body.get("reason") instanceof String reason) {
                store.withdrawSighting(revision, id, sightingRevision, reason, actor, result);
            } else throw invalid();
        } catch (Exception e) { listener.onFailure(e); }
    }

    private static OpenSearchStatusException invalid() { return new OpenSearchStatusException("Invalid indicator catalog request", RestStatus.BAD_REQUEST); }
    public static final class Read extends TransportIndicatorCatalogAction {
        @Inject public Read(TransportService transport, ActionFilters filters, IndicatorCatalogStore store, ThreadPool pool, ClusterService cluster) {
            super(false, transport, filters, store, pool, cluster);
        }
    }
    public static final class Save extends TransportIndicatorCatalogAction {
        @Inject public Save(TransportService transport, ActionFilters filters, IndicatorCatalogStore store, ThreadPool pool, ClusterService cluster) {
            super(true, transport, filters, store, pool, cluster);
        }
    }
}
