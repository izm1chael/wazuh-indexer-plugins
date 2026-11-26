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
import com.wazuh.setup.action.CorrelationPolicyAction;
import com.wazuh.setup.action.IncidentCorrelationRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.CorrelationPlanner;
import com.wazuh.setup.incident.CorrelationPolicyStore;
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
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;

public abstract class TransportCorrelationPolicyAction extends HandledTransportAction<IncidentCorrelationRequest, IncidentReadResponse> {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final boolean save;
    private final CorrelationPolicyStore store;
    private final ThreadPool pool;
    private final ClusterService cluster;
    protected TransportCorrelationPolicyAction(boolean save, TransportService transport, ActionFilters filters,
            CorrelationPolicyStore store, ThreadPool pool, ClusterService cluster) {
        super(save ? CorrelationPolicyAction.SAVE_NAME : CorrelationPolicyAction.READ_NAME, transport, filters, IncidentCorrelationRequest::new);
        this.save = save; this.store = store; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IncidentCorrelationRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings())) throw new OpenSearchStatusException("Incidents disabled", RestStatus.FORBIDDEN);
            String actor = IncidentPrincipal.require(pool.getThreadContext());
            JsonNode node;
            try { node = JSON.readTree(request.payload()); }
            catch (Exception e) { throw invalid(); }
            ActionListener<Map<String, Object>> result = ActionListener.wrap(body -> listener.onResponse(new IncidentReadResponse(body)), listener::onFailure);
            if (save) store.save(parsePolicy(node), actor, result);
            else {
                if (node == null || !node.isObject() || node.size() != 2 || !node.has("policy_id") || !node.has("policy_version")) throw invalid();
                store.get(uuid(node.get("policy_id")), integer(node.get("policy_version")), ActionListener.wrap(policy -> result.onResponse(Map.of("policy", policy)), result::onFailure));
            }
        } catch (Exception e) { listener.onFailure(e); }
    }

    public static CorrelationPlanner.Policy parsePolicy(JsonNode node) {
        if (node == null || !node.isObject() || node.size() != 5 || !node.has("policy_id") || !node.has("policy_version") ||
                !node.has("rules") || !node.has("window_minutes") || !node.has("minimum_findings")) throw invalid();
        var rules = node.get("rules");
        if (!rules.isArray() || rules.isEmpty() || rules.size() > 100) throw invalid();
        var ids = new HashSet<UUID>();
        for (var rule : rules) if (!ids.add(uuid(rule))) throw invalid();
        try { return new CorrelationPlanner.Policy(uuid(node.get("policy_id")), integer(node.get("policy_version")), ids,
                    integer(node.get("window_minutes")), integer(node.get("minimum_findings"))); }
        catch (IllegalArgumentException e) { throw invalid(); }
    }
    private static UUID uuid(JsonNode node) {
        if (node == null || !node.isTextual()) throw invalid();
        try { UUID id = UUID.fromString(node.textValue()); if (!id.toString().equals(node.textValue())) throw invalid(); return id; }
        catch (IllegalArgumentException e) { throw invalid(); }
    }
    private static int integer(JsonNode node) {
        if (node == null || !node.isIntegralNumber() || !node.canConvertToInt() || node.intValue() < 1) throw invalid();
        return node.intValue();
    }
    private static OpenSearchStatusException invalid() { return new OpenSearchStatusException("Invalid correlation policy", RestStatus.BAD_REQUEST); }

    public static final class Read extends TransportCorrelationPolicyAction {
        @Inject public Read(TransportService transport, ActionFilters filters, CorrelationPolicyStore store, ThreadPool pool, ClusterService cluster) {
            super(false, transport, filters, store, pool, cluster);
        }
    }
    public static final class Save extends TransportCorrelationPolicyAction {
        @Inject public Save(TransportService transport, ActionFilters filters, CorrelationPolicyStore store, ThreadPool pool, ClusterService cluster) {
            super(true, transport, filters, store, pool, cluster);
        }
    }
}
