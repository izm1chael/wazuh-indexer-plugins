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
package com.wazuh.setup.incident;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Immutable policy versions. Saving a policy never enables execution. */
public final class CorrelationPolicyStore {
    public static final String INDEX = ".wazuh-correlation-policies-v1";
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;

    public CorrelationPolicyStore(Client client, ThreadPool pool, Clock clock) {
        this.client = client; this.pool = pool; this.clock = clock;
    }

    static Map<String, Object> definition(CorrelationPlanner.Policy policy) {
        return Map.of("policy_id", policy.id().toString(), "policy_version", policy.version(),
                "rules", policy.allowedRules().stream().map(UUID::toString).sorted().toList(),
                "window_minutes", policy.windowMinutes(), "minimum_findings", policy.minimumFindings(),
                "mode", "preview_only");
    }

    public void save(CorrelationPlanner.Policy policy, String actor, ActionListener<Map<String, Object>> listener) {
        String id = policy.id() + ":" + policy.version();
        Map<String, Object> source = new LinkedHashMap<>(definition(policy));
        source.put("created_by", actor);
        source.put("created_at", clock.instant().toString());
        IndexRequest request = new IndexRequest(INDEX).id(id).opType(DocWriteRequest.OpType.CREATE)
                .source(source, XContentType.JSON).setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.wrap(response -> listener.onResponse(Map.of("policy", source, "replayed", false)), error -> {
                if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) { listener.onFailure(error); return; }
                get(policy.id(), policy.version(), ActionListener.wrap(existing -> {
                    var expected = definition(policy);
                    var actual = new LinkedHashMap<String, Object>();
                    expected.keySet().forEach(key -> actual.put(key, existing.get(key)));
                    if (!IncidentRepository.sameEvent(expected, actual)) {
                        listener.onFailure(new OpenSearchStatusException("Policy version already exists with different content", RestStatus.CONFLICT));
                    } else {
                        listener.onResponse(Map.of("policy", existing, "replayed", true));
                    }
                }, listener::onFailure));
            }));
        }
    }

    public void get(UUID id, int version, ActionListener<Map<String, Object>> listener) {
        if (version < 1) throw new IllegalArgumentException("Positive policy version required");
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INDEX, id + ":" + version), ActionListener.wrap(response -> {
                if (!response.isExists()) {
                    listener.onFailure(new OpenSearchStatusException("Correlation policy version not found", RestStatus.NOT_FOUND)); return;
                }
                Map<String, Object> source = response.getSourceAsMap();
                if (!id.toString().equals(source.get("policy_id")) || !Integer.valueOf(version).equals(source.get("policy_version")) ||
                        !"preview_only".equals(source.get("mode"))) throw new IllegalStateException("Invalid stored policy");
                Map<String, Object> result = new LinkedHashMap<>();
                for (String field : java.util.Set.of("policy_id", "policy_version", "rules", "window_minutes",
                        "minimum_findings", "mode", "created_by", "created_at")) result.put(field, source.get(field));
                listener.onResponse(result);
            }, listener::onFailure));
        }
    }
}
