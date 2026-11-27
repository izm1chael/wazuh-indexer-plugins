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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class IncidentAutomationStore {
    public static final String INDEX = ".wazuh-incident-automation-v1";
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;
    record Saved(IncidentAutomationPolicy.Policy policy, String actor, String at) {
        Map<String, Object> project() {
            return Map.of("policy", policy.definition(), "fingerprint", policy.fingerprint(), "created_by", actor, "created_at", at);
        }
    }

    public IncidentAutomationStore(Client client, ThreadPool pool, Clock clock) { this.client = client; this.pool = pool; this.clock = clock; }

    public void save(IncidentAutomationPolicy.Policy policy, String actor, ActionListener<Map<String, Object>> listener) {
        var saved = new Saved(policy, actor, clock.instant().toString());
        String id = policy.id() + ":" + policy.version();
        var request = new IndexRequest(INDEX).id(id).opType(DocWriteRequest.OpType.CREATE).source(saved.project(), XContentType.JSON)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.wrap(response -> listener.onResponse(Map.of("saved", saved.project(), "replayed", false)), error -> {
                if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) { listener.onFailure(error); return; }
                get(policy.id(), policy.version(), ActionListener.wrap(existing -> {
                    if (!IncidentRepository.sameEvent(policy.definition(), existing.policy().definition())) throw conflict();
                    listener.onResponse(Map.of("saved", existing.project(), "replayed", true));
                }, listener::onFailure));
            }));
        }
    }

    public void read(UUID id, int version, ActionListener<Map<String, Object>> listener) {
        get(id, version, ActionListener.wrap(saved -> listener.onResponse(saved.project()), listener::onFailure));
    }

    void get(UUID id, int version, ActionListener<Saved> listener) {
        if (version < 1) throw new IllegalArgumentException("Positive policy version required");
        String document = id + ":" + version;
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INDEX, document), ActionListener.wrap(response -> {
                if (!response.isExists()) throw new OpenSearchStatusException("Automation policy not found", RestStatus.NOT_FOUND);
                if (!INDEX.equals(response.getIndex()) || !document.equals(response.getId())) throw conflict();
                Map<String, Object> source = response.getSourceAsMap();
                if (!source.keySet().equals(Set.of("policy", "fingerprint", "created_by", "created_at")) ||
                        !(source.get("policy") instanceof Map<?, ?> body) || !(source.get("created_by") instanceof String actor) ||
                        actor.isBlank() || actor.length() > 1024 || !(source.get("created_at") instanceof String at)) throw conflict();
                Instant.parse(at);
                var policy = IncidentAutomationPolicy.parse(body);
                if (!id.equals(policy.id()) || version != policy.version() || !policy.fingerprint().equals(source.get("fingerprint")) ||
                        !IncidentRepository.sameEvent(policy.definition(), new LinkedHashMap<>((Map<String,Object>)body))) throw conflict();
                listener.onResponse(new Saved(policy, actor, at));
            }, listener::onFailure));
        }
    }
    private static OpenSearchStatusException conflict() { return new OpenSearchStatusException("Automation policy identity or content conflict", RestStatus.CONFLICT); }
}
