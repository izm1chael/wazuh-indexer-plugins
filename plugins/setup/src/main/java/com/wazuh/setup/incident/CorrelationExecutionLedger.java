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

/**
 * Staged internal durable reservation store. No registered caller or scheduler.
 * Reservation is not an exclusive execution lock, and does not claim an incident was created.
 */
final class CorrelationExecutionLedger {
    static final String INDEX = ".wazuh-correlation-execution-v1";
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;

    CorrelationExecutionLedger(Client client, ThreadPool pool, Clock clock) {
        this.client = client; this.pool = pool; this.clock = clock;
    }

    record Result(String reservationId, UUID incidentId, boolean replayed) {}

    static Map<String, Object> immutableFields(UUID deployment, CorrelationPlanner.Group group) {
        var identity = CorrelationExecutionIdentity.reserve(deployment, group);
        return Map.ofEntries(Map.entry("id", identity.id()), Map.entry("incident_id", identity.incidentId().toString()),
                Map.entry("deployment_id", deployment.toString()), Map.entry("group_key", identity.groupKey()),
                Map.entry("policy_id", group.policyId().toString()), Map.entry("policy_version", group.policyVersion()),
                Map.entry("window_start", group.windowStart().toString()), Map.entry("window_end", group.windowEnd().toString()),
                Map.entry("membership_hash", identity.membershipHash()), Map.entry("finding_count", identity.findingCount()),
                Map.entry("state", "reserved"));
    }

    static boolean matches(Map<String, Object> expected, Map<String, Object> existing) {
        if (existing == null) return false;
        var actual = new LinkedHashMap<String, Object>();
        expected.keySet().forEach(key -> actual.put(key, existing.get(key)));
        return IncidentRepository.sameEvent(expected, actual);
    }

    /**
     * Only a future qualified internal coordinator may call this after validating
     * deployment scope, ingestion watermark, policy activation and visibility.
     * Changed membership (including late arrival) is a conflict, not an implicit update.
     */
    void reserve(UUID deployment, CorrelationPlanner.Group group, ActionListener<Result> listener) {
        Map<String, Object> expected = immutableFields(deployment, group);
        String id = (String) expected.get("id");
        UUID incidentId = UUID.fromString((String) expected.get("incident_id"));
        var source = new LinkedHashMap<>(expected);
        source.put("reserved_at", clock.instant().toString());
        IndexRequest request = new IndexRequest(INDEX).id(id).opType(DocWriteRequest.OpType.CREATE)
                .source(source, XContentType.JSON).setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.wrap(response -> listener.onResponse(new Result(id, incidentId, false)), error -> {
                if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) { listener.onFailure(error); return; }
                verify(expected, id, incidentId, listener);
            }));
        }
    }

    /** Read a previously reserved identity; never creates a reservation during reconciliation. */
    void readReservation(UUID deployment, String id, ActionListener<Map<String, Object>> listener) {
        if (deployment == null || id == null || !id.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid reservation ID");
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INDEX, id), ActionListener.wrap(response -> {
                if (!response.isExists()) {
                    listener.onFailure(new OpenSearchStatusException("Reservation not found", RestStatus.NOT_FOUND));
                    return;
                }
                var source = response.getSourceAsMap();
                if (!id.equals(source.get("id")) || !deployment.toString().equals(source.get("deployment_id")) ||
                        !"reserved".equals(source.get("state")) ||
                        !id.equals(CorrelationExecutionIdentity.reservationId(deployment, (String) source.get("group_key"))) ||
                        !CorrelationExecutionIdentity.incidentId(id).toString().equals(source.get("incident_id"))) {
                    listener.onFailure(new OpenSearchStatusException("Reservation identity mismatch", RestStatus.CONFLICT));
                    return;
                }
                var origin = new LinkedHashMap<String, Object>();
                for (String field : java.util.Set.of("id", "incident_id", "deployment_id", "group_key", "policy_id",
                        "policy_version", "window_start", "window_end", "membership_hash", "finding_count", "state")) {
                    if (source.get(field) == null) throw new IllegalStateException("Incomplete reservation");
                    origin.put(field, source.get(field));
                }
                listener.onResponse(origin);
            }, listener::onFailure));
        }
    }

    /** Separate immutable completion receipt. Does not mutate the reservation or claim a lock. */
    void complete(Map<String, Object> origin, String actor, ActionListener<Void> listener) {
        String id = origin.get("id") + ":completed";
        var expected = new LinkedHashMap<>(origin);
        expected.put("id", id);
        expected.put("state", "completed");
        expected.put("completed_by", actor);
        var source = new LinkedHashMap<>(expected);
        source.put("completed_at", clock.instant().toString());
        IndexRequest request = new IndexRequest(INDEX).id(id).opType(DocWriteRequest.OpType.CREATE)
                .source(source, XContentType.JSON).setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.wrap(response -> listener.onResponse(null), error -> {
                if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) { listener.onFailure(error); return; }
                try (ThreadContext.StoredContext replay = pool.getThreadContext().stashContext()) {
                    client.get(new GetRequest(INDEX, id), ActionListener.wrap(existing -> {
                        if (!existing.isExists() || !matches(expected, existing.getSourceAsMap())) {
                            listener.onFailure(new OpenSearchStatusException("Correlation completion receipt mismatch", RestStatus.CONFLICT));
                            return;
                        }
                        listener.onResponse(null);
                    }, listener::onFailure));
                }
            }));
        }
    }

    private void verify(Map<String, Object> expected, String id, UUID incidentId, ActionListener<Result> listener) {
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INDEX, id), ActionListener.wrap(response -> {
                if (!response.isExists() || !matches(expected, response.getSourceAsMap())) {
                    listener.onFailure(new OpenSearchStatusException("Correlation reservation content changed; reconciliation required", RestStatus.CONFLICT));
                    return;
                }
                listener.onResponse(new Result(id, incidentId, true));
            }, listener::onFailure));
        }
    }
}
