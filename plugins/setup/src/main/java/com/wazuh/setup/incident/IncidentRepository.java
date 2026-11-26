/*
 * Copyright (C) 2026, Wazuh Inc.
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

import org.opensearch.OpenSearchStatusException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.util.Arrays;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Privileged persistence for fixed incident indices. Not an exposed action.
 * Callers must check dedicated cluster permissions and resolve the principal
 * before entering this repository. Never accept arbitrary source/index from REST.
 */
public final class IncidentRepository {
    private static final ObjectMapper AUDIT_JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    public static final String INCIDENTS = ".wazuh-cases-v1";
    public static final String ACTIVITY = ".wazuh-case-activity-v1";

    public record Stored(Map<String, Object> source, long seqNo, long primaryTerm) {}
    private final Client client;
    private final ThreadPool threadPool;

    public IncidentRepository(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
    }

    public void get(UUID id, ActionListener<Stored> listener) {
        try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INCIDENTS, id.toString()), ActionListener.wrap(response -> {
                if (!response.isExists()) {
                    listener.onFailure(new OpenSearchStatusException("Incident not found", RestStatus.NOT_FOUND));
                    return;
                }
                Map<String, Object> source = response.getSourceAsMap();
                if (!id.toString().equals(source.get("id"))) {
                    listener.onFailure(new IllegalStateException("Invalid incident identity"));
                    return;
                }
                listener.onResponse(new Stored(source, response.getSeqNo(), response.getPrimaryTerm()));
            }, listener::onFailure));
        }
    }

    void readCreationActivity(UUID id, ActionListener<Map<String, Object>> listener) {
        try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
            client.get(new GetRequest(ACTIVITY, id + ":1"), ActionListener.wrap(response -> {
                if (!response.isExists()) {
                    listener.onFailure(new OpenSearchStatusException("Creation activity not delivered", RestStatus.CONFLICT));
                    return;
                }
                listener.onResponse(response.getSourceAsMap());
            }, listener::onFailure));
        }
    }

    public void create(Map<String, Object> source, ActionListener<Stored> listener) {
        String id = (String) source.get("id");
        UUID.fromString(id);
        if (!Integer.valueOf(1).equals(source.get("revision")) || source.get("pending_activity") == null) {
            listener.onFailure(new IllegalArgumentException("Initial activity required"));
            return;
        }
        IndexRequest request = new IndexRequest(INCIDENTS).id(id)
                .opType(DocWriteRequest.OpType.CREATE).source(source, XContentType.JSON)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        write(request, source, listener);
    }

    public void commit(Stored previous, Map<String, Object> next, ActionListener<Stored> listener) {
        if (previous.source().get("pending_activity") != null ||
                !previous.source().get("id").equals(next.get("id")) ||
                !(previous.source().get("revision") instanceof Integer revision) ||
                !Integer.valueOf(revision + 1).equals(next.get("revision")) ||
                next.get("pending_activity") == null) {
            listener.onFailure(new IllegalArgumentException("Invalid incident mutation"));
            return;
        }
        replace(previous, next, listener);
    }

    private void replace(Stored previous, Map<String, Object> source, ActionListener<Stored> listener) {
        IndexRequest request = new IndexRequest(INCIDENTS).id((String) source.get("id"))
                .source(source, XContentType.JSON).setIfSeqNo(previous.seqNo())
                .setIfPrimaryTerm(previous.primaryTerm())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        write(request, source, listener);
    }

    private void write(IndexRequest request, Map<String, Object> source, ActionListener<Stored> listener) {
        try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.wrap(response ->
                    listener.onResponse(new Stored(source, response.getSeqNo(), response.getPrimaryTerm())),
                    listener::onFailure));
        }
    }

    /**
     * Delivers one pending event using create-only semantics. A replay may acknowledge an
     * identical persisted event; any mismatch fails closed. The aggregate acknowledgement
     * is another CAS and cannot overwrite concurrent state. Recovery may call this again.
     */
    @SuppressWarnings("unchecked")
    public void deliver(Stored previous, ActionListener<Stored> listener) {
        Object pending = previous.source().get("pending_activity");
        if (pending == null) {
            listener.onResponse(previous);
            return;
        }
        Map<String, Object> event = (Map<String, Object>) pending;
        String id = previous.source().get("id") + ":" + previous.source().get("revision");
        if (!id.equals(event.get("id")) || !previous.source().get("id").equals(event.get("incident_id")) ||
                !previous.source().get("revision").equals(event.get("revision"))) {
            listener.onFailure(new IllegalStateException("Invalid activity identity"));
            return;
        }
        IndexRequest request = new IndexRequest(ACTIVITY).id(id)
                .opType(DocWriteRequest.OpType.CREATE).source(event, XContentType.JSON)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.<IndexResponse>wrap(
                    response -> acknowledge(previous, listener),
                    error -> {
                        if (org.opensearch.ExceptionsHelper.status(error) == RestStatus.CONFLICT) {
                            verifyReplay(id, event, previous, listener);
                        } else {
                            listener.onFailure(error);
                        }
                    }));
        }
    }

    private void verifyReplay(String id, Map<String, Object> event, Stored previous, ActionListener<Stored> listener) {
        try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
            client.get(new GetRequest(ACTIVITY, id), ActionListener.wrap(response -> {
                if (!response.isExists() || !sameEvent(event, response.getSourceAsMap())) {
                    listener.onFailure(new IllegalStateException("Incident activity identity collision"));
                    return;
                }
                acknowledge(previous, listener);
            }, listener::onFailure));
        }
    }

    /** Compare the serialized content, not Java numeric wrapper classes or map ordering. */
    static boolean sameEvent(Map<String, Object> expected, Map<String, Object> actual) {
        if (actual == null) return false;
        try {
            return Arrays.equals(AUDIT_JSON.writeValueAsBytes(expected), AUDIT_JSON.writeValueAsBytes(actual));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to verify persisted activity", e);
        }
    }

    private void acknowledge(Stored previous, ActionListener<Stored> listener) {
        Map<String, Object> next = new LinkedHashMap<>(previous.source());
        next.put("pending_activity", null);
        replace(previous, next, listener);
    }
}
