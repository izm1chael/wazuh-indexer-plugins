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
import java.util.List;
import java.util.Map;

/** Fixed single-SOC catalog. CAS protects the whole bounded document, including its attributed history. */
public final class IndicatorCatalogStore {
    public static final String INDEX = ".wazuh-incident-indicators-v1";
    private static final String ID = "catalog";
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;
    private record Snapshot(Map<String, Object> source, long seqNo, long primaryTerm, boolean exists) {}

    public IndicatorCatalogStore(Client client, ThreadPool pool, Clock clock) {
        this.client = client; this.pool = pool; this.clock = clock;
    }

    public void read(ActionListener<Map<String, Object>> listener) {
        get(ActionListener.wrap(snapshot -> listener.onResponse(IndicatorCatalog.project(snapshot.source(), clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS))), listener::onFailure));
    }

    public void add(int expected, List<?> entries, String actor, ActionListener<Map<String, Object>> listener) {
        mutate(expected, source -> IndicatorCatalog.add(source, expected, entries, actor, clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)), entries.size(), listener);
    }

    public void revoke(int expected, String id, String reason, String actor, ActionListener<Map<String, Object>> listener) {
        mutate(expected, source -> IndicatorCatalog.revoke(source, expected, id, reason, actor, clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)), 1, listener);
    }

    public void sight(int expected, String id, String observedAt, String source, int count, String actor, ActionListener<Map<String, Object>> listener) {
        mutate(expected, current -> IndicatorCatalog.sight(current, expected, id, observedAt, source, count, actor,
                clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)), 1, listener);
    }

    public void withdrawSighting(int expected, String id, int sightingRevision, String reason, String actor, ActionListener<Map<String, Object>> listener) {
        mutate(expected, current -> IndicatorCatalog.withdrawSighting(current, expected, id, sightingRevision, reason, actor,
                clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)), 1, listener);
    }

    private void mutate(int expected, java.util.function.Function<Map<String, Object>, Map<String, Object>> mutation,
            int changed, ActionListener<Map<String, Object>> listener) {
        get(ActionListener.wrap(snapshot -> {
            try {
                if (!Integer.valueOf(expected).equals(snapshot.source().get("revision")))
                    throw new OpenSearchStatusException("Indicator catalog revision changed", RestStatus.CONFLICT);
                Map<String, Object> next = mutation.apply(snapshot.source());
                IndexRequest request = new IndexRequest(INDEX).id(ID).source(next, XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
                if (snapshot.exists()) request.setIfSeqNo(snapshot.seqNo()).setIfPrimaryTerm(snapshot.primaryTerm());
                else request.opType(DocWriteRequest.OpType.CREATE);
                try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
                    client.index(request, ActionListener.wrap(response -> listener.onResponse(
                            Map.of("revision", next.get("revision"), "changed", changed)), error -> {
                        if (ExceptionsHelper.status(error) == RestStatus.CONFLICT)
                            listener.onFailure(new OpenSearchStatusException("Indicator catalog revision changed", RestStatus.CONFLICT));
                        else listener.onFailure(error);
                    }));
                }
            } catch (Exception e) { listener.onFailure(e); }
        }, listener::onFailure));
    }

    private void get(ActionListener<Snapshot> listener) {
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INDEX, ID), ActionListener.wrap(response -> {
                if (!response.isExists()) {
                    listener.onResponse(new Snapshot(IndicatorCatalog.empty(), -1, -1, false));
                    return;
                }
                if (!INDEX.equals(response.getIndex()) || !ID.equals(response.getId()))
                    throw new IllegalStateException("Unexpected indicator catalog identity");
                var source = response.getSourceAsMap();
                IndicatorCatalog.rows(source);
                listener.onResponse(new Snapshot(source, response.getSeqNo(), response.getPrimaryTerm(), true));
            }, listener::onFailure));
        }
    }
}
