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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Bounded outbox recovery on the elected cluster manager. CAS and create-only
 * delivery make an overlapping sweep after failover safe. No caller-facing API.
 */
public final class IncidentRecovery implements Runnable {
    private static final Logger LOG = LogManager.getLogger(IncidentRecovery.class);
    private static final int PAGE_SIZE = 25;

    private final Client client;
    private final ThreadPool pool;
    private final ClusterService cluster;
    private final IncidentRepository repository;
    private final AtomicBoolean running = new AtomicBoolean();
    private volatile String afterId;
    private volatile boolean stopped;

    public IncidentRecovery(Client client, ThreadPool pool, ClusterService cluster, IncidentRepository repository) {
        this.client = client;
        this.pool = pool;
        this.cluster = cluster;
        this.repository = repository;
    }

    private boolean elected() {
        return !stopped && cluster.state().nodes().isLocalNodeElectedClusterManager();
    }

    public void stop() { stopped = true; }

    @Override
    public void run() {
        if (!elected()) {
            afterId = null;
            return;
        }
        if (!cluster.state().getRoutingTable().hasIndex(IncidentRepository.INCIDENTS) ||
                !cluster.state().getRoutingTable().hasIndex(IncidentRepository.ACTIVITY)) return;
        if (!running.compareAndSet(false, true)) return;
        SearchSourceBuilder source = build(afterId);
        SearchRequest request = new SearchRequest(IncidentRepository.INCIDENTS).source(source);
        request.allowPartialSearchResults(false);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.search(request, ActionListener.wrap(response -> {
                if (response.isTimedOut() || response.getFailedShards() > 0) {
                    failed(new IllegalStateException("Incomplete recovery search"));
                    return;
                }
                SearchHit[] hits = response.getHits().getHits();
                if (hits.length == 0) {
                    afterId = null;
                    running.set(false);
                    return;
                }
                // Advance even on an individual poison event. Wrap at end of each pass.
                afterId = hits[hits.length - 1].getId();
                recover(hits, 0);
            }, this::failed));
        } catch (Exception e) {
            failed(e);
        }
    }

    static SearchSourceBuilder build(String afterId) {
        SearchSourceBuilder source = new SearchSourceBuilder()
                .query(QueryBuilders.existsQuery("pending_activity.id"))
                .size(PAGE_SIZE).trackTotalHits(false).sort("id", SortOrder.ASC).fetchSource(false);
        if (afterId != null) source.searchAfter(new Object[]{afterId});
        return source;
    }

    private void recover(SearchHit[] hits, int position) {
        if (position == hits.length || !elected()) {
            running.set(false);
            return;
        }
        try {
            UUID id = UUID.fromString(hits[position].getId());
            // Fetch the latest aggregate/version rather than acknowledging a stale search hit.
            repository.get(id, ActionListener.wrap(stored -> {
                if (!elected()) {
                    running.set(false);
                    return;
                }
                repository.deliver(stored, ActionListener.wrap(
                        delivered -> recover(hits, position + 1),
                        error -> individualFailure(hits, position, error)));
            }, error -> individualFailure(hits, position, error)));
        } catch (Exception e) {
            individualFailure(hits, position, e);
        }
    }

    private void individualFailure(SearchHit[] hits, int position, Exception error) {
        LOG.warn("Incident activity recovery failed for document {}", hits[position].getId(), error);
        recover(hits, position + 1);
    }

    private void failed(Exception error) {
        LOG.warn("Incident activity recovery sweep failed", error);
        running.set(false);
    }
}
