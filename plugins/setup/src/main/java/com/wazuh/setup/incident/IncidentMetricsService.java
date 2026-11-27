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

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Map;

/** One bounded search of the union of the current open backlog and creation cohort. */
public final class IncidentMetricsService {
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;

    public IncidentMetricsService(Client client, ThreadPool pool, Clock clock) {
        this.client = client; this.pool = pool; this.clock = clock;
    }

    static SearchSourceBuilder build(IncidentMetrics.Query query) {
        return new SearchSourceBuilder().query(QueryBuilders.boolQuery()
                .should(QueryBuilders.rangeQuery("created_at").gte(query.from().toString()).lt(query.until().toString()))
                .should(QueryBuilders.termsQuery("status", "new", "triaging", "active"))
                .minimumShouldMatch(1)).size(IncidentMetrics.MAX_RECORDS + 1).trackTotalHits(true)
                .timeout(TimeValue.timeValueSeconds(15))
                .fetchSource(new String[]{"id", "status", "severity", "owner", "created_at", "first_assigned_at",
                        "triage_started_at", "activated_at", "first_closed_at", "closed_at", "reopened_at",
                        "closure.classification", "pending_activity.id"}, new String[0]);
    }

    public void report(IncidentMetrics.Query query, ActionListener<Map<String, Object>> listener) {
        if (query.until().isAfter(clock.instant())) {
            listener.onFailure(new OpenSearchStatusException("Metrics period cannot end in the future", RestStatus.BAD_REQUEST));
            return;
        }
        SearchRequest request = new SearchRequest(IncidentRepository.INCIDENTS).source(build(query));
        request.allowPartialSearchResults(false);
        request.indicesOptions(org.opensearch.action.support.IndicesOptions.strictExpandOpen());
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.search(request, ActionListener.wrap(response -> {
                var hits = response.getHits();
                if (response.isTimedOut() || response.getFailedShards() > 0 || Boolean.TRUE.equals(response.isTerminatedEarly()) ||
                        hits.getTotalHits() == null ||
                        hits.getTotalHits().relation != org.apache.lucene.search.TotalHits.Relation.EQUAL_TO ||
                        hits.getTotalHits().value != hits.getHits().length ||
                        hits.getHits().length > IncidentMetrics.MAX_RECORDS) {
                    listener.onFailure(new OpenSearchStatusException(
                            "Incomplete metrics search or more than 5000 records in cohort/backlog union", RestStatus.CONFLICT));
                    return;
                }
                var records = new ArrayList<Map<String, Object>>();
                for (var hit : hits.getHits()) records.add(hit.getSourceAsMap());
                listener.onResponse(IncidentMetrics.summarize(query, clock.instant(), records));
            }, listener::onFailure));
        }
    }
}
