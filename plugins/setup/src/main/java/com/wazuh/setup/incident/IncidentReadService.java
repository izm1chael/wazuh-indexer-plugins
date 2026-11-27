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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Read-authorized single-SOC summary API. No caller-defined search DSL or index names. */
public final class IncidentReadService {
    private static final Set<String> QUEUES = Set.of("open", "new", "triaging", "active", "closed", "unassigned", "all", "mine", "handover");
    private static final Set<String> SEVERITIES = Set.of("informational", "low", "medium", "high", "critical");
    private static final Set<String> PUBLIC_FIELDS = Set.of("id", "title", "description", "status", "severity",
            "priority", "tlp", "owner", "handover", "created_by", "updated_by", "created_at", "updated_at",
            "first_assigned_at", "triage_started_at", "activated_at", "closed_at", "first_closed_at",
            "reopened_at", "closure", "revision", "finding_count", "tags");

    public record Query(String queue, String severity, String owner, String search, int limit, Long afterTime, String afterId) {
        public Query {
            if (queue == null || !QUEUES.contains(queue) || limit < 1 || limit > 100 ||
                    (severity != null && !SEVERITIES.contains(severity)) ||
                    (owner != null && (owner.isBlank() || owner.length() > 1024)) ||
                    (search != null && (search.length() > 1024 || (search.startsWith("tag:") && !search.substring(4).matches("[a-z0-9][a-z0-9_-]{0,63}")))) ||
                    ((afterTime == null) != (afterId == null))) throw invalid("Invalid incident queue query");
            if (afterId != null) canonicalId(afterId);
        }
    }

    private final Client client;
    private final ThreadPool threadPool;
    private final IncidentRepository repository;

    public IncidentReadService(Client client, ThreadPool threadPool, IncidentRepository repository) {
        this.client = client;
        this.threadPool = threadPool;
        this.repository = repository;
    }

    public void get(UUID id, ActionListener<Map<String, Object>> listener) {
        repository.get(id, ActionListener.wrap(record -> listener.onResponse(project(record.source())), listener::onFailure));
    }

    public void list(Query query, String actor, ActionListener<Map<String, Object>> listener) {
        SearchRequest request = new SearchRequest(IncidentRepository.INCIDENTS).source(build(query, actor));
        request.allowPartialSearchResults(false);
        try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
            client.search(request, ActionListener.wrap(response -> {
                if (response.isTimedOut() || response.getFailedShards() > 0) {
                    listener.onFailure(new OpenSearchStatusException("Incomplete incident queue", RestStatus.SERVICE_UNAVAILABLE));
                    return;
                }
                SearchHit[] hits = response.getHits().getHits();
                List<Map<String, Object>> incidents = new ArrayList<>();
                int count = Math.min(query.limit(), hits.length);
                for (int n = 0; n < count; n++) incidents.add(project(hits[n].getSourceAsMap()));
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("incidents", incidents);
                if (hits.length > count) {
                    Object[] sort = hits[count - 1].getSortValues();
                    if (sort.length != 2 || !(sort[0] instanceof Number) || !(sort[1] instanceof String)) {
                        listener.onFailure(new IllegalStateException("Invalid queue cursor"));
                        return;
                    }
                    result.put("next", Map.of("time", ((Number) sort[0]).longValue(), "id", sort[1]));
                }
                listener.onResponse(result);
            }, listener::onFailure));
        }
    }

    static SearchSourceBuilder build(Query query) { return build(query, null); }

    static SearchSourceBuilder build(Query query, String actor) {
        BoolQueryBuilder filter = QueryBuilders.boolQuery();
        boolean personal = "mine".equals(query.queue()) || "handover".equals(query.queue());
        if (personal && (actor == null || actor.isBlank() || "_shared".equals(actor))) {
            throw new OpenSearchStatusException("Authenticated incident principal required", RestStatus.UNAUTHORIZED);
        }
        if ("open".equals(query.queue()) || "unassigned".equals(query.queue()) || personal) {
            filter.filter(QueryBuilders.termsQuery("status", "new", "triaging", "active"));
        } else if (!"all".equals(query.queue())) {
            filter.filter(QueryBuilders.termQuery("status", query.queue()));
        }
        if ("unassigned".equals(query.queue())) filter.mustNot(QueryBuilders.existsQuery("owner"));
        if ("mine".equals(query.queue())) filter.filter(QueryBuilders.termQuery("owner", actor));
        if ("handover".equals(query.queue())) filter.filter(QueryBuilders.termQuery("handover.target", actor));
        if (query.owner() != null) filter.filter(QueryBuilders.termQuery("owner", query.owner()));
        if (query.severity() != null) filter.filter(QueryBuilders.termQuery("severity", query.severity()));
        if (query.search() != null && !query.search().isBlank()) {
            if (query.search().startsWith("tag:")) filter.filter(QueryBuilders.termQuery("tags", query.search().substring(4)));
            else filter.must(QueryBuilders.multiMatchQuery(query.search(), "title", "description", "id"));
        }
        SearchSourceBuilder source = new SearchSourceBuilder().query(filter).size(query.limit() + 1)
                .trackTotalHits(false).sort("updated_at", SortOrder.DESC).sort("id", SortOrder.ASC)
                .fetchSource(PUBLIC_FIELDS.toArray(String[]::new), new String[0]);
        if (query.afterTime() != null) source.searchAfter(new Object[]{query.afterTime(), query.afterId()});
        return source;
    }

    static Map<String, Object> project(Map<String, Object> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (String field : PUBLIC_FIELDS) if (!"handover".equals(field) && !"tags".equals(field) && source.containsKey(field)) result.put(field, source.get(field));
        if (source.containsKey("tags")) result.put("tags", IncidentEvidenceRegister.storedTags(source));
        Object value = source.get("handover");
        if (value == null) {
            result.put("handover", null);
        } else if (value instanceof Map<?, ?> offer && offer.get("target") instanceof String target
                && offer.get("offered_by") instanceof String by && offer.get("offered_at") instanceof String at
                && by.equals(source.get("owner")) && !target.equals(by)) {
            result.put("handover", Map.of("target", target, "offered_by", by, "offered_at", at));
        } else {
            throw new IllegalStateException("Invalid stored handover");
        }
        return result;
    }

    public static UUID canonicalId(String value) {
        try {
            if (value == null) throw new IllegalArgumentException();
            UUID id = UUID.fromString(value);
            if (!id.toString().equals(value)) throw new IllegalArgumentException();
            return id;
        } catch (IllegalArgumentException e) {
            throw invalid("Canonical incident UUID required");
        }
    }

    private static OpenSearchStatusException invalid(String message) {
        return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST);
    }
}
