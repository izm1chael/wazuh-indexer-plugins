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

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
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
import java.util.function.Supplier;

/** Fixed investigation projections. Finding sources are never read as system or returned here. */
public final class IncidentInvestigationService {
    private static final Set<String> ACTIVITY_FIELDS = Set.of("id", "incident_id", "revision", "kind", "actor", "at");
    private static final Set<String> CHANGE_FIELDS = Set.of("status", "severity", "priority", "tlp", "owner", "finding_count");

    private final Client client;
    private final ThreadPool pool;
    private final IncidentRepository repository;
    private final FindingAccess access;

    public IncidentInvestigationService(Client client, ThreadPool pool, IncidentRepository repository, FindingAccess access) {
        this.client = client;
        this.pool = pool;
        this.repository = repository;
        this.access = access;
    }

    public void activity(UUID id, int before, int limit, ActionListener<Map<String, Object>> listener) {
        repository.get(id, ActionListener.wrap(stored -> {
            int revision = (int) stored.source().get("revision");
            SearchRequest request = new SearchRequest(IncidentRepository.ACTIVITY).source(activityQuery(id, revision, before, limit));
            request.allowPartialSearchResults(false);
            try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
                client.search(request, ActionListener.wrap(response -> {
                    if (response.isTimedOut() || response.getFailedShards() > 0) {
                        listener.onFailure(new OpenSearchStatusException("Incomplete activity search", RestStatus.SERVICE_UNAVAILABLE));
                        return;
                    }
                    var hits = response.getHits().getHits();
                    List<Map<String, Object>> events = new ArrayList<>();
                    int count = Math.min(limit, hits.length);
                    for (int n = 0; n < count; n++) events.add(projectActivity(hits[n].getSourceAsMap()));
                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("events", events);
                    result.put("observed_revision", revision);
                    result.put("activity_pending", stored.source().get("pending_activity") != null);
                    if (hits.length > count) result.put("next_before", events.get(count - 1).get("revision"));
                    listener.onResponse(result);
                }, listener::onFailure));
            }
        }, listener::onFailure));
    }

    /** Related issued records for one caller-visible, revision-bound finding page. */
    @SuppressWarnings("unchecked")
    public void issuedResponses(UUID id, int offset, int limit, int expectedRevision, String actor,
            ActionListener<Map<String, Object>> listener) {
        Supplier<ThreadContext.StoredContext> caller = pool.getThreadContext().newRestorableContext(false);
        findings(id, offset, limit, expectedRevision, actor, ActionListener.wrap(page -> {
            try (ThreadContext.StoredContext ignored = caller.get()) {
                if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) {
                    listener.onFailure(new OpenSearchStatusException("Response caller context lost", RestStatus.FORBIDDEN)); return;
                }
                var refs = new java.util.LinkedHashSet<FindingReference>();
                for (var ref : (List<Map<String, Object>>) page.get("findings")) refs.add(FindingReference.parse(ref));
                IssuedResponseSearch.search(client, refs, ActionListener.wrap(rows -> {
                    var result = new LinkedHashMap<String, Object>();
                    result.put("issued_responses", rows);
                    result.put("revision", page.get("revision"));
                    result.put("visible_finding_count", refs.size());
                    result.put("mode", "exact_visible_finding_page_issued_only");
                    if (page.containsKey("next_offset")) result.put("next_offset", page.get("next_offset"));
                    listener.onResponse(result);
                }, listener::onFailure));
            }
        }, listener::onFailure));
    }

    /** Dedicated response-read action is required; ordinary incident reads omit this content. */
    public void responses(UUID id, ActionListener<Map<String, Object>> listener) {
        repository.get(id, ActionListener.wrap(stored -> listener.onResponse(Map.of(
                "responses", IncidentResponses.project(stored.source()),
                "observed_revision", stored.source().get("revision"),
                "activity_pending", stored.source().get("pending_activity") != null,
                "mode", "manual_tracking_only")), listener::onFailure));
    }

    /** Notes live in delivered immutable activity, rather than an ever-growing aggregate array. */
    public void collaboration(UUID id, int before, int limit, ActionListener<Map<String, Object>> listener) {
        repository.get(id, ActionListener.wrap(stored -> {
            int revision = (int) stored.source().get("revision");
            SearchRequest request = new SearchRequest(IncidentRepository.ACTIVITY).source(
                    notesQuery(id, revision, before, limit));
            request.allowPartialSearchResults(false);
            try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
                client.search(request, ActionListener.wrap(response -> {
                    if (response.isTimedOut() || response.getFailedShards() > 0) {
                        listener.onFailure(new OpenSearchStatusException("Incomplete note search", RestStatus.SERVICE_UNAVAILABLE));
                        return;
                    }
                    var hits = response.getHits().getHits();
                    int count = Math.min(limit, hits.length);
                    List<Map<String, Object>> notes = new ArrayList<>();
                    for (int n = 0; n < count; n++) notes.add(projectNote(hits[n].getSourceAsMap()));
                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("notes", notes);
                    result.put("tasks", projectTasks(stored.source()));
                    result.put("playbooks", IncidentPlaybooks.preview(stored.source()));
                    result.put("playbook_runs", IncidentPlaybooks.runs(stored.source()));
                    result.put("tuning_proposals", IncidentTuningProposals.project(stored.source()));
                    result.put("observed_revision", revision);
                    result.put("activity_pending", stored.source().get("pending_activity") != null);
                    if (hits.length > count) result.put("next_before", notes.get(count - 1).get("revision"));
                    listener.onResponse(result);
                }, listener::onFailure));
            }
        }, listener::onFailure));
    }

    static SearchSourceBuilder notesQuery(UUID id, int revision, int before, int limit) {
        if (before < 0 || limit < 1 || limit > 50) throw invalid("Invalid note page");
        var query = QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("incident_id", id.toString()))
                .filter(QueryBuilders.termQuery("kind", "note_added"))
                .filter(QueryBuilders.rangeQuery("revision").lte(revision));
        if (before > 0) query.filter(QueryBuilders.rangeQuery("revision").lt(before));
        return new SearchSourceBuilder().query(query).size(limit + 1).trackTotalHits(false)
                .sort("revision", SortOrder.DESC);
    }

    static Map<String, Object> projectNote(Map<String, Object> source) {
        if (!"note_added".equals(source.get("kind")) || !(source.get("changes") instanceof Map<?, ?> changes) ||
                !(changes.get("note") instanceof Map<?, ?> note) || !(note.get("after") instanceof String body)) {
            throw new IllegalStateException("Invalid delivered note");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (String field : Set.of("id", "incident_id", "revision", "actor", "at")) result.put(field, source.get(field));
        result.put("body", body);
        return result;
    }

    static List<Map<String, Object>> projectTasks(Map<String, Object> source) {
        Object value = source.getOrDefault("tasks", List.of());
        if (!(value instanceof List<?> tasks) || tasks.size() > 100) throw new IllegalStateException("Invalid task state");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object entry : tasks) {
            if (!(entry instanceof Map<?, ?> task)) throw new IllegalStateException("Invalid task");
            Map<String, Object> projected = new LinkedHashMap<>();
            for (String field : Set.of("id", "title", "status", "created_by", "created_at", "completed_by", "completed_at")) {
                Object item = task.get(field);
                if (!scalar(item)) throw new IllegalStateException("Invalid task field");
                projected.put(field, item);
            }
            result.add(projected);
        }
        return result;
    }

    static SearchSourceBuilder activityQuery(UUID id, int revision, int before, int limit) {
        if (before < 0 || limit < 1 || limit > 100) throw invalid("Invalid activity page");
        var query = QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("incident_id", id.toString()))
                .filter(QueryBuilders.rangeQuery("revision").lte(revision));
        if (before > 0) query.filter(QueryBuilders.rangeQuery("revision").lt(before));
        return new SearchSourceBuilder().query(query).size(limit + 1).trackTotalHits(false)
                .sort("revision", SortOrder.DESC);
    }

    static Map<String, Object> projectActivity(Map<String, Object> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (String field : ACTIVITY_FIELDS) if (source.containsKey(field)) result.put(field, source.get(field));
        Map<String, Object> safe = new LinkedHashMap<>();
        if (source.get("changes") instanceof Map<?, ?> changes) {
            var fields = new java.util.HashSet<>(CHANGE_FIELDS);
            if ("ai_feedback_recorded".equals(source.get("kind"))) {
                fields.addAll(IncidentAiFeedback.FIELDS);
                fields.add(IncidentAiFeedback.REPORT_HASH);
                fields.add("feedback_origin"); fields.add("closure_classification_at_feedback");
            }
            for (String field : fields) {
                if (changes.get(field) instanceof Map<?, ?> change) {
                    Object before = change.get("before");
                    Object after = change.get("after");
                    if (scalar(before) && scalar(after)) {
                        Map<String, Object> pair = new LinkedHashMap<>();
                        pair.put("before", before);
                        pair.put("after", after);
                        safe.put(field, pair);
                    }
                }
            }
        }
        result.put("changes", safe);
        return result;
    }

    private static boolean scalar(Object value) {
        return value == null || value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    /**
     * Take a bounded page from the incident aggregate, then independently check each
     * reference in the original request context. Restore context explicitly after
     * privileged asynchronous reads. Never retry visibility with internal privileges.
     * Denied and expired references are indistinguishable in the response.
     */
    public void findings(UUID id, int offset, int limit, int expectedRevision, String actor,
            ActionListener<Map<String, Object>> listener) {
        if (offset < 0 || offset > 1000 || limit < 1 || limit > 25 ||
                (offset > 0 && expectedRevision < 1) || expectedRevision < 0) {
            throw invalid("Invalid findings page");
        }
        Supplier<ThreadContext.StoredContext> caller = pool.getThreadContext().newRestorableContext(false);
        repository.get(id, ActionListener.wrap(stored -> {
            int revision = (int) stored.source().get("revision");
            if (expectedRevision > 0 && expectedRevision != revision) {
                listener.onFailure(new OpenSearchStatusException("Incident changed; restart finding pagination", RestStatus.CONFLICT));
                return;
            }
            if (!(stored.source().get("findings") instanceof List<?> links) || offset > links.size()) {
                listener.onFailure(invalid("Invalid finding offset"));
                return;
            }
            int end = Math.min(offset + limit, links.size());
            List<Map<String, Object>> visible = new ArrayList<>();
            List<Map<String, Object>> observations = new ArrayList<>();
            check(links, offset, end, caller, actor, visible, observations, ActionListener.wrap(ignored -> {
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("findings", visible);
                result.put("observations", observations);
                result.put("revision", revision);
                result.put("unavailable_count", end - offset - visible.size());
                if (end < links.size()) result.put("next_offset", end);
                listener.onResponse(result);
            }, listener::onFailure));
        }, listener::onFailure));
    }

    @SuppressWarnings("unchecked")
    private void check(List<?> links, int position, int end, Supplier<ThreadContext.StoredContext> caller,
            String actor, List<Map<String, Object>> visible, List<Map<String, Object>> observations, ActionListener<Void> listener) {
        if (position == end) {
            listener.onResponse(null);
            return;
        }
        try (ThreadContext.StoredContext ignored = caller.get()) {
            if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) {
                listener.onFailure(new OpenSearchStatusException("Finding caller context lost", RestStatus.FORBIDDEN));
                return;
            }
            FindingReference reference = FindingReference.parse((Map<String, Object>) links.get(position));
            access.inspect(reference, ActionListener.wrap(observation -> {
                visible.add(reference.toMap());
                observations.add(observation);
                check(links, position + 1, end, caller, actor, visible, observations, listener);
            }, error -> {
                RestStatus status = ExceptionsHelper.status(error);
                if (status == RestStatus.FORBIDDEN || status == RestStatus.NOT_FOUND) {
                    check(links, position + 1, end, caller, actor, visible, observations, listener);
                } else {
                    listener.onFailure(error);
                }
            }));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private static OpenSearchStatusException invalid(String message) {
        return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST);
    }
}
