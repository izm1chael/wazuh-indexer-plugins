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

import org.apache.lucene.search.join.ScoreMode;
import org.apache.lucene.search.TotalHits;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Join a complete caller-visible exact-term hunt to shared SOC incident links. No arbitrary reference input. */
public final class IncidentEntityInvestigationService {
    static final int MAX_CASES = 50;
    private final Client client;
    private final ThreadPool pool;
    private final IncidentHuntService hunt;
    private final java.util.concurrent.Semaphore permits = new java.util.concurrent.Semaphore(1);
    public IncidentEntityInvestigationService(Client client, ThreadPool pool, IncidentHuntService hunt) {
        this.client = client; this.pool = pool; this.hunt = hunt;
    }

    static Set<FindingReference> references(Map<String,Object> result) {
        if (!"caller_visible_findings_exact_terms".equals(result.get("scope")) ||
                !(result.get("rows") instanceof List<?> rows) || rows.size() > IncidentHuntService.MAX_HITS ||
                !Integer.valueOf(rows.size()).equals(result.get("match_count"))) throw incomplete();
        var refs = new HashSet<FindingReference>();
        for (Object item : rows) {
            if (!(item instanceof Map<?,?> row) || !(row.get("index") instanceof String index) ||
                    !(row.get("document_id") instanceof String id) || !refs.add(new FindingReference(index,id))) throw incomplete();
        }
        return Set.copyOf(refs);
    }

    static SearchSourceBuilder build(Set<FindingReference> refs) {
        if (refs.isEmpty() || refs.size() > IncidentHuntService.MAX_HITS) throw incomplete();
        // Group by concrete index. Never independently OR index and document ID across groups.
        var groups = new TreeMap<String,Set<String>>();
        for (var ref : refs) groups.computeIfAbsent(ref.index(), key -> new TreeSet<>()).add(ref.documentId());
        var pairs = QueryBuilders.boolQuery().minimumShouldMatch(1);
        for (var group : groups.entrySet()) {
            pairs.should(QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("findings.index",group.getKey()))
                    .filter(QueryBuilders.termsQuery("findings.document_id",group.getValue())));
        }
        return new SearchSourceBuilder().query(QueryBuilders.nestedQuery("findings",pairs,ScoreMode.None))
                .size(MAX_CASES+1).trackTotalHits(true).timeout(TimeValue.timeValueSeconds(15))
                .fetchSource(new String[]{"id","revision","status","severity","findings","finding_count"},new String[0]);
    }

    static Map<String,Object> project(String documentId, Map<String,Object> source, Set<FindingReference> visible) {
        if (source == null || !documentId.equals(source.get("id")) ||
                !IncidentReadService.canonicalId(documentId).toString().equals(documentId) ||
                !(source.get("revision") instanceof Integer revision) || revision < 1 ||
                !Set.of("new","triaging","active","closed").contains(source.get("status")) ||
                !Set.of("informational","low","medium","high","critical").contains(source.get("severity")) ||
                !(source.get("findings") instanceof List<?> rows) || rows.size() > 1000 ||
                !Integer.valueOf(rows.size()).equals(source.get("finding_count"))) throw incomplete();
        var all = new HashSet<FindingReference>();
        var matched = new ArrayList<FindingReference>();
        for (Object item : rows) {
            if (!(item instanceof Map<?,?> row) || !row.keySet().equals(Set.of("index","document_id")) ||
                    !(row.get("index") instanceof String index) || !(row.get("document_id") instanceof String id)) throw incomplete();
            var ref = new FindingReference(index,id);
            if (!all.add(ref)) throw incomplete();
            if (visible.contains(ref)) matched.add(ref);
        }
        if (matched.isEmpty()) throw incomplete();
        matched.sort(java.util.Comparator.comparing(FindingReference::index).thenComparing(FindingReference::documentId));
        // Never expose other linked references or even their count.
        return Map.of("id",documentId,"revision",revision,"status",source.get("status"),"severity",source.get("severity"),
                "matches",matched.stream().map(FindingReference::toMap).toList());
    }

    public void investigate(IncidentHuntService.Input input, String actor, ActionListener<Map<String,Object>> listener) {
        if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) throw new OpenSearchStatusException("Caller required",RestStatus.FORBIDDEN);
        if (!permits.tryAcquire()) throw new OpenSearchStatusException("Entity investigation busy",RestStatus.TOO_MANY_REQUESTS);
        var released = new java.util.concurrent.atomic.AtomicBoolean();
        ActionListener<Map<String,Object>> done = ActionListener.wrap(value -> {
            if (released.compareAndSet(false,true)) { permits.release(); listener.onResponse(value); }
        }, error -> { if (released.compareAndSet(false,true)) { permits.release(); listener.onFailure(error); } });
        var caller = pool.getThreadContext().newRestorableContext(false);
        try {
            // Search findings first, strictly under original caller. Hidden case lookup happens only after validation.
            hunt.hunt(input,ActionListener.wrap(result -> {
                try (ThreadContext.StoredContext ignored = caller.get()) {
                    if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) throw new OpenSearchStatusException("Caller context lost",RestStatus.FORBIDDEN);
                    var refs = references(result);
                    if (refs.isEmpty()) { done.onResponse(output(result,List.of())); return; }
                    lookup(refs,ActionListener.wrap(cases -> done.onResponse(output(result,cases)),done::onFailure));
                }
            },done::onFailure));
        } catch (Exception e) { done.onFailure(e); }
    }

    private void lookup(Set<FindingReference> refs, ActionListener<List<Map<String,Object>>> listener) {
        var request = new SearchRequest(IncidentRepository.INCIDENTS).source(build(refs));
        request.allowPartialSearchResults(false);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.search(request,ActionListener.wrap(response -> {
                var hits = response.getHits();
                if (response.isTimedOut() || response.getFailedShards()>0 || Boolean.TRUE.equals(response.isTerminatedEarly()) ||
                        hits.getTotalHits()==null || hits.getTotalHits().relation!=TotalHits.Relation.EQUAL_TO ||
                        hits.getTotalHits().value!=hits.getHits().length || hits.getHits().length>MAX_CASES) throw incomplete();
                var rows = new ArrayList<Map<String,Object>>();
                var seen = new HashSet<String>();
                for (var hit : hits.getHits()) {
                    if (!IncidentRepository.INCIDENTS.equals(hit.getIndex()) || !seen.add(hit.getId())) throw incomplete();
                    rows.add(project(hit.getId(),hit.getSourceAsMap(),refs));
                }
                rows.sort(java.util.Comparator.<Map<String,Object>>comparingInt(row -> ((List<?>)row.get("matches")).size()).reversed()
                        .thenComparing(row -> (String)row.get("id")));
                listener.onResponse(List.copyOf(rows));
            },listener::onFailure));
        }
    }

    private static Map<String,Object> output(Map<String,Object> result,List<Map<String,Object>> cases) {
        return Map.of("scope","caller_visible_hunt_shared_case_links","hunt",result,"cases",cases,"case_count",cases.size());
    }
    private static OpenSearchStatusException incomplete() {
        return new OpenSearchStatusException("Entity investigation incomplete or exceeds bounded coverage; narrow the hunt",RestStatus.CONFLICT);
    }
}
