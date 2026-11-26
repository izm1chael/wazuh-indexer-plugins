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
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Read-only caller-context search of existing RC2 issued-action records, never a dispatch adapter. */
final class IssuedResponseSearch {
    static final String INDEX = "wazuh-active-responses*";
    static final int MAX_RESULTS = 100;
    private static final String[] FIELDS = {"@timestamp", "event.index", "event.doc_id",
            "wazuh.active_response.name", "wazuh.active_response.type", "wazuh.active_response.location",
            "wazuh.active_response.agent_id", "wazuh.agent.id"};
    private IssuedResponseSearch() {}

    static SearchSourceBuilder build(Set<FindingReference> references) {
        if (references.isEmpty() || references.size() > 25) throw new IllegalArgumentException("Invalid finding page");
        var query = QueryBuilders.boolQuery().minimumShouldMatch(1);
        for (FindingReference reference : references) {
            query.should(QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("event.index", reference.index()))
                    .filter(QueryBuilders.termQuery("event.doc_id", reference.documentId())));
        }
        return new SearchSourceBuilder().query(query).size(MAX_RESULTS + 1).trackTotalHits(true)
                .timeout(TimeValue.timeValueSeconds(15)).fetchSource(FIELDS, new String[0]);
    }

    static void search(Client client, Set<FindingReference> references, ActionListener<List<Map<String, Object>>> listener) {
        if (references.isEmpty()) { listener.onResponse(List.of()); return; }
        SearchRequest request = new SearchRequest(INDEX).source(build(references));
        request.allowPartialSearchResults(false);
        request.indicesOptions(org.opensearch.action.support.IndicesOptions.strictExpandOpen());
        client.search(request, ActionListener.wrap(response -> {
            var hits = response.getHits();
            if (response.isTimedOut() || response.getFailedShards() > 0 || Boolean.TRUE.equals(response.isTerminatedEarly()) ||
                    hits.getTotalHits() == null || hits.getTotalHits().relation != org.apache.lucene.search.TotalHits.Relation.EQUAL_TO ||
                    hits.getTotalHits().value != hits.getHits().length || hits.getHits().length > MAX_RESULTS) {
                listener.onFailure(new OpenSearchStatusException("Issued response search incomplete or exceeds limit", RestStatus.CONFLICT));
                return;
            }
            var rows = new ArrayList<Map<String, Object>>();
            for (var hit : hits.getHits()) {
                var row = project(hit.getIndex(), hit.getId(), hit.getSourceAsMap(), references);
                if (row != null) rows.add(row);
            }
            listener.onResponse(rows);
        }, listener::onFailure));
    }

    /** Require both exact source reference fields in the caller-visible source, not just query matches. */
    static Map<String, Object> project(String index, String id, Map<String, Object> source, Set<FindingReference> references) {
        if (source == null || index == null || id == null ||
                !(index.startsWith("wazuh-active-responses") || index.startsWith(".ds-wazuh-active-responses"))) return null;
        String sourceIndex = scalar(source, "event.index");
        String sourceId = scalar(source, "event.doc_id");
        FindingReference reference = references.stream().filter(ref -> ref.index().equals(sourceIndex) &&
                ref.documentId().equals(sourceId)).findFirst().orElse(null);
        if (reference == null) return null;
        var result = new LinkedHashMap<String, Object>();
        result.put("index", index); result.put("document_id", id); result.put("finding", reference.toMap());
        String time = scalar(source, "@timestamp");
        try { result.put("issued_at", time == null ? null : Instant.parse(time).toString()); }
        catch (RuntimeException e) { result.put("issued_at", null); }
        result.put("name", scalar(source, "wazuh.active_response.name"));
        result.put("type", scalar(source, "wazuh.active_response.type"));
        result.put("location", scalar(source, "wazuh.active_response.location"));
        result.put("configured_agent_id", scalar(source, "wazuh.active_response.agent_id"));
        result.put("source_agent_id", scalar(source, "wazuh.agent.id"));
        result.put("state", "issued_only"); result.put("execution_verified", false);
        return result;
    }

    private static String scalar(Map<String, Object> source, String path) {
        String[] parts = path.split("\\.");
        Object node = source;
        for (int n = 0; n < parts.length; n++) {
            if (!(node instanceof Map<?, ?> map)) return null;
            String rest = String.join(".", java.util.Arrays.copyOfRange(parts, n, parts.length));
            if (n < parts.length - 1 && map.containsKey(rest)) {
                if (map.containsKey(parts[n])) return null;
                node = map.get(rest); break;
            }
            node = map.get(parts[n]);
        }
        return node instanceof String text && !text.isBlank() && text.length() <= 1024 &&
                text.equals(text.trim()) && text.chars().noneMatch(Character::isISOControl) ? text : null;
    }
}
