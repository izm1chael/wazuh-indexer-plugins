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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;
import org.opensearch.common.unit.TimeValue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Fixed, read-only hunt of currently caller-visible findings. Never run with elevated privileges. */
public final class IncidentHuntService {
    static final int MAX_HITS = 100, MAX_VALUES = 20;
    private static final String FINDINGS = "wazuh-findings-v5*";
    private static final Set<String> FIELDS = Set.of("wazuh.agent.id", "wazuh.agent.name", "host.id",
            "host.name", "host.hostname", "host.ip", "source.ip", "destination.ip",
            "user.name", "user.id", "user.domain", "dns.question.name",
            "file.hash.md5", "file.hash.sha1", "file.hash.sha256");
    private final Client client;

    public IncidentHuntService(Client client) { this.client = client; }

    public record Input(String field, List<String> values, Instant from, Instant until) {
        public Input {
            if (field == null || !FIELDS.contains(field) || values == null || values.isEmpty() ||
                    values.size() > MAX_VALUES || from == null || until == null ||
                    !from.isBefore(until) || from.isBefore(Instant.parse("2000-01-01T00:00:00Z")) ||
                    until.isAfter(Instant.parse("2100-01-01T00:00:00Z")) || until.isAfter(from.plusSeconds(7L * 86400))) {
                throw new IllegalArgumentException("Invalid bounded hunt");
            }
            var unique = new TreeSet<String>();
            for (String value : values) {
                if (!valid(field, value) || !unique.add(value)) throw new IllegalArgumentException("Invalid hunt value");
            }
            values = List.copyOf(unique);
        }
    }

    static boolean valid(String field, String value) {
        if (value == null || value.isBlank() || value.length() > 256 || !value.equals(value.trim()) ||
                value.chars().anyMatch(Character::isISOControl)) return false;
        if (field.equals("file.hash.md5")) return value.matches("[a-fA-F0-9]{32}");
        if (field.equals("file.hash.sha1")) return value.matches("[a-fA-F0-9]{40}");
        if (field.equals("file.hash.sha256")) return value.matches("[a-fA-F0-9]{64}");
        if (field.endsWith(".ip")) {
            // Exact IPv4 literals only in this initial version; never resolve a hostname.
            String[] parts = value.split("\\.", -1);
            if (parts.length != 4) return false;
            for (String part : parts) {
                if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255) return false;
            }
        }
        return true;
    }

    static SearchSourceBuilder build(Input input) {
        return new SearchSourceBuilder().query(QueryBuilders.boolQuery()
                .filter(QueryBuilders.rangeQuery("@timestamp").gte(input.from().toString()).lt(input.until().toString()))
                .filter(QueryBuilders.termsQuery(input.field(), input.values())))
                .size(MAX_HITS + 1).trackTotalHits(true).timeout(TimeValue.timeValueSeconds(15))
                .fetchSource(new String[]{"@timestamp", input.field()}, new String[0]);
    }

    /** Confirm matches against the returned caller-visible source. No raw source or unrelated values leave this boundary. */
    static Map<String, Object> project(Input input, FindingReference reference, Map<String, Object> source) {
        if (source == null) throw incomplete();
        var matched = new TreeSet<String>();
        // The existing bounded extractor may truncate arrays; reject unconfirmed candidates rather than guessing.
        for (String value : FindingIntelligence.values(source, input.field())) {
            if (input.values().contains(value)) matched.add(value);
        }
        String timestamp = FindingIntelligence.first(source, "@timestamp");
        if (matched.isEmpty() || timestamp == null) throw incomplete();
        Instant at;
        try { at = Instant.parse(timestamp); }
        catch (RuntimeException e) { throw incomplete(); }
        if (at.isBefore(input.from()) || !at.isBefore(input.until())) throw incomplete();
        return Map.of("index", reference.index(), "document_id", reference.documentId(),
                "timestamp", at.toString(), "matched_values", List.copyOf(matched));
    }

    public void hunt(Input input, ActionListener<Map<String, Object>> listener) {
        SearchRequest request = new SearchRequest(FINDINGS).source(build(input));
        request.allowPartialSearchResults(false);
        request.indicesOptions(org.opensearch.action.support.IndicesOptions.strictExpandOpen());
        client.search(request, ActionListener.wrap(response -> {
            try {
                var hits = response.getHits();
                if (response.isTimedOut() || response.getFailedShards() > 0 || response.isTerminatedEarly() == Boolean.TRUE ||
                        hits.getTotalHits() == null ||
                        hits.getTotalHits().relation != org.apache.lucene.search.TotalHits.Relation.EQUAL_TO ||
                        hits.getTotalHits().value != hits.getHits().length || hits.getHits().length > MAX_HITS) throw incomplete();
                var rows = new ArrayList<Map<String, Object>>();
                var seen = new HashSet<FindingReference>();
                for (var hit : hits.getHits()) {
                    var ref = new FindingReference(hit.getIndex(), hit.getId());
                    if (!seen.add(ref)) throw incomplete();
                    rows.add(project(input, ref, hit.getSourceAsMap()));
                }
                rows.sort(java.util.Comparator.comparing((Map<String, Object> row) -> Instant.parse((String) row.get("timestamp")))
                        .thenComparing(row -> (String) row.get("index")).thenComparing(row -> (String) row.get("document_id")));
                listener.onResponse(Map.of("scope", "caller_visible_findings_exact_terms", "field", input.field(),
                        "values", input.values(), "from", input.from().toString(), "until", input.until().toString(),
                        "rows", rows, "match_count", rows.size()));
            } catch (Exception e) { listener.onFailure(e); }
        }, listener::onFailure));
    }

    private static OpenSearchStatusException incomplete() {
        return new OpenSearchStatusException("Hunt unavailable, incomplete or exceeds 100 findings; narrow range or check field visibility",
                RestStatus.CONFLICT);
    }
}
