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
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Read-only discovery under the original caller. Never stashes or elevates security context. */
public final class CorrelationPreviewService {
    private static final String FINDINGS = "wazuh-findings-v5*";
    private final Client client;

    public CorrelationPreviewService(Client client) { this.client = client; }

    public record Input(CorrelationPlanner.Policy policy, Instant from, Instant until) {
        public Input {
            if (policy == null || from == null || until == null || !from.isBefore(until) ||
                    from.isBefore(Instant.parse("2000-01-01T00:00:00Z")) ||
                    until.isAfter(Instant.parse("2100-01-01T00:00:00Z")) ||
                    until.isAfter(from.plusSeconds(7L * 86400))) throw new IllegalArgumentException("Invalid preview range");
            long seconds = policy.windowMinutes() * 60L;
            if (from.getNano() != 0 || until.getNano() != 0 ||
                    Math.floorMod(from.getEpochSecond(), seconds) != 0 ||
                    Math.floorMod(until.getEpochSecond(), seconds) != 0) {
                throw new IllegalArgumentException("Preview range must align to complete UTC policy windows");
            }
        }
    }

    static SearchSourceBuilder build(Input input) {
        List<String> rules = input.policy().allowedRules().stream().map(UUID::toString).sorted().toList();
        var ruleQuery = QueryBuilders.boolQuery()
                .should(QueryBuilders.termsQuery("wazuh.rule.uuid", rules))
                .should(QueryBuilders.termsQuery("rule.uuid", rules)).minimumShouldMatch(1);
        return new SearchSourceBuilder().query(QueryBuilders.boolQuery()
                .filter(QueryBuilders.rangeQuery("@timestamp").gte(input.from().toString()).lt(input.until().toString()))
                .filter(ruleQuery))
                .size(CorrelationPlanner.MAX_BATCH + 1).trackTotalHits(true)
                .timeout(TimeValue.timeValueSeconds(15))
                .fetchSource(new String[]{"@timestamp", "wazuh.cluster.name", "wazuh.agent.id",
                        "wazuh.rule.uuid", "rule.uuid"}, new String[0]);
    }

    record Versioned(CorrelationPlanner.Candidate candidate, long seqNo, long primaryTerm) {}
    record Scan(CorrelationPlanner.Preview preview, List<Versioned> candidates) {}

    public void preview(Input input, ActionListener<Map<String, Object>> listener) {
        scan(input, CorrelationPlanner.MAX_BATCH, ActionListener.wrap(result -> listener.onResponse(project(input, result.preview())), listener::onFailure));
    }

    /** Source scan always uses the caller context. Versioned observations are internal only. */
    void scan(Input input, int limit, ActionListener<Scan> listener) {
        if (limit < 1 || limit > CorrelationPlanner.MAX_BATCH) throw new IllegalArgumentException("Invalid scan limit");
        SearchRequest request = new SearchRequest(FINDINGS).source(build(input).size(limit + 1).seqNoAndPrimaryTerm(true));
        request.allowPartialSearchResults(false);
        request.indicesOptions(org.opensearch.action.support.IndicesOptions.strictExpandOpen());
        client.search(request, ActionListener.wrap(response -> {
            var hits = response.getHits();
            if (response.isTimedOut() || response.getFailedShards() > 0 || response.isTerminatedEarly() == Boolean.TRUE ||
                    hits.getTotalHits() == null ||
                    hits.getTotalHits().relation != org.apache.lucene.search.TotalHits.Relation.EQUAL_TO ||
                    hits.getTotalHits().value != hits.getHits().length ||
                    hits.getHits().length > limit) {
                listener.onFailure(new OpenSearchStatusException(
                        "Correlation scan incomplete or exceeds configured finding budget", RestStatus.CONFLICT));
                return;
            }
            List<Versioned> candidates = new ArrayList<>();
            for (var hit : hits.getHits()) {
                candidates.add(new Versioned(CorrelationPlanner.extract(new FindingReference(hit.getIndex(), hit.getId()), hit.getSourceAsMap()),
                        hit.getSeqNo(), hit.getPrimaryTerm()));
            }
            listener.onResponse(new Scan(CorrelationPlanner.plan(input.policy(), candidates.stream().map(Versioned::candidate).toList(),
                    input.from(), input.until()), List.copyOf(candidates)));
        }, listener::onFailure));
    }

    static Map<String, Object> project(Input input, CorrelationPlanner.Preview preview) {
        List<Map<String, Object>> groups = preview.eligible().stream().map(group -> Map.<String, Object>of(
                "key", group.key(), "window_start", group.windowStart().toString(), "window_end", group.windowEnd().toString(),
                "findings", group.findings().stream().map(FindingReference::toMap).toList())).toList();
        return Map.ofEntries(Map.entry("mode", "preview"), Map.entry("scope", "caller_visible_search_snapshot"),
                Map.entry("policy_id", input.policy().id().toString()), Map.entry("policy_version", input.policy().version()),
                Map.entry("from", input.from().toString()), Map.entry("until", input.until().toString()),
                Map.entry("groups", groups), Map.entry("distinct_candidates", preview.distinctCandidates()),
                Map.entry("duplicate_inputs", preview.duplicateInputs()), Map.entry("insufficient_identity", preview.insufficientIdentity()),
                Map.entry("excluded_rule", preview.excludedRule()), Map.entry("outside_range", preview.outsideRange()),
                Map.entry("below_threshold", preview.belowThreshold()));
    }
}
