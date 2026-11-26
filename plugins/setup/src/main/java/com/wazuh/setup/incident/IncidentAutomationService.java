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
import org.opensearch.search.sort.SortOrder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/** Bounded current-state automation sweep. No finding queries, endpoint calls or arbitrary mutations. */
public final class IncidentAutomationService {
    static final int PAGE_SIZE = 10;
    private final Client client;
    private final ThreadPool pool;
    private final IncidentRepository repository;
    private final IncidentAutomationStore store;
    private final Clock clock;
    private final AtomicBoolean running = new AtomicBoolean();

    public IncidentAutomationService(Client client, ThreadPool pool, IncidentRepository repository,
            IncidentAutomationStore store, Clock clock) {
        this.client = client; this.pool = pool; this.repository = repository; this.store = store; this.clock = clock;
    }

    public void history(UUID incident, ActionListener<Map<String, Object>> listener) {
        repository.get(incident, ActionListener.wrap(stored -> listener.onResponse(Map.of(
                "incident_id", incident.toString(), "revision", stored.source().get("revision"),
                "activity_pending", stored.source().get("pending_activity") != null,
                "runs", IncidentAutomationPolicy.receipts(stored.source()))), listener::onFailure));
    }

    public void preview(UUID policy, int version, UUID incident, String actor, ActionListener<Map<String, Object>> listener) {
        store.get(policy, version, ActionListener.wrap(saved -> repository.get(incident, ActionListener.wrap(stored -> {
            var source = stored.source();
            int revision = (Integer) source.get("revision");
            if (source.get("pending_activity") != null || "closed".equals(source.get("status"))) {
                listener.onResponse(previewResult(saved.policy(), incident, revision, "ineligible", null, 0)); return;
            }
            repository.readActivity(incident, revision, ActionListener.wrap(event -> {
                var rule = IncidentAutomationPolicy.match(saved.policy(), source, event);
                if (rule == null) { listener.onResponse(previewResult(saved.policy(), incident, revision, "not_matched", null, 0)); return; }
                Map<String, Object> next;
                try { next = IncidentMutation.automate(source, event, saved.policy(), actor, clock.instant()); }
                catch (OpenSearchStatusException e) {
                    listener.onResponse(previewResult(saved.policy(), incident, revision, "blocked", rule.id(), 0)); return;
                }
                var receipts = IncidentAutomationPolicy.receipts(next);
                listener.onResponse(previewResult(saved.policy(), incident, revision, "matched", rule.id(),
                        (Integer) receipts.get(receipts.size() - 1).get("changed_fields")));
            }, listener::onFailure));
        }, listener::onFailure)), listener::onFailure));
    }

    private static Map<String, Object> previewResult(IncidentAutomationPolicy.Policy policy, UUID incident, int revision,
            String state, String rule, int changes) {
        var out = new LinkedHashMap<String, Object>();
        out.put("policy_id", policy.id().toString()); out.put("policy_version", policy.version());
        out.put("incident_id", incident.toString()); out.put("revision", revision);
        out.put("state", state); out.put("rule_id", rule); out.put("changed_fields", changes);
        return out;
    }

    public void tick(UUID policy, int version, String hash, UUID after, String actor, ActionListener<Map<String, Object>> listener) {
        if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext())) || hash == null || !hash.matches("[a-f0-9]{64}"))
            throw new OpenSearchStatusException("Automation principal or approval unavailable", RestStatus.FORBIDDEN);
        if (!running.compareAndSet(false, true)) throw new OpenSearchStatusException("Automation sweep busy", RestStatus.TOO_MANY_REQUESTS);
        var released = new AtomicBoolean();
        ActionListener<Map<String, Object>> done = ActionListener.wrap(result -> {
            if (released.compareAndSet(false, true)) { running.set(false); listener.onResponse(result); }
        }, error -> { if (released.compareAndSet(false, true)) { running.set(false); listener.onFailure(error); } });
        try {
            store.get(policy, version, ActionListener.wrap(saved -> {
                if (!hash.equals(saved.policy().fingerprint())) throw new OpenSearchStatusException("Automation approval mismatch", RestStatus.FORBIDDEN);
                search(after, ActionListener.wrap(ids -> {
                    var counts = new Counts();
                    process(saved.policy(), ids, 0, actor, counts, done);
                }, done::onFailure));
            }, done::onFailure));
        } catch (Exception e) { done.onFailure(e); }
    }

    static SearchSourceBuilder query(UUID after) {
        var source = new SearchSourceBuilder().query(QueryBuilders.termsQuery("status", List.of("new", "triaging", "active")))
                .sort("id", SortOrder.ASC).size(PAGE_SIZE).trackTotalHits(false).fetchSource(false)
                .timeout(TimeValue.timeValueSeconds(15));
        if (after != null) source.searchAfter(new Object[]{after.toString()});
        return source;
    }

    private void search(UUID after, ActionListener<List<UUID>> listener) {
        var request = new SearchRequest(IncidentRepository.INCIDENTS).source(query(after));
        request.allowPartialSearchResults(false);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.search(request, ActionListener.wrap(response -> {
                if (response.isTimedOut() || response.getFailedShards() > 0 || Boolean.TRUE.equals(response.isTerminatedEarly()))
                    throw new OpenSearchStatusException("Incomplete automation sweep", RestStatus.CONFLICT);
                var ids = new ArrayList<UUID>();
                String prior = after == null ? "" : after.toString();
                for (var hit : response.getHits().getHits()) {
                    UUID id = IncidentReadService.canonicalId(hit.getId());
                    if (!IncidentRepository.INCIDENTS.equals(hit.getIndex()) || id.toString().compareTo(prior) <= 0 || ids.size() >= PAGE_SIZE)
                        throw new IllegalStateException("Invalid sweep ordering");
                    ids.add(id); prior = id.toString();
                }
                listener.onResponse(List.copyOf(ids));
            }, listener::onFailure));
        }
    }

    private static final class Counts {
        int applied, noChange, skipped, pending, failed;
    }

    private void process(IncidentAutomationPolicy.Policy policy, List<UUID> ids, int offset, String actor,
            Counts counts, ActionListener<Map<String, Object>> listener) {
        if (offset == ids.size()) {
            var out = new LinkedHashMap<String, Object>();
            out.put("policy_id", policy.id().toString()); out.put("policy_version", policy.version());
            out.put("fingerprint", policy.fingerprint()); out.put("actor", actor);
            out.put("scanned", ids.size()); out.put("applied", counts.applied); out.put("no_change", counts.noChange);
            out.put("skipped", counts.skipped); out.put("pending", counts.pending); out.put("failed", counts.failed);
            out.put("next_after", ids.size() == PAGE_SIZE ? ids.get(ids.size() - 1).toString() : null);
            listener.onResponse(out); return;
        }
        var id = ids.get(offset);
        Runnable advance = () -> process(policy, ids, offset + 1, actor, counts, listener);
        java.util.function.Consumer<Exception> failure = error -> { counts.failed++; advance.run(); };
        try {
            repository.get(id, ActionListener.wrap(stored -> {
                var source = stored.source();
                if (source.get("pending_activity") != null) { counts.pending++; advance.run(); return; }
                if ("closed".equals(source.get("status")) || IncidentAutomationPolicy.receipts(source).stream().anyMatch(row ->
                        policy.id().toString().equals(row.get("policy_id")) && Integer.valueOf(policy.version()).equals(row.get("policy_version")))) {
                    counts.skipped++; advance.run(); return;
                }
                int revision = (Integer) source.get("revision");
                repository.readActivity(id, revision, ActionListener.wrap(event -> {
                    if (IncidentAutomationPolicy.match(policy, source, event) == null) { counts.skipped++; advance.run(); return; }
                    var next = IncidentMutation.automate(source, event, policy, actor, clock.instant());
                    var history = IncidentAutomationPolicy.receipts(next);
                    int changed = (Integer) history.get(history.size() - 1).get("changed_fields");
                    repository.commit(stored, next, ActionListener.wrap(committed ->
                            repository.deliver(committed, ActionListener.wrap(delivered -> {
                                if (changed == 0) counts.noChange++; else counts.applied++;
                                advance.run();
                            }, error -> { counts.pending++; advance.run(); })), failure::accept));
                }, failure::accept));
            }, failure::accept));
        } catch (Exception e) { failure.accept(e); }
    }
}
