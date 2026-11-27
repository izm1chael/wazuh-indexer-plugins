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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Immutable per-window plan and completion, including zero-match windows. Not a distributed lock. */
final class AnalyticsRunStore {
    static final String INDEX = ".wazuh-analytics-runs-v1";
    private final Client client;
    private final ThreadPool pool;
    private final Clock clock;

    AnalyticsRunStore(Client client, ThreadPool pool, Clock clock) { this.client = client; this.pool = pool; this.clock = clock; }

    void reserve(AnalyticsWindow.Plan plan, String actor, ActionListener<Void> listener) {
        var fields = new LinkedHashMap<>(plan.fields(actor)); fields.put("state", "reserved");
        create(plan.key().id(), fields, listener);
    }

    void complete(AnalyticsWindow.Plan plan, String actor, ActionListener<Map<String, Object>> listener) {
        var fields = new LinkedHashMap<>(plan.fields(actor)); fields.put("state", "completed");
        create(plan.key().id() + ":completed", fields, ActionListener.wrap(ignored ->
                status(plan.key(), ActionListener.wrap(result -> {
                    if (!"completed".equals(result.get("state"))) throw new IllegalStateException("Completion unavailable");
                    listener.onResponse(result);
                }, listener::onFailure)), listener::onFailure));
    }

    private void create(String id, Map<String, Object> fields, ActionListener<Void> listener) {
        var doc = new LinkedHashMap<>(fields); doc.put("recorded_at", clock.instant().toString());
        var request = new IndexRequest(INDEX).id(id).opType(DocWriteRequest.OpType.CREATE).source(doc, XContentType.JSON)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.index(request, ActionListener.wrap(response -> listener.onResponse(null), error -> {
                if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) { listener.onFailure(error); return; }
                get(id, ActionListener.wrap(existing -> {
                    if (existing == null) throw conflict();
                    var actual = new LinkedHashMap<>(existing); actual.remove("recorded_at");
                    if (!IncidentRepository.sameEvent(fields, actual)) throw conflict();
                    listener.onResponse(null);
                }, listener::onFailure));
            }));
        }
    }

    void status(AnalyticsWindow.Key key, ActionListener<Map<String, Object>> listener) {
        get(key.id(), ActionListener.wrap(reserved -> {
            if (reserved == null) {
                get(key.id() + ":completed", ActionListener.wrap(orphan -> {
                    if (orphan != null) throw conflict();
                    listener.onResponse(Map.of("run_id", key.id(), "policy_id", key.policy().toString(), "policy_version", key.version(),
                            "from", key.from().toString(), "until", key.until().toString(), "state", "not_recorded"));
                }, listener::onFailure));
                return;
            }
            validate(key, reserved, "reserved");
            get(key.id() + ":completed", ActionListener.wrap(done -> {
                if (done != null) {
                    validate(key, done, "completed");
                    var expected = new LinkedHashMap<>(reserved); expected.remove("recorded_at"); expected.put("state", "completed");
                    var actual = new LinkedHashMap<>(done); actual.remove("recorded_at");
                    if (!IncidentRepository.sameEvent(expected, actual) ||
                            java.time.Instant.parse((String) done.get("recorded_at")).isBefore(java.time.Instant.parse((String) reserved.get("recorded_at")))) throw conflict();
                }
                var result = new LinkedHashMap<String, Object>();
                result.put("run_id", key.id());
                for (String field : Set.of("policy_id", "policy_version", "from", "until", "finding_count", "group_count", "below_threshold", "actor"))
                    result.put(field, reserved.get(field));
                result.put("state", done == null ? "reserved" : "completed");
                result.put("reserved_at", reserved.get("recorded_at"));
                result.put("completed_at", done == null ? null : done.get("recorded_at"));
                listener.onResponse(result);
            }, listener::onFailure));
        }, listener::onFailure));
    }

    static void validate(AnalyticsWindow.Key key, Map<String, Object> source, String state) {
        if (!source.keySet().equals(Set.of("id", "deployment_id", "policy_id", "policy_version", "from", "until", "actor", "plan_sha256",
                "finding_count", "group_count", "below_threshold", "state", "recorded_at")) ||
                !key.id().equals(source.get("id")) || !key.deployment().toString().equals(source.get("deployment_id")) ||
                !key.policy().toString().equals(source.get("policy_id")) || !Integer.valueOf(key.version()).equals(source.get("policy_version")) ||
                !key.from().toString().equals(source.get("from")) || !key.until().toString().equals(source.get("until")) ||
                !state.equals(source.get("state")) || !(source.get("actor") instanceof String actor) || actor.isBlank() || actor.length() > 1024 ||
                !(source.get("plan_sha256") instanceof String digest) || !digest.matches("[a-f0-9]{64}") ||
                !(source.get("finding_count") instanceof Integer findings) || findings < 0 || findings > AnalyticsWindow.MAX_FINDINGS ||
                !(source.get("group_count") instanceof Integer groups) || groups < 0 || groups > AnalyticsWindow.MAX_GROUPS ||
                !(source.get("below_threshold") instanceof Integer below) || below < 0 || below > findings ||
                groups * 2 > findings - below || (groups == 0) != (findings == below)) throw conflict();
        if (java.time.Instant.parse((String) source.get("recorded_at")).isBefore(key.until().plusSeconds(AnalyticsWindow.GRACE_SECONDS))) throw conflict();
    }

    private void get(String id, ActionListener<Map<String, Object>> listener) {
        try (ThreadContext.StoredContext ignored = pool.getThreadContext().stashContext()) {
            client.get(new GetRequest(INDEX, id), ActionListener.wrap(response -> {
                if (!response.isExists()) { listener.onResponse(null); return; }
                if (!INDEX.equals(response.getIndex()) || !id.equals(response.getId())) throw conflict();
                listener.onResponse(response.getSourceAsMap());
            }, listener::onFailure));
        }
    }

    private static OpenSearchStatusException conflict() {
        return new OpenSearchStatusException("Analytics plan changed or receipt conflicts; operator reconciliation required", RestStatus.CONFLICT);
    }
}
