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
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/** Execution entry point. Only the separately gated transport may supply the deployment and actor. */
public final class AnalyticsExecutionService {
    public static final String RUN_INDEX = AnalyticsRunStore.INDEX;
    public static final String CORRELATION_INDEX = CorrelationExecutionLedger.INDEX;
    private final CorrelationPolicyStore policies;
    private final CorrelationPreviewService preview;
    private final FindingAccess findings;
    private final CorrelationExecutionCoordinator coordinator;
    private final AnalyticsRunStore runs;
    private final ThreadPool pool;
    private final Clock clock;
    private final Semaphore permit = new Semaphore(1);

    public AnalyticsExecutionService(Client client, ThreadPool pool, Clock clock, IncidentRepository incidents) {
        this.pool = pool; this.clock = clock;
        policies = new CorrelationPolicyStore(client, pool, clock);
        preview = new CorrelationPreviewService(client);
        findings = new FindingAccess(client);
        coordinator = new CorrelationExecutionCoordinator(new CorrelationExecutionLedger(client, pool, clock), incidents, clock);
        runs = new AnalyticsRunStore(client, pool, clock);
    }

    public void status(UUID deployment, UUID policy, int version, Instant from, Instant until, ActionListener<Map<String, Object>> listener) {
        runs.status(new AnalyticsWindow.Key(deployment, policy, version, from, until), listener);
    }

    public void execute(UUID deployment, UUID policy, int version, Instant from, Instant until, String actor, String approvedHash,
            ActionListener<Map<String, Object>> listener) {
        var key = new AnalyticsWindow.Key(deployment, policy, version, from, until);
        if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext())) || approvedHash == null || !approvedHash.matches("[a-f0-9]{64}")) throw forbidden();
        if (!permit.tryAcquire()) throw new OpenSearchStatusException("Analytics execution busy", RestStatus.TOO_MANY_REQUESTS);
        var released = new AtomicBoolean();
        ActionListener<Map<String, Object>> finished = ActionListener.wrap(result -> {
            if (released.compareAndSet(false, true)) { permit.release(); listener.onResponse(result); }
        }, error -> {
            if (released.compareAndSet(false, true)) { permit.release(); listener.onFailure(error); }
        });
        try {
            // Capture before the first privileged store access. Restore only for source reads.
            var caller = pool.getThreadContext().newRestorableContext(true);
            long start = System.nanoTime();
            runs.status(key, ActionListener.wrap(status -> {
                if (!"not_recorded".equals(status.get("state")) && !actor.equals(status.get("actor"))) throw forbidden();
                policies.get(policy, version, ActionListener.wrap(saved -> {
                    var definition = policy(saved, policy, version);
                    if (!approvedHash.equals(AnalyticsWindow.policyFingerprint(definition))) throw forbidden();
                    if ("completed".equals(status.get("state"))) { finished.onResponse(status); return; }
                    var input = AnalyticsWindow.input(key, definition, clock.instant());
                    check(start);
                    try (ThreadContext.StoredContext ignored = caller.get()) {
                        if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) throw forbidden();
                        preview.scan(input, AnalyticsWindow.MAX_FINDINGS, ActionListener.wrap(scan -> {
                            var plan = AnalyticsWindow.plan(key, scan);
                            var needed = new HashSet<FindingReference>();
                            scan.preview().eligible().forEach(group -> needed.addAll(group.findings()));
                            var selected = scan.candidates().stream().filter(v -> needed.contains(v.candidate().reference())).toList();
                            capture(selected, 0, new HashMap<>(), actor, caller, start, ActionListener.wrap(receipts -> {
                                check(start);
                                runs.reserve(plan, actor, ActionListener.wrap(nothing ->
                                    createGroups(plan, scan.preview().eligible(), 0, receipts, actor, start, finished), finished::onFailure));
                            }, finished::onFailure));
                        }, finished::onFailure));
                    }
                }, finished::onFailure));
            }, finished::onFailure));
        } catch (Exception e) { finished.onFailure(e); }
    }

    static CorrelationPlanner.Policy policy(Map<String, Object> stored, UUID id, int version) {
        if (!id.toString().equals(stored.get("policy_id")) || !Integer.valueOf(version).equals(stored.get("policy_version")) ||
                !"preview_only".equals(stored.get("mode")) || !(stored.get("rules") instanceof List<?> raw) ||
                !(stored.get("window_minutes") instanceof Integer window) || !(stored.get("minimum_findings") instanceof Integer minimum))
            throw new IllegalStateException("Invalid saved analytics policy");
        var rules = new HashSet<UUID>();
        for (Object rule : raw) {
            if (!(rule instanceof String s) || !rules.add(IncidentReadService.canonicalId(s))) throw new IllegalStateException("Invalid saved rule identity");
        }
        var result = new CorrelationPlanner.Policy(id, version, rules, window, minimum);
        var expected = CorrelationPolicyStore.definition(result);
        var actual = new HashMap<String, Object>(); expected.keySet().forEach(field -> actual.put(field, stored.get(field)));
        if (!IncidentRepository.sameEvent(expected, actual)) throw new IllegalStateException("Saved policy content is not canonical");
        return result;
    }

    private void capture(List<CorrelationPreviewService.Versioned> candidates, int offset, Map<FindingReference, FindingCaptureReceipt> receipts,
            String actor, Supplier<ThreadContext.StoredContext> caller, long start, ActionListener<Map<FindingReference, FindingCaptureReceipt>> listener) {
        check(start);
        if (offset == candidates.size()) { listener.onResponse(Map.copyOf(receipts)); return; }
        try (ThreadContext.StoredContext ignored = caller.get()) {
            if (!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) throw forbidden();
            var candidate = candidates.get(offset);
            findings.captureCorrelation(candidate, actor, clock, ActionListener.wrap(receipt -> {
                if (receipts.putIfAbsent(receipt.reference(), receipt) != null) throw new IllegalStateException("Duplicate capture receipt");
                capture(candidates, offset + 1, receipts, actor, caller, start, listener);
            }, listener::onFailure));
        }
    }

    private void createGroups(AnalyticsWindow.Plan plan, List<CorrelationPlanner.Group> groups, int offset,
            Map<FindingReference, FindingCaptureReceipt> receipts, String actor, long start, ActionListener<Map<String, Object>> listener) {
        check(start);
        if (offset == groups.size()) { runs.complete(plan, actor, listener); return; }
        var group = groups.get(offset);
        var captures = new ArrayList<FindingCaptureReceipt>();
        for (var ref : group.findings()) {
            var receipt = receipts.get(ref);
            if (receipt == null) throw new IllegalStateException("Missing group capture receipt");
            captures.add(receipt);
        }
        coordinator.execute(plan.key().deployment(), group, actor, captures, ActionListener.wrap(result -> {
            if (!CorrelationExecutionIdentity.reserve(plan.key().deployment(), group).incidentId().equals(result.incidentId()))
                throw new IllegalStateException("Unexpected incident identity");
            createGroups(plan, groups, offset + 1, receipts, actor, start, listener);
        }, listener::onFailure));
    }

    private static void check(long start) {
        if (System.nanoTime() - start > 120_000_000_000L)
            throw new OpenSearchStatusException("Analytics execution budget exceeded; inspect window status", RestStatus.CONFLICT);
    }
    private static OpenSearchStatusException forbidden() {
        return new OpenSearchStatusException("Analytics execution principal unavailable", RestStatus.FORBIDDEN);
    }
}
