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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

public class CorrelationExecutionCoordinatorTests extends OpenSearchTestCase {
    private static final UUID DEPLOYMENT = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID POLICY = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final Instant NOW = Instant.EPOCH.plusSeconds(1000);
    private static final FindingReference A = new FindingReference(".ds-wazuh-findings-v5-security-000001", "a");
    private static final FindingReference B = new FindingReference(".ds-wazuh-findings-v5-security-000001", "b");
    private static final String ACTOR = "automation";
    private final CorrelationPlanner.Group group = new CorrelationPlanner.Group("a".repeat(64), POLICY, 1,
            Instant.EPOCH, Instant.EPOCH.plusSeconds(900), List.of(A, B));

    private List<FindingCaptureReceipt> receipts() {
        return group.findings().stream().map(ref -> FindingCaptureReceipt.create(ref, Map.of("message", "private"), NOW, ACTOR, 1, 1)).toList();
    }

    private static OpenSearchStatusException conflict() { return new OpenSearchStatusException("conflict", RestStatus.CONFLICT); }

    private static final class Fake implements CorrelationExecutionCoordinator.LedgerPort, CorrelationExecutionCoordinator.IncidentPort {
        final List<String> calls = new ArrayList<>();
        Map<String, Object> origin;
        IncidentRepository.Stored stored;
        Map<String, Object> event;
        boolean failCompletion;
        boolean failDelivery;
        boolean completed;

        public void reserve(UUID deployment, CorrelationPlanner.Group group, ActionListener<CorrelationExecutionLedger.Result> listener) {
            calls.add("reserve");
            var expected = CorrelationExecutionLedger.immutableFields(deployment, group);
            boolean replayed = origin != null;
            if (replayed && !CorrelationExecutionLedger.matches(expected, origin)) { listener.onFailure(conflict()); return; }
            origin = expected;
            listener.onResponse(new CorrelationExecutionLedger.Result((String) origin.get("id"), UUID.fromString((String) origin.get("incident_id")), replayed));
        }
        public void readReservation(UUID deployment, String id, ActionListener<Map<String, Object>> listener) {
            calls.add("readReservation");
            if (origin == null || !id.equals(origin.get("id")) || !deployment.toString().equals(origin.get("deployment_id"))) {
                listener.onFailure(conflict()); return;
            }
            listener.onResponse(origin);
        }
        public void create(Map<String, Object> source, ActionListener<IncidentRepository.Stored> listener) {
            calls.add("create");
            if (stored != null) { listener.onFailure(conflict()); return; }
            stored = new IncidentRepository.Stored(source, 1, 1);
            listener.onResponse(stored);
        }
        public void get(UUID id, ActionListener<IncidentRepository.Stored> listener) {
            calls.add("get");
            if (stored == null) { listener.onFailure(conflict()); return; }
            listener.onResponse(stored);
        }
        @SuppressWarnings("unchecked")
        public void deliver(IncidentRepository.Stored input, ActionListener<IncidentRepository.Stored> listener) {
            calls.add("deliver");
            if (failDelivery) { listener.onFailure(conflict()); return; }
            event = (Map<String, Object>) input.source().get("pending_activity");
            var source = new LinkedHashMap<>(input.source());
            source.put("pending_activity", null);
            stored = new IncidentRepository.Stored(source, 2, 1);
            listener.onResponse(stored);
        }
        public void readCreationActivity(UUID id, ActionListener<Map<String, Object>> listener) {
            calls.add("readActivity");
            if (event == null) { listener.onFailure(conflict()); return; }
            listener.onResponse(event);
        }
        public void complete(Map<String, Object> origin, String actor, ActionListener<Void> listener) {
            calls.add("complete");
            if (failCompletion) { listener.onFailure(conflict()); return; }
            completed = true;
            listener.onResponse(null);
        }
    }

    private CorrelationExecutionCoordinator coordinator(Fake fake) {
        return new CorrelationExecutionCoordinator(fake, fake, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    public void testCompletionAfterVerifiedActivity() {
        var fake = new Fake();
        var result = new AtomicReference<CorrelationExecutionCoordinator.Result>();
        var failure = new AtomicReference<Exception>();
        coordinator(fake).execute(DEPLOYMENT, group, ACTOR, receipts(), ActionListener.wrap(result::set, failure::set));
        assertNull(failure.get());
        assertNotNull(result.get());
        assertTrue(fake.completed);
        assertEquals(List.of("reserve", "create", "deliver", "readActivity", "complete"), fake.calls);
    }

    public void testInterruptedCompletionReconcilesWithoutCreatingAgain() {
        var fake = new Fake();
        fake.failCompletion = true;
        var result = new AtomicReference<CorrelationExecutionCoordinator.Result>();
        var failure = new AtomicReference<Exception>();
        var coordinator = coordinator(fake);
        coordinator.execute(DEPLOYMENT, group, ACTOR, receipts(), ActionListener.wrap(result::set, failure::set));
        assertNotNull(failure.get());
        assertFalse(fake.completed);
        fake.failCompletion = false;
        fake.calls.clear();
        failure.set(null);
        coordinator.reconcile(DEPLOYMENT, (String) fake.origin.get("id"), ACTOR, ActionListener.wrap(result::set, failure::set));
        assertNull(failure.get());
        assertTrue(result.get().incidentReplayed());
        assertEquals(List.of("readReservation", "get", "readActivity", "complete"), fake.calls);
    }

    public void testDeliveryFailureDoesNotComplete() {
        var fake = new Fake();
        fake.failDelivery = true;
        var failure = new AtomicReference<Exception>();
        coordinator(fake).execute(DEPLOYMENT, group, ACTOR, receipts(), ActionListener.wrap(result -> fail("unexpected completion"), failure::set));
        assertNotNull(failure.get());
        assertFalse(fake.completed);
        assertEquals(List.of("reserve", "create", "deliver"), fake.calls);
    }

    public void testMissingAggregateDuringReconciliationNeverCreates() {
        var fake = new Fake();
        fake.origin = CorrelationExecutionLedger.immutableFields(DEPLOYMENT, group);
        var failure = new AtomicReference<Exception>();
        coordinator(fake).reconcile(DEPLOYMENT, (String) fake.origin.get("id"), ACTOR, ActionListener.wrap(result -> fail("unexpected completion"), failure::set));
        assertNotNull(failure.get());
        assertEquals(List.of("readReservation", "get"), fake.calls);
    }
}
