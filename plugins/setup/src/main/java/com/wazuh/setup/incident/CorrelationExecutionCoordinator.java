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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Staged internal coordinator, not a registered service. A future caller MUST establish
 * trusted deployment scope, policy activation, source authorization and completeness.
 * The supplied receipts are internal capture results, not proof of ingestion completeness.
 */
final class CorrelationExecutionCoordinator {
    private final CorrelationExecutionLedger ledger;
    private final IncidentRepository incidents;
    private final Clock clock;

    CorrelationExecutionCoordinator(CorrelationExecutionLedger ledger, IncidentRepository incidents, Clock clock) {
        this.ledger = ledger; this.incidents = incidents; this.clock = clock;
    }

    record Result(UUID incidentId, boolean reservationReplayed, boolean incidentReplayed) {}

    void execute(UUID deployment, CorrelationPlanner.Group group, String actor,
            List<FindingCaptureReceipt> receipts, ActionListener<Result> listener) {
        final Map<String, Object> source;
        final Map<String, Object> origin;
        try {
            origin = CorrelationIncidentFactory.origin(deployment, group);
            source = CorrelationIncidentFactory.create(deployment, group, actor, clock.instant(), receipts);
        } catch (Exception e) { listener.onFailure(e); return; }
        ledger.reserve(deployment, group, ActionListener.wrap(reservation -> {
            incidents.create(source, ActionListener.wrap(created ->
                    finish(created, origin, actor, reservation, false, listener), error -> {
                if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) { listener.onFailure(error); return; }
                incidents.get(reservation.incidentId(), ActionListener.wrap(existing ->
                        finish(existing, origin, actor, reservation, true, listener), listener::onFailure));
            }));
        }, listener::onFailure));
    }

    private void finish(IncidentRepository.Stored stored, Map<String, Object> origin, String actor,
            CorrelationExecutionLedger.Result reservation, boolean replayed, ActionListener<Result> listener) {
        if (!CorrelationIncidentFactory.matches(stored.source(), origin, actor)) {
            listener.onFailure(new OpenSearchStatusException("Correlation incident identity collision", RestStatus.CONFLICT));
            return;
        }
        // Only recover revision one here. Never overwrite a later analyst mutation.
        if (Integer.valueOf(1).equals(stored.source().get("revision")) && stored.source().get("pending_activity") != null) {
            incidents.deliver(stored, ActionListener.wrap(delivered ->
                    verifyCreation(origin, actor, reservation, replayed, listener), listener::onFailure));
        } else {
            verifyCreation(origin, actor, reservation, replayed, listener);
        }
    }

    private void verifyCreation(Map<String, Object> origin, String actor,
            CorrelationExecutionLedger.Result reservation, boolean replayed, ActionListener<Result> listener) {
        incidents.readCreationActivity(reservation.incidentId(), ActionListener.wrap(event -> {
            if (!CorrelationIncidentFactory.matchesCreationEvent(event, origin, actor)) {
                listener.onFailure(new OpenSearchStatusException("Correlation creation audit mismatch", RestStatus.CONFLICT));
                return;
            }
            ledger.complete(origin, actor, ActionListener.wrap(ignored ->
                    listener.onResponse(new Result(reservation.incidentId(), reservation.replayed(), replayed)), listener::onFailure));
        }, listener::onFailure));
    }
}
