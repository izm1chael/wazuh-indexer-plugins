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

import org.opensearch.core.action.ActionListener;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ExceptionsHelper;
import org.opensearch.core.rest.RestStatus;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/** Internal writer. The authenticated transport action must supply a trusted actor and
 * operation; the caller never submits an aggregate or an activity document. */
public final class IncidentWriteService {
    public record Result(Map<String, Object> incident, boolean activityPending, boolean replayed) {}
    private final IncidentRepository repository;
    private final Clock clock;
    private final FindingAccess findingAccess;
    private final Consumer<Exception> deliveryFailure;

    public IncidentWriteService(IncidentRepository repository, FindingAccess findingAccess, Clock clock, Consumer<Exception> deliveryFailure) {
        this.repository = repository;
        this.findingAccess = findingAccess;
        this.clock = clock;
        this.deliveryFailure = deliveryFailure;
    }

    public void create(Map<String, Object> input, String actor, ActionListener<Result> listener) {
        final Map<String, Object> source;
        final UUID id;
        final String fingerprint;
        try {
            Map<String, Object> payload = new LinkedHashMap<>(input);
            UUID key = IncidentRequestIdentity.requireKey(payload.remove("request_id"));
            id = IncidentRequestIdentity.incidentId(actor, key);
            source = IncidentMutation.create(payload, id, actor, clock.instant());
            fingerprint = IncidentRequestIdentity.createFingerprint(source);
            source.put("create_request_hash", fingerprint);
        } catch (Exception e) {
            listener.onFailure(e);
            return;
        }
        repository.create(source, ActionListener.wrap(stored -> finish(stored, false, listener), error -> {
            if (ExceptionsHelper.status(error) != RestStatus.CONFLICT) {
                listener.onFailure(error);
                return;
            }
            repository.get(id, ActionListener.wrap(existing -> {
                if (!IncidentRequestIdentity.matches(existing.source(), actor, fingerprint)) {
                    listener.onFailure(new OpenSearchStatusException("Create request ID already used with different content", RestStatus.CONFLICT));
                    return;
                }
                // Return the current incident, not a fabricated replay of the original response.
                finish(existing, true, listener);
            }, listener::onFailure));
        }));
    }

    public void command(UUID id, int expectedRevision, IncidentMutation.Operation operation,
            Map<String, Object> input, String actor, ActionListener<Result> listener) {
        if (operation == IncidentMutation.Operation.ATTACH_FINDING || operation == IncidentMutation.Operation.DETACH_FINDING) {
            final FindingReference reference;
            try {
                reference = FindingReference.parse(input);
            } catch (Exception e) {
                listener.onFailure(e);
                return;
            }
            // Both operations require current finding visibility. Otherwise detach could be a membership oracle.
            // Expired/restricted link cleanup requires a separate privileged maintenance workflow.
            // This is the first asynchronous request, before repository.get stashes the caller.
            findingAccess.requireVisible(reference, ActionListener.wrap(
                    ignored -> mutate(id, expectedRevision, operation, input, actor, listener), listener::onFailure));
            return;
        }
        mutate(id, expectedRevision, operation, input, actor, listener);
    }

    private void mutate(UUID id, int expectedRevision, IncidentMutation.Operation operation,
            Map<String, Object> input, String actor, ActionListener<Result> listener) {
        repository.get(id, ActionListener.wrap(previous -> {
            Map<String, Object> next = IncidentMutation.apply(previous.source(), operation, input,
                    expectedRevision, actor, clock.instant());
            repository.commit(previous, next, ActionListener.wrap(stored -> finish(stored, false, listener), listener::onFailure));
        }, listener::onFailure));
    }

    private void finish(IncidentRepository.Stored committed, boolean replayed, ActionListener<Result> listener) {
        repository.deliver(committed, ActionListener.wrap(delivered -> listener.onResponse(publicResult(delivered, false, replayed)),
                error -> {
                    // A committed aggregate is not a rolled-back write just because delivery failed.
                    try {
                        deliveryFailure.accept(error);
                    } catch (RuntimeException ignored) {
                        // Reporting failure cannot change mutation outcome.
                    }
                    listener.onResponse(publicResult(committed, true, replayed));
                }));
    }

    private static Result publicResult(IncidentRepository.Stored stored, boolean pending, boolean replayed) {
        return new Result(IncidentReadService.project(stored.source()), pending, replayed);
    }
}
