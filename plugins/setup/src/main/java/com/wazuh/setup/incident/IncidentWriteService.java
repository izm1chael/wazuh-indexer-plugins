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

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/** Internal writer. The authenticated transport action must supply a trusted actor and
 * operation; the caller never submits an aggregate or an activity document. */
public final class IncidentWriteService {
    public record Result(Map<String, Object> incident, boolean activityPending) {}
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
        try {
            source = IncidentMutation.create(input, UUID.randomUUID(), actor, clock.instant());
        } catch (Exception e) {
            listener.onFailure(e);
            return;
        }
        repository.create(source, ActionListener.wrap(stored -> finish(stored, listener), listener::onFailure));
    }

    public void command(UUID id, int expectedRevision, IncidentMutation.Operation operation,
            Map<String, Object> input, String actor, ActionListener<Result> listener) {
        if (operation == IncidentMutation.Operation.ATTACH_FINDING) {
            final FindingReference reference;
            try {
                reference = FindingReference.parse(input);
            } catch (Exception e) {
                listener.onFailure(e);
                return;
            }
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
            repository.commit(previous, next, ActionListener.wrap(stored -> finish(stored, listener), listener::onFailure));
        }, listener::onFailure));
    }

    private void finish(IncidentRepository.Stored committed, ActionListener<Result> listener) {
        repository.deliver(committed, ActionListener.wrap(delivered -> listener.onResponse(publicResult(delivered, false)),
                error -> {
                    // A committed aggregate is not a rolled-back write just because delivery failed.
                    try {
                        deliveryFailure.accept(error);
                    } catch (RuntimeException ignored) {
                        // Reporting failure cannot change mutation outcome.
                    }
                    listener.onResponse(publicResult(committed, true));
                }));
    }

    private static Result publicResult(IncidentRepository.Stored stored, boolean pending) {
        Map<String, Object> result = new LinkedHashMap<>(stored.source());
        result.remove("pending_activity");
        return new Result(result, pending);
    }
}
