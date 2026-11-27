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

import org.opensearch.core.action.ActionListener;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Reserve once, deliver audit before returning dispatch permission. No network calls here. */
public final class IncidentSoarService {
    private final IncidentRepository repository;
    private final Clock clock;
    public IncidentSoarService(IncidentRepository repository, Clock clock) { this.repository = repository; this.clock = clock; }

    public void dispatch(UUID incident, int revision, String response, String scope, String actor, String manager, Set<String> agents,
            String outcome, ActionListener<Map<String, Object>> listener) {
        repository.get(incident, ActionListener.wrap(stored -> {
            var requested = IncidentResponses.project(stored.source()).stream().filter(row -> response.equals(row.get("id"))).findFirst().orElseThrow();
            if (!scope.equals(requested.get("scope"))) throw new org.opensearch.OpenSearchStatusException("Approved target changed", org.opensearch.core.rest.RestStatus.CONFLICT);
            var next = IncidentMutation.dispatchScan(stored.source(), revision, response, actor, clock.instant(), manager, agents, outcome);
            repository.commit(stored, next, ActionListener.wrap(committed ->
                repository.deliver(committed, ActionListener.wrap(delivered -> {
                    var source = delivered.source();
                    var record = IncidentResponses.project(source).stream().filter(row -> response.equals(row.get("id"))).findFirst().orElseThrow();
                    if (source.get("pending_activity") != null || !Integer.valueOf(revision + 1).equals(source.get("revision")) ||
                            !(outcome == null ? "dispatch_reserved" : outcome).equals(record.get("state"))) throw new IllegalStateException("Dispatch audit not confirmed");
                    listener.onResponse(Map.of("incident_id", incident.toString(), "response_id", response, "revision", revision + 1,
                            "scope", record.get("scope"), "state", record.get("state"), "actor", actor,
                            "at", record.get("finalized_at"), "execution_verified", false));
                }, listener::onFailure)), listener::onFailure));
        }, listener::onFailure));
    }
}
