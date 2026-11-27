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
package com.wazuh.setup.transport;

import com.wazuh.setup.action.IncidentResponseReadAction;
import com.wazuh.setup.action.IncidentReadRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IncidentInvestigationService;
import com.wazuh.setup.incident.IncidentPrincipal;
import com.wazuh.setup.incident.IncidentReadService;
import com.wazuh.setup.settings.PluginSettings;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public final class TransportIncidentResponseReadAction extends HandledTransportAction<IncidentReadRequest, IncidentReadResponse> {
    private final IncidentInvestigationService service;
    private final ThreadPool pool;
    private final ClusterService cluster;

    @Inject public TransportIncidentResponseReadAction(TransportService transport, ActionFilters filters,
            IncidentInvestigationService service, ThreadPool pool, ClusterService cluster) {
        super(IncidentResponseReadAction.NAME, transport, filters, IncidentReadRequest::new);
        this.service = service; this.pool = pool; this.cluster = cluster;
    }

    @Override protected void doExecute(Task task, IncidentReadRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(cluster.getSettings())) throw new OpenSearchStatusException("Incidents disabled", RestStatus.FORBIDDEN);
            String actor = IncidentPrincipal.require(pool.getThreadContext());
            if (request.view() == IncidentReadRequest.View.FINDINGS && request.id() != null && request.query() == null) {
                service.issuedResponses(IncidentReadService.canonicalId(request.id()), request.cursor(), request.limit(), request.expectedRevision(), actor,
                        ActionListener.wrap(body -> listener.onResponse(new IncidentReadResponse(body)), listener::onFailure));
                return;
            }
            if (request.id() == null || request.query() != null || request.view() != IncidentReadRequest.View.SUMMARY ||
                    request.limit() != 0 || request.cursor() != 0 || request.expectedRevision() != 0) {
                throw new OpenSearchStatusException("Exact incident response detail required", RestStatus.BAD_REQUEST);
            }
            service.responses(IncidentReadService.canonicalId(request.id()), ActionListener.wrap(
                    body -> listener.onResponse(new IncidentReadResponse(body)), listener::onFailure));
        } catch (Exception e) { listener.onFailure(e); }
    }
}
