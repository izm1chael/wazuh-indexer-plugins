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
package com.wazuh.setup.transport;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.Map;

import com.wazuh.setup.action.IncidentReadAction;
import com.wazuh.setup.action.IncidentReadRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import com.wazuh.setup.incident.IncidentPrincipal;
import com.wazuh.setup.incident.IncidentReadService;

/** Staged read action; never delegates to a generic client-controlled search endpoint. */
public final class TransportIncidentReadAction extends HandledTransportAction<IncidentReadRequest, IncidentReadResponse> {
    private final IncidentReadService service;
    private final ThreadPool threadPool;

    @Inject
    public TransportIncidentReadAction(TransportService transport, ActionFilters filters, IncidentReadService service, ThreadPool threadPool) {
        super(IncidentReadAction.NAME, transport, filters, IncidentReadRequest::new);
        this.service = service;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, IncidentReadRequest request, ActionListener<IncidentReadResponse> listener) {
        try {
            IncidentPrincipal.require(threadPool.getThreadContext());
            if (request.id() != null) {
                service.get(IncidentReadService.canonicalId(request.id()), ActionListener.wrap(
                        incident -> listener.onResponse(new IncidentReadResponse(Map.of("incident", incident))), listener::onFailure));
            } else {
                service.list(request.query(), ActionListener.wrap(
                        page -> listener.onResponse(new IncidentReadResponse(page)), listener::onFailure));
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }
}
