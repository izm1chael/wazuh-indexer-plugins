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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.cluster.service.ClusterService;
import com.wazuh.setup.settings.PluginSettings;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.action.IncidentWriteAction.Grant;
import com.wazuh.setup.action.IncidentWriteRequest;
import com.wazuh.setup.action.IncidentWriteResponse;
import com.wazuh.setup.incident.IncidentPrincipal;
import com.wazuh.setup.incident.IncidentMutation.Operation;
import com.wazuh.setup.incident.IncidentWriteService;

/** Staged transport actions. Each concrete handler binds its grant independently of the request. */
public abstract class TransportIncidentWriteAction extends HandledTransportAction<IncidentWriteRequest, IncidentWriteResponse> {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final Grant grant;
    private final IncidentWriteService writer;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;

    protected TransportIncidentWriteAction(Grant grant, TransportService transport, ActionFilters filters,
            IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
        super(grant.actionName(), transport, filters, IncidentWriteRequest::new);
        this.grant = grant;
        this.writer = writer;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
    }

    @Override
    protected void doExecute(Task task, IncidentWriteRequest request, ActionListener<IncidentWriteResponse> listener) {
        try {
            if (!PluginSettings.INCIDENTS_ENABLED.get(clusterService.getSettings())) {
                throw new org.opensearch.OpenSearchStatusException("Experimental incidents are disabled", org.opensearch.core.rest.RestStatus.FORBIDDEN);
            }
            if (!grant.permits(request.operation())) {
                listener.onFailure(new OpenSearchStatusException("Operation not permitted by transport action", RestStatus.FORBIDDEN));
                return;
            }
            String actor = IncidentPrincipal.require(threadPool.getThreadContext());
            Map<String, Object> input = JSON.readValue(request.payload(), new TypeReference<Map<String, Object>>() {});
            if (input == null) {
                listener.onFailure(new OpenSearchStatusException("JSON object required", RestStatus.BAD_REQUEST));
                return;
            }
            ActionListener<IncidentWriteService.Result> result = ActionListener.wrap(
                    value -> listener.onResponse(new IncidentWriteResponse(value)), listener::onFailure);
            if (request.operation() == Operation.CREATE) writer.create(input, actor, result);
            else writer.command(request.id(), request.expectedRevision(), request.operation(), input, actor, result);
        } catch (IOException e) {
            listener.onFailure(new OpenSearchStatusException("Invalid incident JSON", RestStatus.BAD_REQUEST));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    public static final class Create extends TransportIncidentWriteAction {
        @Inject
        public Create(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.CREATE, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class Assign extends TransportIncidentWriteAction {
        @Inject
        public Assign(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.ASSIGN, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class Update extends TransportIncidentWriteAction {
        @Inject
        public Update(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.UPDATE, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class Close extends TransportIncidentWriteAction {
        @Inject
        public Close(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.CLOSE, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class Reopen extends TransportIncidentWriteAction {
        @Inject
        public Reopen(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.REOPEN, transport, filters, writer, threadPool, clusterService);
        }
    }
    public static final class Findings extends TransportIncidentWriteAction {
        @Inject
        public Findings(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.FINDINGS, transport, filters, writer, threadPool, clusterService);
        }
    }
    public static final class Collaborate extends TransportIncidentWriteAction {
        @Inject
        public Collaborate(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.COLLABORATE, transport, filters, writer, threadPool, clusterService);
        }
    }
    public static final class ResponseRequest extends TransportIncidentWriteAction {
        @Inject public ResponseRequest(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.RESPONSE_REQUEST, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class ResponseApproval extends TransportIncidentWriteAction {
        @Inject public ResponseApproval(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.RESPONSE_APPROVAL, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class ResponseOutcome extends TransportIncidentWriteAction {
        @Inject public ResponseOutcome(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.RESPONSE_OUTCOME, transport, filters, writer, threadPool, clusterService);
        }
    }
    public static final class PlaybookApply extends TransportIncidentWriteAction {
        @Inject public PlaybookApply(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.PLAYBOOK_APPLY, transport, filters, writer, threadPool, clusterService);
        }
    }
    public static final class AiFeedback extends TransportIncidentWriteAction {
        @Inject public AiFeedback(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.AI_FEEDBACK, transport, filters, writer, threadPool, clusterService);
        }
    }
    public static final class TuningPropose extends TransportIncidentWriteAction {
        @Inject public TuningPropose(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.TUNING_PROPOSE, transport, filters, writer, threadPool, clusterService);
        }
    }

    public static final class TuningReview extends TransportIncidentWriteAction {
        @Inject public TuningReview(TransportService transport, ActionFilters filters, IncidentWriteService writer, ThreadPool threadPool, ClusterService clusterService) {
            super(Grant.TUNING_REVIEW, transport, filters, writer, threadPool, clusterService);
        }
    }
}
