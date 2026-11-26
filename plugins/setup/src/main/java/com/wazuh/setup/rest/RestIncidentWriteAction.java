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
package com.wazuh.setup.rest;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.setup.action.IncidentWriteAction;
import com.wazuh.setup.action.IncidentWriteRequest;
import com.wazuh.setup.action.IncidentWriteResponse;
import com.wazuh.setup.incident.IncidentMutation.Operation;

/** Staged REST facade. Each operation maps to a fixed permission-bearing action. */
public final class RestIncidentWriteAction extends BaseRestHandler {
    private static final String ROOT = "/_plugins/_setup/incidents";
    private static final String COMMAND = ROOT + "/{id}/{command}";

    @Override
    public String getName() { return "wazuh_incident_write"; }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, ROOT), new Route(RestRequest.Method.POST, COMMAND));
    }

    public record Dispatch(IncidentWriteAction action, Operation operation) {}

    public static Dispatch dispatch(String command) {
        if (command == null) return new Dispatch(IncidentWriteAction.CREATE, Operation.CREATE);
        return switch (command) {
            case "assign-self" -> new Dispatch(IncidentWriteAction.ASSIGN, Operation.ASSIGN_SELF);
            case "unassign" -> new Dispatch(IncidentWriteAction.ASSIGN, Operation.UNASSIGN);
            case "start-triage" -> new Dispatch(IncidentWriteAction.UPDATE, Operation.START_TRIAGE);
            case "activate" -> new Dispatch(IncidentWriteAction.UPDATE, Operation.ACTIVATE);
            case "edit" -> new Dispatch(IncidentWriteAction.UPDATE, Operation.EDIT);
            case "close" -> new Dispatch(IncidentWriteAction.CLOSE, Operation.CLOSE);
            case "reopen" -> new Dispatch(IncidentWriteAction.REOPEN, Operation.REOPEN);
            case "attach-finding" -> new Dispatch(IncidentWriteAction.FINDINGS, Operation.ATTACH_FINDING);
            case "detach-finding" -> new Dispatch(IncidentWriteAction.FINDINGS, Operation.DETACH_FINDING);
            case "add-note" -> new Dispatch(IncidentWriteAction.COLLABORATE, Operation.ADD_NOTE);
            case "create-task" -> new Dispatch(IncidentWriteAction.COLLABORATE, Operation.CREATE_TASK);
            case "complete-task" -> new Dispatch(IncidentWriteAction.COLLABORATE, Operation.COMPLETE_TASK);
            case "reopen-task" -> new Dispatch(IncidentWriteAction.COLLABORATE, Operation.REOPEN_TASK);
            case "request-response" -> new Dispatch(IncidentWriteAction.RESPONSE_REQUEST, Operation.REQUEST_RESPONSE);
            case "cancel-response" -> new Dispatch(IncidentWriteAction.RESPONSE_REQUEST, Operation.CANCEL_RESPONSE);
            case "approve-response" -> new Dispatch(IncidentWriteAction.RESPONSE_APPROVAL, Operation.APPROVE_RESPONSE);
            case "reject-response" -> new Dispatch(IncidentWriteAction.RESPONSE_APPROVAL, Operation.REJECT_RESPONSE);
            case "record-response-outcome" -> new Dispatch(IncidentWriteAction.RESPONSE_OUTCOME, Operation.RECORD_RESPONSE_OUTCOME);
            case "record-ai-feedback" -> new Dispatch(IncidentWriteAction.AI_FEEDBACK, Operation.RECORD_AI_FEEDBACK);
            case "apply-playbook" -> new Dispatch(IncidentWriteAction.PLAYBOOK_APPLY, Operation.APPLY_PLAYBOOK);
            default -> throw new IllegalArgumentException("Unknown incident command");
        };
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        // Route matching determines whether a command was supplied; the command value cannot
        // select an arbitrary action or index. Transport also checks operation/grant binding.
        String id = request.param("id");
        String command = request.param("command");
        if ((id == null) != (command == null) || (ROOT.equals(request.path()) && id != null)) {
            throw new IllegalArgumentException("Invalid incident route");
        }
        Dispatch dispatch = dispatch(command);
        int revision = request.paramAsInt("expected_revision", 0);
        String payload = request.hasContent() ? request.content().utf8ToString() : "{}";
        IncidentWriteRequest write = new IncidentWriteRequest(dispatch.operation(), id, revision, payload);
        return channel -> client.execute(dispatch.action(), write,
                new RestResponseListener<IncidentWriteResponse>(channel) {
                    @Override
                    public org.opensearch.rest.RestResponse buildResponse(IncidentWriteResponse response) throws Exception {
                        return new BytesRestResponse(org.opensearch.core.rest.RestStatus.OK,
                                response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
                    }
                });
    }
}
