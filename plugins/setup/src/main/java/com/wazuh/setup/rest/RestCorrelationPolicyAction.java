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
package com.wazuh.setup.rest;

import com.wazuh.setup.action.CorrelationPolicyAction;
import com.wazuh.setup.action.IncidentCorrelationRequest;
import com.wazuh.setup.action.IncidentReadResponse;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;
import java.util.List;

public final class RestCorrelationPolicyAction extends BaseRestHandler {
    private static final String ROOT = "/_plugins/_setup/incident-correlation/policies";
    @Override public String getName() { return "wazuh_correlation_policy"; }
    @Override public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, ROOT + "/save"), new Route(RestRequest.Method.POST, ROOT + "/read"));
    }
    @Override protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        var action = request.path().equals(ROOT + "/save") ? CorrelationPolicyAction.SAVE : CorrelationPolicyAction.READ;
        var body = new IncidentCorrelationRequest(request.content().utf8ToString());
        return channel -> client.execute(action, body, new RestResponseListener<IncidentReadResponse>(channel) {
            @Override public org.opensearch.rest.RestResponse buildResponse(IncidentReadResponse response) throws Exception {
                return new BytesRestResponse(RestStatus.OK, response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        });
    }
}
