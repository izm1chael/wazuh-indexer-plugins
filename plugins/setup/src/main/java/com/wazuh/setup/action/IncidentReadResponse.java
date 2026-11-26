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
package com.wazuh.setup.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Map;

public final class IncidentReadResponse extends ActionResponse implements ToXContent {
    private final Map<String, Object> body;

    public IncidentReadResponse(Map<String, Object> body) { this.body = body; }

    @SuppressWarnings("unchecked")
    public IncidentReadResponse(StreamInput in) throws IOException {
        this.body = (Map<String, Object>) in.readGenericValue();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException { out.writeGenericValue(body); }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException { return builder.map(body); }
}
