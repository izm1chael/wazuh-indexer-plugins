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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

import com.wazuh.setup.incident.IncidentReadService;

/** Exactly one detail or queue query; validated again at the transport boundary. */
public final class IncidentReadRequest extends ActionRequest {
    private final String id;
    private final IncidentReadService.Query query;

    public IncidentReadRequest(String id, IncidentReadService.Query query) {
        this.id = id;
        this.query = query;
    }

    public IncidentReadRequest(StreamInput in) throws IOException {
        super(in);
        this.id = in.readOptionalString();
        this.query = in.readBoolean() ? new IncidentReadService.Query(in.readString(), in.readOptionalString(),
                in.readOptionalString(), in.readOptionalString(), in.readInt(),
                in.readBoolean() ? in.readLong() : null, in.readOptionalString()) : null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(id);
        out.writeBoolean(query != null);
        if (query != null) {
            out.writeString(query.queue());
            out.writeOptionalString(query.severity());
            out.writeOptionalString(query.owner());
            out.writeOptionalString(query.search());
            out.writeInt(query.limit());
            out.writeBoolean(query.afterTime() != null);
            if (query.afterTime() != null) out.writeLong(query.afterTime());
            out.writeOptionalString(query.afterId());
        }
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        if ((id == null) == (query == null)) errors.addValidationError("Exactly one incident detail or queue query required");
        if (id != null) {
            try { IncidentReadService.canonicalId(id); }
            catch (RuntimeException e) { errors.addValidationError("Canonical incident UUID required"); }
        }
        return errors.validationErrors().isEmpty() ? null : errors;
    }

    public String id() { return id; }
    public IncidentReadService.Query query() { return query; }
}
