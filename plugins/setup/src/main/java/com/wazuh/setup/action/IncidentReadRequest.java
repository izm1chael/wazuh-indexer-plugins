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
    public enum View { SUMMARY, ACTIVITY, FINDINGS, COLLABORATION }
    private final View view;
    private final int limit;
    private final int cursor;
    private final int expectedRevision;
    private final String id;
    private final IncidentReadService.Query query;

    public IncidentReadRequest(String id, IncidentReadService.Query query) {
        this(id, query, View.SUMMARY, 0, 0, 0);
    }

    public IncidentReadRequest(String id, IncidentReadService.Query query, View view, int limit, int cursor, int expectedRevision) {
        this.id = id;
        this.query = query;
        this.view = view;
        this.limit = limit;
        this.cursor = cursor;
        this.expectedRevision = expectedRevision;
    }

    public IncidentReadRequest(StreamInput in) throws IOException {
        super(in);
        this.view = in.readEnum(View.class);
        this.limit = in.readInt();
        this.cursor = in.readInt();
        this.expectedRevision = in.readInt();
        this.id = in.readOptionalString();
        this.query = in.readBoolean() ? new IncidentReadService.Query(in.readString(), in.readOptionalString(),
                in.readOptionalString(), in.readOptionalString(), in.readInt(),
                in.readBoolean() ? in.readLong() : null, in.readOptionalString()) : null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeEnum(view);
        out.writeInt(limit);
        out.writeInt(cursor);
        out.writeInt(expectedRevision);
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
        if (view == null || (view != View.SUMMARY && id == null)) errors.addValidationError("Investigation view requires an incident ID");
        if (view == View.ACTIVITY && (limit < 1 || limit > 100 || cursor < 0 || expectedRevision != 0)) errors.addValidationError("Invalid activity page");
        if (view == View.COLLABORATION && (limit < 1 || limit > 50 || cursor < 0 || expectedRevision != 0)) errors.addValidationError("Invalid collaboration page");
        if (view == View.FINDINGS && (limit < 1 || limit > 25 || cursor < 0 || cursor > 1000 || expectedRevision < 0 || (cursor > 0 && expectedRevision == 0))) errors.addValidationError("Invalid findings page");
        if (view == View.SUMMARY && (limit != 0 || cursor != 0 || expectedRevision != 0)) errors.addValidationError("Unexpected investigation parameters");
        if (id != null) {
            try { IncidentReadService.canonicalId(id); }
            catch (RuntimeException e) { errors.addValidationError("Canonical incident UUID required"); }
        }
        return errors.validationErrors().isEmpty() ? null : errors;
    }

    public View view() { return view; }
    public int limit() { return limit; }
    public int cursor() { return cursor; }
    public int expectedRevision() { return expectedRevision; }
    public String id() { return id; }
    public IncidentReadService.Query query() { return query; }
}
