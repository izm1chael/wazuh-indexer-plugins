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
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import com.wazuh.setup.incident.IncidentMutation.Operation;

/** Raw bounded JSON and a workflow command. No user identity or target index is accepted. */
public final class IncidentWriteRequest extends ActionRequest {
    private final Operation operation;
    private final String id;
    private final int expectedRevision;
    private final String payload;

    public IncidentWriteRequest(Operation operation, String id, int expectedRevision, String payload) {
        this.operation = operation;
        this.id = id;
        this.expectedRevision = expectedRevision;
        this.payload = payload;
    }

    public IncidentWriteRequest(StreamInput in) throws IOException {
        super(in);
        this.operation = in.readEnum(Operation.class);
        this.id = in.readOptionalString();
        this.expectedRevision = in.readInt();
        this.payload = in.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeEnum(operation);
        out.writeOptionalString(id);
        out.writeInt(expectedRevision);
        out.writeString(payload);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        if (operation == null) errors.addValidationError("Operation is required");
        if (payload == null || payload.getBytes(StandardCharsets.UTF_8).length > 256 * 1024) {
            errors.addValidationError("JSON body is required and must not exceed 256 KiB");
        }
        if (operation == Operation.CREATE) {
            if (id != null || expectedRevision != 0) errors.addValidationError("Create does not accept an incident ID or revision");
        } else {
            try {
                if (id == null || !UUID.fromString(id).toString().equals(id)) throw new IllegalArgumentException();
            } catch (IllegalArgumentException e) {
                errors.addValidationError("Canonical incident UUID required");
            }
            if (expectedRevision < 1) errors.addValidationError("Positive expected revision required");
        }
        return errors.validationErrors().isEmpty() ? null : errors;
    }

    public Operation operation() { return operation; }
    public UUID id() { return UUID.fromString(id); }
    public int expectedRevision() { return expectedRevision; }
    public String payload() { return payload; }
}
