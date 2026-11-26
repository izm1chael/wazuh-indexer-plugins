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
package com.wazuh.setup.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class IndicatorCatalogRequest extends ActionRequest {
    private final String payload;
    public IndicatorCatalogRequest(String payload) { this.payload = payload; }
    public IndicatorCatalogRequest(StreamInput in) throws IOException { super(in); payload = in.readString(); }
    @Override public void writeTo(StreamOutput out) throws IOException { super.writeTo(out); out.writeString(payload); }
    @Override public ActionRequestValidationException validate() {
        if (payload != null && payload.getBytes(StandardCharsets.UTF_8).length <= 16384) return null;
        ActionRequestValidationException error = new ActionRequestValidationException();
        error.addValidationError("Indicator catalog JSON must not exceed 16 KiB");
        return error;
    }
    public String payload() { return payload; }
}
