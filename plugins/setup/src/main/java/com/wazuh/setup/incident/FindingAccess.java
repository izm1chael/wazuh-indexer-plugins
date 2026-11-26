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
package com.wazuh.setup.incident;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.client.Client;
import java.time.Clock;

/**
 * Verify visibility under the ORIGINAL caller's security context. No stashing or privilege
 * elevation is allowed here. No finding source is returned or copied to case storage.
 */
public final class FindingAccess {
    private final Client client;

    public FindingAccess(Client client) { this.client = client; }

    /** Capture the exact version returned to the authenticated caller. No source leaves this method. */
    void capture(FindingReference reference, String actor, Clock clock, ActionListener<FindingCaptureReceipt> listener) {
        client.get(new GetRequest(reference.index(), reference.documentId()), ActionListener.wrap(response -> {
            if (!response.isExists() || !reference.index().equals(response.getIndex()) ||
                    !reference.documentId().equals(response.getId())) {
                listener.onFailure(new OpenSearchStatusException("Finding not available", RestStatus.NOT_FOUND));
                return;
            }
            listener.onResponse(FindingCaptureReceipt.create(reference, response.getSourceAsMap(),
                    clock.instant(), actor, response.getSeqNo(), response.getPrimaryTerm()));
        }, listener::onFailure));
    }

    public void requireVisible(FindingReference reference, ActionListener<Void> listener) {
        GetRequest request = new GetRequest(reference.index(), reference.documentId());
        client.get(request, ActionListener.wrap(response -> {
            if (!response.isExists() || !reference.index().equals(response.getIndex()) ||
                    !reference.documentId().equals(response.getId())) {
                listener.onFailure(new OpenSearchStatusException("Finding not available", RestStatus.NOT_FOUND));
                return;
            }
            listener.onResponse(null);
        }, listener::onFailure));
    }
}
