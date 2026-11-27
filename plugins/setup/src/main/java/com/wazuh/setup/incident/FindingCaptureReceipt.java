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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fingerprint of the caller-visible parsed source, not a preserved copy of the original
 * raw event. Never expose it in ordinary case projections or use it as a substitute
 * for the source document's authorization rules.
 */
record FindingCaptureReceipt(FindingReference reference, String capturedAt, String actor,
        long seqNo, long primaryTerm, String sha256) {
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    static FindingCaptureReceipt create(FindingReference reference, Map<String, Object> source,
            Instant now, String actor, long seqNo, long primaryTerm) {
        if (source == null || seqNo < 0 || primaryTerm < 1) {
            throw new OpenSearchStatusException("Finding source or version unavailable", RestStatus.CONFLICT);
        }
        try {
            byte[] serialized = JSON.writeValueAsBytes(source);
            // Bound extra hashing/serialization work; this does not bound the original GET.
            if (serialized.length > 4 * 1024 * 1024) {
                throw new OpenSearchStatusException("Finding exceeds receipt size limit", RestStatus.BAD_REQUEST);
            }
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(serialized));
            return new FindingCaptureReceipt(reference, now.toString(), actor, seqNo, primaryTerm, digest);
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Finding receipt could not be generated", e);
        }
    }

    Map<String, Object> toMap() {
        return Map.of("reference", reference.toMap(), "captured_at", capturedAt, "captured_by", actor,
                "seq_no", seqNo, "primary_term", primaryTerm, "sha256", sha256,
                "scope", "caller_visible_parsed_source", "serialization", "sorted-map-json-v1");
    }

    @SuppressWarnings("unchecked")
    static void appendToPending(Map<String, Object> next, FindingCaptureReceipt receipt) {
        var pending = new LinkedHashMap<>((Map<String, Object>) next.get("pending_activity"));
        if (!"attach_finding".equals(pending.get("kind")) || !receipt.actor().equals(pending.get("actor"))) {
            throw new IllegalStateException("Finding receipt does not match activity");
        }
        var changes = new LinkedHashMap<>((Map<String, Object>) pending.get("changes"));
        if (!(changes.get("finding") instanceof Map<?, ?> finding) ||
                !receipt.reference().toMap().equals(finding.get("after"))) {
            throw new IllegalStateException("Finding receipt does not match attached reference");
        }
        Map<String, Object> change = new LinkedHashMap<>();
        change.put("before", null);
        change.put("after", receipt.toMap());
        changes.put("finding_capture_receipt", change);
        pending.put("changes", changes);
        next.put("pending_activity", pending);
    }
}
