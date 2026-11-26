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
import org.opensearch.core.rest.RestStatus;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/** Durable create identity, scoped to the authenticated caller. */
public final class IncidentRequestIdentity {
    private IncidentRequestIdentity() {}

    public static UUID requireKey(Object key) {
        if (!(key instanceof String value)) throw invalid();
        try {
            UUID id = UUID.fromString(value);
            if (!id.toString().equals(value)) throw invalid();
            return id;
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    public static UUID incidentId(String actor, UUID key) {
        byte[] bytes = digest("wazuh-incident-create-v1", actor, key.toString());
        // UUID version 8, RFC variant. Never use a caller-selected target document ID.
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x80);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    public static String createFingerprint(Map<String, Object> validated) {
        return HexFormat.of().formatHex(digest("wazuh-incident-payload-v1",
                (String) validated.get("title"), (String) validated.get("description"),
                (String) validated.get("severity"), (String) validated.get("priority"), (String) validated.get("tlp")));
    }

    static boolean matches(Map<String, Object> stored, String actor, String fingerprint) {
        return actor.equals(stored.get("created_by")) && fingerprint.equals(stored.get("create_request_hash"));
    }

    private static byte[] digest(String... fields) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String field : fields) {
                byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
                digest.update(bytes);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static OpenSearchStatusException invalid() {
        return new OpenSearchStatusException("Canonical request_id UUID required", RestStatus.BAD_REQUEST);
    }
}
