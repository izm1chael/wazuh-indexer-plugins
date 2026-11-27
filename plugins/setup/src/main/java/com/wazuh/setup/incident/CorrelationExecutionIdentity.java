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
package com.wazuh.setup.incident;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/** Pure execution reservation identity. Scope must come from trusted deployment configuration. */
final class CorrelationExecutionIdentity {
    record Reservation(String id, UUID incidentId, String groupKey, String membershipHash, int findingCount) {}

    static Reservation reserve(UUID deployment, CorrelationPlanner.Group group) {
        if (deployment == null || group == null || group.key() == null || !group.key().matches("[a-f0-9]{64}") ||
                group.policyId() == null || group.policyVersion() < 1 || group.windowStart() == null ||
                group.windowEnd() == null || !group.windowStart().isBefore(group.windowEnd()) ||
                group.findings() == null || group.findings().size() < 2 || group.findings().size() > 1000 ||
                group.findings().stream().anyMatch(java.util.Objects::isNull) ||
                new HashSet<>(group.findings()).size() != group.findings().size()) {
            throw new IllegalArgumentException("Invalid correlation reservation");
        }
        String id = reservationId(deployment, group.key());
        List<String> refs = group.findings().stream().sorted(Comparator.comparing(FindingReference::index)
                .thenComparing(FindingReference::documentId))
                .flatMap(ref -> java.util.stream.Stream.of(ref.index(), ref.documentId())).toList();
        return new Reservation(id, incidentId(id), group.key(),
                HexFormat.of().formatHex(hash(refs)), group.findings().size());
    }

    static String reservationId(UUID deployment, String key) {
        if (deployment == null || key == null || !key.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid reservation identity");
        return HexFormat.of().formatHex(hash(List.of("wazuh-correlation-reservation-v1", deployment.toString(), key)));
    }

    static UUID incidentId(String reservationId) {
        if (reservationId == null || !reservationId.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid reservation ID");
        byte[] uuid = hash(List.of("wazuh-correlation-incident-v1", reservationId));
        uuid[6] = (byte) ((uuid[6] & 0x0f) | 0x80);
        uuid[8] = (byte) ((uuid[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(uuid);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static byte[] hash(List<String> values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String value : values) {
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
                digest.update(bytes);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }
}
