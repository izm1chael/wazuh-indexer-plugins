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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** One closed, aligned native-finding correlation window. No arbitrary query or source index. */
final class AnalyticsWindow {
    static final int MAX_FINDINGS = 100, MAX_GROUPS = 20, GRACE_SECONDS = 120;
    record Key(UUID deployment, UUID policy, int version, Instant from, Instant until) {
        Key {
            if (deployment == null || policy == null || version < 1 || from == null || until == null ||
                    from.getNano() != 0 || until.getNano() != 0 || !from.isBefore(until) ||
                    from.isBefore(Instant.parse("2000-01-01T00:00:00Z")) || until.isAfter(Instant.parse("2100-01-01T00:00:00Z")) ||
                    until.isAfter(from.plusSeconds(86400))) throw new IllegalArgumentException("Invalid analytics window");
        }
        String id() { return hash(List.of("wazuh-analytics-window-v1", deployment.toString(), policy.toString(),
                Integer.toString(version), from.toString(), until.toString())); }
    }
    record Plan(Key key, String digest, int findings, int groups, int belowThreshold) {
        Map<String, Object> fields(String actor) {
            return Map.ofEntries(Map.entry("id", key.id()), Map.entry("deployment_id", key.deployment().toString()),
                    Map.entry("policy_id", key.policy().toString()), Map.entry("policy_version", key.version()),
                    Map.entry("from", key.from().toString()), Map.entry("until", key.until().toString()),
                    Map.entry("actor", actor), Map.entry("plan_sha256", digest), Map.entry("finding_count", findings),
                    Map.entry("group_count", groups), Map.entry("below_threshold", belowThreshold));
        }
    }

    static CorrelationPreviewService.Input input(Key key, CorrelationPlanner.Policy policy, Instant now) {
        if (!key.policy().equals(policy.id()) || key.version() != policy.version() ||
                !key.until().equals(key.from().plusSeconds(policy.windowMinutes() * 60L)) ||
                key.until().isAfter(now.minusSeconds(GRACE_SECONDS)) || key.from().isBefore(now.minusSeconds(7L * 86400)))
            throw new IllegalArgumentException("Execution requires one closed, settled policy window within seven days");
        return new CorrelationPreviewService.Input(policy, key.from(), key.until());
    }

    static Plan plan(Key key, CorrelationPreviewService.Scan scan) {
        var preview = scan.preview();
        if (scan.candidates().size() > MAX_FINDINGS || preview.eligible().size() > MAX_GROUPS ||
                preview.duplicateInputs() != 0 || preview.insufficientIdentity() != 0 ||
                preview.excludedRule() != 0 || preview.outsideRange() != 0 ||
                preview.distinctCandidates() != scan.candidates().size()) throw new IllegalArgumentException("Incomplete analytics candidate coverage");
        var refs = new HashSet<FindingReference>();
        var parts = new ArrayList<String>();
        parts.add("wazuh-analytics-plan-v1"); parts.add(key.id());
        for (var candidate : scan.candidates().stream().sorted(Comparator
                .comparing((CorrelationPreviewService.Versioned v) -> v.candidate().reference().index())
                .thenComparing(v -> v.candidate().reference().documentId())).toList()) {
            var ref = candidate.candidate().reference();
            if (candidate.seqNo() < 0 || candidate.primaryTerm() < 1 || !refs.add(ref)) throw new IllegalArgumentException("Missing candidate version");
            parts.add(ref.index()); parts.add(ref.documentId()); parts.add(Long.toString(candidate.seqNo())); parts.add(Long.toString(candidate.primaryTerm()));
        }
        var grouped = new HashSet<FindingReference>();
        for (var group : preview.eligible()) {
            if (!key.policy().equals(group.policyId()) || key.version() != group.policyVersion() ||
                    !key.from().equals(group.windowStart()) || !key.until().equals(group.windowEnd())) throw new IllegalArgumentException("Unexpected group window");
            var identity = CorrelationExecutionIdentity.reserve(key.deployment(), group);
            for (var ref : group.findings()) if (!refs.contains(ref) || !grouped.add(ref)) throw new IllegalArgumentException("Invalid group membership");
            parts.add(group.key()); parts.add(identity.membershipHash());
        }
        if (grouped.size() + preview.belowThreshold() != refs.size()) throw new IllegalArgumentException("Analytics count mismatch");
        parts.add(Integer.toString(preview.belowThreshold()));
        return new Plan(key, hash(parts), refs.size(), preview.eligible().size(), preview.belowThreshold());
    }

    private static String hash(List<String> parts) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            for (String part : parts) {
                byte[] bytes = part.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array()); digest.update(bytes);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
