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

import java.time.Instant;
import java.time.DateTimeException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Pure, deterministic correlation preview. Input must be observations obtained from
 * trusted, authorized reads, not user-asserted source facts. No search, persistence,
 * scheduler or automation privileges are provided by this class.
 */
public final class CorrelationPlanner {
    public static final int MAX_BATCH = 1000;
    private CorrelationPlanner() {}

    public record Policy(UUID id, int version, Set<UUID> allowedRules, int windowMinutes, int minimumFindings) {
        public Policy {
            if (id == null || version < 1 || allowedRules == null || allowedRules.isEmpty() ||
                    allowedRules.size() > 100 || windowMinutes < 5 || windowMinutes > 1440 ||
                    minimumFindings < 2 || minimumFindings > 100) throw new IllegalArgumentException("Invalid correlation policy");
            allowedRules = Set.copyOf(allowedRules);
        }
    }

    public record Candidate(FindingReference reference, String cluster, String agent, UUID rule, Instant at) {}
    public record Group(String key, UUID policyId, int policyVersion, Instant windowStart, Instant windowEnd,
            List<FindingReference> findings) {}
    public record Preview(List<Group> eligible, int distinctCandidates, int duplicateInputs,
            int insufficientIdentity, int excludedRule, int outsideRange, int belowThreshold) {}

    /** Extract only unambiguous single values from known WCS fields. Missing/conflicting data is not inferred. */
    public static Candidate extract(FindingReference reference, Map<String, Object> source) {
        String cluster = single(source, "wazuh.cluster.name");
        String agent = single(source, "wazuh.agent.id");
        String wazuhRule = single(source, "wazuh.rule.uuid");
        String ecsRule = single(source, "rule.uuid");
        UUID rule = null;
        if ((wazuhRule == null || ecsRule == null || wazuhRule.equalsIgnoreCase(ecsRule))) {
            String value = wazuhRule != null ? wazuhRule : ecsRule;
            try {
                if (value != null) {
                    UUID parsed = UUID.fromString(value);
                    if (parsed.toString().equalsIgnoreCase(value)) rule = parsed;
                }
            } catch (IllegalArgumentException ignored) { /* Invalid UUID is not a correlation key. */ }
        }
        Instant at = null;
        try {
            String value = single(source, "@timestamp");
            if (value != null) at = Instant.parse(value);
        } catch (DateTimeException ignored) { /* Missing or invalid time is not guessed. */ }
        // A present multivalued rule field is ambiguous even if the alternate field is singular.
        if (ambiguous(source, "wazuh.rule.uuid") || ambiguous(source, "rule.uuid")) rule = null;
        return new Candidate(reference, cluster, agent, rule, at);
    }

    private static String single(Map<String, Object> source, String path) {
        if (source == null) return null;
        // Multiple extracted values, even identical repeats, are conservatively ineligible.
        List<String> values = FindingIntelligence.values(source, path);
        return values.size() == 1 ? values.get(0) : null;
    }

    private static boolean ambiguous(Map<String, Object> source, String path) {
        return source != null && FindingIntelligence.values(source, path).size() > 1;
    }

    /** Fixed UTC tumbling windows, not sliding windows. Arrival order never changes a group key. */
    public static Preview plan(Policy policy, List<Candidate> candidates, Instant from, Instant until) {
        if (policy == null || candidates == null || candidates.size() > MAX_BATCH || from == null || until == null ||
                !from.isBefore(until) || until.isAfter(from.plusSeconds(7L * 86400))) {
            throw new IllegalArgumentException("Invalid bounded correlation preview");
        }
        Map<FindingReference, Candidate> unique = new LinkedHashMap<>();
        int duplicates = 0;
        for (Candidate candidate : candidates) {
            if (candidate == null || candidate.reference() == null) throw new IllegalArgumentException("Missing finding identity");
            Candidate prior = unique.putIfAbsent(candidate.reference(), candidate);
            if (prior != null) {
                if (!prior.equals(candidate)) throw new IllegalArgumentException("Conflicting facts for duplicate finding identity");
                duplicates++;
            }
        }
        int missing = 0, excluded = 0, outside = 0, below = 0;
        long seconds = policy.windowMinutes() * 60L;
        Map<Key, List<FindingReference>> grouped = new HashMap<>();
        for (Candidate c : unique.values()) {
            if (!validScope(c.cluster()) || !validScope(c.agent()) || c.rule() == null || c.at() == null) {
                missing++; continue;
            }
            if (!policy.allowedRules().contains(c.rule())) { excluded++; continue; }
            if (c.at().isBefore(from) || !c.at().isBefore(until)) { outside++; continue; }
            long start = Math.floorDiv(c.at().getEpochSecond(), seconds) * seconds;
            Key key = new Key(c.cluster(), c.agent(), c.rule(), start);
            grouped.computeIfAbsent(key, ignored -> new ArrayList<>()).add(c.reference());
        }
        List<Group> eligible = new ArrayList<>();
        for (Map.Entry<Key, List<FindingReference>> entry : grouped.entrySet()) {
            List<FindingReference> refs = entry.getValue();
            if (refs.size() < policy.minimumFindings()) { below += refs.size(); continue; }
            Key key = entry.getKey();
            refs.sort(Comparator.comparing(FindingReference::index).thenComparing(FindingReference::documentId));
            eligible.add(new Group(digest(policy, key), policy.id(), policy.version(), Instant.ofEpochSecond(key.start()),
                    Instant.ofEpochSecond(key.start() + seconds), List.copyOf(refs)));
        }
        eligible.sort(Comparator.comparing(Group::windowStart).thenComparing(Group::key));
        return new Preview(List.copyOf(eligible), unique.size(), duplicates, missing, excluded, outside, below);
    }

    private record Key(String cluster, String agent, UUID rule, long start) {}

    private static boolean validScope(String value) {
        return value != null && !value.isBlank() && value.length() <= 1024 &&
                value.equals(value.trim()) && value.chars().noneMatch(Character::isISOControl);
    }

    private static String digest(Policy policy, Key key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String value : List.of("wazuh-correlation-v1", policy.id().toString(), Integer.toString(policy.version()),
                    Integer.toString(policy.windowMinutes()), Integer.toString(policy.minimumFindings()),
                    key.cluster(), key.agent(), key.rule().toString(), Long.toString(key.start()))) {
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
                digest.update(bytes);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
