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
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Bounded live projection of fields in the RC2 WCS findings template. Never persisted. */
final class FindingIntelligence {
    private static final int MAX_VALUES = 16;
    private static final Pattern TECHNIQUE = Pattern.compile("T[0-9]{4}(?:\\.[0-9]{3})?");
    private static final Pattern TACTIC = Pattern.compile("TA[0-9]{4}");
    private static final Pattern HASH = Pattern.compile("[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}");
    private static final Map<String, String> ENTITY_FIELDS = Map.ofEntries(
            Map.entry("wazuh.agent.id", "agent_id"), Map.entry("wazuh.agent.name", "agent_name"),
            Map.entry("host.id", "host_id"), Map.entry("host.name", "host"), Map.entry("host.hostname", "host"),
            Map.entry("host.ip", "host_ip"), Map.entry("source.ip", "source_ip"), Map.entry("destination.ip", "destination_ip"),
            Map.entry("user.name", "user"), Map.entry("user.id", "user_id"), Map.entry("user.domain", "user_domain"),
            Map.entry("dns.question.name", "domain"), Map.entry("file.hash.md5", "hash"),
            Map.entry("file.hash.sha1", "hash"), Map.entry("file.hash.sha256", "hash"));
    private static final List<String> TECHNIQUE_FIELDS = List.of("rule.mitre.technique.id", "rule.mitre.subtechnique.id",
            "wazuh.rule.mitre.technique.id", "wazuh.rule.mitre.subtechnique.id", "threat.technique.id", "threat.technique.subtechnique.id");
    private static final List<String> TACTIC_FIELDS = List.of("rule.mitre.tactic.id", "wazuh.rule.mitre.tactic.id", "threat.tactic.id");

    private FindingIntelligence() {}

    static Map<String, Object> project(FindingReference reference, Map<String, Object> source) {
        Map<String, Object> result = new LinkedHashMap<>(reference.toMap());
        Map<String, Object> safe = source == null ? Map.of() : source;
        result.put("timestamp", timestamp(first(safe, "@timestamp")));
        result.put("rule_id", first(safe, "wazuh.rule.id", "rule.id"));
        // Distinguish the exact Wazuh rule field from the display fallback for prevalence probes.
        result.put("wazuh_rule_id", first(safe, "wazuh.rule.id"));
        result.put("rule_title", first(safe, "wazuh.rule.title", "rule.title", "rule.name"));
        Set<Map<String, String>> entities = new LinkedHashSet<>();
        ENTITY_FIELDS.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            for (String value : values(safe, entry.getKey())) {
                if ("hash".equals(entry.getValue()) && !HASH.matcher(value).matches()) continue;
                String normalized = "hash".equals(entry.getValue()) ? value.toLowerCase(Locale.ROOT) : value;
                entities.add(Map.of("kind", entry.getValue(), "value", normalized, "field", entry.getKey()));
            }
        });
        result.put("entities", new ArrayList<>(entities));
        result.put("techniques", attack(safe, TECHNIQUE_FIELDS, TECHNIQUE));
        result.put("tactics", attack(safe, TACTIC_FIELDS, TACTIC));
        return result;
    }

    private static List<String> attack(Map<String, Object> source, List<String> paths, Pattern pattern) {
        Set<String> values = new LinkedHashSet<>();
        for (String path : paths) {
            for (String value : values(source, path)) {
                String id = value.toUpperCase(Locale.ROOT);
                if (pattern.matcher(id).matches()) values.add(id);
            }
        }
        return new ArrayList<>(values);
    }

    static String first(Map<String, Object> source, String... paths) {
        for (String path : paths) {
            List<String> values = values(source, path);
            if (!values.isEmpty()) return values.get(0);
        }
        return null;
    }

    static List<String> values(Map<String, Object> source, String path) {
        List<String> result = new ArrayList<>();
        collect(source, path.split("\\."), 0, result, new int[]{256});
        return result;
    }

    private static void collect(Object node, String[] path, int offset, List<String> out, int[] budget) {
        if (node == null || out.size() >= MAX_VALUES || budget[0]-- <= 0) return;
        if (node instanceof List<?> list) {
            for (Object value : list) {
                if (out.size() >= MAX_VALUES || budget[0] <= 0) break;
                collect(value, path, offset, out, budget);
            }
        } else if (offset == path.length) {
            if (node instanceof String value && !value.isBlank() && value.length() <= 1024 &&
                    value.chars().noneMatch(Character::isISOControl)) out.add(value.trim());
        } else if (node instanceof Map<?, ?> map) {
            // Prefer the normal nested representation; also support literal dotted WCS keys.
            if (map.containsKey(path[offset])) collect(map.get(path[offset]), path, offset + 1, out, budget);
            else {
                String remaining = String.join(".", java.util.Arrays.copyOfRange(path, offset, path.length));
                collect(map.get(remaining), path, path.length, out, budget);
            }
        }
    }

    private static String timestamp(String value) {
        if (value == null) return null;
        try { return Instant.parse(value).toString(); }
        catch (DateTimeParseException e) { return null; }
    }
}
