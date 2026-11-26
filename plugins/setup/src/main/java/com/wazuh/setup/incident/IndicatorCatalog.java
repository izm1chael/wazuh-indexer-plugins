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

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Shared, bounded analyst indicator catalog. Records are immutable except terminal, attributed revocation. */
public final class IndicatorCatalog {
    public static final int MAX_RECORDS = 200, MAX_BATCH = 20;
    private static final Set<String> INPUT = Set.of("type", "value", "source", "external_id", "confidence", "tlp", "valid_from", "valid_until");
    private static final Set<String> FIELDS = Set.of("type", "value", "source", "external_id", "confidence", "tlp", "valid_from", "valid_until",
            "id", "created_by", "created_at", "created_revision", "revoked_by", "revoked_at", "revoked_revision", "revocation_reason");
    private static final Set<String> TLP = Set.of("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED");
    private IndicatorCatalog() {}

    public static Map<String, Object> empty() { return Map.of("revision", 0, "indicators", List.of()); }

    public static Map<String, Object> definition(Map<?, ?> input) {
        if (input == null || !input.keySet().equals(INPUT)) throw invalid("Unexpected indicator fields");
        String type = text(input.get("type"), 16), value = text(input.get("value"), 253);
        value = canonical(type, value);
        String source = text(input.get("source"), 256);
        Object external = input.get("external_id");
        if (external != null && (!(external instanceof String s) ||
                !s.matches("indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) throw invalid("Invalid external STIX indicator ID");
        if (!(input.get("confidence") instanceof Integer confidence) || confidence < 0 || confidence > 100) throw invalid("Invalid confidence");
        String tlp = text(input.get("tlp"), 32);
        if (!TLP.contains(tlp)) throw invalid("Invalid TLP");
        Instant from = time(input.get("valid_from")), until = time(input.get("valid_until"));
        if (!from.isBefore(until) || until.isAfter(from.plusSeconds(366L * 86400))) throw invalid("Indicator validity must be positive and at most 366 days");
        var result = new LinkedHashMap<String, Object>();
        result.put("type", type); result.put("value", value); result.put("source", source); result.put("external_id", external);
        result.put("confidence", confidence); result.put("tlp", tlp); result.put("valid_from", from.toString()); result.put("valid_until", until.toString());
        return result;
    }

    static String canonical(String type, String value) {
        switch (type) {
            case "ipv4":
                if (!IncidentHuntService.valid("source.ip", value)) throw invalid("Invalid IPv4 indicator");
                return value;
            case "domain":
                String normalized = value.toLowerCase(Locale.ROOT);
                if (!normalized.matches("(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?") ||
                        normalized.matches("[0-9.]+")) throw invalid("Invalid ASCII domain indicator");
                return normalized;
            case "md5": case "sha1": case "sha256":
                if (!IncidentHuntService.valid("file.hash." + type, value)) throw invalid("Invalid hash indicator");
                return value.toLowerCase(Locale.ROOT);
            default: throw invalid("Unsupported indicator type");
        }
    }

    public static Map<String, Object> add(Map<String, Object> current, int expected, List<?> items, String actor, Instant now) {
        var rows = rows(current);
        int revision = revision(current, expected);
        if (items == null || items.isEmpty() || items.size() > MAX_BATCH || rows.size() + items.size() > MAX_RECORDS) throw invalid("Indicator batch or catalog capacity exceeded");
        var keys = new HashSet<String>();
        var external = new HashSet<String>();
        for (var row : rows) {
            keys.add(identity(row));
            if (row.get("external_id") != null) external.add((String) row.get("external_id"));
        }
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> raw)) throw invalid("Indicator object required");
            var row = definition(raw);
            if (!keys.add(identity(row)) || (row.get("external_id") != null && !external.add((String) row.get("external_id"))))
                throw conflict("Indicator identity already recorded; no batch changes applied");
            row.put("id", UUID.randomUUID().toString()); row.put("created_by", text(actor, 1024)); row.put("created_at", now.toString());
            row.put("created_revision", revision + 1);
            row.put("revoked_by", null); row.put("revoked_at", null); row.put("revoked_revision", null); row.put("revocation_reason", null);
            rows.add(row);
        }
        return Map.of("revision", revision + 1, "indicators", rows);
    }

    public static Map<String, Object> revoke(Map<String, Object> current, int expected, String id, String reason, String actor, Instant now) {
        var rows = rows(current);
        int revision = revision(current, expected);
        IncidentReadService.canonicalId(id);
        for (int n = 0; n < rows.size(); n++) {
            var old = rows.get(n);
            if (!id.equals(old.get("id"))) continue;
            if (old.get("revoked_at") != null || now.isBefore(time(old.get("created_at")))) throw conflict("Indicator already revoked or clock moved backwards");
            var row = new LinkedHashMap<>(old);
            row.put("revoked_by", text(actor, 1024)); row.put("revoked_at", now.toString());
            row.put("revoked_revision", revision + 1); row.put("revocation_reason", text(reason, 1024));
            rows.set(n, row);
            return Map.of("revision", revision + 1, "indicators", rows);
        }
        throw conflict("Indicator unavailable");
    }

    public static Map<String, Object> project(Map<String, Object> source, Instant now) {
        var rows = rows(source);
        return Map.of("revision", source.get("revision"), "observed_at", now.toString(), "indicators", rows.stream().map(row -> {
            var projected = new LinkedHashMap<>(row);
            String state = row.get("revoked_at") != null ? "revoked" : !now.isBefore(time(row.get("valid_until"))) ? "expired" :
                    now.isBefore(time(row.get("valid_from"))) ? "pending" : "active";
            projected.put("state", state); return projected;
        }).toList());
    }

    static ArrayList<Map<String, Object>> rows(Map<String, Object> source) {
        try {
            if (!source.keySet().equals(Set.of("revision", "indicators")) || !(source.get("revision") instanceof Integer revision) || revision < 0 ||
                    !(source.get("indicators") instanceof List<?> items) || items.size() > MAX_RECORDS ||
                    (revision == 0) != items.isEmpty()) throw invalid("Invalid catalog");
            var rows = new ArrayList<Map<String, Object>>();
            var ids = new HashSet<String>(); var keys = new HashSet<String>(); var external = new HashSet<String>();
            for (Object item : items) {
                if (!(item instanceof Map<?, ?> raw) || !raw.keySet().equals(FIELDS)) throw invalid("Invalid indicator record");
                var input = new LinkedHashMap<String, Object>(); INPUT.forEach(field -> input.put(field, raw.get(field)));
                var row = definition(input);
                if (!row.equals(input)) throw invalid("Noncanonical stored indicator");
                FIELDS.forEach(field -> row.put(field, raw.get(field)));
                String id = IncidentReadService.canonicalId(text(row.get("id"), 36)).toString();
                if (!ids.add(id) || !keys.add(identity(row)) ||
                        (row.get("external_id") != null && !external.add((String) row.get("external_id")))) throw invalid("Duplicate catalog identity");
                text(row.get("created_by"), 1024); Instant created = time(row.get("created_at"));
                if (!(row.get("created_revision") instanceof Integer cr) || cr < 1 || cr > revision) throw invalid("Invalid creation revision");
                if (row.get("revoked_at") == null) {
                    if (row.get("revoked_by") != null || row.get("revoked_revision") != null || row.get("revocation_reason") != null) throw invalid("Invalid revocation");
                } else {
                    if (time(row.get("revoked_at")).isBefore(created) || !(row.get("revoked_revision") instanceof Integer rr) ||
                            rr <= cr || rr > revision) throw invalid("Invalid revocation revision");
                    text(row.get("revoked_by"), 1024); text(row.get("revocation_reason"), 1024);
                }
                rows.add(row);
            }
            return rows;
        } catch (RuntimeException e) { throw new IllegalStateException("Invalid stored indicator catalog", e); }
    }

    private static int revision(Map<String, Object> current, int expected) {
        int revision = (Integer) current.get("revision");
        if (revision != expected || revision == Integer.MAX_VALUE) throw conflict("Indicator catalog revision changed");
        return revision;
    }
    private static String identity(Map<String, Object> row) { return row.get("type") + ":" + row.get("value"); }
    private static String text(Object value, int max) {
        if (!(value instanceof String s) || s.isBlank() || s.length() > max || !s.equals(s.trim()) ||
                s.chars().anyMatch(Character::isISOControl)) throw invalid("Invalid indicator text");
        return s;
    }
    private static Instant time(Object value) {
        try {
            Instant at = Instant.parse(text(value, 30));
            if (at.isBefore(Instant.parse("2000-01-01T00:00:00Z")) || at.isAfter(Instant.parse("2100-01-01T00:00:00Z"))) throw invalid("Invalid time");
            return at;
        } catch (RuntimeException e) { throw invalid("Invalid indicator timestamp"); }
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message, RestStatus.CONFLICT); }
}
