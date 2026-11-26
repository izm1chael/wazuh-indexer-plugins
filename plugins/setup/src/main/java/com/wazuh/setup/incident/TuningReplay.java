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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Recomputes metrics from externally supplied paired outcomes, not a rule execution engine. */
final class TuningReplay {
    static final int MAX_ROWS = 1000;
    static final int MIN_CLASS = 10;
    private record Row(String id, String label, boolean baseline, boolean candidate) {}
    private TuningReplay() {}

    static Map<String, Object> evaluate(Object raw) {
        if (!(raw instanceof List<?> items) || items.isEmpty() || items.size() > MAX_ROWS) {
            throw new IllegalArgumentException("One to 1000 paired holdout rows required");
        }
        var seen = new HashSet<String>();
        var rows = new ArrayList<Row>();
        int malicious = 0, benign = 0, unknown = 0, unknownChanged = 0;
        int btp = 0, ctp = 0, bfp = 0, cfp = 0, lost = 0, gained = 0, removed = 0, added = 0;
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> row) || !row.keySet().equals(Set.of("id", "label", "baseline", "candidate")) ||
                    !(row.get("id") instanceof String id) || !id.matches("[A-Za-z0-9_.:-]{1,128}") || !seen.add(id) ||
                    !(row.get("label") instanceof String label) || !Set.of("malicious", "benign", "unknown").contains(label) ||
                    !(row.get("baseline") instanceof Boolean baseline) || !(row.get("candidate") instanceof Boolean candidate)) {
                throw new IllegalArgumentException("Invalid or duplicate paired sample");
            }
            rows.add(new Row(id, label, baseline, candidate));
            switch (label) {
                case "malicious":
                    malicious++;
                    if (baseline) btp++;
                    if (candidate) ctp++;
                    if (baseline && !candidate) lost++;
                    if (!baseline && candidate) gained++;
                    break;
                case "benign":
                    benign++;
                    if (baseline) bfp++;
                    if (candidate) cfp++;
                    if (baseline && !candidate) removed++;
                    if (!baseline && candidate) added++;
                    break;
                default:
                    unknown++;
                    if (baseline != candidate) unknownChanged++;
            }
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("fixture_sha256", fingerprint(rows));
        result.put("total", rows.size()); result.put("malicious", malicious); result.put("benign", benign);
        result.put("unknown", unknown); result.put("unknown_changed", unknownChanged);
        result.put("baseline_tp", btp); result.put("candidate_tp", ctp);
        result.put("baseline_fp", bfp); result.put("candidate_fp", cfp);
        result.put("lost_malicious", lost); result.put("gained_malicious", gained);
        result.put("removed_benign", removed); result.put("added_benign", added);
        result.put("gate", gate(result));
        return result;
    }

    // The restricted ASCII token grammar excludes tab/newline; canonical order is by sample ID.
    private static String fingerprint(List<Row> rows) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            digest.update("wazuh-tuning-fixture-v1\n".getBytes(StandardCharsets.UTF_8));
            for (Row row : rows.stream().sorted(Comparator.comparing(Row::id)).toList()) {
                String line = row.id() + "\t" + row.label() + "\t" + (row.baseline() ? "1" : "0") +
                        "\t" + (row.candidate() ? "1" : "0") + "\n";
                digest.update(line.getBytes(StandardCharsets.UTF_8));
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    static final Set<String> FIELDS = Set.of("fixture_sha256", "total", "malicious", "benign", "unknown", "unknown_changed",
            "baseline_tp", "candidate_tp", "baseline_fp", "candidate_fp", "lost_malicious", "gained_malicious",
            "removed_benign", "added_benign", "gate");

    static Map<String, Object> validate(Object raw) {
        if (!(raw instanceof Map<?, ?> value) || !value.keySet().equals(FIELDS) ||
                !(value.get("fixture_sha256") instanceof String hash) || !hash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Invalid replay receipt");
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("fixture_sha256", hash);
        for (String field : FIELDS) {
            if (field.equals("fixture_sha256") || field.equals("gate")) continue;
            if (!(value.get(field) instanceof Integer n) || n < 0 || n > MAX_ROWS) throw new IllegalArgumentException("Invalid replay count");
            result.put(field, n);
        }
        int total = number(result, "total"), m = number(result, "malicious"), b = number(result, "benign"), u = number(result, "unknown");
        int bt = number(result, "baseline_tp"), ct = number(result, "candidate_tp"), bf = number(result, "baseline_fp"), cf = number(result, "candidate_fp");
        int lost = number(result, "lost_malicious"), gained = number(result, "gained_malicious");
        int removed = number(result, "removed_benign"), added = number(result, "added_benign");
        if (total < 1 || total != m + b + u || number(result, "unknown_changed") > u ||
                bt > m || ct > m || bf > b || cf > b ||
                lost > bt || lost > m - ct || gained > m - bt || gained > ct || ct != bt - lost + gained ||
                removed > bf || removed > b - cf || added > b - bf || added > cf || cf != bf - removed + added ||
                !gate(result).equals(value.get("gate"))) throw new IllegalArgumentException("Replay counts do not reconcile");
        result.put("gate", value.get("gate"));
        return result;
    }

    private static int number(Map<String, Object> row, String key) { return (Integer) row.get(key); }
    private static String gate(Map<String, Object> row) {
        return number(row, "malicious") >= MIN_CLASS && number(row, "benign") >= MIN_CLASS &&
                number(row, "unknown") == 0 && number(row, "lost_malicious") == 0 &&
                number(row, "added_benign") == 0 && number(row, "removed_benign") > 0
                ? "eligible_for_human_review" : "blocked";
    }
}
