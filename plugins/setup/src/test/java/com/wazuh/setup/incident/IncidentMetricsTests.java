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

import org.opensearch.test.OpenSearchTestCase;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

public class IncidentMetricsTests extends OpenSearchTestCase {
    private static final Instant START = Instant.parse("2026-11-26T12:00:00Z");
    private static final Instant NOW = START.plusSeconds(3600);
    private final IncidentMetrics.Query query = new IncidentMetrics.Query(START, NOW, 600, 1200);

    private Map<String, Object> item(String id, String status, Instant created) {
        var value = new LinkedHashMap<String, Object>();
        value.put("id", id); value.put("status", status); value.put("created_at", created.toString());
        value.put("severity", "high"); return value;
    }

    public void testCohortAndOpenBacklogUseDifferentDenominators() {
        var closed = item("a", "closed", START);
        closed.put("triage_started_at", START.plusSeconds(30).toString());
        closed.put("activated_at", START.plusSeconds(630).toString());
        closed.put("first_closed_at", START.plusSeconds(1200).toString());
        closed.put("closed_at", START.plusSeconds(1200).toString());
        closed.put("closure", Map.of("classification", "false_positive"));
        var old = item("b", "new", START.minusSeconds(86400));
        var reopened = item("c", "active", START.plusSeconds(1));
        reopened.put("owner", "analyst");
        reopened.put("reopened_at", START.plusSeconds(100).toString());
        reopened.put("first_closed_at", START.plusSeconds(90).toString());
        var result = IncidentMetrics.summarize(query, NOW, List.of(closed, old, reopened));
        assertEquals(2, result.get("cohort_count"));
        assertEquals(2, result.get("open_backlog"));
        assertEquals(1, result.get("unassigned"));
        assertEquals(1, result.get("reopened_incidents"));
        assertEquals(2, result.get("open_resolution_breached"));
        var triage = (Map<?, ?>) result.get("mttt");
        assertEquals(1, triage.get("samples"));
        assertEquals(1, triage.get("missing"));
        assertEquals(1, triage.get("breached"));
        var resolution = (Map<?, ?>) result.get("mttr");
        assertEquals(1, resolution.get("samples"));
        assertEquals(1, resolution.get("breached"));
        assertEquals(1200d, resolution.get("mean_seconds"));
        assertEquals(false, result.get("mtti_available"));
    }

    public void testZeroAndInvalidAreNotMissingOrInvented() {
        var a = item("a", "closed", START);
        a.put("closed_at", START.toString());
        var b = item("b", "closed", START);
        b.put("closed_at", START.minusSeconds(1).toString());
        var c = item("c", "closed", START);
        var result = IncidentMetrics.summarize(query, NOW, List.of(a, b, c));
        var metric = (Map<?, ?>) result.get("mttr");
        assertEquals(1, metric.get("samples"));
        assertEquals(1, metric.get("missing"));
        assertEquals(1, metric.get("invalid"));
        assertEquals(0d, metric.get("mean_seconds"));
        assertEquals(1, metric.get("met"));
        assertNull(((Map<?, ?>) IncidentMetrics.summarize(query, NOW, List.of()).get("mttt")).get("mean_seconds"));
    }

    public void testDuplicateRecordsAndFutureCohortRejected() {
        var a = item("a", "new", START);
        expectThrows(IllegalArgumentException.class, () -> IncidentMetrics.summarize(query, NOW, List.of(a, a)));
        expectThrows(IllegalArgumentException.class, () -> IncidentMetrics.summarize(query, START, List.of()));
    }
}
