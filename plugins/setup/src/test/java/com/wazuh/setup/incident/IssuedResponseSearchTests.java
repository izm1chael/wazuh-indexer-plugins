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
import java.util.Map;
import java.util.List;
import java.util.Set;

public class IssuedResponseSearchTests extends OpenSearchTestCase {
    private static final FindingReference REF = new FindingReference(".ds-wazuh-findings-v5-security-000001", "doc");
    private static final String INDEX = ".ds-wazuh-active-responses-000001";

    public void testExactPairAndNoExecutableContent() {
        var source = Map.<String, Object>of("event", Map.of("index", REF.index(), "doc_id", REF.documentId()),
                "wazuh", Map.of("active_response", Map.of("name", "Review", "executable", "SECRET", "extra_arguments", List.of("SECRET"))),
                "@timestamp", "2026-11-26T12:00:00Z");
        var projected = IssuedResponseSearch.project(INDEX, "response", source, Set.of(REF));
        assertEquals("issued_only", projected.get("state"));
        assertEquals(false, projected.get("execution_verified"));
        assertEquals("Review", projected.get("name"));
        assertFalse(projected.toString().contains("SECRET"));
        assertNull(IssuedResponseSearch.project(INDEX, "response", Map.of("event.index", "other", "event.doc_id", REF.documentId()), Set.of(REF)));
        assertNull(IssuedResponseSearch.project(INDEX, "response", Map.of("event.doc_id", REF.documentId()), Set.of(REF)));
        assertNull(IssuedResponseSearch.project(INDEX, "response", Map.of("event.index", List.of(REF.index()), "event.doc_id", REF.documentId()), Set.of(REF)));
    }

    public void testFixedBoundedQuery() {
        var query = IssuedResponseSearch.build(Set.of(REF));
        assertEquals(101, query.size());
        assertTrue(query.query().toString().contains("event.index"));
        assertTrue(query.query().toString().contains("event.doc_id"));
        assertFalse(query.toString().contains("extra_arguments"));
    }
}
