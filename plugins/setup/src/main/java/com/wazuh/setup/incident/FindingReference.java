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

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** A concrete findings backing-index reference, never a wildcard, alias, or client-supplied query. */
public record FindingReference(String index, String documentId) {
    private static final Pattern INDEX = Pattern.compile("(?:\\.ds-)?wazuh-findings-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}");

    public FindingReference {
        if (index == null || index.length() > 255 || !INDEX.matcher(index).matches() ||
                documentId == null || documentId.isBlank() || documentId.length() > 512 ||
                documentId.chars().anyMatch(Character::isISOControl)) {
            throw new OpenSearchStatusException("Invalid concrete finding reference", RestStatus.BAD_REQUEST);
        }
    }

    public static FindingReference parse(Map<String, Object> input) {
        if (input == null || !input.keySet().equals(Set.of("index", "document_id")) ||
                !(input.get("index") instanceof String index) ||
                !(input.get("document_id") instanceof String id)) {
            throw new OpenSearchStatusException("Finding index and document ID required", RestStatus.BAD_REQUEST);
        }
        return new FindingReference(index, id);
    }

    public Map<String, Object> toMap() {
        return Map.of("index", index, "document_id", documentId);
    }
}
