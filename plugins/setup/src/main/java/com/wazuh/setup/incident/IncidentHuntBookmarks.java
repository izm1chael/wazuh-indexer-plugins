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
import java.util.Map;
import java.util.Set;

/** Analyst-authored shared-case query bookmarks. No stored results, automatic execution or visibility claims. */
final class IncidentHuntBookmarks {
    static final int MAX = 20;
    private static final Set<String> FIELDS = Set.of("id","label","query","created_by","created_at","state","withdrawn_by","withdrawn_at","withdrawal_reason","withdrawn_revision");
    private IncidentHuntBookmarks() {}

    static Map<String,Object> query(Object raw) {
        if (!(raw instanceof Map<?,?> row) || !row.keySet().equals(Set.of("field","values","from","until")) ||
                !(row.get("field") instanceof String field) || !(row.get("values") instanceof List<?> values) ||
                values.isEmpty() || values.size()>20 || !(row.get("from") instanceof String from) || !(row.get("until") instanceof String until))
            throw invalid("Invalid bookmark query");
        var terms = new ArrayList<String>();
        for (Object value : values) {
            if (!(value instanceof String s)) throw invalid("Exact bookmark values required");
            terms.add(s);
        }
        try {
            var input = new IncidentHuntService.Input(field,terms,Instant.parse(from),Instant.parse(until));
            if (input.from().getNano()%1000000!=0 || input.until().getNano()%1000000!=0) throw invalid("Millisecond query bounds required");
            return Map.of("field",input.field(),"values",input.values(),"from",input.from().toString(),"until",input.until().toString());
        } catch (RuntimeException e) { throw invalid("Invalid bounded bookmark query"); }
    }

    static List<Map<String,Object>> project(Map<String,Object> source) {
        if (!(source.getOrDefault("hunt_bookmarks",List.of()) instanceof List<?> rows) || rows.size()>MAX ||
                !(source.get("revision") instanceof Integer revision) || revision<1 || !(source.get("id") instanceof String id))
            throw conflict("Invalid bookmark history");
        var result = new ArrayList<Map<String,Object>>();
        var revisions = new HashSet<Integer>(); var active = new HashSet<Map<String,Object>>();
        int prior = 0;
        for (Object item : rows) {
            if (!(item instanceof Map<?,?> row) || !row.keySet().equals(FIELDS)) throw conflict("Invalid bookmark record");
            String key = text(row.get("id"),64);
            if (!key.startsWith(id+":")) throw conflict("Invalid bookmark identity");
            int created;
            try { created=Integer.parseInt(key.substring(id.length()+1)); } catch (RuntimeException e) { throw conflict("Invalid bookmark revision"); }
            if (!key.equals(id+":"+created) || created<=prior || created>revision || !revisions.add(created)) throw conflict("Invalid bookmark revision");
            prior=created;
            String label=text(row.get("label"),128), actor=text(row.get("created_by"),1024), at=text(row.get("created_at"),64);
            var createdAt=Instant.parse(at);
            var definition=query(row.get("query"));
            if (!definition.equals(row.get("query"))) throw conflict("Noncanonical bookmark query");
            String state=text(row.get("state"),32);
            if ("saved".equals(state)) {
                if (row.get("withdrawn_by")!=null || row.get("withdrawn_at")!=null || row.get("withdrawal_reason")!=null ||
                        row.get("withdrawn_revision")!=null || !active.add(definition)) throw conflict("Invalid active bookmark");
            } else if ("withdrawn".equals(state)) {
                text(row.get("withdrawn_by"),1024); text(row.get("withdrawal_reason"),1024);
                if (!(row.get("withdrawn_revision") instanceof Integer withdrawn) || withdrawn<=created || withdrawn>revision || !revisions.add(withdrawn) ||
                        Instant.parse(text(row.get("withdrawn_at"),64)).isBefore(createdAt)) throw conflict("Invalid bookmark withdrawal");
            } else throw conflict("Invalid bookmark state");
            var out=new LinkedHashMap<String,Object>();
            out.put("id",key); out.put("label",label); out.put("query",definition); out.put("created_by",actor); out.put("created_at",at); out.put("state",state);
            for(String field:List.of("withdrawn_by","withdrawn_at","withdrawal_reason","withdrawn_revision")) out.put(field,row.get(field));
            result.add(out);
        }
        return result;
    }

    static String apply(Map<String,Object> next, Map<String,Object> changes, IncidentMutation.Operation op,
            Map<String,Object> input,String actor,String now,int revision) {
        var rows=project(next); Map<String,Object> before=null, after; String kind;
        if (op==IncidentMutation.Operation.SAVE_HUNT_BOOKMARK) {
            if (!input.keySet().equals(Set.of("label","query"))) throw invalid("Exact bookmark definition required");
            if (rows.size()>=MAX) throw conflict("Bookmark lifetime capacity reached");
            var definition=query(input.get("query"));
            if (rows.stream().anyMatch(row -> "saved".equals(row.get("state")) && definition.equals(row.get("query")))) throw conflict("Query already bookmarked");
            after=new LinkedHashMap<>();
            after.put("id",next.get("id")+":"+revision); after.put("label",text(input.get("label"),128)); after.put("query",definition);
            after.put("created_by",actor); after.put("created_at",now); after.put("state","saved");
            for(String field:List.of("withdrawn_by","withdrawn_at","withdrawal_reason","withdrawn_revision")) after.put(field,null);
            rows.add(after); kind="hunt_bookmark_saved";
        } else {
            if (!input.keySet().equals(Set.of("bookmark_id","reason"))) throw invalid("Exact bookmark withdrawal required");
            String id=text(input.get("bookmark_id"),64);
            before=rows.stream().filter(row->id.equals(row.get("id"))).findFirst().orElseThrow(()->conflict("Bookmark not found"));
            if (!"saved".equals(before.get("state"))) throw conflict("Bookmark already withdrawn");
            after=new LinkedHashMap<>(before); after.put("state","withdrawn"); after.put("withdrawn_by",actor); after.put("withdrawn_at",now);
            after.put("withdrawal_reason",text(input.get("reason"),1024)); after.put("withdrawn_revision",revision);
            rows.set(rows.indexOf(before),after); kind="hunt_bookmark_withdrawn";
        }
        next.put("hunt_bookmarks",rows);
        var change=new LinkedHashMap<String,Object>(); change.put("before",before); change.put("after",after);
        changes.put("hunt_bookmark",change);
        changes.put("bookmark_id",Map.of("before",after.get("id"),"after",after.get("id")));
        return kind;
    }
    private static String text(Object value,int max) {
        if (!(value instanceof String s) || s.isBlank() || s.length()>max || !s.equals(s.trim()) ||
                s.chars().anyMatch(Character::isISOControl)) throw invalid("Invalid bookmark text");
        return s;
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message,RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message,RestStatus.CONFLICT); }
}
