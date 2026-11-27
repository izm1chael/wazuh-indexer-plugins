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

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Deterministic descriptive finding-volume baseline, not a calibrated probability or risk score. */
public final class EntityBehaviourModel {
    public static final int DAYS = 7;
    public static final long DAY = 86400;
    public static final Set<String> FIELDS = Set.of("wazuh.agent.id","host.id","host.name","host.hostname","host.ip",
            "source.ip","destination.ip","user.name","user.id");
    private EntityBehaviourModel() {}

    public static void window(String field, List<String> values, Instant from, Instant until, Instant now) {
        if (!FIELDS.contains(field) || values.isEmpty() || values.size()>5 || from.getNano()!=0 || until.getNano()!=0 ||
                Math.floorMod(from.getEpochSecond(),DAY)!=0 || !until.equals(from.plusSeconds(DAY)) ||
                until.isAfter(now.minusSeconds(120)) || from.minusSeconds(DAYS*DAY).isBefore(Instant.parse("2000-01-01T00:00:00Z")) ||
                until.isAfter(Instant.parse("2100-01-01T00:00:00Z"))) throw new IllegalArgumentException("Expected completed UTC day and one to five exact entities");
    }

    public record Assessment(int baselineTotal, int activeDays, int baselineMaximum, int threshold, int current, String classification) {
        Map<String,Object> project(String value,List<Integer> daily) {
            return Map.of("value",value,"daily_counts",daily,"baseline_total",baselineTotal,"active_days",activeDays,
                    "baseline_maximum",baselineMaximum,"threshold",threshold,"current_count",current,"classification",classification);
        }
    }

    public static Assessment assess(List<Integer> daily,int current) {
        if (daily==null || daily.size()!=DAYS || current<0 || current>100) throw new IllegalArgumentException("Invalid daily counts");
        int total=0,active=0,max=0;
        for (Integer count:daily) {
            if (count==null || count<0 || count>100) throw new IllegalArgumentException("Invalid baseline count");
            total+=count; if(count>0) active++; max=Math.max(max,count);
        }
        if(total>100) throw new IllegalArgumentException("Baseline exceeds bounded hunt");
        // Integer arithmetic, transparent threshold. No normal-distribution assumption.
        int threshold=Math.max(5,Math.max(max+3,(2*total+DAYS-1)/DAYS));
        String classification=total==0 ? (current==0?"no_observed_activity":"newly_observed") :
                active<3 ? "sparse_baseline" : current>=threshold ? "elevated_volume" : "within_volume_threshold";
        return new Assessment(total,active,max,threshold,current,classification);
    }

    /** Count each concrete finding once per exact literal; a multi-valued finding can count for several literals. */
    public static List<Map<String,Object>> evaluate(String field,List<String> values,Instant from,Instant until,
            Map<String,Object> baseline,Map<String,Object> current) {
        var seen=new HashSet<FindingReference>();
        int[][] daily=counts(field,values,from.minusSeconds(DAYS*DAY),from,baseline,DAYS,seen);
        int[][] target=counts(field,values,from,until,current,1,seen);
        var result=new ArrayList<Map<String,Object>>();
        for(int n=0;n<values.size();n++) {
            var row=new ArrayList<Integer>();
            for(int d=0;d<DAYS;d++) row.add(daily[n][d]);
            result.add(assess(row,target[n][0]).project(values.get(n),List.copyOf(row)));
        }
        return List.copyOf(result);
    }

    private static int[][] counts(String field,List<String> values,Instant from,Instant until,Map<String,Object> report,
            int days,Set<FindingReference> seen) {
        if (report==null || !report.keySet().equals(Set.of("scope","field","values","from","until","rows","match_count")) ||
                !"caller_visible_findings_exact_terms".equals(report.get("scope")) || !field.equals(report.get("field")) ||
                !values.equals(report.get("values")) || !from.toString().equals(report.get("from")) || !until.toString().equals(report.get("until")) ||
                !(report.get("rows") instanceof List<?> rows) || rows.size()>100 || !Integer.valueOf(rows.size()).equals(report.get("match_count")))
            throw new IllegalArgumentException("Incomplete behaviour population");
        int[][] counts=new int[values.size()][days];
        for(Object item:rows) {
            if(!(item instanceof Map<?,?> row) || !row.keySet().equals(Set.of("index","document_id","timestamp","matched_values")) ||
                    !(row.get("index") instanceof String index) || !(row.get("document_id") instanceof String id) ||
                    !(row.get("timestamp") instanceof String timestamp) || !(row.get("matched_values") instanceof List<?> matches) ||
                    matches.isEmpty() || matches.size()>values.size() || !seen.add(new FindingReference(index,id)))
                throw new IllegalArgumentException("Invalid behaviour finding identity");
            Instant at=Instant.parse(timestamp);
            if(at.isBefore(from) || !at.isBefore(until)) throw new IllegalArgumentException("Finding outside window");
            int day=(int)((at.getEpochSecond()-from.getEpochSecond())/DAY);
            var unique=new HashSet<>();
            for(Object value:matches) {
                int n=values.indexOf(value);
                if(n<0 || !unique.add(value)) throw new IllegalArgumentException("Invalid matched value");
                counts[n][day]++;
            }
        }
        return counts;
    }
}
