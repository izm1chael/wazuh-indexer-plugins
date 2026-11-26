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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** A single exact entity/rule pair over 28 baseline days and one comparison day. */
public final class RuleBehaviourModel {
    public static final int DAYS=28, MAX_HITS=2000, SAMPLE=20;
    public static final long DAY=86400;
    public static final String MODEL="rule_volume_v2";
    private RuleBehaviourModel() {}

    public record Input(String field,String value,UUID rule,Instant day) {
        public Input {
            if(field==null||!EntityBehaviourModel.FIELDS.contains(field)||!IncidentHuntService.valid(field,value)||rule==null||day==null||
                    day.getNano()!=0||Math.floorMod(day.getEpochSecond(),DAY)!=0||
                    day.isBefore(Instant.parse("2000-01-29T00:00:00Z"))||!day.plusSeconds(DAY).isBefore(Instant.parse("2100-01-01T00:00:00Z")))
                throw new IllegalArgumentException("Invalid exact rule behaviour input");
        }
        public Instant from(){return day.minusSeconds(DAYS*DAY);}
        public Instant until(){return day.plusSeconds(DAY);}
        public Map<String,Object> definition(){return Map.of("field",field,"value",value,"rule_uuid",rule.toString(),"day",day.toString());}
        public void requireCompleted(Instant now){
            if(until().isAfter(now.minusSeconds(120))) throw new IllegalArgumentException("Comparison day not completed");
        }
    }

    public record Observation(FindingReference reference,Instant at) {}
    public static Map<String,Object> assess(List<Integer> daily,int current) {
        if(daily==null||daily.size()!=DAYS||current<0||current>MAX_HITS)throw new IllegalArgumentException("Invalid rule volume counts");
        int total=0,active=0,weekdayMax=0;
        int[] sorted=new int[DAYS];
        for(int n=0;n<DAYS;n++){
            Integer count=daily.get(n);
            if(count==null||count<0||count>MAX_HITS)throw new IllegalArgumentException("Invalid daily count");
            sorted[n]=count;total+=count;if(count>0)active++;
            if(n%7==0)weekdayMax=Math.max(weekdayMax,count);
        }
        if(total+current>MAX_HITS)throw new IllegalArgumentException("Population exceeds scan cap");
        Arrays.sort(sorted);
        // Twice the median, and twice the median absolute deviation, retain exact half-count arithmetic.
        int median2=sorted[13]+sorted[14];
        int[] deviations=Arrays.stream(sorted).map(n->Math.abs(2*n-median2)).sorted().toArray();
        int mad4=deviations[13]+deviations[14];
        int robust=(2*median2+3*mad4+3)/4;
        int threshold=Math.max(5,Math.max(weekdayMax+3,Math.max((2*total+DAYS-1)/DAYS,robust)));
        String state=total==0?(current==0?"no_observed_activity":"newly_observed"):
                active<7?"sparse_baseline":current>=threshold?"elevated_rule_volume":"within_volume_threshold";
        return Map.of("daily_counts",List.copyOf(daily),"baseline_total",total,"active_days",active,
                "same_weekday_maximum",weekdayMax,"median_times_two",median2,"mad_times_four",mad4,
                "threshold",threshold,"current_count",current,"classification",state);
    }

    public static Map<String,Object> evaluate(Input input,List<Observation> rows) {
        if(rows==null||rows.size()>MAX_HITS)throw new IllegalArgumentException("Incomplete rule behaviour population");
        var seen=new HashSet<FindingReference>();
        var ordered=new ArrayList<>(rows);
        for(var row:ordered){
            if(row==null||row.reference()==null||row.at()==null||!seen.add(row.reference())||
                    row.at().isBefore(input.from())||!row.at().isBefore(input.until()))
                throw new IllegalArgumentException("Invalid exact finding population");
        }
        ordered.sort(java.util.Comparator.comparing(Observation::at).thenComparing(row->row.reference().index()).thenComparing(row->row.reference().documentId()));
        int[] counts=new int[DAYS+1];
        var sample=new ArrayList<Map<String,Object>>();
        for(var row:ordered){
            int n=(int)((row.at().getEpochSecond()-input.from().getEpochSecond())/DAY);
            counts[n]++;
            if(n==DAYS&&sample.size()<SAMPLE)sample.add(Map.of("index",row.reference().index(),"document_id",row.reference().documentId(),"timestamp",row.at().toString()));
        }
        var daily=Arrays.stream(counts,0,DAYS).boxed().toList();
        return Map.of("scope","caller_visible_rule_finding_scan","model",MODEL,"query",input.definition(),
                "baseline_from",input.from().toString(),"until",input.until().toString(),"finding_count",rows.size(),
                "assessment",assess(daily,counts[DAYS]),"current_sample",sample,
                "coverage","search_complete_telemetry_unverified");
    }
}
