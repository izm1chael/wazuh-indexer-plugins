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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Descriptive native event profile. No decoder correctness or telemetry completeness is inferred. */
public final class EventBehaviourModel {
    public static final int DAYS=28, MAX=2000, MAX_RELATIONS=100;
    public static final long DAY=86400;
    public static final Set<String> MODES=Set.of("authentication","process","network");
    private EventBehaviourModel(){}
    public record Input(String mode,String cluster,String space,String dataset,String subject,Instant day){
        public Input {
            if(!MODES.contains(mode)||!valid(cluster)||!valid(space)||!valid(dataset)||!valid(subject)||day==null||
                    day.getNano()!=0||Math.floorMod(day.getEpochSecond(),DAY)!=0||
                    day.isBefore(Instant.parse("2000-01-29T00:00:00Z"))||
                    !day.plusSeconds(DAY).isBefore(Instant.parse("2100-01-01T00:00:00Z")))throw invalid();
        }
        public String field(){return "authentication".equals(mode)?"user.id":"host.id";}
        public Instant from(){return day.minusSeconds(DAYS*DAY);}
        public Instant until(){return day.plusSeconds(DAY);}
        public Map<String,Object> definition(){return Map.of("mode",mode,"cluster",cluster,"space",space,"dataset",dataset,"subject",subject,"day",day.toString());}
        public void completed(Instant now){if(until().isAfter(now.minusSeconds(120)))throw invalid();}
    }
    public record Ref(String index,String id){
        public Ref {
            if(index==null||index.length()>255||!index.matches("(?:\\.ds-)?wazuh-events-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}")||
                    id==null||id.isBlank()||id.length()>512||id.chars().anyMatch(Character::isISOControl))throw invalid();
        }
    }
    public record Row(Ref ref,Instant at,Instant ingested,String outcome,String relation,String auxiliary){}
    private static boolean valid(String value){
        return value!=null&&!value.isBlank()&&value.length()<=256&&value.equals(value.trim())&&!value.chars().anyMatch(Character::isISOControl);
    }
    /** Reject mixed nested/dotted keys and object/array ambiguity. */
    static Object raw(Map<String,Object> source,String field){
        if(source==null)throw invalid();
        String[] parts=field.split("\\.");
        Object node=source;
        for(int n=0;n<parts.length;n++){
            if(node==null)return null;
            if(!(node instanceof Map<?,?> map))throw invalid();
            String remaining=String.join(".",Arrays.copyOfRange(parts,n,parts.length));
            if(n<parts.length-1&&map.containsKey(remaining)){
                if(map.containsKey(parts[n]))throw invalid();
                return map.get(remaining);
            }
            node=map.get(parts[n]);
        }
        return node;
    }
    private static String scalar(Map<String,Object> source,String field){
        Object raw=raw(source,field);
        if(raw==null)return null;
        if(!(raw instanceof String s)||!valid(s))throw invalid();
        return s;
    }
    private static boolean includes(Map<String,Object> source,String field,String expected){
        Object raw=raw(source,field);
        if(raw instanceof String s)return valid(s)&&expected.equals(s);
        if(!(raw instanceof List<?> rows)||rows.isEmpty()||rows.size()>16)return false;
        var seen=new HashSet<String>();
        for(Object item:rows)if(!(item instanceof String s)||!valid(s)||!seen.add(s))throw invalid();
        return seen.contains(expected);
    }
    private static Instant timestamp(Map<String,Object> source,String field){
        String s=scalar(source,field);return s==null?null:Instant.parse(s);
    }
    static Row project(Input input,Ref ref,Map<String,Object> source){
        if(!input.cluster().equals(scalar(source,"wazuh.cluster.name"))||!input.space().equals(scalar(source,"wazuh.space.name"))||
                !input.dataset().equals(scalar(source,"event.dataset"))||!input.subject().equals(scalar(source,input.field()))||
                !includes(source,"event.category",input.mode()))throw invalid();
        if("process".equals(input.mode())&&!includes(source,"event.type","start"))throw invalid();
        Instant at=timestamp(source,"@timestamp");
        if(at==null||at.isBefore(input.from())||!at.isBefore(input.until()))throw invalid();
        Instant ingested=timestamp(source,"event.ingested");
        String outcome="not_applicable";
        if("authentication".equals(input.mode())){
            String value=scalar(source,"event.outcome");
            outcome="success".equals(value)||"failure".equals(value)?value:"unknown";
        }
        String relation=switch(input.mode()){
            case "authentication" -> scalar(source,"host.id");
            case "process" -> scalar(source,"process.executable");
            default -> scalar(source,"destination.ip");
        };
        String auxiliary="authentication".equals(input.mode())?scalar(source,"source.ip"):null;
        // Only canonical IPv4 relationships in this version; unsupported forms are counted as missing, not rewritten.
        if("network".equals(input.mode())&&!IncidentHuntService.valid("destination.ip",relation))relation=null;
        if(auxiliary!=null&&!IncidentHuntService.valid("source.ip",auxiliary))auxiliary=null;
        return new Row(ref,at,ingested,outcome,relation,auxiliary);
    }
    private static final class Relations {
        final Set<String> history=new HashSet<>();
        final Map<String,Integer> current=new TreeMap<>();
        int missingHistory,missingCurrent;
        void add(String value,boolean comparison){
            if(value==null){if(comparison)missingCurrent++;else missingHistory++;return;}
            if(comparison)current.merge(value,1,Integer::sum);else history.add(value);
            if(history.size()>MAX_RELATIONS||current.size()>MAX_RELATIONS)throw invalid();
        }
        Map<String,Object> report(){
            var novel=new ArrayList<Map<String,Object>>();
            for(var entry:current.entrySet())if(!history.contains(entry.getKey()))novel.add(Map.of("value",entry.getKey(),"count",entry.getValue()));
            return Map.of("baseline_distinct",history.size(),"comparison_distinct",current.size(),"newly_observed",novel,
                    "baseline_missing",missingHistory,"comparison_missing",missingCurrent);
        }
    }
    public static Map<String,Object> evaluate(Input input,List<Row> rows,Instant observed){
        input.completed(observed);
        if(rows==null||rows.size()>MAX)throw invalid();
        int[] days=new int[DAYS+1];int[] failures=new int[DAYS+1];int[] successes=new int[DAYS+1];int[] unknown=new int[DAYS+1];
        int lagKnown=0,late=0,negative=0,future=0;
        long maxLag=0;
        var seen=new HashSet<Ref>();var primary=new Relations();var auxiliary=new Relations();
        for(Row row:rows){
            if(row==null||row.ref()==null||row.at()==null||!seen.add(row.ref())||row.at().isBefore(input.from())||!row.at().isBefore(input.until()))throw invalid();
            int n=(int)((row.at().getEpochSecond()-input.from().getEpochSecond())/DAY);
            days[n]++;
            if("authentication".equals(input.mode())){
                switch(row.outcome()){case "success" -> successes[n]++;case "failure" -> failures[n]++;case "unknown" -> unknown[n]++;default -> throw invalid();}
            }else if(!"not_applicable".equals(row.outcome()))throw invalid();
            primary.add(row.relation(),n==DAYS);
            if("authentication".equals(input.mode()))auxiliary.add(row.auxiliary(),n==DAYS);
            if(row.ingested()!=null){
                if(row.ingested().isBefore(row.at()))negative++;
                else if(row.ingested().isAfter(observed))future++;
                else {
                    lagKnown++;long lag=java.time.Duration.between(row.at(),row.ingested()).getSeconds();
                    if(lag>120)late++;maxLag=Math.max(maxLag,lag);
                }
            }
        }
        var result=new LinkedHashMap<String,Object>();
        result.put("scope","caller_visible_native_event_profile");result.put("model","event_profile_v1");
        result.put("query",input.definition());result.put("observed_at",observed.toString());
        result.put("event_count",rows.size());result.put("volume",volume(days));
        result.put("authentication", "authentication".equals(input.mode())?Map.of("success",volume(successes),"failure",volume(failures),"unknown",volume(unknown)):null);
        result.put("relationship",primary.report());
        result.put("source_relationship","authentication".equals(input.mode())?auxiliary.report():null);
        result.put("coverage",Map.of("status","search_complete_telemetry_unverified","active_baseline_days",Arrays.stream(days,0,DAYS).filter(n->n>0).count(),
                "ingest_lag_known",lagKnown,"ingest_lag_missing",rows.size()-lagKnown-negative-future,
                "ingest_before_event",negative,"ingest_after_observation",future,"lag_over_120s",late,"max_lag_seconds",maxLag));
        return result;
    }
    private static Map<String,Object> volume(int[] counts){
        return RuleBehaviourModel.assess(Arrays.stream(counts,0,DAYS).boxed().toList(),counts[DAYS]);
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid or incomplete native event profile");}
}
