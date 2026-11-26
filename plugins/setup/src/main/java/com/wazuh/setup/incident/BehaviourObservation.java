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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Shared SOC observation state. No raw findings or client-supplied statistics are persisted. */
public final class BehaviourObservation {
    private static final Set<String> KEYS=Set.of("id","model","query","actor","observed_at","coverage","finding_count",
            "assessment","state","revision","review","incident_id");
    private BehaviourObservation() {}
    public static String fingerprint(RuleBehaviourModel.Input input) {
        return HexFormat.of().formatHex(digest("wazuh-rule-behaviour-scope-v1",input.field(),input.value(),input.rule().toString()));
    }
    public static UUID id(RuleBehaviourModel.Input input,String actor) {
        byte[] bytes=digest("wazuh-rule-behaviour-observation-v1",actor,fingerprint(input),input.day().toString());
        bytes[6]=(byte)((bytes[6]&15)|128);bytes[8]=(byte)((bytes[8]&63)|128);
        var buffer=ByteBuffer.wrap(bytes);return new UUID(buffer.getLong(),buffer.getLong());
    }
    private static byte[] digest(String... fields) {
        try {
            var hash=MessageDigest.getInstance("SHA-256");
            for(String field:fields){byte[] bytes=field.getBytes(StandardCharsets.UTF_8);hash.update(ByteBuffer.allocate(4).putInt(bytes.length).array());hash.update(bytes);}
            return hash.digest();
        }catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
    static String text(Object value,int max) {
        if(!(value instanceof String s)||s.isBlank()||s.length()>max||!s.equals(s.trim())||s.chars().anyMatch(Character::isISOControl))throw invalid();
        return s;
    }
    public static RuleBehaviourModel.Input input(Object raw) {
        if(!(raw instanceof Map<?,?> q)||!q.keySet().equals(Set.of("field","value","rule_uuid","day")))throw invalid();
        String rule=text(q.get("rule_uuid"),36),day=text(q.get("day"),20);
        UUID uuid=UUID.fromString(rule);Instant at=Instant.parse(day);
        if(!uuid.toString().equals(rule)||!at.toString().equals(day))throw invalid();
        return new RuleBehaviourModel.Input(text(q.get("field"),64),text(q.get("value"),256),uuid,at);
    }
    static Map<String,Object> create(RuleBehaviourModel.Input input,String actor,Map<String,Object> report) {
        if(!input.definition().equals(report.get("query"))||!actor.equals(report.get("actor"))||
                !"caller_visible_rule_finding_scan".equals(report.get("scope")))throw invalid();
        var doc=new LinkedHashMap<String,Object>();
        doc.put("id",id(input,actor).toString());
        for(String key:List.of("model","query","actor","observed_at","coverage","finding_count","assessment"))doc.put(key,report.get(key));
        if(!(doc.get("assessment") instanceof Map<?,?> assessment))throw invalid();
        doc.put("state",flagged(assessment)?"unreviewed":"not_flagged");doc.put("revision",1);
        doc.put("review",null);doc.put("incident_id",null);
        validate(doc);return doc;
    }
    private static boolean flagged(Map<?,?> assessment){
        return Set.of("newly_observed","elevated_rule_volume").contains(assessment.get("classification"));
    }
    public static void validate(Map<String,Object> row) {
        if(row==null||!row.keySet().equals(KEYS)||!RuleBehaviourModel.MODEL.equals(row.get("model"))||
                !"search_complete_telemetry_unverified".equals(row.get("coverage"))||
                !(row.get("assessment") instanceof Map<?,?> a)||!(a.get("daily_counts") instanceof List<?> raw)||
                !(a.get("current_count") instanceof Integer current)||!(row.get("revision") instanceof Integer revision))throw invalid();
        var input=input(row.get("query"));String actor=text(row.get("actor"),1024);
        Instant at=Instant.parse(text(row.get("observed_at"),64));input.requireCompleted(at);
        if(!id(input,actor).toString().equals(row.get("id")))throw invalid();
        var counts=new java.util.ArrayList<Integer>();
        for(Object n:raw){if(!(n instanceof Integer count))throw invalid();counts.add(count);}
        var expected=RuleBehaviourModel.assess(counts,current);
        if(!expected.equals(a)||!Integer.valueOf((Integer)expected.get("baseline_total")+current).equals(row.get("finding_count")))throw invalid();
        String state=text(row.get("state"),32);
        if(revision==1){
            if(!(flagged(a)?"unreviewed":"not_flagged").equals(state)||row.get("review")!=null||row.get("incident_id")!=null)throw invalid();
            return;
        }
        if(!flagged(a)||!(row.get("review") instanceof Map<?,?> review)||!review.keySet().equals(Set.of("actor","at","decision","reason")))throw invalid();
        String reviewer=text(review.get("actor"),1024),decision=text(review.get("decision"),32);
        text(review.get("reason"),1024);
        if(actor.equals(reviewer)||Instant.parse(text(review.get("at"),64)).isBefore(at)||
                !Set.of("dismissed","monitor","escalation_requested").contains(decision))throw invalid();
        if(revision==2&&decision.equals(state)&&row.get("incident_id")==null)return;
        if(revision==3&&"promoted".equals(state)&&"escalation_requested".equals(decision)&&
                incidentId(row,reviewer).toString().equals(row.get("incident_id")))return;
        throw invalid();
    }
    static Map<String,Object> review(Map<String,Object> row,int revision,String reviewer,String decision,String reason,Instant now){
        validate(row);
        if(!Integer.valueOf(revision).equals(row.get("revision"))||!"unreviewed".equals(row.get("state"))||
                row.get("actor").equals(reviewer)||!Set.of("dismissed","monitor","escalation_requested").contains(decision))throw invalid();
        var next=new LinkedHashMap<>(row);next.put("state",decision);next.put("revision",2);
        next.put("review",Map.of("actor",text(reviewer,1024),"at",now.toString(),"decision",decision,"reason",text(reason,1024)));
        validate(next);return next;
    }
    static UUID incidentId(Map<String,Object> row,String reviewer){
        return IncidentRequestIdentity.incidentId(reviewer,UUID.fromString((String)row.get("id")));
    }
    static Map<String,Object> incidentPayload(Map<String,Object> row,String reviewer){
        validate(row);
        if(!"escalation_requested".equals(row.get("state"))||!reviewer.equals(((Map<?,?>)row.get("review")).get("actor")))throw invalid();
        return Map.of("request_id",row.get("id"),"title","Behaviour observation requiring investigation",
                "description","Reviewed statistical observation "+row.get("id")+". Finding-volume deviation only; telemetry coverage unverified. Review the observation and independently capture supporting findings. No confirmed compromise.",
                "severity","informational","priority","medium","tlp","TLP:AMBER");
    }
    static Map<String,Object> promoted(Map<String,Object> row,String reviewer,UUID incident){
        incidentPayload(row,reviewer);
        if(!incidentId(row,reviewer).equals(incident))throw invalid();
        var next=new LinkedHashMap<>(row);next.put("state","promoted");next.put("revision",3);next.put("incident_id",incident.toString());
        validate(next);return next;
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid behavioural observation or transition");}
}
