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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Shared wire contract, duplicated byte-for-byte across the two independently loaded plugins. */
public final class DetectionRelease {
    public static final String INDEX = ".wazuh-detection-releases-v1";
    public static final String FORMAT = "wazuh-detection-release-v1";
    private static final Set<String> EVIDENCE = Set.of("pack_sha256","test_sha256","custom_sha256","preview_sha256",
            "labels_sha256","integration","changed_rules","historical_events","prospective_events",
            "prospective_seconds","historical_metrics","prospective_metrics");
    private static final Set<String> METRICS = Set.of("positive","negative","unknown","lost_positive","gained_positive",
            "new_false_positive","removed_false_positive","baseline_tp","baseline_fp","baseline_tn","baseline_fn",
            "candidate_tp","candidate_fp","candidate_tn","candidate_fn");
    private static final Set<String> RECORD = Set.of("format","id","evidence","author","submitted_at","state","revision",
            "review","reservation","outcome");
    private DetectionRelease() {}
    public static String text(Object value,int cap) {
        if (!(value instanceof String s)||s.isBlank()||s.length()>cap||!s.equals(s.trim())||
                s.chars().anyMatch(Character::isISOControl)) throw invalid();
        return s;
    }
    public static String hash(Object value) {
        String s=text(value,64);if(!s.matches("[a-f0-9]{64}"))throw invalid();return s;
    }
    public static String actor(Object value) {
        String s=text(value,1024);if("_shared".equals(s))throw invalid();return s;
    }
    public static String uuid(Object value) {
        String s=text(value,36);if(!UUID.fromString(s).toString().equals(s))throw invalid();return s;
    }
    public static Instant instant(Object value) {
        String s=text(value,64);Instant at;
        try{at=Instant.parse(s);}catch(java.time.DateTimeException e){throw invalid();}
        if(!at.toString().equals(s))throw invalid();
        return at;
    }
    private static int count(Object value,int cap) {
        if(!(value instanceof Integer n)||n<0||n>cap)throw invalid();
        return n;
    }
    @SuppressWarnings("unchecked")
    public static Map<String,Object> exact(Object value,Set<String> keys) {
        if(!(value instanceof Map<?,?> m)||!m.keySet().equals(keys))throw invalid();
        return (Map<String,Object>) m;
    }
    public static List<String> rules(Object value) {
        if(!(value instanceof List<?> raw)||raw.isEmpty()||raw.size()>20)throw invalid();
        var rules=new ArrayList<String>();
        for(Object item:raw){
            String rule=uuid(item);
            if(!rules.isEmpty()&&rules.get(rules.size()-1).compareTo(rule)>=0)throw invalid();
            rules.add(rule);
        }
        return List.copyOf(rules);
    }
    private static void metrics(Object value,int population,boolean historical) {
        var m=exact(value,METRICS);
        var n=new LinkedHashMap<String,Integer>();
        m.forEach((k,v)->n.put(k,count(v,population)));
        int pos=n.get("positive"),neg=n.get("negative"),unknown=n.get("unknown");
        int lost=n.get("lost_positive"),gained=n.get("gained_positive");
        int newFp=n.get("new_false_positive"),removed=n.get("removed_false_positive");
        int btp=n.get("baseline_tp"),bfp=n.get("baseline_fp"),btn=n.get("baseline_tn"),bfn=n.get("baseline_fn");
        int ctp=n.get("candidate_tp"),cfp=n.get("candidate_fp"),ctn=n.get("candidate_tn"),cfn=n.get("candidate_fn");
        if(pos+neg+unknown!=population||pos<10||neg<10||unknown!=0||
                btp+bfn!=pos||ctp+cfn!=pos||bfp+btn!=neg||cfp+ctn!=neg||
                lost>Math.min(btp,cfn)||gained>Math.min(bfn,ctp)||
                newFp>Math.min(btn,cfp)||removed>Math.min(bfp,ctn)||
                ctp!=btp+gained-lost||cfp!=bfp+newFp-removed||lost!=0||newFp!=0||
                (historical&&gained==0&&removed==0))throw invalid();
    }
    public static Map<String,Object> evidence(Object raw) {
        var e=exact(raw,EVIDENCE);
        for(String key:List.of("pack_sha256","test_sha256","custom_sha256","preview_sha256","labels_sha256"))hash(e.get(key));
        uuid(e.get("integration"));
        List<String> rules=rules(e.get("changed_rules"));
        int h=count(e.get("historical_events"),30000),p=count(e.get("prospective_events"),30000);
        if(h+p>30000||count(e.get("prospective_seconds"),288*3600)<86400)throw invalid();
        var historical=exact(e.get("historical_metrics"),Set.copyOf(rules));
        var prospective=exact(e.get("prospective_metrics"),Set.copyOf(rules));
        for(String rule:rules){metrics(historical.get(rule),h,true);metrics(prospective.get(rule),p,false);}
        return e;
    }
    public static Map<String,Object> submit(String plan,Object evidence,String author,Instant now) {
        var record=new LinkedHashMap<String,Object>();
        record.put("format",FORMAT);record.put("id",hash(plan));record.put("evidence",evidence(evidence));
        record.put("author",actor(author));record.put("submitted_at",now.toString());record.put("state","submitted");
        record.put("revision",1);record.put("review",null);record.put("reservation",null);record.put("outcome",null);
        validate(record);return record;
    }
    public static void validate(Map<String,Object> record) {
        exact(record,RECORD);
        if(!FORMAT.equals(record.get("format")))throw invalid();
        hash(record.get("id"));var e=evidence(record.get("evidence"));
        String author=actor(record.get("author"));Instant submitted=instant(record.get("submitted_at"));
        int revision=count(record.get("revision"),4);String state=text(record.get("state"),32);
        if(revision==1&&"submitted".equals(state)&&record.get("review")==null&&record.get("reservation")==null&&record.get("outcome")==null)return;
        var review=exact(record.get("review"),Set.of("actor","at","decision","reason","pack_sha256","deployer","expires"));
        String reviewer=actor(review.get("actor"));Instant reviewed=instant(review.get("at"));
        if(author.equals(reviewer)||reviewed.isBefore(submitted)||!e.get("pack_sha256").equals(hash(review.get("pack_sha256"))))throw invalid();
        text(review.get("reason"),1024);
        String decision=text(review.get("decision"),16);
        if("rejected".equals(decision)){
            if(revision==2&&"rejected".equals(state)&&review.get("deployer")==null&&review.get("expires")==null&&
                    record.get("reservation")==null&&record.get("outcome")==null)return;
            throw invalid();
        }
        if(!"approved".equals(decision))throw invalid();
        String deployer=actor(review.get("deployer"));Instant expires=instant(review.get("expires"));
        if(deployer.equals(author)||deployer.equals(reviewer)||!expires.isAfter(reviewed)||expires.isAfter(reviewed.plusSeconds(3600))||
                expires.getNano()!=0)throw invalid();
        if(revision==2&&"approved".equals(state)&&record.get("reservation")==null&&record.get("outcome")==null)return;
        var reserved=exact(record.get("reservation"),Set.of("actor","at"));
        Instant at=instant(reserved.get("at"));
        if(!deployer.equals(actor(reserved.get("actor")))||at.isBefore(reviewed)||!at.isBefore(expires))throw invalid();
        if(revision==3&&"reserved".equals(state)&&record.get("outcome")==null)return;
        var outcome=exact(record.get("outcome"),Set.of("at","native_status"));
        if(revision!=4||!"native_reported".equals(state)||instant(outcome.get("at")).isBefore(at)||
                count(outcome.get("native_status"),599)<100)throw invalid();
    }
    public static Map<String,Object> review(Map<String,Object> old,String actor,String pack,String decision,String reason,
                                            Object deployer,Object expires,Instant now) {
        validate(old);
        if(!"submitted".equals(old.get("state"))||old.get("author").equals(actor))throw invalid();
        var next=new LinkedHashMap<>(old);
        var review=new LinkedHashMap<String,Object>();
        review.put("actor",actor(actor));review.put("at",now.toString());review.put("decision",decision);
        review.put("reason",text(reason,1024));review.put("pack_sha256",hash(pack));review.put("deployer",deployer);review.put("expires",expires);
        next.put("review",review);next.put("state",decision);next.put("revision",2);validate(next);return next;
    }
    public static Map<String,Object> reserve(Map<String,Object> old,String plan,String deployer,List<String> changed,Instant now) {
        validate(old);
        if(!"approved".equals(old.get("state"))||!hash(plan).equals(old.get("id")))throw invalid();
        var e=evidence(old.get("evidence"));
        var review=exact(old.get("review"),Set.of("actor","at","decision","reason","pack_sha256","deployer","expires"));
        if(!rules(e.get("changed_rules")).equals(changed)||!actor(deployer).equals(review.get("deployer"))||
                !now.isBefore(instant(review.get("expires"))))throw invalid();
        var next=new LinkedHashMap<>(old);
        next.put("state","reserved");next.put("revision",3);
        next.put("reservation",Map.of("actor",deployer,"at",now.toString()));
        validate(next);return next;
    }
    public static Map<String,Object> report(Map<String,Object> old,int status,Instant now) {
        validate(old);
        if(!"reserved".equals(old.get("state")))throw invalid();
        var next=new LinkedHashMap<>(old);
        next.put("state","native_reported");next.put("revision",4);
        next.put("outcome",Map.of("at",now.toString(),"native_status",status));validate(next);return next;
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid detection release or transition");}
}
