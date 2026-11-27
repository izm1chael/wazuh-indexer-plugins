// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.*;
import java.time.*;
import java.util.*;
import java.security.*;
import java.nio.charset.StandardCharsets;
import static com.wazuh.wade.PairedTemporalReplay.*;
import static com.wazuh.wade.TemporalPromotion.*;

/** Persistent paired evidence and revocation; no direct import of supplied outcomes. */
public final class IndexReplayEvidence implements Evidence {
    public static final String INDEX="wade-v1-temporal-evidence";
    public enum Kind { REPLAY, SHADOW }
    public enum Operation { CAPTURE, VERIFY, REVOKE }
    public record Capture(Kind kind,Instant created,String attestation,Report report,boolean revoked) {
        public Capture {Objects.requireNonNull(kind);Objects.requireNonNull(created);hex(attestation);Objects.requireNonNull(report);}
    }
    /** Authoritative label, validation, live-shadow population and principal checks are supplied by the host. */
    @FunctionalInterface public interface Authority {void require(Rule rule,Kind kind,Operation operation,String attestation,Instant now,Report report,List<Case> cases);}
    private final IndexWindowStore.Backend backend;private final Rule rule;private final PairedTemporalReplay replay;private final Authority authority;private final Clock clock;private final Duration maxAge;private final boolean enabled;private final int minShadowBenign,minShadowMalicious;
    public IndexReplayEvidence(IndexWindowStore.Backend backend,Rule rule,PairedTemporalReplay replay,Authority authority,Clock clock,Duration maxAge,boolean enabled,int minShadowBenign,int minShadowMalicious){
        this.backend=Objects.requireNonNull(backend);this.rule=Objects.requireNonNull(rule);this.replay=Objects.requireNonNull(replay);this.authority=Objects.requireNonNull(authority);this.clock=Objects.requireNonNull(clock);this.maxAge=Objects.requireNonNull(maxAge);this.enabled=enabled;this.minShadowBenign=minShadowBenign;this.minShadowMalicious=minShadowMalicious;if(minShadowBenign<1||minShadowMalicious<1)throw new IllegalArgumentException("invalid shadow policy");if(maxAge.isNegative()||maxAge.isZero()||maxAge.compareTo(Duration.ofDays(30))>0)throw new IllegalArgumentException("invalid evidence age");
    }
    public String capture(String actor,Kind kind,String attestation,TemporalAdmission.Definition champion,TemporalAdmission.Definition candidate,List<Case> cases,int minBenign,int minMalicious){
        writable();hex(attestation);checkRule(champion);checkRule(candidate);Instant now=clock.instant();authority.require(rule,kind,Operation.CAPTURE,attestation,now,null,List.copyOf(cases));
        Report report=replay.run(actor,champion,candidate,cases,minBenign,minMalicious);Instant created=clock.instant();authority.require(rule,kind,Operation.CAPTURE,attestation,created,report,List.copyOf(cases));
        Capture capture=new Capture(kind,created,attestation,report,false);String id=id(kind,report.receipt());var body=encode(capture);
        if(!backend.create(INDEX,id,body)){Capture old=load(kind,report.receipt());if(old.revoked()||!old.report().equals(report)||!old.attestation().equals(attestation))throw new IllegalStateException("immutable evidence conflict");}
        return report.receipt();
    }
    public boolean revoke(Kind kind,String receipt){
        writable();String id=id(kind,receipt);var doc=required(id);Capture old=decode(doc,kind,receipt);authority.require(rule,kind,Operation.REVOKE,old.attestation(),clock.instant(),old.report(),List.of());if(old.revoked())return true;
        return backend.replace(INDEX,id,doc.sequence(),doc.primaryTerm(),encode(new Capture(kind,old.created(),old.attestation(),old.report(),true)));
    }
    public Report verifiedReport(Rule requested,String replayReceipt,String shadowReceipt){return pair(requested,replayReceipt,shadowReceipt,clock.instant())[0].report();}
    public void requireCurrent(Rule requested,Approval approval,Instant now){
        var pair=pair(requested,approval.replayReceipt(),approval.shadowReceipt(),now);if(!pair[0].report().champion().equals(approval.champion())||!pair[0].report().challenger().equals(approval.candidate()))throw new SecurityException("approval evidence mismatch");
    }
    private Capture[] pair(Rule requested,String replayReceipt,String shadowReceipt,Instant now){
        if(!rule.equals(requested)||replayReceipt.equals(shadowReceipt))throw new SecurityException("invalid evidence scope");
        Capture a=load(Kind.REPLAY,replayReceipt),b=load(Kind.SHADOW,shadowReceipt);
        for(Capture c:List.of(a,b)){if(c.revoked()||c.created().isAfter(now)||!now.isBefore(c.created().plus(maxAge)))throw new SecurityException("stale or revoked evidence");authority.require(rule,c.kind(),Operation.VERIFY,c.attestation(),now,c.report(),List.of());}
        if(!a.report().champion().equals(b.report().champion())||!a.report().challenger().equals(b.report().challenger())||a.attestation().equals(b.attestation()))throw new SecurityException("unpaired evidence");
        Set<String> ids=new HashSet<>();for(var r:a.report().rows())ids.add(r.id());for(var r:b.report().rows())if(!ids.add(r.id()))throw new SecurityException("overlapping replay and shadow cases");
        if(!shadowPassed(b.report()))throw new SecurityException("shadow quality gate failed");return new Capture[]{a,b};
    }
    private boolean shadowPassed(Report r){int benign=0,malicious=0,before=0,after=0;for(var row:r.rows()){if(row.protectedCase()&&(row.label()!=Label.MALICIOUS||row.challenger()!=Outcome.MATCH))return false;if(row.label()==Label.UNLABELLED)continue;if(row.champion()==Outcome.UNKNOWN||row.challenger()==Outcome.UNKNOWN)return false;if(row.label()==Label.MALICIOUS){malicious++;if(row.champion()==Outcome.MATCH&&row.challenger()!=Outcome.MATCH)return false;}else{benign++;if(row.champion()==Outcome.MATCH)before++;if(row.challenger()==Outcome.MATCH)after++;}}return benign>=Math.max(minShadowBenign,r.minBenign())&&malicious>=Math.max(minShadowMalicious,r.minMalicious())&&after<=before;}
    private Capture load(Kind kind,String receipt){return decode(required(id(kind,receipt)),kind,receipt);}
    private IndexWindowStore.Document required(String id){var d=backend.get(INDEX,id);if(d==null)throw new SecurityException("missing evidence");return d;}
    private Map<String,Object> encode(Capture c){
        try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){out.writeInt(1);out.writeUTF(c.kind().name());out.writeUTF(c.created().toString());out.writeUTF(c.attestation());out.writeBoolean(c.revoked());Report r=c.report();out.writeUTF(r.champion());out.writeUTF(r.challenger());out.writeInt(r.minBenign());out.writeInt(r.minMalicious());out.writeUTF(r.receipt());out.writeInt(r.rows().size());for(var row:r.rows()){out.writeUTF(row.id());out.writeUTF(row.label().name());out.writeBoolean(row.protectedCase());out.writeUTF(row.champion().name());out.writeUTF(row.challenger().name());out.writeUTF(row.receipt());}}
        byte[] raw=bytes.toByteArray();if(raw.length>262144)throw new IllegalArgumentException("evidence budget");return Map.of("schema_version",1L,"tenant",rule.tenant(),"rule_key",rule.keyDigest(),"kind",c.kind().name(),"receipt",c.report().receipt(),"created",c.created().toString(),"revoked",c.revoked(),"payload",Base64.getEncoder().encodeToString(raw),"payload_digest",digest(raw));}catch(IOException e){throw new IllegalStateException(e);}
    }
    private Capture decode(IndexWindowStore.Document doc,Kind kind,String receipt){
        var b=doc.body();if(!id(kind,receipt).equals(doc.id())||!rule.tenant().equals(b.get("tenant"))||!rule.keyDigest().equals(b.get("rule_key"))||!receipt.equals(b.get("receipt"))||!kind.name().equals(b.get("kind"))||!(b.get("payload") instanceof String encoded)||encoded.length()>350000)throw new SecurityException("evidence identity mismatch");
        byte[] raw=Base64.getDecoder().decode(encoded);if(raw.length>262144||!digest(raw).equals(b.get("payload_digest")))throw new IllegalStateException("evidence integrity");
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(raw))){if(in.readInt()!=1||!kind.name().equals(in.readUTF()))throw new IOException("format");Instant created=Instant.parse(in.readUTF());String attestation=in.readUTF();boolean revoked=in.readBoolean();String champion=in.readUTF(),challenger=in.readUTF();int benign=in.readInt(),malicious=in.readInt();String r=in.readUTF();int n=in.readInt();if(n<1||n>1000||!receipt.equals(r))throw new IOException("report bounds");List<RowResult> rows=new ArrayList<>();Set<String> ids=new HashSet<>();for(int i=0;i<n;i++){var row=new RowResult(in.readUTF(),Label.valueOf(in.readUTF()),in.readBoolean(),Outcome.valueOf(in.readUTF()),Outcome.valueOf(in.readUTF()),in.readUTF());if(!ids.add(row.id()))throw new IOException("duplicate case");rows.add(row);}Capture c=new Capture(kind,created,attestation,new Report(champion,challenger,benign,malicious,rows,r),revoked);var expected=encode(c);if(in.read()!=-1||!b.keySet().equals(expected.keySet()))throw new IOException("noncanonical evidence");for(var e:expected.entrySet()){Object v=b.get(e.getKey());if(e.getValue() instanceof Long l?!(v instanceof Integer||v instanceof Long)||((Number)v).longValue()!=l:!e.getValue().equals(v))throw new IOException("noncanonical field");}return c;}catch(IOException e){throw new IllegalStateException(e);}
    }
    private void checkRule(TemporalAdmission.Definition d){if(!rule.tenant().equals(d.tenant())||!rule.id().equals(d.ruleId()))throw new SecurityException("foreign rule");}
    private void writable(){if(!enabled)throw new IllegalStateException("evidence writes disabled");}
    private String id(Kind kind,String receipt){hex(receipt);return digest((rule.keyDigest()+":"+kind.name()+":"+receipt).getBytes(StandardCharsets.UTF_8));}
    private static void hex(String s){if(s==null||!s.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("digest required");}
    private static String digest(byte[] bytes){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
}
