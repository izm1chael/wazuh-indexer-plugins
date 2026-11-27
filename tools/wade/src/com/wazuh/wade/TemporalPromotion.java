// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.PairedTemporalReplay.*;
import static com.wazuh.wade.WindowService.*;

/** Paired-replay promotion policy and single active pointer. Trusted persistence and identity ports. */
public final class TemporalPromotion implements TemporalAdmission.Approved {
    public enum Action { APPROVE, ACTIVATE, WITHDRAW, DEACTIVATE, EXECUTE }
    public record Rule(String tenant,String id){public Rule{key(tenant);key(id);}public String keyDigest(){return hash("wade-promotion-rule-v1",tenant,id);}}
    public record Revision(TemporalAdmission.Definition definition,String author){public Revision{Objects.requireNonNull(definition);key(author);}}
    public record Approval(String champion,String candidate,String replayReceipt,String shadowReceipt,String approver,String author,Instant expires){
        public Approval{hex(champion);hex(candidate);hex(replayReceipt);hex(shadowReceipt);key(approver);key(author);Objects.requireNonNull(expires);if(champion.equals(candidate)||approver.equals(author))throw new IllegalArgumentException("invalid approval");}
    }
    public record State(String ruleKey,long sequence,String champion,boolean active,Approval pending,String lastAudit){
        public State{hex(ruleKey);hex(champion);if(sequence<0||sequence==0&&(active||pending!=null||lastAudit!=null)||sequence>0&&lastAudit==null||pending!=null&&!pending.champion().equals(champion))throw new IllegalArgumentException("invalid state");if(lastAudit!=null)hex(lastAudit);}
        /** Baseline revision is an offline comparison reference, not an activated detector. */
        public static State baseline(Rule rule,String digest){return new State(rule.keyDigest(),0,digest,false,null,null);}
    }
    public interface States {State load(Rule rule);boolean compareAndSet(Rule rule,State old,State next);}
    @FunctionalInterface public interface Definitions { Revision resolve(Rule rule,String digest); }
    /** Must derive actor from the authenticated service context. */
    @FunctionalInterface public interface Authority {void require(String actor,Rule rule,Action action);}
    public interface Evidence {
        /** Resolve and verify the stored paired report, validation and shadow evidence for the exact candidate. */
        Report verifiedReport(Rule rule,String replayReceipt,String shadowReceipt);
        /** Revalidate receipt authority, revocation and shadow/validation freshness at activation. */
        void requireCurrent(Rule rule,Approval approval,Instant now);
    }
    private final Rule rule;private final States states;private final Definitions definitions;private final Authority authority;private final Evidence evidence;private final Clock clock;private final boolean enabled;private final int minBenign,minMalicious;
    public TemporalPromotion(Rule rule,States states,Definitions definitions,Authority authority,Evidence evidence,Clock clock,boolean enabled,int minBenign,int minMalicious){
        this.rule=Objects.requireNonNull(rule);this.states=Objects.requireNonNull(states);this.definitions=Objects.requireNonNull(definitions);this.authority=Objects.requireNonNull(authority);this.evidence=Objects.requireNonNull(evidence);this.clock=Objects.requireNonNull(clock);this.enabled=enabled;
        if(minBenign<1||minMalicious<1)throw new IllegalArgumentException("invalid review policy");this.minBenign=minBenign;this.minMalicious=minMalicious;
    }
    public boolean approve(String actor,long expected,String replayReceipt,String shadowReceipt,Duration ttl){
        key(actor);expected(expected);hex(replayReceipt);hex(shadowReceipt);if(ttl.isZero()||ttl.isNegative()||ttl.compareTo(Duration.ofDays(7))>0)throw new IllegalArgumentException("approval expiry");
        authority.require(actor,rule,Action.APPROVE);State old=required(expected);Instant now=clock.instant();
        if(old.pending()!=null&&now.isBefore(old.pending().expires()))throw new IllegalStateException("existing approval");
        Report report=evidence.verifiedReport(rule,replayReceipt,shadowReceipt);
        if(report==null||!report.receipt().equals(replayReceipt)||!old.champion().equals(report.champion()))throw new IllegalStateException("unverified or stale baseline");
        revision(report.champion());Revision candidate=revision(report.challenger());
        if(actor.equals(candidate.author())||!eligible(report,minBenign,minMalicious))throw new SecurityException("review gate failed");
        Approval approval=new Approval(report.champion(),report.challenger(),replayReceipt,shadowReceipt,actor,candidate.author(),now.plus(ttl));
        evidence.requireCurrent(rule,approval,now);authority.require(actor,rule,Action.APPROVE);
        return states.compareAndSet(rule,old,new State(old.ruleKey(),Math.incrementExact(old.sequence()),old.champion(),old.active(),approval,audit(old,Action.APPROVE,actor,approval,now)));
    }
    public boolean activate(String actor,long expected){
        key(actor);expected(expected);authority.require(actor,rule,Action.ACTIVATE);if(!enabled)throw new IllegalStateException("activation disabled");
        State old=required(expected);Approval p=old.pending();Instant now=clock.instant();
        if(p==null||!now.isBefore(p.expires())||actor.equals(p.author())||!revision(p.candidate()).author().equals(p.author()))throw new SecurityException("invalid independent activation");
        evidence.requireCurrent(rule,p,now);authority.require(actor,rule,Action.ACTIVATE);
        return states.compareAndSet(rule,old,new State(old.ruleKey(),Math.incrementExact(old.sequence()),p.candidate(),true,null,audit(old,Action.ACTIVATE,actor,p,now)));
    }
    public boolean withdraw(String actor,long expected){
        key(actor);expected(expected);authority.require(actor,rule,Action.WITHDRAW);State old=required(expected);if(old.pending()==null)throw new IllegalStateException("no approval");
        return states.compareAndSet(rule,old,new State(old.ruleKey(),Math.incrementExact(old.sequence()),old.champion(),old.active(),null,audit(old,Action.WITHDRAW,actor,old.pending(),clock.instant())));
    }
    /** Emergency stop. A stopped revision cannot resume without a newly approved candidate. */
    public boolean deactivate(String actor,long expected){
        key(actor);expected(expected);authority.require(actor,rule,Action.DEACTIVATE);State old=required(expected);
        if(!old.active()&&old.pending()==null)throw new IllegalStateException("already inactive");
        String audit=hash("wade-deactivate-v1",old.ruleKey(),Long.toString(old.sequence()),Objects.toString(old.lastAudit(),""),old.champion(),actor,clock.instant().toString());
        authority.require(actor,rule,Action.DEACTIVATE);
        return states.compareAndSet(rule,old,new State(old.ruleKey(),Math.incrementExact(old.sequence()),old.champion(),false,null,audit));
    }
    /** Called in the authenticated execution context; never returns a draft or unactivated baseline. */
    public TemporalAdmission.Definition resolve(Request request){
        if(!enabled||!request.scope().tenant().equals(rule.tenant()))throw new SecurityException("foreign scope");
        State state=required(-1);if(!state.active()||!state.champion().equals(request.policy().version()))throw new SecurityException("not active");
        var definition=revision(state.champion()).definition();if(!definition.policy().equals(request.policy()))throw new SecurityException("policy mismatch");return definition;
    }
    private Revision revision(String digest){
        hex(digest);Revision r=definitions.resolve(rule,digest);if(r==null||!r.definition().tenant().equals(rule.tenant())||!r.definition().ruleId().equals(rule.id())||!r.definition().policy().version().equals(digest))throw new SecurityException("invalid immutable definition");return r;
    }
    private State required(long expected){State s=states.load(rule);if(s==null||!s.ruleKey().equals(rule.keyDigest())||expected>=0&&s.sequence()!=expected)throw new IllegalStateException("missing or stale promotion state");return s;}
    private static boolean eligible(Report report,int minBenign,int minMalicious){
        int benign=0,malicious=0,before=0,after=0;Set<String> ids=new HashSet<>();
        for(var row:report.rows()){
            if(!ids.add(row.id()))return false;
            if(row.protectedCase()&&(row.label()!=Label.MALICIOUS||row.challenger()!=Outcome.MATCH))return false;
            if(row.label()==Label.UNLABELLED)continue;
            if(row.champion()==Outcome.UNKNOWN||row.challenger()==Outcome.UNKNOWN)return false;
            if(row.label()==Label.MALICIOUS){malicious++;if(row.champion()==Outcome.MATCH&&row.challenger()!=Outcome.MATCH)return false;}
            else{benign++;if(row.champion()==Outcome.MATCH)before++;if(row.challenger()==Outcome.MATCH)after++;}
        }
        return benign>=Math.max(minBenign,report.minBenign())&&malicious>=Math.max(minMalicious,report.minMalicious())&&after<before;
    }
    private static String audit(State s,Action a,String actor,Approval p,Instant now){return hash("wade-promotion-audit-v1",s.ruleKey(),Long.toString(s.sequence()),Objects.toString(s.lastAudit(),""),a.name(),actor,p.champion(),p.candidate(),p.replayReceipt(),p.shadowReceipt(),p.approver(),p.author(),p.expires().toString(),now.toString());}
    private static void expected(long n){if(n<0)throw new IllegalArgumentException("expected sequence required");}
    private static void hex(String s){if(s==null||!s.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("invalid digest");}
    private static void key(String s){if(s==null||s.isBlank()||s.length()>1024||!StandardCharsets.UTF_8.newEncoder().canEncode(s))throw new IllegalArgumentException("invalid key");}
    private static String hash(String... fields){try{MessageDigest d=MessageDigest.getInstance("SHA-256");for(String s:fields){byte[] b=s.getBytes(StandardCharsets.UTF_8);d.update(ByteBuffer.allocate(4).putInt(b.length).array());d.update(b);}return HexFormat.of().formatHex(d.digest());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
}
