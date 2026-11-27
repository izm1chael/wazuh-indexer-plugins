// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.*;
import java.security.*;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.TemporalPromotion.*;

/** One scoped CAS document containing immutable revisions and a single promotion pointer. */
public final class IndexTemporalRegistry implements States,Definitions {
    public static final String INDEX="wade-v1-temporal-registry";
    private static final int MAX_REVISIONS=32, MAX_BYTES=262144;
    private final IndexWindowStore.Backend backend;private final Rule rule;private final boolean enabled;
    private record Entry(State state,List<Revision> revisions){Entry{revisions=List.copyOf(revisions);}}
    public IndexTemporalRegistry(IndexWindowStore.Backend backend,Rule rule,boolean enabled){this.backend=Objects.requireNonNull(backend);this.rule=Objects.requireNonNull(rule);this.enabled=enabled;}
    /** Create-only inactive baseline. Registration and author authority are service responsibilities. */
    public boolean provision(Revision baseline){write(rule);checkRevision(baseline);return backend.create(INDEX,rule.keyDigest(),encode(new Entry(State.baseline(rule,baseline.definition().policy().version()),List.of(baseline))));}
    public boolean register(Revision revision){
        write(rule);checkRevision(revision);var doc=required();Entry old=decode(doc);
        for(Revision r:old.revisions())if(r.definition().revision().equals(revision.definition().revision())){if(!r.equals(revision))throw new IllegalStateException("immutable revision conflict");return true;}
        if(old.revisions().size()>=MAX_REVISIONS)throw new IllegalStateException("registry limit");List<Revision> next=new ArrayList<>(old.revisions());next.add(revision);
        return backend.replace(INDEX,rule.keyDigest(),doc.sequence(),doc.primaryTerm(),encode(new Entry(old.state(),next)));
    }
    public State load(Rule requested){scope(requested);var doc=backend.get(INDEX,rule.keyDigest());return doc==null?null:decode(doc).state();}
    public Revision resolve(Rule requested,String digest){scope(requested);Entry e=decode(required());return e.revisions().stream().filter(r->r.definition().policy().version().equals(digest)).findFirst().orElse(null);}
    public boolean compareAndSet(Rule requested,State expected,State next){
        write(requested);if(!rule.keyDigest().equals(expected.ruleKey())||!rule.keyDigest().equals(next.ruleKey())||next.sequence()!=Math.incrementExact(expected.sequence()))throw new IllegalArgumentException("invalid promotion transition");
        var doc=required();Entry e=decode(doc);if(!e.state().equals(expected))return false;
        return backend.replace(INDEX,rule.keyDigest(),doc.sequence(),doc.primaryTerm(),encode(new Entry(next,e.revisions())));
    }
    private IndexWindowStore.Document required(){var d=backend.get(INDEX,rule.keyDigest());if(d==null)throw new IllegalStateException("missing registry");return d;}
    private void scope(Rule requested){if(!rule.equals(requested))throw new SecurityException("foreign registry");}
    private void write(Rule requested){scope(requested);if(!enabled)throw new IllegalStateException("registry writes disabled");}
    private void checkRevision(Revision r){if(!rule.tenant().equals(r.definition().tenant())||!rule.id().equals(r.definition().ruleId()))throw new SecurityException("foreign revision");}
    private void validate(Entry e){
        if(!rule.keyDigest().equals(e.state().ruleKey())||e.revisions().isEmpty()||e.revisions().size()>MAX_REVISIONS)throw new IllegalStateException("invalid registry");
        Map<String,Revision> byDigest=new HashMap<>();Set<String> versions=new HashSet<>();for(Revision r:e.revisions()){checkRevision(r);if(!versions.add(r.definition().revision())||byDigest.putIfAbsent(r.definition().policy().version(),r)!=null)throw new IllegalStateException("duplicate definition");}
        if(!byDigest.containsKey(e.state().champion()))throw new IllegalStateException("unknown champion");
        Approval p=e.state().pending();if(p!=null&&(!byDigest.containsKey(p.candidate())||!byDigest.get(p.candidate()).author().equals(p.author())))throw new IllegalStateException("unknown candidate or author");
    }
    private Map<String,Object> encode(Entry e){
        validate(e);try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){
            out.writeInt(1);out.writeUTF(rule.keyDigest());State s=e.state();out.writeLong(s.sequence());out.writeUTF(s.champion());out.writeBoolean(s.active());opt(out,s.lastAudit());out.writeBoolean(s.pending()!=null);
            if(s.pending()!=null){Approval p=s.pending();out.writeUTF(p.champion());out.writeUTF(p.candidate());out.writeUTF(p.replayReceipt());out.writeUTF(p.shadowReceipt());out.writeUTF(p.approver());out.writeUTF(p.author());out.writeUTF(p.expires().toString());}
            out.writeInt(e.revisions().size());for(Revision revision:e.revisions()){
                var d=revision.definition();out.writeUTF(d.revision());out.writeUTF(revision.author());out.writeUTF(d.mode().name());out.writeUTF(d.span().toString());out.writeInt(d.inputLimit());out.writeInt(d.workLimit());out.writeInt(d.stages().size());
                for(var stage:d.stages()){out.writeUTF(stage.id());out.writeInt(stage.terms().size());for(var term:new TreeMap<>(stage.terms()).entrySet()){out.writeUTF(term.getKey());out.writeUTF(term.getValue());}}
            }
        }byte[] raw=bytes.toByteArray();if(raw.length>MAX_BYTES)throw new IllegalStateException("registry payload limit");return Map.of("schema_version",1L,"tenant",rule.tenant(),"rule_id",rule.id(),"rule_key",rule.keyDigest(),"sequence",e.state().sequence(),"champion_digest",e.state().champion(),"active",e.state().active(),"payload",Base64.getEncoder().encodeToString(raw),"payload_digest",digest(raw));}
        catch(IOException x){throw new IllegalStateException("registry encoding",x);}
    }
    private Entry decode(IndexWindowStore.Document doc){
        var b=doc.body();if(!doc.id().equals(rule.keyDigest())||!rule.tenant().equals(b.get("tenant"))||!rule.id().equals(b.get("rule_id"))||!rule.keyDigest().equals(b.get("rule_key"))||number(b.get("schema_version"))!=1)throw new IllegalStateException("registry scope mismatch");
        if(!(b.get("payload") instanceof String encoded)||encoded.length()>350000)throw new IllegalStateException("payload bound");byte[] raw=Base64.getDecoder().decode(encoded);if(raw.length>MAX_BYTES||!digest(raw).equals(b.get("payload_digest")))throw new IllegalStateException("registry integrity");
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(raw))){
            if(in.readInt()!=1||!rule.keyDigest().equals(in.readUTF()))throw new IOException("registry identity");long seq=in.readLong();String champion=in.readUTF();boolean active=in.readBoolean();String audit=opt(in);Approval approval=null;
            if(in.readBoolean())approval=new Approval(in.readUTF(),in.readUTF(),in.readUTF(),in.readUTF(),in.readUTF(),in.readUTF(),Instant.parse(in.readUTF()));
            State state=new State(rule.keyDigest(),seq,champion,active,approval,audit);int count=in.readInt();if(count<1||count>MAX_REVISIONS)throw new IOException("revision limit");List<Revision> revisions=new ArrayList<>();
            for(int i=0;i<count;i++){
                String version=in.readUTF(),author=in.readUTF();var mode=CrossWindowCorrelation.Mode.valueOf(in.readUTF());Duration span=Duration.parse(in.readUTF());int limit=in.readInt(),work=in.readInt(),n=in.readInt();if(n<2||n>16)throw new IOException("stage limit");List<TemporalAdmission.Stage> stages=new ArrayList<>();
                for(int j=0;j<n;j++){String id=in.readUTF();int m=in.readInt();if(m<1||m>6)throw new IOException("term limit");Map<String,String> terms=new HashMap<>();for(int k=0;k<m;k++)if(terms.putIfAbsent(in.readUTF(),in.readUTF())!=null)throw new IOException("duplicate term");stages.add(new TemporalAdmission.Stage(id,terms));}
                revisions.add(new Revision(new TemporalAdmission.Definition(rule.tenant(),rule.id(),version,mode,span,limit,work,stages),author));
            }
            Entry result=new Entry(state,revisions);if(in.read()!=-1||!same(b,encode(result)))throw new IOException("noncanonical registry");return result;
        }catch(IOException x){throw new IllegalStateException("registry decoding",x);}
    }
    private static boolean same(Map<String,Object> actual,Map<String,Object> expected){if(!actual.keySet().equals(expected.keySet()))return false;for(var e:expected.entrySet())if(e.getValue() instanceof Long n?number(actual.get(e.getKey()))!=n:!e.getValue().equals(actual.get(e.getKey())))return false;return true;}
    private static long number(Object x){if(x instanceof Long n)return n;if(x instanceof Integer n)return n.longValue();throw new IllegalStateException("invalid integer");}
    private static void opt(DataOutputStream out,String s)throws IOException{out.writeBoolean(s!=null);if(s!=null)out.writeUTF(s);}
    private static String opt(DataInputStream in)throws IOException{return in.readBoolean()?in.readUTF():null;}
    private static String digest(byte[] raw){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}catch(NoSuchAlgorithmException x){throw new IllegalStateException(x);}}
}
