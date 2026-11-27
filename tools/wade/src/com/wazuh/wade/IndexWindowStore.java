// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static com.wazuh.wade.FindingReconciliation.*;
import static com.wazuh.wade.WindowService.*;

/** Indexer document protocol; the backend supplies authenticated native GET/create/CAS operations. */
public final class IndexWindowStore implements Store,Sink {
    public static final String STATE="wade-v1-window-reconciliation", PUBLICATIONS="wade-v1-window-publications";
    public record Document(String id,long sequence,long primaryTerm,Map<String,Object> body) {
        public Document { hex(id); if(sequence<0||primaryTerm<1)throw new IllegalArgumentException("invalid CAS metadata");body=Map.copyOf(body); }
    }
    public interface Backend {
        /** Return null only on a verified document-not-found response; never mask permission errors. */
        Document get(String index,String id);
        /** Return false only on a verified create conflict. Ambiguous failures must propagate. */
        boolean create(String index,String id,Map<String,Object> body);
        /** Conditional index using if_seq_no and if_primary_term; false only on a version conflict. */
        boolean replace(String index,String id,long sequence,long primaryTerm,Map<String,Object> body);
    }
    private final Backend backend; private final Scope scope; private final boolean enabled;
    public IndexWindowStore(Backend backend,Scope scope,boolean enabled) { this.backend=Objects.requireNonNull(backend);this.scope=Objects.requireNonNull(scope);this.enabled=enabled; }
    private void writable(){if(!enabled)throw new IllegalStateException("writes disabled");}
    public Envelope load(String id){hex(id);Document d=backend.get(STATE,id);return d==null?null:decode(d,id);}
    public boolean compareAndSet(String id,Envelope expected,Envelope next){
        writable();hex(id);Objects.requireNonNull(expected);Objects.requireNonNull(next);
        if(!id.equals(expected.state().windowKey())||!id.equals(next.state().windowKey())||next.token()!=Math.incrementExact(expected.token()))throw new IllegalArgumentException("invalid state transition");
        Document current=backend.get(STATE,id);Map<String,Object> body=encode(id,next);
        if(current==null){if(!expected.equals(Envelope.initial(id)))return false;return backend.create(STATE,id,body);}
        if(!decode(current,id).equals(expected))return false;
        return backend.replace(STATE,id,current.sequence(),current.primaryTerm(),body);
    }
    public void deliver(Request request,Pending pending){
        writable();Objects.requireNonNull(request);Objects.requireNonNull(pending);var p=pending.publication();
        if(!scope.equals(request.scope())||!request.windowKey().equals(p.windowKey())||p.asOf().isAfter(request.asOf()))throw new IllegalArgumentException("foreign publication");
        // Only an exact, currently staged publication may be delivered. A concurrent successful ack is safe.
        Map<String,Object> body=publication(pending);
        Envelope current=load(p.windowKey());
        if(current==null||!pending.equals(current.pending())){
            Document existing=backend.get(PUBLICATIONS,p.id());if(existing==null||!same(existing,p.id(),body))throw new IllegalStateException("publication not staged");return;
        }
        if(!backend.create(PUBLICATIONS,p.id(),body)){
            Document existing=backend.get(PUBLICATIONS,p.id());if(existing==null||!same(existing,p.id(),body))throw new IllegalStateException("immutable publication conflict");
        }
    }
    private Map<String,Object> publication(Pending pending){
        var p=pending.publication();hex(p.id());hex(p.findingId());hex(p.evidenceDigest());hex(p.receipt());hex(p.windowKey());
        if(p.revision()<1||!Set.of(Action.CREATE,Action.AMEND,Action.RETRACT,Action.RESTORE).contains(p.action()))throw new IllegalArgumentException("invalid publication");
        return Map.ofEntries(Map.entry("schema_version",1L),Map.entry("tenant",scope.tenant()),Map.entry("scope_key",scope.canonical()),Map.entry("window_key",p.windowKey()),Map.entry("publication_id",p.id()),Map.entry("revision",p.revision()),Map.entry("action",p.action().name()),Map.entry("finding_id",p.findingId()),Map.entry("evidence_digest",p.evidenceDigest()),Map.entry("receipt",p.receipt()),Map.entry("as_of",p.asOf().toString()),Map.entry("sources",pending.sources()));
    }
    private static boolean same(Document existing,String id,Map<String,Object> expected){
        if(!id.equals(existing.id())||!existing.body().keySet().equals(expected.keySet()))return false;
        for(var entry:expected.entrySet()){Object value=existing.body().get(entry.getKey()),wanted=entry.getValue();if(wanted instanceof Long l){if(number(value)!=l)return false;}else if(!wanted.equals(value))return false;}return true;
    }
    private Map<String,Object> encode(String id,Envelope envelope){
        try {
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){
                var s=envelope.state();out.writeInt(1);out.writeUTF(id);out.writeLong(envelope.token());out.writeLong(s.revision());opt(out,s.evaluatedAt()==null?null:s.evaluatedAt().toString());out.writeUTF(s.status().name());opt(out,s.findingId());opt(out,s.evidenceDigest());
                out.writeBoolean(s.last()!=null);if(s.last()!=null){var d=s.last();out.writeUTF(d.outcome().name());opt(out,d.receipt());opt(out,d.findingId());opt(out,d.evidenceDigest());}
                out.writeBoolean(envelope.pending()!=null);if(envelope.pending()!=null){var pending=envelope.pending();var p=pending.publication();out.writeUTF(p.id());out.writeUTF(p.action().name());out.writeLong(p.revision());out.writeUTF(p.findingId());out.writeUTF(p.evidenceDigest());out.writeUTF(p.receipt());out.writeUTF(p.asOf().toString());out.writeInt(pending.sources().size());for(String ref:pending.sources())out.writeUTF(ref);}
            }
            byte[] data=bytes.toByteArray();if(data.length>65536)throw new IllegalArgumentException("state payload limit");
            return Map.of("schema_version",1L,"tenant",scope.tenant(),"scope_key",scope.canonical(),"window_key",id,"token",envelope.token(),"revision",envelope.state().revision(),"status",envelope.state().status().name(),"payload",Base64.getEncoder().encodeToString(data),"payload_digest",digest(data));
        }catch(IOException e){throw new IllegalStateException("state encoding failure",e);}
    }
    private Envelope decode(Document doc,String id){
        Map<String,Object> b=doc.body();if(!doc.id().equals(id)||number(b.get("schema_version"))!=1||!scope.tenant().equals(b.get("tenant"))||!scope.canonical().equals(b.get("scope_key"))||!id.equals(b.get("window_key")))throw new IllegalStateException("state scope/schema mismatch");
        if(!(b.get("payload") instanceof String encoded)||encoded.length()>90000)throw new IllegalStateException("payload bound");
        byte[] raw=Base64.getDecoder().decode(encoded);if(raw.length>65536||!digest(raw).equals(b.get("payload_digest")))throw new IllegalStateException("payload integrity");
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(raw))){
            if(in.readInt()!=1||!id.equals(in.readUTF()))throw new IOException("state identity");long token=in.readLong(),revision=in.readLong();String time=opt(in);Instant evaluated=time==null?null:Instant.parse(time);var status=FindingReconciliation.Status.valueOf(in.readUTF());String fid=opt(in),evidence=opt(in);
            Decision last=null;if(in.readBoolean())last=new Decision(id,evaluated,Outcome.valueOf(in.readUTF()),opt(in),opt(in),opt(in));
            var state=new State(id,revision,evaluated,last,status,fid,evidence);Pending pending=null;
            if(in.readBoolean()){
                var p=new Publication(in.readUTF(),Action.valueOf(in.readUTF()),id,in.readLong(),in.readUTF(),in.readUTF(),in.readUTF(),Instant.parse(in.readUTF()));int n=in.readInt();if(n<0||n>16)throw new IOException("source limit");List<String> refs=new ArrayList<>();for(int i=0;i<n;i++)refs.add(in.readUTF());pending=new Pending(p,refs);publication(pending);
            }
            Envelope result=new Envelope(token,state,pending);if(in.read()!=-1||!same(doc,id,encode(id,result)))throw new IOException("noncanonical state");return result;
        }catch(IOException e){throw new IllegalStateException("state decoding failure",e);}
    }
    private static void opt(DataOutputStream out,String s)throws IOException{out.writeBoolean(s!=null);if(s!=null)out.writeUTF(s);}
    private static String opt(DataInputStream in)throws IOException{return in.readBoolean()?in.readUTF():null;}
    private static long number(Object x){if(x instanceof Long l)return l;if(x instanceof Integer i)return i.longValue();throw new IllegalStateException("invalid integer field");}
    private static void hex(String s){if(s==null||!s.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("invalid digest");}
    private static String digest(byte[] data){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
}
