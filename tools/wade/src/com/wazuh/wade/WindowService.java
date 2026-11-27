// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.*;
import java.util.*;

/** In-process orchestration. Trusted adapters must enforce permissions and atomic durable CAS. */
public final class WindowService {
    public enum Permission { EVALUATE, PUBLISH, DRAIN }
    public enum Status { WITHHELD, NO_CHANGE, STAGED, RECOVERED, CONFLICT }
    public record Scope(String tenant,String namespace,String kind,String id) {
        public Scope { key(tenant); key(namespace); key(id); if(!Set.of("USER","HOST","SERVICE","CLOUD_PRINCIPAL","AGENT").contains(kind)) throw new IllegalArgumentException("scope kind"); }
        public String canonical() { return hash("wade-scope-v1",tenant,namespace,kind,id); }
    }
    public record Request(Scope scope,CrossWindowCorrelation.Policy policy,Instant start,Instant end,Instant asOf) {
        public Request {
            Objects.requireNonNull(scope); Objects.requireNonNull(policy); Objects.requireNonNull(start); Objects.requireNonNull(end); Objects.requireNonNull(asOf);
            if(!start.isBefore(end) || Duration.between(start,end).compareTo(Duration.ofDays(31))>0 || asOf.isBefore(end)) throw new IllegalArgumentException("invalid window");
        }
        public String windowKey() { return CrossWindowCorrelation.logicalKey(policy,scope.canonical(),new CrossWindowCorrelation.Window(start,end,asOf,start,asOf,false)); }
        public Instant lookback() { return start.minus(policy.span()); }
    }
    public record Snapshot(Request request,Instant coverageStart,Instant watermark,boolean complete,List<CrossWindowCorrelation.Event> events) {
        public Snapshot {
            Objects.requireNonNull(request); Objects.requireNonNull(coverageStart); Objects.requireNonNull(watermark);
            if(events.size()>10000) throw new IllegalArgumentException("snapshot limit"); events=List.copyOf(events);
        }
    }
    public record Pending(FindingReconciliation.Publication publication,List<String> sources) {
        public Pending {
            Objects.requireNonNull(publication); sources=List.copyOf(sources);
            boolean retract=publication.action()==FindingReconciliation.Action.RETRACT;
            if(retract?!sources.isEmpty():sources.isEmpty() || sources.size()>16 || new HashSet<>(sources).size()!=sources.size()) throw new IllegalArgumentException("invalid witness");
            sources.forEach(WindowService::key);
        }
    }
    public record Envelope(long token,FindingReconciliation.State state,Pending pending) {
        public Envelope {
            Objects.requireNonNull(state);
            if(token<0 || (pending!=null && (!state.windowKey().equals(pending.publication().windowKey()) || state.revision()!=pending.publication().revision()
                || !Objects.equals(state.findingId(),pending.publication().findingId()) || !Objects.equals(state.evidenceDigest(),pending.publication().evidenceDigest())))) throw new IllegalArgumentException("invalid envelope");
        }
        public static Envelope initial(String key) { return new Envelope(0,FindingReconciliation.State.initial(key),null); }
    }
    /** Principal must be resolved from authenticated context, not from the request body. */
    @FunctionalInterface public interface Authority { void require(String principal,Request request,Permission permission); }
    /** Verify exact approved immutable rule policy, scope and evaluation mode before source access. */
    @FunctionalInterface public interface Registry { void requireApproved(Request request); }
    @FunctionalInterface public interface Source { Snapshot read(Request request); }
    public interface Store {
        Envelope load(String windowKey);
        /** Atomically compare the entire expected version and persist state plus pending output together. */
        boolean compareAndSet(String windowKey,Envelope expected,Envelope next);
    }
    /** Must create-only or verify exact immutable duplicate; return only after durable delivery. */
    @FunctionalInterface public interface Sink { void deliver(Request request,Pending pending); }
    private final Authority authority; private final Registry registry; private final Source source;
    private final Store store; private final Sink sink; private final Clock clock;
    public WindowService(Authority authority,Registry registry,Source source,Store store,Sink sink,Clock clock) {
        this.authority=Objects.requireNonNull(authority); this.registry=Objects.requireNonNull(registry); this.source=Objects.requireNonNull(source);
        this.store=Objects.requireNonNull(store); this.sink=Objects.requireNonNull(sink); this.clock=Objects.requireNonNull(clock);
    }
    public Status execute(String principal,Request request) {
        key(principal); Objects.requireNonNull(request);
        if(request.asOf().isAfter(clock.instant())) throw new IllegalArgumentException("future evaluation");
        authority.require(principal,request,Permission.EVALUATE); registry.requireApproved(request);
        String id=request.windowKey(); Envelope old=load(id);
        if(old.pending()!=null) return recover(principal,request,old);
        Snapshot snapshot=source.read(request);
        if(!request.equals(snapshot.request())) throw new IllegalStateException("snapshot request mismatch");
        var window=new CrossWindowCorrelation.Window(request.start(),request.end(),request.asOf(),snapshot.coverageStart(),snapshot.watermark(),snapshot.complete());
        var result=CrossWindowCorrelation.evaluate(request.policy(),request.scope().canonical(),window,snapshot.events());
        var decision=new FindingReconciliation.Decision(id,request.asOf(),FindingReconciliation.Outcome.valueOf(result.status().name()),result.receipt(),result.findingId(),result.evidenceDigest());
        var transition=FindingReconciliation.apply(old.state(),old.state().revision(),decision);
        if(transition.action()==FindingReconciliation.Action.WITHHELD) return Status.WITHHELD;
        if(transition.state().equals(old.state())) return Status.NO_CHANGE;
        Pending pending=transition.publication()==null?null:new Pending(transition.publication(),result.sources());
        authority.require(principal,request,Permission.EVALUATE); registry.requireApproved(request);
        if(pending!=null) authority.require(principal,request,Permission.PUBLISH);
        Envelope next=new Envelope(Math.incrementExact(old.token()),transition.state(),pending);
        if(!store.compareAndSet(id,old,next)) return Status.CONFLICT;
        return pending==null?Status.NO_CHANGE:Status.STAGED;
    }
    /** Recover only the already-persisted envelope. Never re-evaluate while delivery is pending. */
    private Status recover(String principal,Request request,Envelope old) {
        authority.require(principal,request,Permission.PUBLISH); registry.requireApproved(request);
        if(old.pending().publication().asOf().isAfter(request.asOf())) throw new IllegalStateException("stale recovery request");
        sink.deliver(request,old.pending());
        authority.require(principal,request,Permission.PUBLISH);
        return store.compareAndSet(request.windowKey(),old,new Envelope(Math.incrementExact(old.token()),old.state(),null))?Status.RECOVERED:Status.CONFLICT;
    }
    /** Authorized drain of already-staged output, including retired rules; never reads telemetry. */
    public Status drain(String principal,Request request){
        key(principal);Objects.requireNonNull(request);
        if(request.asOf().isAfter(clock.instant()))throw new IllegalArgumentException("future drain");
        authority.require(principal,request,Permission.DRAIN);
        String id=request.windowKey();Envelope old=load(id);
        if(old.pending()==null)return Status.NO_CHANGE;
        if(old.pending().publication().asOf().isAfter(request.asOf()))throw new IllegalStateException("stale drain request");
        sink.deliver(request,old.pending());
        authority.require(principal,request,Permission.DRAIN);
        return store.compareAndSet(id,old,new Envelope(Math.incrementExact(old.token()),old.state(),null))?Status.RECOVERED:Status.CONFLICT;
    }
    private Envelope load(String id) {
        Envelope result=store.load(id);
        if(result==null) return Envelope.initial(id);
        if(!id.equals(result.state().windowKey())) throw new IllegalStateException("storage scope mismatch"); return result;
    }
    private static void key(String s) { if(s==null || s.isBlank() || s.length()>1024 || !StandardCharsets.UTF_8.newEncoder().canEncode(s)) throw new IllegalArgumentException("invalid key"); }
    private static String hash(String... fields) {
        try { MessageDigest d=MessageDigest.getInstance("SHA-256"); for(String s:fields){byte[] b=s.getBytes(StandardCharsets.UTF_8); d.update(ByteBuffer.allocate(4).putInt(b.length).array());d.update(b);}return HexFormat.of().formatHex(d.digest()); }
        catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
}
