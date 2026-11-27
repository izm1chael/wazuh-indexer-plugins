// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;

/** One bounded scheduler tick. No threads or runtime registration; the native scheduler calls tick. */
public final class TemporalJobRunner {
    public record Job(Scope scope,CrossWindowCorrelation.Policy policy,Duration cadence,Duration grace,Duration lateHorizon,Instant origin) {
        public Job { Objects.requireNonNull(scope);Objects.requireNonNull(policy);Objects.requireNonNull(cadence);Objects.requireNonNull(grace);Objects.requireNonNull(lateHorizon);Objects.requireNonNull(origin);
            if(cadence.compareTo(Duration.ofSeconds(1))<0||cadence.compareTo(Duration.ofDays(1))>0||grace.isNegative()||grace.compareTo(Duration.ofDays(1))>0||lateHorizon.isNegative()||lateHorizon.compareTo(Duration.ofDays(31))>0)throw new IllegalArgumentException("invalid job schedule"); }
        public String id(){return hash("wade-temporal-job-v1",scope.canonical(),policy.version(),policy.mode().name(),policy.span().toString(),Integer.toString(policy.inputLimit()),Integer.toString(policy.workLimit()),hash(policy.stages().toArray(String[]::new)),cadence.toString(),grace.toString(),lateHorizon.toString(),origin.toString());}
    }
    public record Cursor(String jobId,long revision,long fence,Instant checkpoint,Instant lateEnd,String owner,Instant expires,String receipt) {
        public Cursor { hex(jobId);if(revision<0||fence<0||fence>revision)throw new IllegalArgumentException("invalid cursor");Objects.requireNonNull(checkpoint);Objects.requireNonNull(expires);if(owner==null&&!expires.equals(Instant.MIN)||owner!=null&&(owner.isBlank()||owner.length()>1024)||lateEnd!=null&&lateEnd.isAfter(checkpoint))throw new IllegalArgumentException("invalid lease or late cursor");if(receipt!=null)hex(receipt); }
        public static Cursor initial(Job job){return new Cursor(job.id(),0,0,job.origin(),null,null,Instant.MIN,null); }
    }
    public interface Cursors { Cursor load(Job job); boolean compareAndSet(Job job,Cursor expected,Cursor next); }
    /** Must check authenticated service principal, active revision, scope and job permission. */
    @FunctionalInterface public interface Authority { void require(String principal,Job job); }
    public enum Result { BUSY, CONFLICT, NOT_READY, WITHHELD, ADVANCED, RECONSIDERED }
    private final Authority authority;private final Cursors cursors;private final WindowService service;private final Store windows;private final Clock clock;
    public TemporalJobRunner(Authority authority,Cursors cursors,WindowService service,Store windows,Clock clock){this.authority=Objects.requireNonNull(authority);this.cursors=Objects.requireNonNull(cursors);this.service=Objects.requireNonNull(service);this.windows=Objects.requireNonNull(windows);this.clock=Objects.requireNonNull(clock);}
    /** Prefer forward work, or explicitly request a late sweep. Schedule both with independent quotas. */
    public Result tick(String principal,Job job,Duration ttl,boolean late){
        if(principal==null||principal.isBlank()||principal.length()>1024||ttl.isZero()||ttl.isNegative()||ttl.compareTo(Duration.ofMinutes(10))>0)throw new IllegalArgumentException("invalid tick");
        authority.require(principal,job);Cursor prior=required(job);Instant cutoff=clock.instant();
        if(prior.checkpoint().isAfter(cutoff))throw new IllegalStateException("clock before checkpoint");
        if(prior.owner()!=null&&cutoff.isBefore(prior.expires()))return Result.BUSY;
        Instant start,end;Instant nextLate=prior.lateEnd();
        if(!late){start=prior.checkpoint();end=start.plus(job.cadence());if(end.isAfter(cutoff.minus(job.grace())))return Result.NOT_READY;}
        else{
            Instant floor=cutoff.minus(job.lateHorizon());if(floor.isBefore(job.origin()))floor=job.origin();end=prior.lateEnd()==null?prior.checkpoint():prior.lateEnd();
            if(end.minus(job.cadence()).isBefore(floor))end=prior.checkpoint();
            start=end.minus(job.cadence());if(start.isBefore(floor)||end.isAfter(cutoff.minus(job.grace())))return Result.NOT_READY;
            nextLate=start;
        }
        Cursor lease=new Cursor(job.id(),Math.incrementExact(prior.revision()),Math.incrementExact(prior.fence()),prior.checkpoint(),prior.lateEnd(),principal,cutoff.plus(ttl),prior.receipt());
        if(!cursors.compareAndSet(job,prior,lease))return Result.CONFLICT;
        Request request=new Request(job.scope(),job.policy(),start,end,cutoff);
        Result result=Result.WITHHELD;String receipt=null;
        // A recovery may acknowledge an older publication first. Reevaluate at this tick's cutoff.
        for(int i=0;i<3;i++){
            if(!owns(job,lease))return Result.CONFLICT;
            authority.require(principal,job);
            Status status=service.execute(principal,request);
            if(status==Status.WITHHELD)break;
            if(status==Status.CONFLICT)return Result.CONFLICT;
            Envelope accepted=windows.load(request.windowKey());
            if(accepted!=null&&request.windowKey().equals(accepted.state().windowKey())&&accepted.pending()==null&&cutoff.equals(accepted.state().evaluatedAt())){
                receipt=accepted.state().last().receipt();hex(receipt);result=late?Result.RECONSIDERED:Result.ADVANCED;break;
            }
        }
        if(!owns(job,lease))return Result.CONFLICT;
        authority.require(principal,job);
        boolean done=receipt!=null;
        Cursor next=new Cursor(job.id(),Math.incrementExact(lease.revision()),lease.fence(),done&&!late?end:lease.checkpoint(),done&&late?nextLate:lease.lateEnd(),null,Instant.MIN,done?receipt:lease.receipt());
        return cursors.compareAndSet(job,lease,next)?result:Result.CONFLICT;
    }
    private boolean owns(Job job,Cursor lease){return lease.equals(required(job))&&clock.instant().isBefore(lease.expires());}
    private Cursor required(Job job){Cursor c=cursors.load(job);if(c==null||!job.id().equals(c.jobId())||c.checkpoint().isBefore(job.origin())||c.lateEnd()!=null&&c.lateEnd().isBefore(job.origin()))throw new IllegalStateException("missing or foreign job");return c;}
    private static void hex(String s){if(s==null||!s.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("invalid digest");}
    private static String hash(String... fields){try{MessageDigest d=MessageDigest.getInstance("SHA-256");for(String s:fields){byte[] b=s.getBytes(StandardCharsets.UTF_8);d.update(ByteBuffer.allocate(4).putInt(b.length).array());d.update(b);}return HexFormat.of().formatHex(d.digest());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
}
