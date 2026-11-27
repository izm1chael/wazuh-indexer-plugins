// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.IOException;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.DetectionKernel.*;

public final class PipelineTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("tenant","user","alice");
    private static final Window W=new Window(T,T.plusSeconds(60));
    private static int checks;
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    @FunctionalInterface interface Task { void run() throws IOException; }
    private static void reject(Task task) throws IOException {
        try{task.run();throw new AssertionError("expected rejection");}
        catch(IllegalArgumentException|IllegalStateException expected){checks++;}
    }
    private static ReplayEngine.Observed event(String id,int time,int available){
        return new ReplayEngine.Observed(new Evidence(S,new Source("events",id),T.plusSeconds(time),null),T.plusSeconds(available));
    }
    private static ReplayEngine.Case example(String id, DetectionQuality.Label label, Coverage coverage,List<ReplayEngine.Observed> inputs){
        return new ReplayEngine.Case(id,S,W,W.end(),W.end(),coverage,label,inputs);
    }
    public static void main(String[] args) throws IOException {
        var rule=new Rule("r","1",Mode.EVENT_COUNT,2,10);
        var d=new ReplayEngine.Definition("tenant",rule,"a".repeat(64));
        var registry=new ReplayEngine.Registry(); var v=new ReplayEngine.Version("tenant","r","1");
        check(registry.register(d).equals(registry.register(d)),"idempotent registration");
        reject(()->registry.register(new ReplayEngine.Definition("tenant",rule,"b".repeat(64))));
        reject(()->registry.require(new ReplayEngine.Version("other","r","1")));
        var a=event("a",1,2); var b=event("b",2,3); var late=event("late",3,61);
        var positive=example("p",DetectionQuality.Label.MALICIOUS,Coverage.COMPLETE,List.of(a,b));
        var negative=example("n",DetectionQuality.Label.BENIGN,Coverage.COMPLETE,List.of(a,late));
        var unknown=example("u",DetectionQuality.Label.MALICIOUS,Coverage.UNKNOWN,List.of(a,b));
        var report=ReplayEngine.run(registry,v,List.of(positive,negative,unknown));
        check(report.metrics().tp()==1 && report.metrics().tn()==1 && report.metrics().unknownMalicious()==1,"replay metrics");
        check(report.metrics().conservativeRecall()==0.5,"conservative recall");
        check(report.equals(ReplayEngine.run(registry,v,List.of(unknown,negative,
            example("p",DetectionQuality.Label.MALICIOUS,Coverage.COMPLETE,List.of(b,a))))),"order invariant");
        check(report.equals(ReplayEngine.run(registry,v,List.of(positive,
            example("n",DetectionQuality.Label.BENIGN,Coverage.COMPLETE,List.of(a)),unknown))),"future arrival excluded from receipt");
        check(!report.receipt().equals(ReplayEngine.run(registry,v,List.of(positive,
            example("n",DetectionQuality.Label.BENIGN,Coverage.COMPLETE,List.of(a,a)),unknown)).receipt()),"input multiplicity bound");
        reject(()->ReplayEngine.run(registry,v,List.of(positive,positive)));
        var foreign=new ReplayEngine.Case("f",new Scope("foreign","user","alice"),W,W.end(),W.end(),Coverage.COMPLETE,DetectionQuality.Label.BENIGN,List.of());
        reject(()->ReplayEngine.run(registry,v,List.of(foreign)));
        Path dir=Files.createTempDirectory("wade-pipeline-");
        try{
            var store=new LocalWindowStore(dir,"tenant/r/1");
            var initial=store.initialize(T);
            check(initial.equals(new LocalWindowStore(dir,"tenant/r/1").initialize(T.plusSeconds(1))),"restart no reset");
            var lease=store.acquire(0,"a",T.plusSeconds(60),Duration.ofSeconds(10));
            reject(()->store.acquire(1,"b",T.plusSeconds(61),Duration.ofSeconds(10)));
            var takeover=new LocalWindowStore(dir,"tenant/r/1").acquire(1,"b",T.plusSeconds(70),Duration.ofSeconds(10));
            check(takeover.state().fence()>lease.state().fence(),"persistent fencing");
            var out=LocalWindowStore.Pending.of(report.receipt(),"synthetic output payload");
            reject(()->store.complete(2,1,"a",T.plusSeconds(71),W.end(),out));
            var done=store.complete(2,2,"b",T.plusSeconds(71),W.end(),out);
            var restarted=new LocalWindowStore(dir,"tenant/r/1");
            check(restarted.read().equals(done) && restarted.read().pending().payload().equals(out.payload()),"checkpoint and payload survive reopen");
            reject(()->restarted.acquire(3,"c",T.plusSeconds(72),Duration.ofSeconds(10)));
            reject(()->restarted.acknowledge(3,LocalWindowStore.Pending.of(out.id(),"wrong payload")));
            var ack=restarted.acknowledge(3,out);
            check(ack.pending()==null && ack.state().checkpoint().equals(W.end()),"ack retains checkpoint");
            check(restarted.acknowledge(3,out).equals(ack),"ack retry idempotent");
            reject(()->new LocalWindowStore.Pending(out.id(),out.digest(),"tampered"));
            var other=new LocalWindowStore(dir,"tenant/r/2");
            check(other.initialize(T).state().revision()==0,"job isolation");
            var runnerStore=new LocalWindowStore(dir,WindowRunner.jobKey(v,S));
            runnerStore.initialize(T);
            runnerStore.acquire(0,"runner",W.end(),Duration.ofSeconds(30));
            var uncertain=example("window",DetectionQuality.Label.UNLABELLED,Coverage.UNKNOWN,List.of(a,b));
            var withheld=WindowRunner.stage(registry,v,uncertain,runnerStore,1,1,"runner",W.end());
            check(withheld.outcome().status()==Status.UNKNOWN && runnerStore.read().state().checkpoint().equals(T),"unknown never advances");
            reject(()->WindowRunner.stage(registry,v,positive,runnerStore,1,1,"runner",W.end()));
            var operational=example("window",DetectionQuality.Label.UNLABELLED,Coverage.COMPLETE,List.of(a,b));
            var staged=WindowRunner.stage(registry,v,operational,runnerStore,1,1,"runner",W.end());
            check(staged.outcome().status()==Status.MATCH && staged.snapshot().state().checkpoint().equals(W.end()),"count rule staged atomically");
            var payload=staged.snapshot().pending().payload();
            var decoded=Arrays.stream(payload.split("\\n")).map(x->new String(Base64.getUrlDecoder().decode(x),java.nio.charset.StandardCharsets.UTF_8)).toList();
            check(decoded.contains(staged.outcome().finding().id()) && decoded.contains("a") && decoded.contains("b"),"actual finding provenance in outbox");
            reject(()->WindowRunner.stage(registry,v,operational,runnerStore,1,1,"runner",W.end()));
            var delivered=runnerStore.acknowledge(2,staged.snapshot().pending());
            check(delivered.state().revision()==3 && delivered.pending()==null,"delivery acknowledged");
            // Corrupt persisted bytes must not silently reset the job or advance state.
            try(var stream=Files.list(dir)){
                Path target=stream.filter(p->p.getFileName().toString().endsWith(".bin"))
                    .filter(p->p.getFileName().toString().startsWith(ReplayEngine.hash("wade-local-job-v1","tenant/r/1"))).findFirst().orElseThrow();
                Files.write(target,new byte[]{1,2,3});
            }
            try{restarted.read();throw new AssertionError("corruption accepted");}catch(IOException expected){checks++;}
        }finally{
            try(var walk=Files.walk(dir)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}
        }
        System.out.println("WADE pipeline checks passed: "+checks);
    }
}
