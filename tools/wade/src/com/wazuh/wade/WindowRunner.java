// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/** Offline single-scope count window coordinator. Does not call Wazuh or deliver outputs. */
public final class WindowRunner {
    private WindowRunner() {}
    public static String jobKey(ReplayEngine.Version v, DetectionKernel.Scope scope) {
        if (!v.tenant().equals(scope.tenant())) throw new IllegalArgumentException("foreign scope");
        return ReplayEngine.hash("wade-window-job-v1",v.tenant(),v.id(),v.version(),scope.entityType(),scope.entityId());
    }
    public record Result(ReplayEngine.Outcome outcome, LocalWindowStore.Snapshot snapshot) {}
    public static Result stage(ReplayEngine.Registry registry, ReplayEngine.Version version,
                               ReplayEngine.Case input, LocalWindowStore store,
                               long revision,long fence,String owner,Instant now) throws IOException {
        var current=store.read(); var st=current.state();
        if (!st.job().equals(jobKey(version,input.scope())) || st.revision()!=revision || st.fence()!=fence
            || !Objects.equals(st.owner(),owner) || !now.isBefore(st.expires()) || current.pending()!=null)
            throw new IllegalStateException("invalid job or lease");
        if (!st.checkpoint().equals(input.window().start()) || input.asOf().isAfter(now)
            || input.label()!=DetectionQuality.Label.UNLABELLED)
            throw new IllegalArgumentException("invalid operational window");
        var report=ReplayEngine.run(registry,version,List.of(input));
        var outcome=report.outcomes().get(0);
        if (outcome.status()==DetectionKernel.Status.UNKNOWN || outcome.status()==DetectionKernel.Status.NOT_READY)
            return new Result(outcome,current);
        // Versioned, length-safe payload: each field is one URL-safe base64 line. No raw event values.
        List<String> fields=new ArrayList<>(List.of("wade-window-output-v1",st.job(),report.ruleDigest(),report.receipt(),
            input.scope().tenant(),input.scope().entityType(),input.scope().entityId(),version.id(),version.version(),
            input.window().start().toString(),input.window().end().toString(),outcome.status().name(),outcome.reason()));
        var f=outcome.finding();
        if(f!=null){
            fields.addAll(List.of(f.id(),f.evidenceDigest(),Integer.toString(f.observedCount()),Integer.toString(f.sources().size())));
            for(var source:f.sources()){fields.add(source.index());fields.add(source.documentId());}
        }
        var encoder=Base64.getUrlEncoder().withoutPadding();
        String payload=String.join("\n",fields.stream().map(x->encoder.encodeToString(x.getBytes(StandardCharsets.UTF_8))).toList());
        String id=ReplayEngine.hash("wade-window-output-id-v1",st.job(),input.window().start().toString(),input.window().end().toString());
        var pending=LocalWindowStore.Pending.of(id,payload);
        return new Result(outcome,store.complete(revision,fence,owner,now,input.window().end(),pending));
    }
}
