// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.Instant;
import java.util.*;
import static com.wazuh.wade.TemporalJobRunner.*;

/** Scoped CAS job cursor adapter. No index bootstrap or automatic provisioning. */
public final class IndexTemporalJobs implements Cursors {
    public static final String INDEX="wade-v1-temporal-jobs";
    private final IndexWindowStore.Backend backend;private final WindowService.Scope scope;private final boolean enabled;
    public IndexTemporalJobs(IndexWindowStore.Backend backend,WindowService.Scope scope,boolean enabled){this.backend=Objects.requireNonNull(backend);this.scope=Objects.requireNonNull(scope);this.enabled=enabled;}
    public boolean provision(Job job){write(job);return backend.create(INDEX,job.id(),encode(job,Cursor.initial(job)));}
    public Cursor load(Job job){requireScope(job);var d=backend.get(INDEX,job.id());return d==null?null:decode(job,d);}
    public boolean compareAndSet(Job job,Cursor expected,Cursor next){
        write(job);if(!job.id().equals(expected.jobId())||!job.id().equals(next.jobId())||next.revision()!=Math.incrementExact(expected.revision())||next.checkpoint().isBefore(expected.checkpoint())||next.fence()<expected.fence()||next.fence()>expected.fence()+1)throw new IllegalArgumentException("invalid job transition");
        var d=backend.get(INDEX,job.id());if(d==null||!decode(job,d).equals(expected))return false;
        return backend.replace(INDEX,job.id(),d.sequence(),d.primaryTerm(),encode(job,next));
    }
    private Map<String,Object> encode(Job job,Cursor c){
        if(c.checkpoint().isBefore(job.origin())||c.lateEnd()!=null&&c.lateEnd().isBefore(job.origin()))throw new IllegalArgumentException("cursor before origin");
        Map<String,Object> m=new HashMap<>(Map.of("schema_version",1L,"tenant",scope.tenant(),"scope_key",scope.canonical(),"job_id",job.id(),"revision",c.revision(),"fence",c.fence(),"checkpoint",c.checkpoint().toString()));
        if(c.lateEnd()!=null)m.put("late_end",c.lateEnd().toString());if(c.owner()!=null){m.put("owner",c.owner());m.put("expires",c.expires().toString());}if(c.receipt()!=null)m.put("receipt",c.receipt());return Map.copyOf(m);
    }
    private Cursor decode(Job job,IndexWindowStore.Document d){
        Map<String,Object> m=d.body();if(!job.id().equals(d.id())||!scope.tenant().equals(m.get("tenant"))||!scope.canonical().equals(m.get("scope_key"))||!job.id().equals(m.get("job_id"))||number(m.get("schema_version"))!=1)throw new IllegalStateException("scope or schema mismatch");
        String owner=(String)m.get("owner"),late=(String)m.get("late_end"),expiry=(String)m.get("expires");
        Cursor c=new Cursor(job.id(),number(m.get("revision")),number(m.get("fence")),Instant.parse((String)m.get("checkpoint")),late==null?null:Instant.parse(late),owner,expiry==null?Instant.MIN:Instant.parse(expiry),(String)m.get("receipt"));
        Map<String,Object> canonical=encode(job,c);if(!canonical.keySet().equals(m.keySet()))throw new IllegalStateException("unknown cursor fields");
        for(var e:canonical.entrySet())if(e.getValue() instanceof Long n?number(m.get(e.getKey()))!=n:!e.getValue().equals(m.get(e.getKey())))throw new IllegalStateException("noncanonical cursor");return c;
    }
    private static long number(Object x){if(x instanceof Long l)return l;if(x instanceof Integer i)return i.longValue();throw new IllegalStateException("invalid integer");}
    private void requireScope(Job job){if(!scope.equals(job.scope()))throw new SecurityException("foreign job scope");}
    private void write(Job job){requireScope(job);if(!enabled)throw new IllegalStateException("writes disabled");}
}
