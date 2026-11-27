// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import static java.nio.file.StandardOpenOption.*;

/** Single-job local reference store. NOT a distributed Indexer storage adapter. */
public final class LocalWindowStore {
    private static final int MAGIC = 0x57414445;
    private final Path dir, file, lock;
    private final String job;
    public record Pending(String id, String digest, String payload) {
        public Pending {
            ReplayEngine.digestKey(id); ReplayEngine.digestKey(digest); Objects.requireNonNull(payload);
            if (payload.length()>4096 || !java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(payload)
                || !ReplayEngine.hash("wade-output-v1",payload).equals(digest))
                throw new IllegalArgumentException("invalid output payload/digest");
        }
        public static Pending of(String id,String payload) {
            return new Pending(id,ReplayEngine.hash("wade-output-v1",payload),payload);
        }
    }
    public record Snapshot(ExecutionControl.State state, Pending pending, Pending lastAck) {
        public Snapshot { Objects.requireNonNull(state); }
    }
    public LocalWindowStore(Path directory, String job) throws IOException {
        ReplayEngine.key(job); this.job = job;
        // Caller must supply a trusted, private local directory, not a network filesystem.
        dir = Files.createDirectories(directory).toRealPath();
        String name = ReplayEngine.hash("wade-local-job-v1",job);
        file = dir.resolve(name+".bin"); lock = dir.resolve(name+".lock");
    }
    public Snapshot initialize(Instant checkpoint) throws IOException {
        return transact(s -> s == null ? new Snapshot(ExecutionControl.initial(job,checkpoint),null,null) : s);
    }
    public Snapshot read() throws IOException { return transact(s -> required(s)); }
    public Snapshot acquire(long revision, String owner, Instant now, Duration ttl) throws IOException {
        return transact(s -> {
            required(s);
            if (s.pending()!=null) throw new IllegalStateException("delivery pending");
            return new Snapshot(ExecutionControl.acquire(s.state(),revision,owner,now,ttl),null,s.lastAck());
        });
    }
    /** Advance checkpoint and stage an immutable output receipt in the same durable snapshot. */
    public Snapshot complete(long revision,long fence,String owner,Instant now,Instant checkpoint,
                             Pending output) throws IOException {
        Objects.requireNonNull(output);
        return transact(s -> {
            required(s);
            if (s.pending()!=null || (s.lastAck()!=null && output.id().equals(s.lastAck().id()))) throw new IllegalStateException("output already staged/delivered");
            var completed = ExecutionControl.complete(s.state(),revision,fence,owner,now,checkpoint,output.id());
            return new Snapshot(completed,output,s.lastAck());
        });
    }
    /** Caller must first verify durable, idempotent delivery of exactly this output. */
    public Snapshot acknowledge(long revision, Pending output) throws IOException {
        Objects.requireNonNull(output);
        return transact(s -> {
            required(s);
            if (s.pending()==null && output.equals(s.lastAck())) return s;
            var st=s.state();
            if (st.revision()!=revision || !output.equals(s.pending()) || st.owner()!=null)
                throw new IllegalStateException("stale or mismatched delivery");
            var next=new ExecutionControl.State(st.job(),Math.incrementExact(st.revision()),st.fence(),null,
                Instant.MIN,st.checkpoint(),st.receipt());
            return new Snapshot(next,null,output);
        });
    }
    private static Snapshot required(Snapshot s) {
        if(s==null) throw new IllegalStateException("uninitialized job"); return s;
    }
    @FunctionalInterface private interface Transition { Snapshot apply(Snapshot s); }
    private Snapshot transact(Transition t) throws IOException {
        // Cross-process file lock; concurrent same-JVM overlapping locks may fail and must be retried.
        try (FileChannel channel=FileChannel.open(lock,CREATE,WRITE); FileLock guard=channel.lock()) {
            if (!guard.isValid()) throw new IOException("lock unavailable");
            Snapshot before=load(); Snapshot after=t.apply(before);
            if(!after.equals(before)) save(after);
            return after;
        }
    }
    private Snapshot load() throws IOException {
        if(!Files.exists(file)) return null;
        if(Files.size(file)>65536) throw new IOException("invalid snapshot size");
        try(DataInputStream in=new DataInputStream(Files.newInputStream(file))) {
            if(in.readInt()!=MAGIC || in.readInt()!=1 || !job.equals(in.readUTF())) throw new IOException("invalid snapshot identity/version");
            var state=new ExecutionControl.State(job,in.readLong(),in.readLong(),optional(in),
                Instant.parse(in.readUTF()),Instant.parse(in.readUTF()),optional(in));
            Snapshot s=new Snapshot(state,pending(in),pending(in));
            if(in.read()!=-1 || (s.pending()!=null && (!s.pending().id().equals(state.receipt()) || state.owner()!=null)))
                throw new IOException("invalid snapshot contents");
            return s;
        } catch (RuntimeException e) { throw new IOException("invalid snapshot",e); }
    }
    private void save(Snapshot s) throws IOException {
        Path tmp=Files.createTempFile(dir,"wade-",".tmp");
        try {
            try(FileChannel channel=FileChannel.open(tmp,WRITE,TRUNCATE_EXISTING);
                DataOutputStream out=new DataOutputStream(java.nio.channels.Channels.newOutputStream(channel))) {
                var st=s.state(); out.writeInt(MAGIC); out.writeInt(1); out.writeUTF(job);
                out.writeLong(st.revision()); out.writeLong(st.fence()); optional(out,st.owner());
                out.writeUTF(st.expires().toString()); out.writeUTF(st.checkpoint().toString()); optional(out,st.receipt());
                pending(out,s.pending()); pending(out,s.lastAck()); out.flush(); channel.force(true);
            }
            Files.move(tmp,file,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            // Linux local filesystem durability. Fail instead of silently degrading on unsupported filesystems.
            try(FileChannel directory=FileChannel.open(dir,READ)) { directory.force(true); }
        } finally { Files.deleteIfExists(tmp); }
    }
    private static String optional(DataInputStream in) throws IOException { return in.readBoolean()?in.readUTF():null; }
    private static void optional(DataOutputStream out,String s) throws IOException { out.writeBoolean(s!=null); if(s!=null) out.writeUTF(s); }
    private static Pending pending(DataInputStream in) throws IOException { return in.readBoolean()?new Pending(in.readUTF(),in.readUTF(),in.readUTF()):null; }
    private static void pending(DataOutputStream out,Pending p) throws IOException {
        out.writeBoolean(p!=null); if(p!=null){out.writeUTF(p.id());out.writeUTF(p.digest());out.writeUTF(p.payload());}
    }
}
