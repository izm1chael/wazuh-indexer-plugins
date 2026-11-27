// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.*;
import java.util.*;

/** Bounded, causal correlation anchored to a disjoint completion window. */
public final class CrossWindowCorrelation {
    private CrossWindowCorrelation() {}
    public enum Mode { ORDERED, UNORDERED }
    public enum Status { MATCH, NO_MATCH, UNKNOWN, NOT_READY }
    public record Policy(String version, List<String> stages, Mode mode, Duration span, int inputLimit, int workLimit) {
        public Policy {
            key(version); stages = List.copyOf(stages); Objects.requireNonNull(mode); Objects.requireNonNull(span);
            if (stages.size() < 2 || stages.size() > 16 || new HashSet<>(stages).size() != stages.size()
                || span.isZero() || span.isNegative() || span.compareTo(Duration.ofDays(31)) > 0
                || inputLimit < stages.size() || inputLimit > 10000 || workLimit < 1 || workLimit > 250000)
                throw new IllegalArgumentException("invalid policy");
            stages.forEach(CrossWindowCorrelation::key);
        }
    }
    public record Event(String scope, String source, Instant occurred, Instant available, Set<String> stages) {
        public Event {
            key(scope); key(source); Objects.requireNonNull(occurred); Objects.requireNonNull(available);
            stages = Set.copyOf(stages);
            if (available.isBefore(occurred) || stages.size() > 16) throw new IllegalArgumentException("invalid event");
            stages.forEach(CrossWindowCorrelation::key);
        }
    }
    public record Window(Instant start, Instant end, Instant asOf, Instant coverageStart, Instant watermark, boolean complete) {
        public Window {
            Objects.requireNonNull(start); Objects.requireNonNull(end); Objects.requireNonNull(asOf);
            Objects.requireNonNull(coverageStart); Objects.requireNonNull(watermark);
            if (!start.isBefore(end) || Duration.between(start,end).compareTo(Duration.ofDays(31)) > 0
                || watermark.isAfter(asOf)) throw new IllegalArgumentException("invalid window");
        }
    }
    public record Result(Status status, String reason, String findingId, String evidenceDigest, String receipt, List<String> sources) {
        public Result { sources = List.copyOf(sources); }
    }
    public static Result evaluate(Policy p, String scope, Window w, List<Event> input) {
        Objects.requireNonNull(p); key(scope); Objects.requireNonNull(w); Objects.requireNonNull(input);
        Instant lookback = w.start().minus(p.span());
        if (w.asOf().isBefore(w.end()) || w.watermark().isBefore(w.end())) return empty(Status.NOT_READY,"WINDOW_OPEN");
        if (!w.complete() || w.coverageStart().isAfter(lookback)) return empty(Status.UNKNOWN,"INCOMPLETE_LOOKBACK");
        if (input.size() > p.inputLimit()) return empty(Status.UNKNOWN,"INPUT_LIMIT");
        Map<String,Event> unique = new TreeMap<>();
        for (Event e : input) {
            if (!scope.equals(e.scope())) return empty(Status.UNKNOWN,"SCOPE_MISMATCH");
            if (e.available().isAfter(w.asOf()) || e.occurred().isBefore(lookback) || !e.occurred().isBefore(w.end())) continue;
            Event previous = unique.putIfAbsent(e.source(),e);
            if (previous != null && !previous.equals(e)) return empty(Status.UNKNOWN,"CONFLICTING_SOURCE");
        }
        List<Event> events = unique.values().stream().sorted(Comparator.comparing(Event::occurred).thenComparing(Event::source)).toList();
        List<String> fields = new ArrayList<>(List.of("wade-cross-window-v1",p.version(),p.mode().name(),p.span().toString(),
            Integer.toString(p.inputLimit()),Integer.toString(p.workLimit()),Integer.toString(p.stages().size())));
        fields.addAll(p.stages()); fields.addAll(List.of(scope,w.start().toString(),w.end().toString(),w.asOf().toString(),
            w.coverageStart().toString(),w.watermark().toString()));
        for (Event e:events) {
            List<String> f=new ArrayList<>(List.of(e.source(),e.occurred().toString(),e.available().toString()));
            f.addAll(new TreeSet<>(e.stages())); fields.add(hash(f));
        }
        // Search from the final event backwards: each witness must actually complete in [start,end).
        // For unordered matching, any stage may own the final event; other stages cannot use it again.
        int[] work={p.workLimit()};
        try {
            for (int i=0;i<events.size();i++) {
                spend(work); Event anchor=events.get(i);
                if (anchor.occurred().isBefore(w.start())) continue;
                int first=p.mode()==Mode.ORDERED?p.stages().size()-1:0;
                for (int stage=first;stage<p.stages().size();stage++) {
                    spend(work);
                    if (!anchor.stages().contains(p.stages().get(stage))) continue;
                    Event[] witness=new Event[p.stages().size()]; witness[stage]=anchor;
                    if (assign(p,events,i,anchor,witness,p.stages().size()-1,anchor.occurred(),new HashSet<>(Set.of(anchor.source())),work)) {
                        List<String> refs=Arrays.stream(witness).map(Event::source).toList();
                        List<String> receiptFields=new ArrayList<>(fields); receiptFields.add("MATCH"); receiptFields.addAll(refs);
                        // Stable logical ID per immutable policy definition, scope and completion window.
                        List<String> witnessFields=new ArrayList<>(List.of("wade-cross-window-evidence-v1"));
                        for (Event e:witness) {
                            List<String> f=new ArrayList<>(List.of(e.source(),e.occurred().toString(),e.available().toString()));
                            f.addAll(new TreeSet<>(e.stages())); witnessFields.add(hash(f));
                        }
                        return new Result(Status.MATCH,"ANCHORED_WITNESS",logicalKey(p,scope,w),hash(witnessFields),hash(receiptFields),refs);
                    }
                }
            }
        } catch (Limit ex) { return empty(Status.UNKNOWN,"WORK_LIMIT"); }
        fields.add("NO_MATCH"); return new Result(Status.NO_MATCH,"NO_ANCHORED_SEQUENCE",null,null,hash(fields),List.of());
    }
    public static String logicalKey(Policy p,String scope,Window w) {
        Objects.requireNonNull(p); key(scope); Objects.requireNonNull(w);
        List<String> identity=new ArrayList<>(List.of("wade-cross-window-id-v1",p.version(),scope,w.start().toString(),w.end().toString(),p.mode().name(),p.span().toString(),Integer.toString(p.inputLimit()),Integer.toString(p.workLimit())));
        identity.addAll(p.stages()); return hash(identity);
    }
    private static boolean assign(Policy p,List<Event> events,int last,Event anchor,Event[] witness,int stage,Instant upper,Set<String> used,int[] work) {
        if (stage<0) return true;
        if (witness[stage]!=null) return assign(p,events,last,anchor,witness,stage-1,upper,used,work);
        for (int i=last;i>=0;i--) {
            spend(work); Event e=events.get(i);
            if (Duration.between(e.occurred(),anchor.occurred()).compareTo(p.span())>0) break;
            if (!e.stages().contains(p.stages().get(stage)) || used.contains(e.source())) continue;
            if (p.mode()==Mode.ORDERED && !e.occurred().isBefore(upper)) continue;
            witness[stage]=e; used.add(e.source());
            if (assign(p,events,p.mode()==Mode.ORDERED?i-1:last,anchor,witness,stage-1,e.occurred(),used,work)) return true;
            used.remove(e.source()); witness[stage]=null;
        }
        return false;
    }
    private static final class Limit extends RuntimeException { private static final long serialVersionUID=1L; }
    private static void spend(int[] work) { if (--work[0]<0) throw new Limit(); }
    private static Result empty(Status s,String reason) { return new Result(s,reason,null,null,null,List.of()); }
    private static void key(String s) {
        if (s==null || s.isBlank() || s.length()>1024 || !StandardCharsets.UTF_8.newEncoder().canEncode(s)) throw new IllegalArgumentException("invalid key");
    }
    private static String hash(List<String> fields) {
        try {
            MessageDigest d=MessageDigest.getInstance("SHA-256");
            for (String s:fields) { byte[] b=s.getBytes(StandardCharsets.UTF_8); d.update(ByteBuffer.allocate(4).putInt(b.length).array()); d.update(b); }
            return HexFormat.of().formatHex(d.digest());
        } catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
}
