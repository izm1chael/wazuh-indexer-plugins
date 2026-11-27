// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.TemporalAdmission.*;

/** Read-only paired replay of two exact definitions against one captured source cohort per case. */
public final class PairedTemporalReplay {
    public enum Label { BENIGN, MALICIOUS, UNLABELLED }
    public enum Outcome { MATCH, NO_MATCH, UNKNOWN }
    public record Case(String id, Scope scope, Instant start, Instant end, Instant asOf, Label label, boolean protectedCase, String labelReceipt) {
        public Case { hex(id); hex(labelReceipt); Objects.requireNonNull(scope); Objects.requireNonNull(label); Objects.requireNonNull(start); Objects.requireNonNull(end); Objects.requireNonNull(asOf); }
    }
    public record RowResult(String id, Label label, boolean protectedCase, Outcome champion, Outcome challenger, String receipt) {
        public RowResult { hex(id); hex(receipt); Objects.requireNonNull(label); Objects.requireNonNull(champion); Objects.requireNonNull(challenger); }
    }
    public record Report(String champion, String challenger, int minBenign, int minMalicious, List<RowResult> rows, String receipt) {
        public Report { hex(champion); hex(challenger); hex(receipt); rows=List.copyOf(rows); if(minBenign<1||minMalicious<1||rows.size()>1000)throw new IllegalArgumentException("invalid report"); }
        /** Exact advisory offline Dashboard import schema. No raw telemetry or principal identities. */
        public String cohortJson() {
            StringJoiner cases=new StringJoiner(",","[","]");
            for(var r:rows)cases.add("{\"id\":\""+r.id()+"\",\"label\":\""+r.label()+"\",\"champion\":\""+r.champion()+"\",\"challenger\":\""+r.challenger()+"\",\"protected\":"+r.protectedCase()+"}");
            return "{\"format\":\"wade-tuning-cohort-v1\",\"champion_digest\":\""+champion+"\",\"challenger_digest\":\""+challenger+"\",\"min_benign\":"+minBenign+",\"min_malicious\":"+minMalicious+",\"cases\":"+cases+"}";
        }
    }
    /** Verify both immutable definitions, case label provenance, and read scope; no publish permission needed. */
    @FunctionalInterface public interface ReplayAuthority { void require(String actor, Definition champion, Definition challenger, Case c); }
    private final ReplayAuthority authority; private final InventorySource inventory; private final Reader reader; private final Clock clock;
    public PairedTemporalReplay(ReplayAuthority authority,InventorySource inventory,Reader reader,Clock clock){this.authority=Objects.requireNonNull(authority);this.inventory=Objects.requireNonNull(inventory);this.reader=Objects.requireNonNull(reader);this.clock=Objects.requireNonNull(clock);}
    public Report run(String actor,Definition champion,Definition challenger,List<Case> cases,int minBenign,int minMalicious){
        if(actor==null||actor.isBlank()||!champion.tenant().equals(challenger.tenant())||!champion.ruleId().equals(challenger.ruleId())||champion.revision().equals(challenger.revision())||cases.isEmpty()||cases.size()>1000||minBenign<1||minBenign>100000||minMalicious<1||minMalicious>100000)throw new IllegalArgumentException("invalid paired replay");
        var cp=champion.policy();var np=challenger.policy();Instant now=clock.instant();Map<String,Case> ordered=new TreeMap<>();
        for(Case c:cases){
            if(!c.scope().tenant().equals(champion.tenant())||!c.scope().kind().equals("AGENT")||c.asOf().isAfter(now)||ordered.putIfAbsent(c.id(),c)!=null)throw new IllegalArgumentException("invalid cohort case");
            new Request(c.scope(),cp,c.start(),c.end(),c.asOf());new Request(c.scope(),np,c.start(),c.end(),c.asOf());
            authority.require(actor,champion,challenger,c);
        }
        List<RowResult> results=new ArrayList<>();int[] remaining={100000,512};
        for(Case c:ordered.values()){
            authority.require(actor,champion,challenger,c);
            Request a=new Request(c.scope(),cp,c.start(),c.end(),c.asOf()),b=new Request(c.scope(),np,c.start(),c.end(),c.asOf());
            Request wide=a.lookback().isBefore(b.lookback())?a:b;
            var captured=capture(wide,Math.max(cp.inputLimit(),np.inputLimit()),remaining);
            var first=evaluate(a,champion,captured);var second=evaluate(b,challenger,captured);
            String receipt=hash("wade-paired-case-v1",c.id(),c.scope().canonical(),c.start().toString(),c.end().toString(),c.asOf().toString(),c.label().name(),Boolean.toString(c.protectedCase()),c.labelReceipt(),captured.receipt(),cp.version(),np.version(),first.status().name(),Objects.toString(first.receipt(),""),second.status().name(),Objects.toString(second.receipt(),""));
            results.add(new RowResult(c.id(),c.label(),c.protectedCase(),outcome(first),outcome(second),receipt));
        }
        List<String> receipt=new ArrayList<>(List.of("wade-paired-report-v1",cp.version(),np.version(),Integer.toString(minBenign),Integer.toString(minMalicious)));
        results.forEach(r->receipt.add(r.receipt()));return new Report(cp.version(),np.version(),minBenign,minMalicious,results,hash(receipt.toArray(String[]::new)));
    }
    private record Capture(Inventory inventory, Map<Partition,List<Row>> rows, String receipt) {}
    private Capture capture(Request wide,int limit,int[] remaining){
        Inventory inv=inventory.resolve(wide);if(!inv.complete()||inv.partitions().isEmpty())return unknown("inventory");
        Set<String> names=new HashSet<>(),uuids=new HashSet<>();
        for(var p:inv.partitions())if(!p.scope().equals(wide.scope())||!names.add(p.index())||!uuids.add(p.uuid())||p.coverageStart().isAfter(wide.lookback())||p.watermark().isBefore(wide.end())||p.watermark().isAfter(wide.asOf()))return unknown("partition");
        Map<Partition,List<Row>> rows=new HashMap<>();Set<String> refs=new HashSet<>();List<String> digests=new ArrayList<>();int scanned=0;
        for(var p:inv.partitions()){
            int budget=Math.min(limit-scanned,remaining[0]);if(budget<=0||remaining[1]<=0)return unknown("budget"); remaining[1]--;
            Batch batch=reader.read(p,wide.lookback(),wide.end(),budget+1);remaining[0]-=Math.min(remaining[0],batch.rows().size());
            if(!batch.complete()||batch.rows().size()>budget)return unknown("partial-or-budget");scanned+=batch.rows().size();
            List<Row> visible=new ArrayList<>();digests.add(hash("partition",p.index(),p.uuid(),p.coverageStart().toString(),p.watermark().toString()));
            for(Row row:batch.rows()){
                if(!p.index().equals(row.index())||!p.uuid().equals(row.uuid())||!wide.scope().id().equals(row.agent())||row.occurred().isBefore(wide.lookback())||!row.occurred().isBefore(wide.end())||!refs.add(hash(row.uuid(),row.id())))return unknown("row");
                visible.add(row);if(row.available().isAfter(wide.asOf()))continue;
                List<String> fields=new ArrayList<>(List.of("row",row.uuid(),row.id(),row.occurred().toString(),row.available().toString()));
                new TreeMap<>(row.fields()).forEach((k,v)->{fields.add(k);fields.add(Integer.toString(v.size()));fields.addAll(v.stream().sorted().toList());});digests.add(hash(fields.toArray(String[]::new)));
            }
            rows.put(p,List.copyOf(visible)); digests.add(hash("scanned",p.uuid(),Integer.toString(batch.rows().size())));
        }
        Collections.sort(digests);return new Capture(inv,Map.copyOf(rows),hash(digests.toArray(String[]::new)));
    }
    private static Capture unknown(String reason){return new Capture(new Inventory(false,List.of()),Map.of(),hash("incomplete",reason));}
    private static CrossWindowCorrelation.Result evaluate(Request request,Definition d,Capture c){
        TemporalAdmission admission=new TemporalAdmission(r->d,r->c.inventory(),(p,from,to,limit)->{
            List<Row> rows=c.rows().getOrDefault(p,List.of()).stream().filter(row->!row.occurred().isBefore(from)&&row.occurred().isBefore(to)).toList();
            return rows.size()>limit?new Batch(false,List.of()):new Batch(true,rows);
        });
        Snapshot s=admission.read(request);
        return CrossWindowCorrelation.evaluate(request.policy(),request.scope().canonical(),new CrossWindowCorrelation.Window(request.start(),request.end(),request.asOf(),s.coverageStart(),s.watermark(),s.complete()),s.events());
    }
    private static Outcome outcome(CrossWindowCorrelation.Result r){return switch(r.status()){case MATCH->Outcome.MATCH;case NO_MATCH->Outcome.NO_MATCH;case UNKNOWN,NOT_READY->Outcome.UNKNOWN;};}
    private static void hex(String s){if(s==null||!s.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("opaque digest required");}
    private static String hash(String... fields){try{MessageDigest d=MessageDigest.getInstance("SHA-256");for(String s:fields){byte[] bytes=s.getBytes(StandardCharsets.UTF_8);d.update(ByteBuffer.allocate(4).putInt(bytes.length).array());d.update(bytes);}return HexFormat.of().formatHex(d.digest());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
}
