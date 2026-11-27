// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;

/** Restricted WCS admission for the in-process temporal service, not a Sigma compiler. */
public final class TemporalAdmission implements Registry, Source {
    private static final Set<String> FIELDS=Set.of("event.kind","event.category","event.action","event.outcome","event.code","event.provider");
    public record Stage(String id,Map<String,String> terms) {
        public Stage {
            key(id); terms=Map.copyOf(terms);
            if(terms.isEmpty()||terms.size()>FIELDS.size()||!"event".equals(terms.get("event.kind"))||!FIELDS.containsAll(terms.keySet())) throw new IllegalArgumentException("invalid WCS selector");
            terms.values().forEach(TemporalAdmission::key);
        }
    }
    public record Definition(String tenant,String ruleId,String revision,CrossWindowCorrelation.Mode mode,Duration span,int inputLimit,int workLimit,List<Stage> stages) {
        public Definition {
            key(tenant);key(ruleId);key(revision);Objects.requireNonNull(mode);Objects.requireNonNull(span);stages=List.copyOf(stages);
            if(stages.size()<2||stages.size()>16||stages.stream().map(Stage::terms).distinct().count()!=stages.size())throw new IllegalArgumentException("invalid stages");
            new CrossWindowCorrelation.Policy("validation",stages.stream().map(Stage::id).toList(),mode,span,inputLimit,workLimit);
        }
        public CrossWindowCorrelation.Policy policy(){
            List<String> fields=new ArrayList<>(List.of("wade-wcs-temporal-v2",tenant,ruleId,revision,mode.name(),span.toString(),Integer.toString(inputLimit),Integer.toString(workLimit),Integer.toString(stages.size())));
            for(Stage stage:stages){fields.add(stage.id());fields.add(Integer.toString(stage.terms().size()));new TreeMap<>(stage.terms()).forEach((k,v)->{fields.add(k);fields.add(v);});}
            return new CrossWindowCorrelation.Policy(hash(fields.toArray(String[]::new)),stages.stream().map(Stage::id).toList(),mode,span,inputLimit,workLimit);
        }
    }
    public record Partition(String index,String uuid,Scope scope,Instant coverageStart,Instant watermark) {
        public Partition {
            if(index==null||!index.matches("\\.ds-wazuh-events-v5-[a-z0-9._-]{1,180}"))throw new IllegalArgumentException("concrete backing index required");
            key(uuid);Objects.requireNonNull(scope);Objects.requireNonNull(coverageStart);Objects.requireNonNull(watermark);
        }
    }
    public record Row(String index,String uuid,String id,String agent,Instant occurred,Instant available,Map<String,List<String>> fields) {
        public Row {
            key(index);key(uuid);key(id);key(agent);Objects.requireNonNull(occurred);Objects.requireNonNull(available);
            if(available.isBefore(occurred)||!FIELDS.containsAll(fields.keySet()))throw new IllegalArgumentException("invalid row");
            Map<String,List<String>> copy=new TreeMap<>();fields.forEach((k,v)->{if(v.isEmpty()||v.size()>32)throw new IllegalArgumentException("field limit");v.forEach(TemporalAdmission::key);copy.put(k,List.copyOf(v));});fields=Map.copyOf(copy);
        }
    }
    public record Inventory(boolean complete,List<Partition> partitions) { public Inventory {if(partitions.size()>64)throw new IllegalArgumentException("partition limit");partitions=List.copyOf(partitions);} }
    public record Batch(boolean complete,List<Row> rows) { public Batch {if(rows.size()>10001)throw new IllegalArgumentException("row limit");rows=List.copyOf(rows);} }
    /** Return only an approved immutable definition under the authenticated execution context. */
    @FunctionalInterface public interface Approved { Definition resolve(Request request); }
    /** Attest full partition inventory, scope, schema, ingestion clock, UUID and lookback coverage. */
    @FunctionalInterface public interface InventorySource { Inventory resolve(Request request); }
    /** Bounded exact-index query; must verify concrete UUID and return all requested rows or incomplete. */
    @FunctionalInterface public interface Reader { Batch read(Partition partition,Instant from,Instant to,int limit); }
    private final Approved approved; private final InventorySource inventory; private final Reader reader;
    public TemporalAdmission(Approved approved,InventorySource inventory,Reader reader){this.approved=Objects.requireNonNull(approved);this.inventory=Objects.requireNonNull(inventory);this.reader=Objects.requireNonNull(reader);}
    private Definition definition(Request request){
        Definition d=approved.resolve(request);
        if(d==null||!d.tenant().equals(request.scope().tenant())||!d.policy().equals(request.policy())||!request.scope().kind().equals("AGENT"))throw new SecurityException("unapproved revision or scope");
        return d;
    }
    public void requireApproved(Request request){definition(request);}
    public Snapshot read(Request request){
        Definition d=definition(request);Inventory inv=inventory.resolve(request);
        if(!inv.complete()||inv.partitions().isEmpty())return incomplete(request);
        Set<String> names=new HashSet<>(),uuids=new HashSet<>();
        Instant watermark=request.asOf(),coverage=request.lookback();
        // Verify the whole inventory before any read.
        for(Partition p:inv.partitions()){
            if(!p.scope().equals(request.scope())||!names.add(p.index())||!uuids.add(p.uuid())||p.coverageStart().isAfter(request.lookback())||p.watermark().isBefore(request.end())||p.watermark().isAfter(request.asOf()))return incomplete(request);
            if(p.watermark().isBefore(watermark))watermark=p.watermark();
        }
        List<CrossWindowCorrelation.Event> events=new ArrayList<>();Set<String> refs=new HashSet<>();int scanned=0;
        for(Partition p:inv.partitions()){
            int left=request.policy().inputLimit()-scanned;Batch b=reader.read(p,request.lookback(),request.end(),left+1);
            if(!b.complete()||b.rows().size()>left)return incomplete(request);
            scanned+=b.rows().size();
            for(Row row:b.rows()){
                if(!p.index().equals(row.index())||!p.uuid().equals(row.uuid())||!request.scope().id().equals(row.agent())||row.occurred().isBefore(request.lookback())||!row.occurred().isBefore(request.end()))return incomplete(request);
                String ref=hash("wade-source-v1",row.uuid(),row.id());if(!refs.add(ref))return incomplete(request);
                if(row.available().isAfter(request.asOf()))continue;
                Set<String> matched=new HashSet<>();
                for(Stage stage:d.stages()){
                    boolean no=false,missing=false;
                    for(var term:stage.terms().entrySet()){
                        List<String> values=row.fields().get(term.getKey());
                        if(values==null)missing=true;else if(!values.contains(term.getValue()))no=true;
                    }
                    if(!no&&missing)return incomplete(request);
                    if(!no)matched.add(stage.id());
                }
                events.add(new CrossWindowCorrelation.Event(request.scope().canonical(),ref,row.occurred(),row.available(),matched));
            }
        }
        return new Snapshot(request,coverage,watermark,true,events);
    }
    private static Snapshot incomplete(Request r){return new Snapshot(r,r.lookback(),r.end(),false,List.of());}
    private static void key(String s){if(s==null||s.isBlank()||s.length()>1024||!StandardCharsets.UTF_8.newEncoder().canEncode(s))throw new IllegalArgumentException("invalid value");}
    private static String hash(String... fields){
        try{MessageDigest d=MessageDigest.getInstance("SHA-256");for(String s:fields){byte[] b=s.getBytes(StandardCharsets.UTF_8);d.update(ByteBuffer.allocate(4).putInt(b.length).array());d.update(b);}return HexFormat.of().formatHex(d.digest());}
        catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
}
