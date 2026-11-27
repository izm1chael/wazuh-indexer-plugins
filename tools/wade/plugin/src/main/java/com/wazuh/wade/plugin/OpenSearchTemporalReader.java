// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade.plugin;

import com.wazuh.wade.TemporalAdmission;
import java.time.Instant;
import java.util.*;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

/** Unregistered bounded reader candidate; the caller supplies a scoped client and UUID authority. */
public final class OpenSearchTemporalReader implements TemporalAdmission.Reader {
    private static final String[] INCLUDES={"@timestamp","agent.id","event.ingested","event.kind",
        "event.category","event.action","event.outcome","event.code","event.provider"};
    private static final List<String> TERMS=List.of("kind","category","action","outcome","code","provider");
    @FunctionalInterface public interface IdentityFence {
        /** Confirm a trusted concrete index UUID and an immutable read interval, including empty results. */
        void require(TemporalAdmission.Partition partition,Instant from,Instant to);
    }
    private final Client client;
    private final Runnable worker;
    private final IdentityFence fence;
    private final TimeValue timeout;
    public OpenSearchTemporalReader(Client client,Runnable worker,IdentityFence fence,int seconds){
        this.client=Objects.requireNonNull(client);this.worker=Objects.requireNonNull(worker);
        this.fence=Objects.requireNonNull(fence);if(seconds<1||seconds>30)throw new IllegalArgumentException("timeout");
        this.timeout=TimeValue.timeValueSeconds(seconds);
    }
    @Override public TemporalAdmission.Batch read(TemporalAdmission.Partition p,Instant from,Instant to,int limit){
        if(limit<1||limit>10001||!from.isBefore(to)||!p.scope().kind().equals("AGENT"))throw new IllegalArgumentException("query boundary");
        worker.run();fence.require(p,from,to);
        var source=new SearchSourceBuilder()
            .query(QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("agent.id",p.scope().id()))
                .filter(QueryBuilders.rangeQuery("@timestamp").gte(from.toString()).lt(to.toString())))
            .fetchSource(INCLUDES,new String[0]).size(Math.min(limit,10000)).trackTotalHits(true).timeout(timeout);
        SearchResponse response=client.search(new SearchRequest(p.index()).source(source)
            .allowPartialSearchResults(false)).actionGet(timeout);
        fence.require(p,from,to);
        if(response.isTimedOut()||Boolean.TRUE.equals(response.isTerminatedEarly())||response.getFailedShards()!=0
            ||response.getSuccessfulShards()!=response.getTotalShards()||response.getTotalShards()<1)return incomplete();
        var total=response.getHits().getTotalHits();
        SearchHit[] hits=response.getHits().getHits();
        if(total==null||total.relation()!=org.apache.lucene.search.TotalHits.Relation.EQUAL_TO||total.value()!=hits.length||hits.length>limit)return incomplete();
        List<TemporalAdmission.Row> rows=new ArrayList<>();
        try{
            for(SearchHit h:hits){
                if(!p.index().equals(h.getIndex())||h.getShard()==null
                    ||!p.uuid().equals(h.getShard().getShardId().getIndex().getUUID()))return incomplete();
                Map<String,Object> doc=h.getSourceAsMap();
                if(!(doc.get("agent") instanceof Map<?,?> agent)||!(doc.get("event") instanceof Map<?,?> event))return incomplete();
                Map<String,List<String>> fields=new HashMap<>();
                for(String name:TERMS){
                    Object raw=event.get(name);if(raw==null)continue;
                    List<String> values=new ArrayList<>();
                    if(raw instanceof String value)values.add(value);
                    else if(raw instanceof List<?> list){if(list.size()>32)return incomplete();for(Object v:list)values.add(string(v));}
                    else return incomplete();
                    fields.put("event."+name,values);
                }
                rows.add(new TemporalAdmission.Row(h.getIndex(),p.uuid(),h.getId(),string(agent.get("id")),
                    Instant.parse(string(doc.get("@timestamp"))),Instant.parse(string(event.get("ingested"))),fields));
            }
        }catch(IllegalArgumentException|java.time.DateTimeException e){return incomplete();}
        return new TemporalAdmission.Batch(true,rows);
    }
    private static String string(Object o){if(!(o instanceof String s)||s.isBlank()||s.length()>1024)throw new IllegalArgumentException("invalid source field");return s;}
    private static TemporalAdmission.Batch incomplete(){return new TemporalAdmission.Batch(false,List.of());}
}
