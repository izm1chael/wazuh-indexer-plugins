// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade.plugin;

import com.wazuh.wade.*;
import java.io.InputStream;
import java.time.*;
import java.util.*;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

/**
 * Embedded, disposable two-data-node integration candidate.
 * No external endpoint, production credentials or real WCS source data.
 * Fixture authorities are not the OpenSearch Security implementation.
 */
@OpenSearchIntegTestCase.ClusterScope(
        scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 2, supportsDedicatedMasters = false)
public class NativeTemporalRuntimeTests extends OpenSearchIntegTestCase {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final String SOURCE=".ds-wazuh-events-v5-wade-lab-000001";
    private static final WindowService.Scope SCOPE=new WindowService.Scope("lab","embedded-test","AGENT","001");
    private static final TemporalPromotion.Rule RULE=new TemporalPromotion.Rule("lab","auth-sequence");
    private static final List<String> CONTRACTS=List.of("window-reconciliation","window-publications","temporal-jobs","temporal-registry","temporal-evidence");
    private static Instant t(int n){return T.plusSeconds(n);}

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins(){return List.of(WadePlugin.class);}

    @SuppressWarnings("unchecked")
    private Map<String,Object> mapping(String name) throws Exception {
        try(InputStream stream=getClass().getResourceAsStream("/"+name+".json")){
            assertNotNull("missing actual committed contract "+name,stream);
            try(var parser=XContentFactory.xContent(XContentType.JSON)
                    .createParser(NamedXContentRegistry.EMPTY,DeprecationHandler.THROW_UNSUPPORTED_OPERATION,stream)){
                Map<String,Object> contract=parser.map();
                assertEquals(List.of("wade-v1-"+name),contract.get("index_patterns"));
                Map<String,Object> template=(Map<String,Object>)contract.get("template");
                Map<String,Object> result=(Map<String,Object>)template.get("mappings");
                assertEquals("strict",result.get("dynamic"));return result;
            }
        }
    }
    private void create(String index,Map<String,Object> mappings){
        var request=new CreateIndexRequest().index(index)
                .settings(Settings.builder().put("index.number_of_shards",1).put("index.number_of_replicas",1))
                .mapping(mappings).waitForActiveShards(ActiveShardCount.ALL);
        var response=client().admin().indices().create(request).actionGet();
        assertTrue(response.isAcknowledged());assertTrue(response.isShardsAcknowledged());
    }
    private static Map<String,Object> keyword(){return Map.of("type","keyword");}
    private String uuid(String index){
        // internalCluster() rejects external clusters; never resolve an arbitrary external index.
        var meta=internalCluster().getInstance(ClusterService.class).state().metadata().index(index);
        assertNotNull(meta);return meta.getIndexUUID();
    }
    private void event(String id,int time,String outcome){
        var request=new IndexRequest(SOURCE).id(id).create(true)
                .source(Map.of("@timestamp",t(time).toString(),"agent",Map.of("id","001"),
                    "event",Map.of("ingested",t(time).toString(),"kind","event","outcome",outcome)),XContentType.JSON)
                .waitForActiveShards(ActiveShardCount.ALL).setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
        assertEquals(0,client().index(request).actionGet().getShardInfo().getFailed());
    }
    private static TemporalAdmission.Definition definition(String version,String outcome){
        return new TemporalAdmission.Definition(RULE.tenant(),RULE.id(),version,CrossWindowCorrelation.Mode.ORDERED,
                Duration.ofSeconds(10),100,1000,List.of(
                    new TemporalAdmission.Stage("failure",Map.of("event.kind","event","event.outcome","failure")),
                    new TemporalAdmission.Stage("success",Map.of("event.kind","event","event.outcome",outcome))));
    }
    private static PairedTemporalReplay.Case item(String id,int start,PairedTemporalReplay.Label label){
        return new PairedTemporalReplay.Case(id.repeat(64),SCOPE,t(start),t(start+10),t(start+10),label,
                label==PairedTemporalReplay.Label.MALICIOUS,"f".repeat(64));
    }
    private static final class TestContext implements NativeTemporalRuntime.Context {
        String actor="author";boolean denyDrain;
        public String principal(){return actor;}
        public void requireWorker(){if(Thread.currentThread().getName().contains("transport_worker"))throw new SecurityException("wrong worker");}
        public void requireRegistryWrite(TemporalPromotion.Rule rule){if(!RULE.equals(rule)||!actor.equals("author"))throw new SecurityException();}
        public void requirePromotion(TemporalPromotion.Rule rule,TemporalPromotion.Action action){
            if(!RULE.equals(rule)||!Set.of("reviewer","operator").contains(actor))throw new SecurityException();
        }
        public void requireWindow(WindowService.Request request,WindowService.Permission permission){
            if(!SCOPE.equals(request.scope())||permission==WindowService.Permission.DRAIN&&(denyDrain||!actor.equals("operator"))
                    ||permission!=WindowService.Permission.DRAIN&&!actor.equals("worker"))throw new SecurityException();
        }
        public void requireJob(TemporalJobRunner.Job job){if(!SCOPE.equals(job.scope())||!actor.equals("worker"))throw new SecurityException();}
        public void requireReplay(TemporalAdmission.Definition champion,TemporalAdmission.Definition challenger,PairedTemporalReplay.Case item){
            if(!actor.equals("reviewer")||!SCOPE.equals(item.scope())||!champion.tenant().equals(RULE.tenant())||!challenger.tenant().equals(RULE.tenant()))throw new SecurityException();
        }
    }

    public void testNativeTemporalReleaseFlow() throws Exception {
        // Refuse any externally managed test cluster before writes.
        internalCluster();
        for(String name:CONTRACTS)create("wade-v1-"+name,mapping(name));
        create(SOURCE,Map.of("dynamic","strict","properties",Map.of(
            "@timestamp",Map.of("type","date_nanos"),
            "agent",Map.of("properties",Map.of("id",keyword())),
            "event",Map.of("properties",Map.of("ingested",Map.of("type","date_nanos"),"kind",keyword(),"outcome",keyword())))));
        ensureGreen();
        for(int start:List.of(0,20,40,60,80)){
            event("failure-"+start,start+1,"failure");event("success-"+start,start+2,"success");
            if(start==20||start==60||start==80)event("other-"+start,start+3,"other");
        }
        String uuid=uuid(SOURCE);TestContext ctx=new TestContext();
        Clock clock=Clock.fixed(t(100),ZoneOffset.UTC);
        TemporalAdmission.InventorySource inventory=request->new TemporalAdmission.Inventory(true,List.of(
                new TemporalAdmission.Partition(SOURCE,uuid,SCOPE,t(-10),request.end())));
        OpenSearchTemporalReader.IdentityFence fence=(partition,from,to)->{
            if(!SOURCE.equals(partition.index())||!uuid.equals(uuid(SOURCE))||!SCOPE.equals(partition.scope()))throw new SecurityException();
        };
        IndexReplayEvidence.Authority evidence=(rule,kind,operation,attestation,now,report,cases)->{
            if(!RULE.equals(rule)||!Set.of("reviewer","operator").contains(ctx.actor)
                    ||!attestation.equals((kind==IndexReplayEvidence.Kind.REPLAY?"a":"b").repeat(64)))throw new SecurityException();
        };
        var runtime=new NativeTemporalRuntime(client(),ctx,RULE,SCOPE,inventory,fence,evidence,Duration.ofMinutes(5),clock,
                new NativeTemporalRuntime.Settings(true,true,30,1,1));
        var a=definition("1","success");var b=definition("2","other");
        assertTrue(runtime.provision(a));assertTrue(runtime.register(b));ctx.actor="reviewer";
        String replay=runtime.captureEvidence(IndexReplayEvidence.Kind.REPLAY,"a".repeat(64),a.policy().version(),b.policy().version(),
                List.of(item("1",0,PairedTemporalReplay.Label.BENIGN),item("2",20,PairedTemporalReplay.Label.MALICIOUS)),1,1);
        String shadow=runtime.captureEvidence(IndexReplayEvidence.Kind.SHADOW,"b".repeat(64),a.policy().version(),b.policy().version(),
                List.of(item("3",40,PairedTemporalReplay.Label.BENIGN),item("4",60,PairedTemporalReplay.Label.MALICIOUS)),1,1);
        assertTrue(runtime.approve(0,replay,shadow,Duration.ofMinutes(1)));ctx.actor="operator";
        assertTrue(runtime.activate(1));ctx.actor="worker";
        var job=new TemporalJobRunner.Job(SCOPE,b.policy(),Duration.ofSeconds(10),Duration.ZERO,Duration.ZERO,t(80));
        assertTrue(runtime.provisionJob(job));
        assertEquals(TemporalJobRunner.Result.ADVANCED,runtime.tick(job,Duration.ofSeconds(60),false));
        var backend=new OpenSearchWindowBackend(client(),30,ctx::requireWorker);
        var jobs=new IndexTemporalJobs(backend,SCOPE,false);
        assertEquals(t(90),jobs.load(job).checkpoint());
        var request=new WindowService.Request(SCOPE,b.policy(),t(80),t(90),t(100));
        var accepted=new IndexWindowStore(backend,SCOPE,false).load(request.windowKey());
        assertNotNull(accepted);assertNull(accepted.pending());
        assertEquals(FindingReconciliation.Status.ACTIVE,accepted.state().status());
        assertEquals(1L,client().prepareSearch(IndexWindowStore.PUBLICATIONS).setSize(0).setTrackTotalHits(true).get().getHits().getTotalHits().value());
        ctx.actor="operator";assertTrue(runtime.deactivate(2));
        assertEquals(WindowService.Status.NO_CHANGE,runtime.drain(request));ctx.denyDrain=true;
        expectThrows(SecurityException.class,()->runtime.drain(request));
        ctx.actor="worker";expectThrows(SecurityException.class,()->runtime.tick(job,Duration.ofSeconds(60),false));
    }
}
