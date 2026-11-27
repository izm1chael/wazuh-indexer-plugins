// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade.plugin;

import com.wazuh.wade.*;
import java.time.*;
import java.util.*;
import org.opensearch.transport.client.Client;

/** Explicit composition root for one tenant/rule/agent. Not registered by the inert plugin. */
public final class NativeTemporalRuntime {
    public record Settings(boolean writesEnabled,boolean activationEnabled,int timeoutSeconds,int minBenign,int minMalicious) {
        public Settings {if(activationEnabled&&!writesEnabled||timeoutSeconds<1||timeoutSeconds>30||minBenign<1||minMalicious<1)throw new IllegalArgumentException("invalid runtime settings");}
        public static Settings readOnly(){return new Settings(false,false,10,20,10);}
    }
    /** Trusted native adapter must implement real authenticated context and authorization. */
    public interface Context {
        String principal();
        void requireWorker();
        void requireRegistryWrite(TemporalPromotion.Rule rule);
        void requirePromotion(TemporalPromotion.Rule rule,TemporalPromotion.Action action);
        void requireWindow(WindowService.Request request,WindowService.Permission permission);
        void requireJob(TemporalJobRunner.Job job);
        void requireReplay(TemporalAdmission.Definition champion,TemporalAdmission.Definition challenger,PairedTemporalReplay.Case item);
    }
    private final Context context;
    private final TemporalPromotion.Rule rule;
    private final WindowService.Scope scope;
    private final IndexTemporalRegistry registry;
    private final TemporalPromotion promotion;
    private final IndexTemporalJobs jobs;
    private final TemporalJobRunner runner;
    private final PairedTemporalReplay replay;

    public NativeTemporalRuntime(Client scopedClient,Context context,TemporalPromotion.Rule rule,WindowService.Scope scope,
            TemporalAdmission.InventorySource inventory,OpenSearchTemporalReader.IdentityFence fence,
            TemporalPromotion.Evidence evidence,Clock clock,Settings settings) {
        this.context=Objects.requireNonNull(context);this.rule=Objects.requireNonNull(rule);this.scope=Objects.requireNonNull(scope);
        if(!rule.tenant().equals(scope.tenant())||!scope.kind().equals("AGENT"))throw new IllegalArgumentException("scope mismatch");
        var backend=new OpenSearchWindowBackend(scopedClient,settings.timeoutSeconds(),context::requireWorker);
        var reader=new OpenSearchTemporalReader(scopedClient,context::requireWorker,fence,settings.timeoutSeconds());
        registry=new IndexTemporalRegistry(backend,rule,settings.writesEnabled());
        promotion=new TemporalPromotion(rule,registry,registry,(actor,r,action)->{
            sameActor(actor);context.requirePromotion(r,action);
        },evidence,clock,settings.activationEnabled(),settings.minBenign(),settings.minMalicious());
        TemporalAdmission admission=new TemporalAdmission(promotion,inventory,reader);
        IndexWindowStore windows=new IndexWindowStore(backend,scope,settings.writesEnabled());
        jobs=new IndexTemporalJobs(backend,scope,settings.writesEnabled());
        WindowService service=new WindowService((actor,request,permission)->{
            sameActor(actor);requireScope(request.scope());context.requireWindow(request,permission);
        },admission,admission,windows,windows,clock);
        runner=new TemporalJobRunner((actor,job)->{
            sameActor(actor);requireScope(job.scope());context.requireJob(job);
        },jobs,service,windows,clock);
        replay=new PairedTemporalReplay((actor,a,b,item)->{
            sameActor(actor);requireScope(item.scope());context.requireReplay(a,b,item);
            if(!definition(a.policy().version()).equals(a)||!definition(b.policy().version()).equals(b))throw new SecurityException("unregistered revision");
        },inventory,reader,clock);
    }
    public boolean provision(TemporalAdmission.Definition baseline){
        context.requireRegistryWrite(rule);return registry.provision(new TemporalPromotion.Revision(baseline,principal()));
    }
    public boolean register(TemporalAdmission.Definition revision){
        context.requireRegistryWrite(rule);return registry.register(new TemporalPromotion.Revision(revision,principal()));
    }
    public PairedTemporalReplay.Report replay(String champion,String challenger,List<PairedTemporalReplay.Case> cases,int minBenign,int minMalicious){
        return replay.run(principal(),definition(champion),definition(challenger),cases,minBenign,minMalicious);
    }
    public boolean approve(long expected,String replayReceipt,String shadowReceipt,Duration ttl){return promotion.approve(principal(),expected,replayReceipt,shadowReceipt,ttl);}
    public boolean activate(long expected){return promotion.activate(principal(),expected);}
    public boolean withdraw(long expected){return promotion.withdraw(principal(),expected);}
    public boolean provisionJob(TemporalJobRunner.Job job){
        requireScope(job.scope());context.requireJob(job);
        var active=registry.load(rule);
        if(active==null||!active.active()||!active.champion().equals(job.policy().version())||!definition(active.champion()).policy().equals(job.policy()))throw new SecurityException("inactive job policy");
        return jobs.provision(job);
    }
    public TemporalJobRunner.Result tick(TemporalJobRunner.Job job,Duration ttl,boolean late){
        requireScope(job.scope());return runner.tick(principal(),job,ttl,late);
    }
    private TemporalAdmission.Definition definition(String digest){
        var revision=registry.resolve(rule,digest);if(revision==null)throw new IllegalArgumentException("unknown revision");return revision.definition();
    }
    private void requireScope(WindowService.Scope candidate){if(!scope.equals(candidate))throw new SecurityException("foreign runtime scope");}
    private String principal(){context.requireWorker();String actor=context.principal();if(actor==null||actor.isBlank())throw new SecurityException("missing principal");return actor;}
    private void sameActor(String actor){if(!principal().equals(actor))throw new SecurityException("actor mismatch");}
}
