// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Instant;
import java.util.List;

public final class GovernanceTests {
    private static int checks;
    private static void check(boolean ok,String why) { if(!ok) throw new AssertionError(why); checks++; }
    private static void reject(Runnable r) {
        try { r.run(); throw new AssertionError("expected rejection"); }
        catch(IllegalArgumentException|IllegalStateException expected) { checks++; }
    }
    public static void main(String[] args) {
        Instant t=Instant.parse("2026-11-26T00:00:00Z");
        var k=new EntityResolver.Key("t",EntityResolver.Type.HOST,"directory","host",EntityResolver.Kind.VERIFIED_ALIAS);
        var old=new EntityResolver.Binding(k,"id-old",t.minusSeconds(60),t,t.minusSeconds(60),"p1");
        var next=new EntityResolver.Binding(k,"id-new",t,null,t,"p2");
        var future=new EntityResolver.Binding(k,"future",t,null,t.plusSeconds(1),"p3");
        check(EntityResolver.resolve(k,t,t,List.of(old,next,future)).canonicalId().equals("id-new"),"reuse and as-of");
        check(EntityResolver.resolve(k,t.minusSeconds(1),t,List.of(old,next)).canonicalId().equals("id-old"),"historical binding");
        check(EntityResolver.resolve(k,t,t,List.of(old,future)).status()==EntityResolver.Status.UNKNOWN,"future context not visible");
        check(EntityResolver.resolve(k,t,t.plusSeconds(2),List.of(next,future)).status()==EntityResolver.Status.AMBIGUOUS,"ambiguous no merge");
        check(EntityResolver.resolve(k,t,t,List.of(next,next)).provenance().size()==1,"duplicate provenance");
        var ip=new EntityResolver.Key("t",EntityResolver.Type.HOST,"network","192.0.2.1",EntityResolver.Kind.IP_ADDRESS);
        check(EntityResolver.resolve(ip,t,t,List.of(new EntityResolver.Binding(ip,"id",t,null,t,"p"))).status()==EntityResolver.Status.UNKNOWN,"IP only");
        var foreign=new EntityResolver.Key("other",EntityResolver.Type.HOST,"directory","host",EntityResolver.Kind.VERIFIED_ALIAS);
        check(EntityResolver.resolve(k,t,t,List.of(next,new EntityResolver.Binding(foreign,"id",t,null,t,"p"))).status()==EntityResolver.Status.UNKNOWN,"foreign scope");
        String digest="a".repeat(64);
        var draft=new RuleLifecycle.Revision("t","r","1",digest,"author",RuleLifecycle.Stage.DRAFT,0);
        var pass=new RuleLifecycle.Evidence(digest,"receipt",true);
        var wrong=new RuleLifecycle.Evidence("b".repeat(64),"receipt",true);
        var fail=new RuleLifecycle.Evidence(digest,"receipt",false);
        reject(()->RuleLifecycle.transition(draft,0,RuleLifecycle.Action.ACTIVATE,"reviewer",true,pass,true));
        reject(()->RuleLifecycle.transition(draft,0,RuleLifecycle.Action.VALIDATE,"author",false,pass,false));
        reject(()->RuleLifecycle.transition(draft,0,RuleLifecycle.Action.VALIDATE,"author",true,wrong,false));
        reject(()->RuleLifecycle.transition(draft,0,RuleLifecycle.Action.VALIDATE,"author",true,fail,false));
        var validated=RuleLifecycle.transition(draft,0,RuleLifecycle.Action.VALIDATE,"author",true,pass,false);
        reject(()->RuleLifecycle.transition(validated,0,RuleLifecycle.Action.START_SHADOW,"author",true,pass,false));
        var shadow=RuleLifecycle.transition(validated,1,RuleLifecycle.Action.START_SHADOW,"author",true,pass,false);
        reject(()->RuleLifecycle.transition(shadow,2,RuleLifecycle.Action.APPROVE,"author",true,pass,false));
        var approved=RuleLifecycle.transition(shadow,2,RuleLifecycle.Action.APPROVE,"reviewer",true,pass,false);
        reject(()->RuleLifecycle.transition(approved,3,RuleLifecycle.Action.ACTIVATE,"reviewer",true,pass,false));
        var active=RuleLifecycle.transition(approved,3,RuleLifecycle.Action.ACTIVATE,"reviewer",true,pass,true);
        check(active.stage()==RuleLifecycle.Stage.ACTIVE && active.sequence()==4,"controlled activation");
        check(RuleLifecycle.transition(active,4,RuleLifecycle.Action.RETIRE,"reviewer",true,pass,false).stage()==RuleLifecycle.Stage.RETIRED,"retire");
        System.out.println("WADE governance checks passed: "+checks);
    }
}
