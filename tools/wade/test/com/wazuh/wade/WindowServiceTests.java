// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;

public final class WindowServiceTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("tenant","directory","HOST","h1");
    private static final CrossWindowCorrelation.Policy P=new CrossWindowCorrelation.Policy("immutable-rule-v1",List.of("a","b"),CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000);
    private static int checks;
    private static Instant t(int s){return T.plusSeconds(s);}
    private static Request r(int cutoff){return new Request(S,P,T,t(10),t(cutoff));}
    private static CrossWindowCorrelation.Event e(String id,int time,int available,String stage){return new CrossWindowCorrelation.Event(S.canonical(),id,t(time),t(available),Set.of(stage));}
    private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
    private static void reject(Runnable task){try{task.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|IllegalStateException|SecurityException expected){checks++;}}
    private static final class Memory implements Store {
        final Map<String,Envelope> rows=new HashMap<>(); boolean conflict;
        public Envelope load(String id){return rows.get(id);}
        public boolean compareAndSet(String id,Envelope old,Envelope next){if(conflict){conflict=false;return false;}if(!rows.getOrDefault(id,Envelope.initial(id)).equals(old))return false;rows.put(id,next);return true;}
    }
    private static final class Fixture {
        final Memory memory=new Memory(); final Map<String,Pending> delivered=new HashMap<>();
        final List<CrossWindowCorrelation.Event> events=new ArrayList<>();
        boolean complete=true, approved=true, allow=true, publish=true, failDelivery, wrongSnapshot; int reads;
        final WindowService service=new WindowService((actor,request,permission)->{if(!allow||!actor.equals("analyst")||!request.scope().equals(S)||permission==Permission.PUBLISH&&!publish)throw new SecurityException("denied");},
            request->{if(!approved||!request.policy().equals(P))throw new SecurityException("unapproved");},
            request->{reads++;return new Snapshot(wrongSnapshot?r(25):request,request.lookback(),request.end(),complete,events);},memory,
            (request,pending)->{var old=delivered.putIfAbsent(pending.publication().id(),pending);if(old!=null&&!old.equals(pending))throw new IllegalStateException("sink conflict");if(failDelivery)throw new IllegalStateException("simulated acknowledgement loss");},Clock.fixed(t(30),ZoneOffset.UTC));
        Status run(int cutoff){return service.execute("analyst",r(cutoff));}
        Envelope state(){return memory.load(r(10).windowKey());}
    }
    public static void main(String[] args){
        var f=new Fixture(); f.events.add(e("a",-1,0,"a")); f.events.add(e("b",1,11,"b"));
        check(f.run(10)==Status.NO_CHANGE && f.state().state().status()==FindingReconciliation.Status.NEVER_MATCHED,"initial causal negative");
        check(f.run(11)==Status.STAGED && f.state().pending().sources().equals(List.of("a","b")),"actual late cross-window stage");
        int reads=f.reads; f.failDelivery=true; reject(()->f.run(12));
        check(f.state().pending()!=null && f.delivered.size()==1 && f.reads==reads,"pending recovery without read");
        f.failDelivery=false; f.memory.conflict=true;
        check(f.run(12)==Status.CONFLICT && f.state().pending()!=null,"CAS acknowledgement lost");
        check(f.run(12)==Status.RECOVERED && f.state().pending()==null && f.delivered.size()==1,"idempotent immutable recovery");
        check(f.run(12)==Status.NO_CHANGE && f.state().pending()==null,"unchanged evidence no publication");
        f.complete=false; long token=f.state().token(); check(f.run(13)==Status.WITHHELD && f.state().token()==token,"incomplete cannot retract");
        f.complete=true; f.events.remove(1); check(f.run(14)==Status.STAGED && f.state().pending().publication().action()==FindingReconciliation.Action.RETRACT,"complete correction stages retraction");
        check(f.run(14)==Status.RECOVERED && f.delivered.size()==2,"retraction delivery");
        f.events.add(e("b",1,11,"b")); check(f.run(15)==Status.STAGED && f.state().pending().publication().action()==FindingReconciliation.Action.RESTORE,"restore same finding");
        f.publish=false; reject(()->f.run(16)); check(f.state().pending()!=null,"unauthorized recovery cannot acknowledge");
        f.publish=true; check(f.run(16)==Status.RECOVERED,"authorized recovery");
        f.approved=false; reads=f.reads; reject(()->f.run(17)); check(f.reads==reads,"approval before source read");
        f.approved=true; f.allow=false; reject(()->f.run(17)); check(f.reads==reads,"authority before source read");
        f.allow=true; reject(()->f.run(31));
        f.wrongSnapshot=true; reject(()->f.run(17)); f.wrongSnapshot=false;
        f.memory.conflict=true; token=f.state().token(); check(f.run(17)==Status.CONFLICT && f.state().token()==token,"state CAS conflict");
        reject(()->f.service.execute("other",r(18)));
        check(!S.canonical().equals(new Scope("other","directory","HOST","h1").canonical()),"tenant identity isolation");
        check(r(10).windowKey().equals(r(20).windowKey()),"stable reevaluation key");
        var plan=WindowPlan.plan(t(20),t(55),Duration.ofSeconds(10),Duration.ofSeconds(5),Duration.ofSeconds(50),2,2);
        check(plan.forward().equals(List.of(new WindowPlan.Interval(t(20),t(30)),new WindowPlan.Interval(t(30),t(40))))&&plan.backlog(),"bounded forward backlog");
        check(plan.reconsider().equals(List.of(new WindowPlan.Interval(t(10),t(20)))),"bounded late horizon");
        var grace=WindowPlan.plan(t(20),t(29),Duration.ofSeconds(10),Duration.ZERO,Duration.ZERO,1,0);
        check(grace.forward().isEmpty()&&!grace.backlog(),"incomplete next window");
        reject(()->WindowPlan.plan(t(20),t(19),Duration.ofSeconds(10),Duration.ZERO,Duration.ZERO,1,0));
        System.out.println("WADE window service checks passed: "+checks);
    }
}
