// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.WindowService.*;
import static com.wazuh.wade.TemporalJobRunner.*;
public final class TemporalJobRunnerTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");
    private static final Scope S=new Scope("t","cluster","AGENT","001");
    private static final CrossWindowCorrelation.Policy P=new CrossWindowCorrelation.Policy("r1",List.of("a","b"),CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000);
    private static final Job J=new Job(S,P,Duration.ofSeconds(10),Duration.ofSeconds(2),Duration.ofSeconds(60),T);
    private static final Duration TTL=Duration.ofSeconds(5);
    private static int checks;
    private static Instant t(int n){return T.plusSeconds(n);}
    private static void check(boolean ok,String m){if(!ok)throw new AssertionError(m);checks++;}
    private static final class MutableClock extends Clock {
        Instant now=t(12); public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){if(!zone.equals(ZoneOffset.UTC))throw new IllegalArgumentException();return this;}public Instant instant(){return now;}
    }
    private static final class Fixture {
        final MutableClock clock=new MutableClock(); Cursor cursor=Cursor.initial(J);boolean complete=true,fail,deny,conflict,expire;int reads;
        final Map<String,Envelope> rows=new HashMap<>();final Map<String,Pending> delivered=new HashMap<>();
        final Store store=new Store(){public Envelope load(String k){return rows.get(k);}public boolean compareAndSet(String k,Envelope a,Envelope b){if(!rows.getOrDefault(k,Envelope.initial(k)).equals(a))return false;rows.put(k,b);return true;}};
        final WindowService service=new WindowService((a,r,p)->{},r->{},r->{reads++;if(expire)clock.now=clock.now.plus(TTL);var events=new ArrayList<CrossWindowCorrelation.Event>();if(!t(1).isBefore(r.lookback())&&t(2).isBefore(r.end())){events.add(new CrossWindowCorrelation.Event(S.canonical(),"a",t(1),t(1),Set.of("a")));events.add(new CrossWindowCorrelation.Event(S.canonical(),"b",t(2),t(2),Set.of("b")));}return new Snapshot(r,r.lookback(),r.end(),complete,events);},store,(r,p)->{delivered.putIfAbsent(p.publication().id(),p);if(fail)throw new IllegalStateException("lost ack");},clock);
        final TemporalJobRunner runner=new TemporalJobRunner((a,j)->{if(deny)throw new SecurityException();},new Cursors(){public Cursor load(Job j){return cursor;}public boolean compareAndSet(Job j,Cursor a,Cursor b){if(conflict){conflict=false;return false;}if(!cursor.equals(a))return false;cursor=b;return true;}},service,store,clock);
        TemporalJobRunner.Result run(boolean late){return runner.tick("worker",J,TTL,late);}
    }
    public static void main(String[] args){
        var f=new Fixture();f.clock.now=t(11);check(f.run(false)==TemporalJobRunner.Result.NOT_READY&&f.reads==0,"grace");f.clock.now=t(12);f.complete=false;
        check(f.run(false)==TemporalJobRunner.Result.WITHHELD&&f.cursor.checkpoint().equals(T)&&f.cursor.owner()==null,"unknown no advance");f.complete=true;f.fail=true;
        try{f.run(false);throw new AssertionError("expected failure");}catch(IllegalStateException e){checks++;}
        check(f.cursor.checkpoint().equals(T)&&f.delivered.size()==1&&f.cursor.owner()!=null,"ambiguous delivery preserves cursor");check(f.run(false)==TemporalJobRunner.Result.BUSY,"active lease");
        f.fail=false;f.clock.now=t(18);check(f.run(false)==TemporalJobRunner.Result.ADVANCED&&f.cursor.checkpoint().equals(t(10))&&f.delivered.size()==1,"takeover recovers then evaluates new cutoff");
        f.clock.now=t(22);check(f.run(false)==TemporalJobRunner.Result.ADVANCED&&f.cursor.checkpoint().equals(t(20)),"next contiguous window");
        f.clock.now=t(23);check(f.run(true)==TemporalJobRunner.Result.RECONSIDERED&&f.cursor.lateEnd().equals(t(10))&&f.cursor.checkpoint().equals(t(20)),"late sweep no forward move");
        f.clock.now=t(24);check(f.run(true)==TemporalJobRunner.Result.RECONSIDERED&&f.cursor.lateEnd().equals(T),"late cursor progresses");
        f.clock.now=t(25);check(f.run(true)==TemporalJobRunner.Result.RECONSIDERED&&f.cursor.lateEnd().equals(t(10)),"late sweep wraps at origin");
        f.conflict=true;f.clock.now=t(32);check(f.run(false)==TemporalJobRunner.Result.CONFLICT&&f.cursor.checkpoint().equals(t(20)),"CAS conflict no advance");
        f.deny=true;int reads=f.reads;try{f.run(false);throw new AssertionError("expected denial");}catch(SecurityException e){checks++;}check(f.reads==reads,"denial before read");
        f.deny=false;f.expire=true;check(f.run(false)==TemporalJobRunner.Result.CONFLICT&&f.cursor.checkpoint().equals(t(20)),"expired job cannot advance");
        check(!J.id().equals(new Job(S,P,Duration.ofSeconds(20),J.grace(),J.lateHorizon(),J.origin()).id()),"job policy identity");
        System.out.println("WADE job runner checks passed: "+checks);
    }
}
