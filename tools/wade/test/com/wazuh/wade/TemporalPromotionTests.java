// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;
import java.time.*;
import java.util.*;
import static com.wazuh.wade.TemporalPromotion.*;
import static com.wazuh.wade.PairedTemporalReplay.*;
public final class TemporalPromotionTests {
    private static final Instant T=Instant.parse("2026-11-26T00:00:00Z");private static final Rule R=new Rule("t","r");private static final String RR="e".repeat(64),SR="f".repeat(64);
    private static int checks;
    private static TemporalAdmission.Definition def(String v,String outcome){return new TemporalAdmission.Definition("t","r",v,CrossWindowCorrelation.Mode.ORDERED,Duration.ofSeconds(10),100,1000,List.of(new TemporalAdmission.Stage("a",Map.of("event.kind","event","event.outcome","failure")),new TemporalAdmission.Stage("b",Map.of("event.kind","event","event.outcome",outcome))));}
    private static final TemporalAdmission.Definition A=def("1","success"),B=def("2","other");
    private static final String AD=A.policy().version(),BD=B.policy().version();
    private static void check(boolean ok,String m){if(!ok)throw new AssertionError(m);checks++;}
    private static void reject(Runnable r){try{r.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|IllegalStateException|SecurityException e){checks++;}}
    private static Report report(Outcome result){return new Report(AD,BD,1,1,List.of(new RowResult("a".repeat(64),Label.BENIGN,false,Outcome.MATCH,Outcome.NO_MATCH,"b".repeat(64)),new RowResult("c".repeat(64),Label.MALICIOUS,true,Outcome.MATCH,result,"d".repeat(64))),RR);}
    private static final class Fixture {
        State state=State.baseline(R,AD);boolean denied,revoked,conflict;Report report=report(Outcome.MATCH);Instant now=T;
        final States store=new States(){public State load(Rule r){return state;}public boolean compareAndSet(Rule r,State a,State b){if(conflict||!a.equals(state))return false;state=b;return true;}};
        final Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){if(!z.equals(ZoneOffset.UTC))throw new IllegalArgumentException();return this;}public Instant instant(){return now;}};
        TemporalPromotion service(boolean enabled,int min){return new TemporalPromotion(R,store,(r,d)->d.equals(AD)?new Revision(A,"author"):d.equals(BD)?new Revision(B,"author"):null,(actor,r,a)->{if(denied)throw new SecurityException();},new Evidence(){public Report verifiedReport(Rule r,String replay,String shadow){return report;}public void requireCurrent(Rule r,Approval p,Instant n){if(revoked)throw new SecurityException();}},clock,enabled,min,min);}
        WindowService.Request request(TemporalAdmission.Definition d){return new WindowService.Request(new WindowService.Scope("t","cluster","AGENT","001"),d.policy(),T,T.plusSeconds(10),T.plusSeconds(10));}
    }
    public static void main(String[] args){
        var f=new Fixture();var s=f.service(true,1);reject(()->s.resolve(f.request(A)));reject(()->s.approve("author",0,RR,SR,Duration.ofMinutes(1)));reject(()->s.approve("reviewer",-1,RR,SR,Duration.ofMinutes(1)));
        f.report=report(Outcome.UNKNOWN);reject(()->s.approve("reviewer",0,RR,SR,Duration.ofMinutes(1)));f.report=report(Outcome.MATCH);
        reject(()->f.service(true,2).approve("reviewer",0,RR,SR,Duration.ofMinutes(1)));
        f.denied=true;reject(()->s.approve("reviewer",0,RR,SR,Duration.ofMinutes(1)));f.denied=false;
        f.conflict=true;check(!s.approve("reviewer",0,RR,SR,Duration.ofMinutes(1))&&f.state.pending()==null,"CAS conflict");f.conflict=false;
        check(s.approve("reviewer",0,RR,SR,Duration.ofMinutes(1))&&!f.state.active(),"independent approval not activation");reject(()->s.resolve(f.request(B)));
        reject(()->f.service(false,1).activate("reviewer",1));reject(()->s.activate("author",1));reject(()->s.activate("reviewer",0));
        f.revoked=true;reject(()->s.activate("reviewer",1));f.revoked=false;
        f.now=T.plusSeconds(61);reject(()->s.activate("reviewer",1));check(s.withdraw("reviewer",1)&&f.state.pending()==null,"withdraw expired approval");
        check(s.approve("reviewer",2,RR,SR,Duration.ofMinutes(1)),"new valid approval");check(s.activate("operator",3)&&f.state.active()&&f.state.champion().equals(BD),"explicit active pointer");
        check(s.resolve(f.request(B)).equals(B),"only active policy resolved");reject(()->f.service(false,1).resolve(f.request(B)));reject(()->s.resolve(f.request(A)));reject(()->s.approve("reviewer",4,RR,SR,Duration.ofMinutes(1)));
        System.out.println("WADE promotion checks passed: "+checks);
    }
}
