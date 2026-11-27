// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.*;
import java.util.*;

/** Bounded scheduling plan; caller supplies durable checkpoint and authoritative clock. */
public final class WindowPlan {
    private WindowPlan() {}
    public record Interval(Instant start,Instant end) {
        public Interval { Objects.requireNonNull(start); Objects.requireNonNull(end); if(!start.isBefore(end)) throw new IllegalArgumentException("invalid interval"); }
    }
    public record Plan(List<Interval> forward,List<Interval> reconsider,boolean backlog) {
        public Plan { forward=List.copyOf(forward); reconsider=List.copyOf(reconsider); }
    }
    public static Plan plan(Instant checkpoint,Instant now,Duration cadence,Duration grace,Duration lateHorizon,int forwardLimit,int lateLimit) {
        Objects.requireNonNull(checkpoint); Objects.requireNonNull(now); Objects.requireNonNull(cadence); Objects.requireNonNull(grace); Objects.requireNonNull(lateHorizon);
        if(checkpoint.isAfter(now) || cadence.compareTo(Duration.ofSeconds(1))<0 || cadence.compareTo(Duration.ofDays(1))>0 || grace.isNegative() || grace.compareTo(Duration.ofDays(1))>0
            || lateHorizon.isNegative() || lateHorizon.compareTo(Duration.ofDays(31))>0 || forwardLimit<1 || forwardLimit>1000 || lateLimit<0 || lateLimit>1000) throw new IllegalArgumentException("invalid schedule");
        Instant eligible=now.minus(grace), cursor=checkpoint;
        List<Interval> forward=new ArrayList<>(), late=new ArrayList<>();
        while(forward.size()<forwardLimit && !cursor.plus(cadence).isAfter(eligible)) { Instant end=cursor.plus(cadence); forward.add(new Interval(cursor,end)); cursor=end; }
        Instant floor=now.minus(lateHorizon), end=checkpoint;
        // Most recent completed windows first; no overlap with forward work. No implied persistence.
        while(late.size()<lateLimit && !end.isAfter(eligible) && !end.minus(cadence).isBefore(floor)) { Instant start=end.minus(cadence); late.add(new Interval(start,end)); end=start; }
        return new Plan(forward,late,!cursor.plus(cadence).isAfter(eligible));
    }
}
