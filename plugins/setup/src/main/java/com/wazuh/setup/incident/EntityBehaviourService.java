/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.setup.incident;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/** Two bounded original-caller searches. No persisted baseline, privileged source read or mutation. */
public final class EntityBehaviourService {
    private final ThreadPool pool;
    private final IncidentHuntService hunt;
    private final Clock clock;
    private final Semaphore permits=new Semaphore(1);
    public EntityBehaviourService(ThreadPool pool,IncidentHuntService hunt,Clock clock) {
        this.pool=pool;this.hunt=hunt;this.clock=clock;
    }
    public void assess(IncidentHuntService.Input input,String actor,ActionListener<Map<String,Object>> listener) {
        if(!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) throw new OpenSearchStatusException("Caller required",RestStatus.FORBIDDEN);
        EntityBehaviourModel.window(input.field(),input.values(),input.from(),input.until(),clock.instant());
        var baseline=new IncidentHuntService.Input(input.field(),input.values(),input.from().minusSeconds(EntityBehaviourModel.DAYS*EntityBehaviourModel.DAY),input.from());
        if(!permits.tryAcquire()) throw new OpenSearchStatusException("Behaviour assessment busy",RestStatus.TOO_MANY_REQUESTS);
        var released=new AtomicBoolean();
        ActionListener<Map<String,Object>> done=ActionListener.wrap(value->{
            if(released.compareAndSet(false,true)){permits.release();listener.onResponse(value);}
        },error->{if(released.compareAndSet(false,true)){permits.release();listener.onFailure(error);}});
        try {
            var caller=pool.getThreadContext().newRestorableContext(false);
            hunt.hunt(baseline,ActionListener.wrap(history->{
                try(ThreadContext.StoredContext ignored=caller.get()){
                    if(!actor.equals(IncidentPrincipal.require(pool.getThreadContext()))) throw new OpenSearchStatusException("Caller context lost",RestStatus.FORBIDDEN);
                    hunt.hunt(input,ActionListener.wrap(current->{
                        var rows=EntityBehaviourModel.evaluate(input.field(),input.values(),input.from(),input.until(),history,current);
                        done.onResponse(Map.of("scope","caller_visible_finding_volume","model","daily_volume_v1",
                                "baseline",history,"current",current,"assessments",rows));
                    },done::onFailure));
                }
            },done::onFailure));
        }catch(Exception e){done.onFailure(e);}
    }
}
