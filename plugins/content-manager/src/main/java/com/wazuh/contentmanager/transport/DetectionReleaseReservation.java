/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Fixed index CAS; never grants elevated access to native content mutations. */
final class DetectionReleaseReservation {
    private final Client client;
    private final ThreadPool pool;
    DetectionReleaseReservation(Client client,ThreadPool pool){this.client=client;this.pool=pool;}
    record Reserved(Map<String,Object> source,long seqNo,long primaryTerm){}
    static String principal(ThreadPool pool){
        if(pool==null)throw denied();
        String info=pool.getThreadContext().getTransient("_opendistro_security_user_info");
        if(info==null||info.isBlank())throw denied();
        // Match the setup AuthenticatedUser parser, including escaped pipes.
        String[] parts=info.split("(?<!\\\\)\\|");
        if(parts.length==0)throw denied();
        try{return DetectionRelease.actor(parts[0].trim().replace("\\|","|"));}
        catch(IllegalArgumentException e){throw denied();}
    }
    void reserve(String plan,String deployer,List<String> rules,String previewHash,String configuredExpiry,ActionListener<Reserved> listener){
        if(!deployer.equals(principal(pool)))throw denied();
        DetectionRelease.hash(plan);
        var restored=ContextPreservingActionListener.wrapPreservingContext(listener,pool.getThreadContext());
        try(var ignored=pool.getThreadContext().stashContext()){
            client.get(new GetRequest(DetectionRelease.INDEX,plan),ActionListener.wrap(response->{
                if(!response.isExists()||!DetectionRelease.INDEX.equals(response.getIndex())||!plan.equals(response.getId()))throw denied();
                var row=response.getSourceAsMap();
                DetectionRelease.validate(row);
                if(!DetectionRelease.hash(previewHash).equals(DetectionRelease.evidence(row.get("evidence")).get("preview_sha256")))throw denied();
                var review=DetectionRelease.exact(row.get("review"),java.util.Set.of("actor","at","decision","reason","pack_sha256","deployer","expires"));
                if(!configuredExpiry.equals(review.get("expires"))||!PromotionPlanFingerprint.active(configuredExpiry,Instant.now()))throw denied();
                var reserved=DetectionRelease.reserve(row,plan,deployer,rules,Instant.now());
                var request=new IndexRequest(DetectionRelease.INDEX).id(plan).source(reserved,XContentType.JSON)
                        .setIfSeqNo(response.getSeqNo()).setIfPrimaryTerm(response.getPrimaryTerm());
                write(request,reserved,restored);
            },restored::onFailure));
        }
    }
    void report(Reserved reserved,int status,ActionListener<Reserved> listener){
        var row=DetectionRelease.report(reserved.source(),status,Instant.now());
        var request=new IndexRequest(DetectionRelease.INDEX).id((String)row.get("id")).source(row,XContentType.JSON)
                .setIfSeqNo(reserved.seqNo()).setIfPrimaryTerm(reserved.primaryTerm());
        var restored=ContextPreservingActionListener.wrapPreservingContext(listener,pool.getThreadContext());
        write(request,row,restored);
    }
    private void write(IndexRequest request,Map<String,Object> row,ActionListener<Reserved> listener){
        // Real-time GET plus sequence-number/primary-term CAS: no refresh dependency or retry.
        try(var ignored=pool.getThreadContext().stashContext()){
            client.index(request,ActionListener.wrap(response->{
                if(!DetectionRelease.INDEX.equals(response.getIndex())||!row.get("id").equals(response.getId()))throw denied();
                listener.onResponse(new Reserved(row,response.getSeqNo(),response.getPrimaryTerm()));
            },listener::onFailure));
        }
    }
    static OpenSearchStatusException denied(){
        return new OpenSearchStatusException("Approved detection release missing, expired, consumed or mismatched",RestStatus.FORBIDDEN);
    }
}
