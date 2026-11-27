// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade.plugin;

import java.util.Map;
import java.util.Objects;

import com.wazuh.wade.IndexWindowStore;
import com.wazuh.wade.IndexTemporalJobs;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.transport.client.Client;

/**
 * Opt-in native client candidate for the window document protocol.
 * Not registered by WadePlugin. Calls block and must run on a dedicated bounded worker,
 * never a REST or transport thread. The caller supplies an authenticated scoped client.
 */
public final class OpenSearchWindowBackend implements IndexWindowStore.Backend {
    private final Client client;
    private final TimeValue timeout;
    private final Runnable requireWorkerContext;

    public OpenSearchWindowBackend(Client client, int timeoutSeconds, Runnable requireWorkerContext) {
        this.client = Objects.requireNonNull(client);
        this.requireWorkerContext = Objects.requireNonNull(requireWorkerContext);
        if (timeoutSeconds < 1 || timeoutSeconds > 30) {
            throw new IllegalArgumentException("invalid timeout");
        }
        this.timeout = TimeValue.timeValueSeconds(timeoutSeconds);
    }

    @Override
    public IndexWindowStore.Document get(String index, String id) {
        requireAllowed(index, id);
        requireWorkerContext.run();
        GetResponse response = client.get(new GetRequest(index, id).realtime(true)).actionGet(timeout);
        verifyIdentity(index, id, response.getIndex(), response.getId());
        if (!response.isExists()) {
            return null;
        }
        return new IndexWindowStore.Document(
                id, response.getSeqNo(), response.getPrimaryTerm(), response.getSourceAsMap());
    }

    @Override
    public boolean create(String index, String id, Map<String, Object> body) {
        requireAllowed(index, id);
        requireWorkerContext.run();
        return write(request(index, id, body).create(true), index, id, DocWriteResponse.Result.CREATED);
    }

    @Override
    public boolean replace(
            String index, String id, long sequence, long primaryTerm, Map<String, Object> body) {
        requireAllowed(index, id);
        if ((!IndexWindowStore.STATE.equals(index) && !IndexTemporalJobs.INDEX.equals(index)) || sequence < 0 || primaryTerm < 1) {
            throw new IllegalArgumentException("invalid conditional state write");
        }
        requireWorkerContext.run();
        return write(
                request(index, id, body).setIfSeqNo(sequence).setIfPrimaryTerm(primaryTerm),
                index, id, DocWriteResponse.Result.UPDATED);
    }

    private IndexRequest request(String index, String id, Map<String, Object> body) {
        // Exact concrete, pre-provisioned indices only. Role must forbid index creation and aliases.
        return new IndexRequest(index)
                .id(id)
                .source(Objects.requireNonNull(body), XContentType.JSON)
                .timeout(timeout)
                .waitForActiveShards(ActiveShardCount.ALL)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
    }

    private boolean write(
            IndexRequest request, String index, String id, DocWriteResponse.Result expected) {
        final IndexResponse response;
        try {
            response = client.index(request).actionGet(timeout);
        } catch (RuntimeException failure) {
            if (ExceptionsHelper.unwrapCause(failure) instanceof VersionConflictEngineException) {
                return false;
            }
            // Timeout, security and transport failures may be ambiguous; never treat them as a conflict.
            throw failure;
        }
        verifyIdentity(index, id, response.getIndex(), response.getId());
        var shards = response.getShardInfo();
        if (response.getResult() != expected || shards.getFailed() != 0
                || shards.getSuccessful() != shards.getTotal()) {
            throw new IllegalStateException("unqualified Indexer acknowledgement");
        }
        return true;
    }

    private static void requireAllowed(String index, String id) {
        if ((!IndexWindowStore.STATE.equals(index) && !IndexWindowStore.PUBLICATIONS.equals(index) && !IndexTemporalJobs.INDEX.equals(index))
                || id == null || !id.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("unsupported index or document identity");
        }
    }

    private static void verifyIdentity(String index, String id, String actualIndex, String actualId) {
        if (!index.equals(actualIndex) || !id.equals(actualId)) {
            throw new IllegalStateException("unexpected Indexer document identity");
        }
    }
}
