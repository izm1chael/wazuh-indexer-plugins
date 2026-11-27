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
package com.wazuh.setup;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.cluster.LocalNodeClusterManagerListener;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import com.wazuh.setup.action.GetAiAssistantSettingsAction;
import com.wazuh.setup.action.IncidentReadAction;
import com.wazuh.setup.action.IncidentResponseReadAction;
import com.wazuh.setup.rest.RestIncidentResponseReadAction;
import com.wazuh.setup.transport.TransportIncidentResponseReadAction;
import com.wazuh.setup.action.IncidentMetricsAction;
import com.wazuh.setup.incident.IncidentMetricsService;
import com.wazuh.setup.rest.RestIncidentMetricsAction;
import com.wazuh.setup.transport.TransportIncidentMetricsAction;
import com.wazuh.setup.action.IncidentCorrelationAction;
import com.wazuh.setup.action.IncidentHuntAction;
import com.wazuh.setup.action.IncidentEntityInvestigationAction;
import com.wazuh.setup.action.EntityBehaviourAction;
import com.wazuh.setup.action.RuleBehaviourAction;
import com.wazuh.setup.action.EventBehaviourAction;
import com.wazuh.setup.incident.EventBehaviourService;
import com.wazuh.setup.rest.RestEventBehaviourAction;
import com.wazuh.setup.transport.TransportEventBehaviourAction;
import com.wazuh.setup.action.BehaviourObservationAction;
import com.wazuh.setup.action.DetectionReleaseAction;
import com.wazuh.setup.incident.DetectionRelease;
import com.wazuh.setup.incident.DetectionReleaseService;
import com.wazuh.setup.rest.RestDetectionReleaseAction;
import com.wazuh.setup.transport.TransportDetectionReleaseAction;
import com.wazuh.setup.incident.BehaviourObservationService;
import com.wazuh.setup.rest.RestBehaviourObservationAction;
import com.wazuh.setup.transport.TransportBehaviourObservationAction;
import com.wazuh.setup.incident.RuleBehaviourService;
import com.wazuh.setup.rest.RestRuleBehaviourAction;
import com.wazuh.setup.transport.TransportRuleBehaviourAction;
import com.wazuh.setup.incident.EntityBehaviourService;
import com.wazuh.setup.rest.RestEntityBehaviourAction;
import com.wazuh.setup.transport.TransportEntityBehaviourAction;
import com.wazuh.setup.incident.IncidentEntityInvestigationService;
import com.wazuh.setup.rest.RestIncidentEntityInvestigationAction;
import com.wazuh.setup.transport.TransportIncidentEntityInvestigationAction;
import com.wazuh.setup.incident.IncidentHuntService;
import com.wazuh.setup.rest.RestIncidentHuntAction;
import com.wazuh.setup.transport.TransportIncidentHuntAction;
import com.wazuh.setup.action.CorrelationPolicyAction;
import com.wazuh.setup.action.AnalyticsRunAction;
import com.wazuh.setup.action.IncidentAutomationAction;
import com.wazuh.setup.action.IncidentSoarAction;
import com.wazuh.setup.incident.IncidentSoarService;
import com.wazuh.setup.rest.RestIncidentSoarAction;
import com.wazuh.setup.transport.TransportIncidentSoarAction;
import com.wazuh.setup.incident.IncidentAutomationStore;
import com.wazuh.setup.incident.IncidentAutomationService;
import com.wazuh.setup.rest.RestIncidentAutomationAction;
import com.wazuh.setup.transport.TransportIncidentAutomationAction;
import com.wazuh.setup.incident.AnalyticsExecutionService;
import com.wazuh.setup.rest.RestAnalyticsRunAction;
import com.wazuh.setup.transport.TransportAnalyticsRunAction;
import com.wazuh.setup.action.IndicatorCatalogAction;
import com.wazuh.setup.incident.IndicatorCatalogStore;
import com.wazuh.setup.rest.RestIndicatorCatalogAction;
import com.wazuh.setup.transport.TransportIndicatorCatalogAction;
import com.wazuh.setup.incident.CorrelationPolicyStore;
import com.wazuh.setup.rest.RestCorrelationPolicyAction;
import com.wazuh.setup.transport.TransportCorrelationPolicyAction;
import com.wazuh.setup.incident.CorrelationPreviewService;
import com.wazuh.setup.rest.RestIncidentCorrelationAction;
import com.wazuh.setup.transport.TransportIncidentCorrelationAction;
import com.wazuh.setup.action.IncidentWriteAction;
import com.wazuh.setup.incident.FindingAccess;
import com.wazuh.setup.incident.IncidentReadService;
import com.wazuh.setup.incident.IncidentInvestigationService;
import com.wazuh.setup.incident.IncidentRecovery;
import com.wazuh.setup.incident.IncidentRepository;
import com.wazuh.setup.incident.IncidentWriteService;
import com.wazuh.setup.rest.RestIncidentReadAction;
import com.wazuh.setup.rest.RestIncidentWriteAction;
import com.wazuh.setup.transport.TransportIncidentReadAction;
import com.wazuh.setup.transport.TransportIncidentWriteAction;
import com.wazuh.setup.action.PutAiAssistantSessionAction;
import com.wazuh.setup.action.PutAiAssistantSettingsAction;
import com.wazuh.setup.action.PutSettingsAction;
import com.wazuh.setup.index.AiAssistantSessionsIndex;
import com.wazuh.setup.index.AiAssistantSettingsAdminIndex;
import com.wazuh.setup.index.ContentIndex;
import com.wazuh.setup.index.Index;
import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.index.SettingsIndex;
import com.wazuh.setup.index.SetupStatusIndex;
import com.wazuh.setup.index.StateIndex;
import com.wazuh.setup.index.StreamIndex;
import com.wazuh.setup.rest.RestDeleteAiAssistantProviderAction;
import com.wazuh.setup.rest.RestDeleteAiAssistantSessionAction;
import com.wazuh.setup.rest.RestGetAiAssistantSettingsAction;
import com.wazuh.setup.rest.RestListAiAssistantProvidersAction;
import com.wazuh.setup.rest.RestPatchAiAssistantSessionAction;
import com.wazuh.setup.rest.RestPostAiAssistantProviderAction;
import com.wazuh.setup.rest.RestPostAiAssistantSessionAction;
import com.wazuh.setup.rest.RestPutAiAssistantProviderAction;
import com.wazuh.setup.rest.RestPutAiAssistantSessionAction;
import com.wazuh.setup.rest.RestPutAiAssistantSettingsAction;
import com.wazuh.setup.rest.RestPutSettingsAction;
import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.transport.TransportGetAiAssistantSettingsAction;
import com.wazuh.setup.transport.TransportPutAiAssistantSessionAction;
import com.wazuh.setup.transport.TransportPutAiAssistantSettingsAction;
import com.wazuh.setup.transport.TransportPutSettingsAction;
import com.wazuh.setup.utils.JsonUtils;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin implements ClusterPlugin, ActionPlugin {

    private static final Logger log = LogManager.getLogger(SetupPlugin.class);
    public static final String CLUSTER_DEFAULT_NUMBER_OF_REPLICAS =
            "cluster.default_number_of_replicas";
    private final List<Index> indices = new ArrayList<>();
    private Client client;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private SettingsIndex settingsIndex;
    private SetupStatusIndex setupStatusIndex;
    private AiAssistantSettingsAdminIndex settingsAdminIndex;
    private AiAssistantSessionsIndex sessionsIndex;
    private IncidentRecovery incidentRecovery;
    private Scheduler.Cancellable incidentRecoveryTask;
    // spotless:off
    private final String[] categories = {
        "access-management",
        "applications",
        "cloud-services",
        "network-activity",
        "security",
        "system-activity",
        "other",
        "unclassified"
    };
    // spotless:on

    /** Default constructor */
    public SetupPlugin() {}

    @Override
    public Collection<Object> createComponents(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService,
            ScriptService scriptService,
            NamedXContentRegistry xContentRegistry,
            Environment environment,
            NodeEnvironment nodeEnvironment,
            NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        // spotless:off
        // Setup status index - Holds the initialization marker read by other plugins (e.g.
        // Content Manager) to defer their startup work until setup completes. Added first so its
        // own initialize() (which writes the "running" marker) runs before any other index,
        // invalidating a stale marker from a previous boot as early as possible.
        this.setupStatusIndex = new SetupStatusIndex(SetupStatusIndex.INDEX_NAME, "templates/setup-status");
        this.indices.add(this.setupStatusIndex);

        // ISM index
        this.indices.add(new IndexStateManagement(IndexStateManagement.ISM_INDEX_NAME, "templates/ism-config"));
        // Decoder indices
        for (String category : this.categories) {
            this.indices.add(new StreamIndex(
                "wazuh-events-v5-" + category
            ));
        }
        // Findings data streams (stores detection findings per category)
        for (String category : this.categories) {
            this.indices.add(new StreamIndex(
                "wazuh-findings-v5-" + category,
                "templates/streams/findings"
            ));
        }
        // Raw events data stream (stores original unprocessed events)
        this.indices.add(new StreamIndex("wazuh-events-raw-v5", "templates/streams/raw"));

        // Active responses data stream (stores active response execution requests from monitor triggers)
        this.indices.add(new StreamIndex("wazuh-active-responses", "templates/streams/active-responses"));

        // Metrics data streams
        this.indices.add(new StreamIndex("wazuh-metrics-agents", "templates/streams/metrics-agents"));
        this.indices.add(new StreamIndex("wazuh-metrics-comms-v4", "templates/streams/metrics-comms"));
        this.indices.add(new StreamIndex("wazuh-metrics-normalization", "templates/streams/metrics-normalization"));

        // AI assistant sessions data stream (stores the users' conversations with the AI assistant)
        this.indices.add(new StreamIndex("wazuh-ai-assistant-sessions", "templates/streams/ai-assistant-sessions"));

        // Opt-in only. Do not provision these indices for ordinary Wazuh installations.
        if (PluginSettings.INCIDENTS_ENABLED.get(environment.settings())) {
            this.indices.add(new StateIndex(IncidentRepository.INCIDENTS, "templates/cases/incidents"));
            if (PluginSettings.BEHAVIOUR_OBSERVATIONS_ENABLED.get(environment.settings()))
                this.indices.add(new StateIndex(BehaviourObservationService.INDEX, "templates/cases/behaviour-observations"));
            this.indices.add(new StateIndex(IncidentRepository.ACTIVITY, "templates/cases/activity"));
            this.indices.add(new StateIndex(CorrelationPolicyStore.INDEX, "templates/cases/correlation-policies"));
            this.indices.add(new StateIndex(IncidentAutomationStore.INDEX, "templates/cases/automation-policies"));
            if (PluginSettings.ANALYTICS_ENABLED.get(environment.settings())) {
                this.indices.add(new StateIndex(AnalyticsExecutionService.RUN_INDEX, "templates/cases/analytics-runs"));
                this.indices.add(new StateIndex(AnalyticsExecutionService.CORRELATION_INDEX, "templates/cases/correlation-execution"));
            }
            this.indices.add(new StateIndex(IndicatorCatalogStore.INDEX, "templates/cases/indicators"));
        }

        // State indices
        if (PluginSettings.DETECTION_RELEASES_ENABLED.get(environment.settings()))
            this.indices.add(new StateIndex(DetectionRelease.INDEX, "templates/cases/detection-releases"));
        this.indices.add(new StateIndex("wazuh-agent-config", "templates/states/agent-config"));
        this.indices.add(new StateIndex("wazuh-agent-stats", "templates/states/agent-stats"));
        this.indices.add(new StateIndex("wazuh-states-sca", "templates/states/sca"));
        this.indices.add(new StateIndex("wazuh-states-fim-files", "templates/states/fim-files"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-keys", "templates/states/fim-registry-keys"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-values", "templates/states/fim-registry-values"));
        this.indices.add(new StateIndex("wazuh-states-inventory-browser-extensions", "templates/states/inventory-browser-extensions"));
        this.indices.add(new StateIndex("wazuh-states-inventory-groups", "templates/states/inventory-groups"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hardware", "templates/states/inventory-hardware"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hotfixes", "templates/states/inventory-hotfixes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-interfaces", "templates/states/inventory-interfaces"));
        this.indices.add(new StateIndex("wazuh-states-inventory-networks", "templates/states/inventory-networks"));
        this.indices.add(new StateIndex("wazuh-states-inventory-packages", "templates/states/inventory-packages"));
        this.indices.add(new StateIndex("wazuh-states-inventory-ports", "templates/states/inventory-ports"));
        this.indices.add(new StateIndex("wazuh-states-inventory-processes", "templates/states/inventory-processes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-protocols", "templates/states/inventory-protocols"));
        this.indices.add(new StateIndex("wazuh-states-inventory-services", "templates/states/inventory-services"));
        this.indices.add(new StateIndex("wazuh-states-inventory-system", "templates/states/inventory-system"));
        this.indices.add(new StateIndex("wazuh-states-inventory-users", "templates/states/inventory-users"));
        this.indices.add(new StateIndex("wazuh-states-vulnerabilities", "templates/states/vulnerabilities"));

        // Threat intel content indices - Hold the catalog content the Content Manager downloads
        // from CTI. Created as <name>-a with the public alias <name> pointing at it, so the Content
        // Manager can rebuild content into the <name>-b slot and swap the alias atomically. The
        // Content Manager defers all its work until the setup status index is marked ready, so these
        // are always in place before the first write reaches them.
        this.indices.add(new ContentIndex("wazuh-threatintel-enrichments", "templates/content/ioc"));
        this.indices.add(new ContentIndex("wazuh-threatintel-filters", "templates/content/filters"));
        this.indices.add(new ContentIndex("wazuh-threatintel-decoders", "templates/content/decoders"));
        this.indices.add(new ContentIndex("wazuh-threatintel-rules", "templates/content/rules"));
        this.indices.add(new ContentIndex("wazuh-threatintel-kvdbs", "templates/content/kvdbs"));
        this.indices.add(new ContentIndex("wazuh-threatintel-integrations", "templates/content/integrations"));
        this.indices.add(new ContentIndex("wazuh-threatintel-policies", "templates/content/policies"));
        this.indices.add(new ContentIndex(".wazuh-threatintel-vulnerabilities", "templates/content/vulnerabilities"));

        // Wazuh settings index - Instantiated as it is required by the RestPutSettingsAction.
        this.settingsIndex = new SettingsIndex(".wazuh-settings", "templates/settings");
        this.indices.add(this.settingsIndex);

        // spotless:on

        // Inject dependencies
        JsonUtils utils = new JsonUtils();
        this.indices.forEach(
                index -> {
                    index.setClient(client);
                    index.setClusterService(clusterService);
                    index.setUtils(utils);
                });

        // Privileged access to the AI assistant's providers
        this.settingsAdminIndex = new AiAssistantSettingsAdminIndex(client, threadPool);

        // Privileged access to the AI assistant's chat sessions. Mediates every write to the
        // wazuh-ai-assistant-sessions data stream so that the document's `user` field is stamped
        // from the authenticated caller instead of being taken from the request body.
        this.sessionsIndex = new AiAssistantSessionsIndex(client, threadPool);

        // Expose the settings index and the two privileged accessors so they can be injected into
        // their respective transport actions.
        IncidentRepository incidents = new IncidentRepository(client, threadPool);
        if (PluginSettings.INCIDENTS_ENABLED.get(environment.settings())) {
            this.incidentRecovery = new IncidentRecovery(client, threadPool, clusterService, incidents);
        }
        IncidentReadService incidentReader = new IncidentReadService(client, threadPool, incidents);
        IncidentInvestigationService investigation = new IncidentInvestigationService(client, threadPool, incidents, new FindingAccess(client));
        IncidentWriteService incidentWriter = new IncidentWriteService(incidents, new FindingAccess(client),
                Clock.systemUTC(), error -> log.warn("Incident activity delivery pending", error));
        IncidentAutomationStore automationStore = new IncidentAutomationStore(client, threadPool, Clock.systemUTC());
        IncidentAutomationService automation = new IncidentAutomationService(client, threadPool, incidents, automationStore, Clock.systemUTC());
        IncidentHuntService hunt = new IncidentHuntService(client);
        RuleBehaviourService ruleBehaviour = new RuleBehaviourService(client, threadPool, Clock.systemUTC());
        return List.of(new DetectionReleaseService(client, threadPool, Clock.systemUTC()), new EventBehaviourService(client, threadPool, Clock.systemUTC()), new BehaviourObservationService(client, threadPool, ruleBehaviour, incidentWriter, Clock.systemUTC()), ruleBehaviour, new EntityBehaviourService(threadPool, hunt, Clock.systemUTC()), new IncidentEntityInvestigationService(client, threadPool, hunt), new IncidentSoarService(incidents, Clock.systemUTC()), automationStore, automation, this.settingsIndex, this.settingsAdminIndex, this.sessionsIndex, incidentReader, incidentWriter, investigation, new CorrelationPreviewService(client), new AnalyticsExecutionService(client, threadPool, Clock.systemUTC(), incidents), hunt, new CorrelationPolicyStore(client, threadPool, Clock.systemUTC()), new IndicatorCatalogStore(client, threadPool, Clock.systemUTC()), new IncidentMetricsService(client, threadPool, Clock.systemUTC()));
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        if (this.incidentRecovery != null) {
            // A node becoming cluster manager later must also be able to recover the outbox.
            this.incidentRecoveryTask = this.threadPool.scheduleWithFixedDelay(this.incidentRecovery,
                    TimeValue.timeValueSeconds(30), ThreadPool.Names.GENERIC);
        }
        AtomicBoolean started = new AtomicBoolean(false);
        LocalNodeClusterManagerListener listener =
                new LocalNodeClusterManagerListener() {
                    @Override
                    public void onClusterManager() {
                        if (!started.compareAndSet(false, true)) {
                            return;
                        }
                        SetupPlugin.this
                                .threadPool
                                .generic()
                                .execute(
                                        () -> {
                                            // Apply cluster.default_number_of_replicas from
                                            // opensearch.yml settings if present
                                            try {
                                                String defaultNumberOfReplicas =
                                                        SetupPlugin.this
                                                                .clusterService
                                                                .getSettings()
                                                                .get(CLUSTER_DEFAULT_NUMBER_OF_REPLICAS);
                                                if (defaultNumberOfReplicas != null) {
                                                    ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
                                                    request.persistentSettings(
                                                            Settings.builder()
                                                                    .put(CLUSTER_DEFAULT_NUMBER_OF_REPLICAS, defaultNumberOfReplicas)
                                                                    .build());
                                                    SetupPlugin.this
                                                            .client
                                                            .admin()
                                                            .cluster()
                                                            .updateSettings(request)
                                                            .actionGet(
                                                                    PluginSettings.getTimeout(
                                                                            SetupPlugin.this.clusterService.getSettings()));
                                                    log.info(
                                                            "Successfully updated cluster.default_number_of_replicas to {}",
                                                            defaultNumberOfReplicas);
                                                }
                                            } catch (Exception e) {
                                                log.error("Failed to update cluster.default_number_of_replicas", e);
                                            }

                                            try {
                                                SetupPlugin.this.indices.forEach(Index::initialize);
                                                SetupPlugin.this.setupStatusIndex.markReady();
                                            } catch (Exception e) {
                                                log.error("Setup initialization failed: {}", e.getMessage(), e);
                                                SetupPlugin.this.setupStatusIndex.markFailed();
                                            }
                                        });
                    }

                    @Override
                    public void offClusterManager() {}
                };

        this.clusterService.addLocalNodeClusterManagerListener(listener);

        // The listener only fires on transitions. If the node is already the
        // elected cluster manager (the election happened before this method
        // runs), trigger the callback explicitly.
        if (this.clusterService.state().nodes().isLocalNodeElectedClusterManager()) {
            listener.onClusterManager();
        }
    }

    @Override
    public void close() {
        if (this.incidentRecovery != null) this.incidentRecovery.stop();
        if (this.incidentRecoveryTask != null) this.incidentRecoveryTask.cancel();
    }

    @Override
    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
        List<RestHandler> handlers = new ArrayList<>(List.of(
                new RestPutSettingsAction(),
                new RestGetAiAssistantSettingsAction(),
                new RestListAiAssistantProvidersAction(),
                new RestPutAiAssistantSettingsAction(),
                new RestPostAiAssistantProviderAction(),
                new RestPutAiAssistantProviderAction(),
                new RestDeleteAiAssistantProviderAction(),
                new RestPostAiAssistantSessionAction(),
                new RestPutAiAssistantSessionAction(),
                new RestPatchAiAssistantSessionAction(),
                new RestDeleteAiAssistantSessionAction()));
        if (PluginSettings.INCIDENTS_ENABLED.get(settings)) {
            handlers.add(new RestIncidentReadAction());
            handlers.add(new RestIncidentResponseReadAction());
            handlers.add(new RestIncidentMetricsAction());
            handlers.add(new RestIncidentWriteAction());
            handlers.add(new RestIncidentCorrelationAction());
            handlers.add(new RestIncidentHuntAction());
            handlers.add(new RestIncidentEntityInvestigationAction());
            handlers.add(new RestEntityBehaviourAction());
            handlers.add(new RestRuleBehaviourAction());
            handlers.add(new RestEventBehaviourAction());
            if (PluginSettings.BEHAVIOUR_OBSERVATIONS_ENABLED.get(settings)) handlers.add(new RestBehaviourObservationAction());
            handlers.add(new RestCorrelationPolicyAction());
            handlers.add(new RestIncidentAutomationAction());
            if (PluginSettings.SOAR_ENABLED.get(settings)) handlers.add(new RestIncidentSoarAction());
            if (PluginSettings.ANALYTICS_ENABLED.get(settings)) handlers.add(new RestAnalyticsRunAction());
            handlers.add(new RestIndicatorCatalogAction());
        }
        if (PluginSettings.DETECTION_RELEASES_ENABLED.get(settings)) handlers.add(new RestDetectionReleaseAction());
        return handlers;
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
                new ActionPlugin.ActionHandler<>(
                        PutSettingsAction.INSTANCE, TransportPutSettingsAction.class),
                new ActionPlugin.ActionHandler<>(
                        GetAiAssistantSettingsAction.INSTANCE, TransportGetAiAssistantSettingsAction.class),
                new ActionPlugin.ActionHandler<>(
                        PutAiAssistantSettingsAction.INSTANCE, TransportPutAiAssistantSettingsAction.class),
                new ActionPlugin.ActionHandler<>(
                        PutAiAssistantSessionAction.INSTANCE, TransportPutAiAssistantSessionAction.class),
                new ActionPlugin.ActionHandler<>(CorrelationPolicyAction.READ, TransportCorrelationPolicyAction.Read.class),
                new ActionPlugin.ActionHandler<>(AnalyticsRunAction.READ, TransportAnalyticsRunAction.Read.class),
                new ActionPlugin.ActionHandler<>(IncidentSoarAction.DISPATCH, TransportIncidentSoarAction.class),
                new ActionPlugin.ActionHandler<>(IncidentAutomationAction.READ, TransportIncidentAutomationAction.Read.class),
                new ActionPlugin.ActionHandler<>(IncidentAutomationAction.SAVE, TransportIncidentAutomationAction.Save.class),
                new ActionPlugin.ActionHandler<>(IncidentAutomationAction.EXECUTE, TransportIncidentAutomationAction.Execute.class),
                new ActionPlugin.ActionHandler<>(AnalyticsRunAction.EXECUTE, TransportAnalyticsRunAction.Execute.class),
                new ActionPlugin.ActionHandler<>(IndicatorCatalogAction.READ, TransportIndicatorCatalogAction.Read.class),
                new ActionPlugin.ActionHandler<>(IndicatorCatalogAction.SAVE, TransportIndicatorCatalogAction.Save.class),
                new ActionPlugin.ActionHandler<>(CorrelationPolicyAction.SAVE, TransportCorrelationPolicyAction.Save.class),
                new ActionPlugin.ActionHandler<>(IncidentCorrelationAction.INSTANCE, TransportIncidentCorrelationAction.class),
                new ActionPlugin.ActionHandler<>(IncidentHuntAction.INSTANCE, TransportIncidentHuntAction.class),
                new ActionPlugin.ActionHandler<>(IncidentEntityInvestigationAction.INSTANCE, TransportIncidentEntityInvestigationAction.class),
                new ActionPlugin.ActionHandler<>(EntityBehaviourAction.INSTANCE, TransportEntityBehaviourAction.class),
                new ActionPlugin.ActionHandler<>(RuleBehaviourAction.INSTANCE, TransportRuleBehaviourAction.class),
                new ActionPlugin.ActionHandler<>(EventBehaviourAction.INSTANCE, TransportEventBehaviourAction.class),
                new ActionPlugin.ActionHandler<>(DetectionReleaseAction.SUBMIT, TransportDetectionReleaseAction.Submit.class),
                new ActionPlugin.ActionHandler<>(DetectionReleaseAction.READ, TransportDetectionReleaseAction.Read.class),
                new ActionPlugin.ActionHandler<>(DetectionReleaseAction.DAY, TransportDetectionReleaseAction.Day.class),
                new ActionPlugin.ActionHandler<>(DetectionReleaseAction.REVIEW, TransportDetectionReleaseAction.Review.class),
                new ActionPlugin.ActionHandler<>(BehaviourObservationAction.PUBLISH, TransportBehaviourObservationAction.Publish.class),
                new ActionPlugin.ActionHandler<>(BehaviourObservationAction.READ, TransportBehaviourObservationAction.Read.class),
                new ActionPlugin.ActionHandler<>(BehaviourObservationAction.REVIEW, TransportBehaviourObservationAction.Review.class),
                new ActionPlugin.ActionHandler<>(BehaviourObservationAction.PROMOTE, TransportBehaviourObservationAction.Promote.class),
                new ActionPlugin.ActionHandler<>(IncidentMetricsAction.INSTANCE, TransportIncidentMetricsAction.class),
                new ActionPlugin.ActionHandler<>(IncidentResponseReadAction.INSTANCE, TransportIncidentResponseReadAction.class),
                new ActionPlugin.ActionHandler<>(IncidentReadAction.INSTANCE, TransportIncidentReadAction.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.CREATE, TransportIncidentWriteAction.Create.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.ASSIGN, TransportIncidentWriteAction.Assign.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.UPDATE, TransportIncidentWriteAction.Update.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.CLOSE, TransportIncidentWriteAction.Close.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.REOPEN, TransportIncidentWriteAction.Reopen.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.FINDINGS, TransportIncidentWriteAction.Findings.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.COLLABORATE, TransportIncidentWriteAction.Collaborate.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.RESPONSE_REQUEST, TransportIncidentWriteAction.ResponseRequest.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.RESPONSE_APPROVAL, TransportIncidentWriteAction.ResponseApproval.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.RESPONSE_OUTCOME, TransportIncidentWriteAction.ResponseOutcome.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.WORKFLOW_OPERATE, TransportIncidentWriteAction.WorkflowOperate.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.PLAYBOOK_APPLY, TransportIncidentWriteAction.PlaybookApply.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.AI_FEEDBACK, TransportIncidentWriteAction.AiFeedback.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.TUNING_PROPOSE, TransportIncidentWriteAction.TuningPropose.class),
                new ActionPlugin.ActionHandler<>(IncidentWriteAction.TUNING_REVIEW, TransportIncidentWriteAction.TuningReview.class));
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(
                PluginSettings.TIMEOUT,
                PluginSettings.BACKOFF,
                PluginSettings.MAX_RETRIES,
                PluginSettings.SETTINGS_UPDATE_ENABLED,
                PluginSettings.INCIDENTS_ENABLED, PluginSettings.ANALYTICS_ENABLED, PluginSettings.ANALYTICS_DEPLOYMENT,
                PluginSettings.ANALYTICS_ACTOR, PluginSettings.ANALYTICS_POLICIES, PluginSettings.AUTOMATION_ENABLED,
                PluginSettings.AUTOMATION_ACTOR, PluginSettings.AUTOMATION_POLICY, PluginSettings.SOAR_ENABLED, PluginSettings.SOAR_ACTOR,
                PluginSettings.SOAR_MANAGER, PluginSettings.SOAR_AGENTS, PluginSettings.WORKFLOWS_ENABLED, PluginSettings.BEHAVIOUR_ENABLED, PluginSettings.RULE_BEHAVIOUR_ENABLED, PluginSettings.BEHAVIOUR_OBSERVATIONS_ENABLED,
                PluginSettings.EVENT_BEHAVIOUR_ENABLED, PluginSettings.BEHAVIOUR_PROMOTION_ENABLED, PluginSettings.BEHAVIOUR_PUBLISHER, PluginSettings.BEHAVIOUR_SCOPES, PluginSettings.DETECTION_RELEASES_ENABLED);
    }
}
