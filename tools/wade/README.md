# WADE reference kernel — phase A
Tracking: [WADE-01](https://github.com/izm1chael/wazuh-indexer-plugins/issues/4), [WADE-02](https://github.com/izm1chael/wazuh-indexer-plugins/issues/5), [master epic](https://github.com/izm1chael/wazuh-dashboard-plugins/issues/14).

## Isolation and architecture decision (provisional)
Base: personal fork `siem/rc2-base`, commit e2871f7d68ee46fef2b01e21d3261dc6ab411489 (VERSION.json = 5.0.0 rc2). Root settings.gradle registers setup and content-manager only. Content-manager/build.gradle extends opensearch-job-scheduler and wazuh-indexer-security-analytics, with OpenSearch 3.6.0-SNAPSHOT default and external security-analytics artifacts. This repository does not itself contain those engines; native operator and scheduler semantics must be audited against their pinned artifacts before claiming compatibility. Do not modify the existing content-manager or setup plugins, root build, incident branch, or installed cluster as part of this slice.

This directory is an unregistered, dependency-free Java reference kernel, not a deployed plugin or service. Prefer existing Security Analytics/Sigma and Job Scheduler capabilities when compatible. A separate plugin adapter is provisional until the native APIs, permissions, state and resource isolation have been proven. A companion worker is a fallback only if native integration cannot satisfy those constraints. No production activation path exists here.

## Run locally
With JDK 17+ (JDK 21 recommended), from the repository root:
```sh
sh tools/wade/test.sh
```
No Gradle, network, Docker, credentials or Indexer needed for this reference suite. It is intentionally not wired into upstream CI yet.

## Executable contract
The evaluator consumes one already-authorized, already rule-matched collection per tenant/typed entity, rule version and half-open UTC event-time window. Event count and distinct-value count are supported as primitive operations, not a Sigma parser. Maximum 10,000 candidate inputs and 31-day window per evaluation; individual identifiers/values capped at 1,024 UTF-16 code units. The adapter must enforce fetch/page limits BEFORE materializing this collection. Duplicate source references are deduplicated; conflicting in-window references, mismatched scope, missing distinct values, input overflow or incomplete coverage return UNKNOWN with no finding. Open windows return NOT_READY. COMPLETE is an explicit caller assertion, not a property inferred from the input. A NO_MATCH is valid only for a complete closed window.

Logical finding IDs use length-framed SHA-256 of scope, rule ID/version and window. The version must be immutable in the future rule registry. The evidence digest distinguishes changed snapshots, and output contains ordered source references rather than raw distinct values. Same-ID updates require a future compare-and-set publication policy, not blind overwrite; revisions must preserve previous evidence and support retraction when a replay changes MATCH to NO_MATCH. No publishing, storage, scheduler, parsing, or source querying is implemented. Scope checks are defense-in-depth, not authorization.

## Follow-on integration gates
1. Inspect exact Security Analytics native rule schema, finding identity/index and supported Sigma correlation operators; build positive/negative fixtures and explicit unsupported-operator errors.
2. Verify WCS mapping and tenant/DLS/FLS permissions with native identities. Derive scope from trusted request/auth context, never telemetry. Use immutable source index identity (including index UUID where available) and authorize every referenced document.
3. Implement paged bounded event-time reads (stable cursor and event/ingest timestamps), source-health completeness, lateness/watermark policy, and replay. Distinguish unknown from zero; no false coverage claims.
4. Implement durable versioned rule and execution ledger, checkpoint/lease fencing, CAS finding revisions and transactional/outbox-style recovery; crash and concurrency tests before any scheduler registration.
5. Build native adapter with feature off by default, RBAC, independent retention, strict index templates, no recursive ingestion, bounded queries and explicit disabled/unknown status. Coordinate only via versioned contracts with the incident branch.
6. Establish workload (EPS, rule count, cardinality, window sizes, retention) and benchmark off/on CPU, RSS, query latency, ingestion lag, finding latency and detection quality. Initial budgets in master epic are unqualified. Record JDK and commit, exact local commands and outputs. Full RC2 cluster, migration, tenant isolation, crash recovery and Docker qualification remain pending.
