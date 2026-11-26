# Entity behaviour analytics — daily volume v1

Development candidate. Default off. This is the first deterministic UEBA foundation, not a production-calibrated user/entity risk engine. It measures retained, caller-visible **findings**, not authentication sessions, all endpoint events or confirmed security incidents.

## Scope and execution

POST /_plugins/_setup/incident-behaviour/assess accepts the existing bounded four-field hunt request (field, values, from, until). Requires incidents and behaviour enabled, authenticated original caller and dedicated cluster:admin/wazuh/incident/behaviour_read action permission. Native finding search permissions still apply. No shared case reads, hidden-index writes, scheduled execution, external calls, AI inference, responses or incident creation.

Nine fields: wazuh.agent.id, host.id, host.name, host.hostname, host.ip, source.ip, destination.ip, user.name, user.id. One to five exact distinct values of a single field; existing hunt literal rules, IPv4 only, no normalization/alias resolution or wildcard DSL. The requested comparison interval is exactly one UTC day, aligned to UTC midnight, ending at least 120 seconds before the indexer's clock. Previous seven consecutive UTC days form the baseline. Half-open intervals, nonoverlapping; 120 seconds is a conservative delay, not an ingestion-completeness guarantee.

Two sequential fixed hunts share existing per-node hunt concurrency; behaviour service additionally has one permit per instance and dashboard shares its one in-flight hunt budget. First baseline, then comparison; restore original caller security context before second search and verify exact principal. Both must return complete results according to existing exact-hunt requirements (max 100 distinct findings per whole interval, no partial results, exact totals, strict source-value/timestamp projection, concrete references). A cap or failure rejects the whole assessment; no sample extrapolation or fabricated zero. Busy/high-volume entities may exceed the deliberately conservative limit. No point-in-time snapshot, atomicity or persistent baseline. Searches can observe different index versions, retention and permissions. Existing per-search timeout is 15s; no new independent distributed semaphore or end-to-end deadline.

## Model daily_volume_v1

Count distinct concrete (index, document ID) findings per literal per baseline day and comparison day. Reject duplicates across both windows, mismatched counts and fields, out-of-window rows or unexpected/duplicate matched values. Multi-valued finding can contribute to several literals, never twice to one literal. Cross-literal totals need not equal distinct findings. Counts per day include zero matches, but do not assert telemetry coverage.

For each literal, let S be the sum of seven baseline day counts, A number of days with at least one finding, M baseline maximum, C comparison count. Compute integer threshold T = max(5, M + 3, ceil(2*S/7)). Classification:
- S=0 and C=0: no_observed_activity
- S=0 and C>0: newly_observed (only relative to this bounded retained window, not first-ever)
- S>0 and A<3: sparse_baseline (no elevated-volume classification, regardless of C)
- A>=3 and C>=T: elevated_volume
- Otherwise: within_volume_threshold (not normal/benign)

This heuristic is transparent but not fitted or calibrated. It does not account for seasonality, ingestion gaps, new rules, severity, login outcome, changing privileges, identities across fields, entity role or missing agent telemetry. It may miss both meaningful activity and malicious low-volume behaviour. No 0-100 risk score, no probability, no suppression or incident generation. A baseline with observed matches on three days is sufficient only to apply this heuristic, not proof of coverage. Use independent coverage and evidence before acting.

Response contains scope caller_visible_finding_volume, model daily_volume_v1, exact bounded baseline and current hunt projections (reference, timestamp, matched literal only), assessments with per-day counts, total, active days, maximum, threshold, current count and classification. Dashboard adapter and browser independently recompute counts and classification from both returned populations; fail on any mismatch. No raw finding source or persisted results. Dashboard workspace /incidents/behaviour shows comparison and baseline chart, exact findings, classification explanation and explicit related-case hunt pivot (fresh permission-checked search; no auto-execution).

## Activation

```yaml
plugins.setup.incidents.enabled: true
plugins.setup.incidents.behaviour.enabled: true
```

Both default off, use matched builds and identical node configuration. Assign only dedicated role fixture plus necessary native source permissions. No hidden index access granted and no new mapping or storage index. Do not enable in production before disposable qualification.

## Integrated qualification

- Build exact heads and execute Java, Jest, Python role tests; verify independent gate, action grant and source RBAC, original caller context in both async searches including DLS/FLS and no elevation. Verify native exact field mappings, concrete index and time format. Test current-user dashboard adapter and browser access denied, malformed JSON, unavailable sources, timeout, partial results and concurrency.
- Test 0, 1, 2 and 3 active baseline days, threshold equality, maximum and mean branches, sparse high-volume result, zero both, exact values, duplicate cross-window reference, same ID different indices, UTC day/nanosecond boundaries, 100/101 whole-window cap, invalid fields, five/six literals. Verify browser independent recomputation and absence of partial/fabricated results.
- Use known telemetry coverage and synthetic/disposable finding populations. Establish empirical false-positive/false-negative behaviour before any use as detection. Record retention, ingest lag, rule drift, changes in visibility and query costs. Check two-minute boundary is not a watermark. No automatic response or scheduled worker. Measure on low-resource Docker host and qualify concurrent request behavior.
- Test chart and reference counts, no auto-run on pivot, separate hunt/entity investigation grants, no storage or network disclosure to AI.

Cloud evidence: exact EntityBehaviourModel.java 29a31cfb80ccd61aa7782b22b9f31f42e4b833fd, EntityBehaviourModelTests.java cd16130c848390a031c4a1785081731fc996343b and FindingReference.java 8d272ea27b0b54c8ad0a980ec6e6e1293fae98fa reproduced locally, git hash-object matched, javac compiled and 21 assertions passed with minimal OpenSearchTestCase/exception/status stubs. Exact final behaviour-contract.ts 53933d7bf1a05d853cfe2e5224df4722a4414b7a, behaviour-contract.test.ts 3e8c0368fa45406b7194f06b26ef3abd1c01efdb and hunt-contract.ts 27da0e5ebd1d0e386682fd27415fad1a43a9cc1c reproduced, hashes verified, strict tsc compiled and three standalone Node groups / 25 assertions passed. 26 cross-repository source checks passed before import-only cleanup; final exact TS recompiled and retested. Full OpenSearch transport, security, Java/Jest/Python suites, browser and performance remain unqualified. No deployment, upstream change or endpoint actions.

Next UEBA increments: coverage and ingest-watermark evidence, scalable exact event aggregation under caller permissions, versioned rule-specific auth and endpoint behaviour metrics after field/semantics qualification, historical baselines and feature drift, explainable scoring with outcome calibration, durable scheduled anomaly records, governed incident generation and Agentic SOC consumption. Do not equate a finding-volume comparison with complete UEBA.
