# WADE consolidated close-out handoff (qualification, not production acceptance)

## Repositories

- Indexer: izm1chael/wazuh-indexer-plugins, siem/wade-foundation, draft PR #14, base RC2 e2871f7d68ee46fef2b01e21d3261dc6ab411489.
- Dashboard: izm1chael/wazuh-dashboard-plugins, siem/wade-foundation, draft PR #29, base RC2 22901fa354f20616d4bc707003b4b8a115cfb3d9. Initial workspace head d888e7f1670033ad4ccc9d7429cafdd5a2a5d5fb.
- Incident branches and main/base remain independent. Do not merge or activate automatically.

## Single local reference/build run

From a clean Indexer WADE checkout, Python 3.11+, JDK 21, Node 22 and tsc available, exact RC2 build artifacts/repositories accessible:

    python3 -B tools/wade/qualify.py --dashboard-checkout /absolute/path/to/dashboard-wade --native-build --out /absolute/path/to/new-wade-qualification

Provide the actual RC2 artifact version with --opensearch-version if the default 3.6.0-SNAPSHOT does not match the installed distribution. Use new private output directory outside both checkouts. The command checks each pinned base and isolation, runs all Java, Python, mapping and gate self-tests, compiles Dashboard review/app TS and runs its model tests, and optionally cleans/builds the independent Indexer plugin ZIP. It records per-stage logs and SHA-256, exact branch heads and ZIP descriptor/hash. It performs no live cluster requests or installation. The build may fetch dependencies. A mutable SNAPSHOT build is not proof of exact runtime ABI. A build result PASS is not a production result; production remains BLOCKED unconditionally. No false positives from an empty gate or skipped requested native build. The gate is tested at the unit level (five tests); full end-to-end gate not executed here because no full local checkouts or OpenSearch artifacts. Inspect report and logs locally; avoid exposing secrets in build logs.

## Consolidated implementation and remaining acceptance scope

| Workstream | Evidence delivered | Must still deliver before closing |
|---|---|---|
| WADE-01 #4 Indexer | Java in-process service, storage protocol, native client/reader candidate, bounded plan | exact RC2 compile, trusted adapters, native registration, scheduler/leases/checkpoints, migration, security, resource qualification |
| WADE-02 #5 Indexer | Count/cardinality and temporal reference, anchored lookback and WCS admission | native Sigma conformance, live source and qualified immutable snapshots, scheduled/replay execution, lateness tests |
| WADE-03 #6 Indexer | identity resolver, typed relationship reference | verified inventory/identity mapping, scoped graph storage, direction semantics, authoritative evidence |
| WADE-04 #7 Indexer | risk projection, causal history, local signal ledger | persistent typed risk ledger, risk dispatch, thresholds and actual evidence |
| WADE-05 #8 Indexer | robust anomaly and categorical novelty | native feature extraction, storage, baselines/peer/seasonality, calibration |
| WADE-06 #9 Indexer | version registry, lifecycle, replay quality, reconciliation, tuning review | native immutable approvals, live historical replay/shadow, canary/rollback, verified receipts |
| WADE-07 #10 Indexer | health and completeness contracts | measured source populations, heartbeat/watermark/coverage and observable ATT&CK |
| WADE-08 #11 Indexer | local persisted graph and revision intents | native graph fusion, verified relationships, publication/incident consumption |
| WADE-09 #12 Indexer | robust statistics only; advanced ML not implemented | ablation with labelled corpus before adding optional models; defer if no measured benefit |
| WADE-10 #13 Indexer | offline paired tuning engine | disposition ingestion, authoritative cohorts, proposal lifecycle and independent approval |
| WADE-11 #15 Dashboard | offline imported-cohort review, draft #29 | native OSD build/mount, authenticated APIs, rule editor, live replay/shadow, health/entities/risk, permission and browser tests |
| WADE-12 #16 Dashboard | no AI integration | shared provider, scoped read-only tools, cited proposals, injection resistance, deterministic validation; never autonomous writes |
| WADE-13 #17 Dashboard | standalone tests, two disabled candidate detections, this gate | larger verified content packs, real labelled replay, secured disposable cluster, load/fault/security/rollback tests |

## One coordinated completion cycle (no issue closure based on prototype tests)

1. Run the gate on exact clean heads; remediate all compile and regression defects in the WADE branches. Do not install on the existing SIEM.
2. Complete missing native source inventory/approval/authority, scheduler and persistent analytics integrations. Run two-node secured disposable RC2 with scoped service roles, deterministic synthetic fixtures, actual WCS population, native rule parity, late and incomplete evidence, restart/failover, revocation and idempotent publications. Verify strict mappings, retention, no cross-tenant reads/writes and no permission elevation. No mock-only acceptance.
3. Integrate Dashboard into actual OSD packaging and authenticated API surface; use exact receipts, real promotion approvals, live replay/shadow, protected regression evidence, and separate AI review from autonomous changes. Coordinate incident finding revisions without deleting evidence or auto-closing cases.
4. Qualify real source coverage and resource budget, benchmark against native detections, verify rollback/uninstall, and retain reproducible evidence. Close each issue only after its original acceptance criteria are demonstrated. Advanced ML remains optional and only ships with measurable incremental value.

## This pass

98 Java assertions passed across five local suites, including 17 new admission checks. The five qualification-runner unit tests and seven Dashboard review model tests passed. Dashboard DOM application compiled in strict TypeScript; actual OSD entrypoint and both native OpenSearch candidates remain uncompiled. No end-to-end gate, native cluster, live backtest, browser or production acceptance. User should perform the consolidated gate locally, then deliver its report and failures rather than repeating isolated algorithm batches.
