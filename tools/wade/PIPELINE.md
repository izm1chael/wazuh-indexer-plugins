# WADE offline execution pipeline (phase A/B)

Tracks WADE-01, WADE-02 and WADE-06. Run: sh tools/wade/test-analytics.sh (JDK 17+, Linux local filesystem).

## Implemented

ReplayEngine composes the existing count/distinct kernel and labelled metrics. In-memory registry keys are tenant/rule/version, with a selector digest and immutable definition. Replay requires a caller-supplied complete, already scoped and matched source snapshot, event availability times, as-of and watermark. Future arrivals excluded; scope mismatch, future event, duplicate case IDs and input ceilings fail closed. Receipt binds rule definition, case/label/scope, window, availability cutoff, admitted evidence hashes with multiplicity and result. Reordering the input produces identical receipts. No native selector compilation or corpus authentication yet.

LocalWindowStore stores one bounded job snapshot, with file lock, revision/fence, checkpoint and pending output payload atomically replaced after flushing the file and then syncing the directory. It is a Linux local-filesystem reference, not an Indexer adapter or distributed lock. A pending payload blocks new execution until an external publisher verifies delivery and acknowledges the exact ID/digest/payload. The caller must reconcile an ambiguous I/O failure by reloading, not retry blindly. No publisher exists yet; last acknowledgement is retained, not a full delivery history. No arbitrary trusted-directory access from telemetry. No encryption; use only a trusted private test directory. Reopening and truncated file rejection tested; process-kill, concurrent process, storage failure, full snapshot integrity and distributed fault tests remain open.

WindowRunner connects the registry, count kernel, checkpoint and outbox for one unlabelled operational window, one scope and immutable rule version. Requires contiguous checkpoint, valid lease, no pending output, and as-of no later than supplied clock. UNKNOWN and NOT_READY do not advance. MATCH or NO_MATCH stages a bounded versioned base64-line envelope with stable window ID, rule/receipt digests, scope and evidence references; no raw event values. 4,096-character payload cap rejects oversized output before checkpoint advances. The caller supplies clock, coverage and source authority; this is not an authorization boundary. No live delivery, late reconciliation, temporal/risk/UEBA dispatch or scheduler yet.

## RC2 native integration evidence

Inspected pinned base e2871f7d68ee46fef2b01e21d3261dc6ab411489:
- plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/SecurityAnalyticsService.java exposes evaluateRulesAsync against normalized events, integration ID, log type and source indices, as well as native rule/detector operations. Reuse native matching; do not invent Sigma conformance.
- plugins/content-manager/src/main/java/com/wazuh/contentmanager/jobscheduler/ContentJobParameter.java and ContentJobRunner.java demonstrate OpenSearch Job Scheduler SPI parameters and dispatch. WADE still needs a dedicated adapter, job index, lock/fence authority and registration lifecycle.
- plugins/setup/src/main/resources/templates/streams/findings.json defines native wazuh-findings-v5* data streams and strict template-controlled WCS mappings. wcs/stateless/events/findings/fields/subset.yml includes event.doc_id, event.index, rule and risk. Do not inject WADE envelopes into that data stream. Use isolated WADE storage and qualify explicit projection or incident-consumer contract first.
- tests/content-manager/test_findings_generation.py is the existing RC2 native finding integration-test pattern: promote content, create native detector, ingest matching WCS events, execute monitor, verify finding source references.

Next: authoritative event/availability fields and source completeness; native adapter with explicit permissions and bounded PIT/search_after; strict separate mappings and retention; durable Indexer CAS/outbox and idempotent consumer; golden native matching and fault tests. No changes to setup/content-manager, existing findings, permissions or runtime configuration in this batch.

## Local evidence

JDK 21; javac --release 17 -Xlint:all -Werror. All five suites run together: 20 kernel, 27 analytics, 21 control, 16 governance, 28 pipeline = 112 checks. These are assertions in standalone test mains, not cluster or production qualification.
