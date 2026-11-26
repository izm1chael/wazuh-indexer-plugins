# WADE control-plane reference contracts

Tracks WADE-01, WADE-06 and WADE-07. Run all standalone checks using `sh tools/wade/test-analytics.sh`.

ExecutionControl specifies immutable job revision, lease, monotonically increasing fencing token, bounded TTL, checkpoint and receipt transitions. Acquisition, takeover, completion and abandon must be applied against authoritative persisted state using atomic compare-and-set. This implementation is not a store or distributed lock. A trusted clock, durable result/outbox commit, receipt verification, stale-write fencing at every output sink, renewal and crash-recovery tests are required before scheduling real work. Never advance a checkpoint for unknown or incomplete processing.

DetectionQuality computes an explicit health state from declared required-source heartbeats, schema validity and query completeness. COMPLETE is a reference precondition, not proof of full window coverage; production coverage also requires authoritative source watermarks, expected partitions, access scope and no truncation. Missing/future/conflicting observations are UNKNOWN; stale or malformed sources are DEGRADED. No absence/anomaly rule may equate these states to zero activity.

Replay metrics consume unique labelled case outcomes. Explicit counts for unknown malicious/benign and unlabelled cases, precision, evaluated-only recall, conservative recall including unknown malicious, and labelled evaluation coverage. Undefined ratios are null, not fabricated zero. Label and case IDs must originate from a versioned, independently labelled test corpus; this module does not execute historical Indexer queries or establish actual precision/recall. Champion/challenger comparisons must use identical case populations and availability cutoffs.

Production adapters, actual replay, registry, telemetry ingestion, ATT&CK mapping, scheduler, persistence, access control, load tests and native finding integration remain open.
