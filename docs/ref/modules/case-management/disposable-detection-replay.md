# Disposable detection-only replay runner

RC2 provides POST /_plugins/_content_manager/logtest/detection, which accepts space, integration and normalized input. It evaluates enabled integration rule bodies through Security Analytics. Inspect LogtestService.executeDetectionAsync: empty rule sets and some rule fetch failures can return success with rules_evaluated=0, so a 200 response alone is not a negative outcome.

The operator-only tools/incident_tuning_replay.py CLI uses that exact endpoint with two explicitly confirmed pre-provisioned disposable test integrations (each contains exactly one enabled rule). It does not create/promote/modify rules or integrations, run normalization, write findings or use a production target. HTTPS literal loopback with explicit port, caller-provided trusted CA, no redirects/proxies, separate disposable credentials through WAZUH_REPLAY_BASELINE_USER/PASSWORD and WAZUH_REPLAY_CANDIDATE_USER/PASSWORD, no raw response/error logging. Use separate isolated stacks/ports or distinct isolated test integration UUIDs. Do not use production port forwards. Review actual integration membership, enabled rule version, field mappings and isolation before the run. The tool cannot verify loaded version matches supplied asset bytes or that the endpoint is truly disposable.

Input JSON has split:"holdout", controls (2–20 rows) and rows (1–1000). Each item has an opaque id, label (malicious/benign/unknown; controls must contain both malicious and benign), and normalized input object. Holdout labels must be independently curated; controls are disjoint by ID and excluded from metrics. Positive and negative controls must pass on both sides before AND after the paired run. Every response must be HTTP 200 with structured message.status=success, exactly one evaluated rule, and reconciled zero/one matches. Any error or mismatch aborts; no retry or missing-result substitution. The 15-second HTTP timeout is per request; 1000-row jobs can take substantial time and load.

Example invocation (use disposable targets only):

```
python3 tools/incident_tuning_replay.py --confirm-disposable \
  --fixture holdout-normalized.json --output replay-result.json \
  --baseline-url https://127.0.0.1:19200 --baseline-integration BASELINE_UUID \
  --baseline-ca lab-ca.pem --baseline-rule baseline-rule.json \
  --candidate-url https://127.0.0.1:19201 --candidate-integration CANDIDATE_UUID \
  --candidate-ca lab-ca.pem --candidate-rule candidate-rule.json
```

The output envelope contains fixture (extract for the dashboard paired evaluator or incident proposal) and receipt (input digest, canonical outcome digest, control count, rule-asset file hashes via fixture, integration IDs, completion time). Raw events are never output. Asset hashes are operator-supplied file provenance, NOT verified loaded version hashes; retain actual content snapshots and integration membership independently. This runner evaluates stateless normalized-event matching only; it cannot certify normalization, correlation thresholds, time windows, stateful detector behavior, incident labels or production coverage. Local mock tests validate contract and failure handling; an actual disposable RC2 stack and real Security Analytics percolation remain mandatory before interpreting any live result.
