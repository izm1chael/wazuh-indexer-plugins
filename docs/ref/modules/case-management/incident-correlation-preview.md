# Correlation preview foundation (not automatic incident creation)

The deterministic planner groups explicit, allowlisted rule UUIDs by exact Wazuh cluster name, agent ID and UTC time bucket. It only accepts observations produced by trusted authorized callers. Missing time/scope/rule, conflicting rule identities, and conflicting duplicate facts are not guessed. Same finding identity is counted once. Each policy is identified by UUID and version, supports a 5–1440 minute fixed tumbling window and minimum of 2–100 findings. A preview accepts at most 1,000 candidates and at most seven days of input range. Group keys are deterministic across arrival ordering and contain policy and window identity; this is not a proof of real-world identity or a complete correlation search.

## Deliberate limits

- A dedicated read-only current-user preview API is registered under the incident opt-in flag. No scheduler, persisted policy configuration, grouping ledger, privileged worker, automated case creation, update or reopen has been registered.
- Fixed windows split findings at boundaries; a group can be incomplete when the input range or result cap truncates a window. A future execution service must verify full-window coverage and persist a checkpoint before committing outcomes.
- Agent IDs are cluster-scoped, not globally unique. Cluster-name collisions and agent ID reuse across deployments must be ruled out or addressed with stronger deployment identity before automatic execution. No IP-only, username-only or cross-rule grouping by default.
- Group identity includes the entire sorted allowed-rule list and policy parameters; any policy change should still advance the version. Never treat the key as authorization or a secret.
- Preview classification is not a detection verdict; it only identifies candidate groups.

## Execution gates

Implement ingestion completeness receipts, late-arrival policy, durable idempotency and group-to-incident ledger; decide automation principal, read/disclosure scope, retention and failure behavior. Use dry-run comparison against manually labelled findings and qualify concurrency/replay, source expiry, retries, false grouping and disabled-by-default activation. No production automatic writes until reviewed.

Correlation identities deliberately reject arrays, malformed alternate rule UUIDs and mixed nested/dotted representations; display extraction remains more permissive. This may exclude valid but unusual source documents and must be measured during qualification.


## Current-user preview API

POST `/_plugins/_setup/incident-correlation/preview` requires the dedicated `cluster:admin/wazuh/incident/correlation_preview` action and the caller's existing finding search privileges. The body has exactly seven fields: policy_id, policy_version, rules (canonical lowercase UUIDs), window_minutes, minimum_findings, from and until (UTC timestamps). The time range must align with complete fixed UTC windows, be at most seven days, and the search is limited to 1,000 matching visible hits. A fixed query over `wazuh-findings-v5*` selects exact canonical rule UUID terms and a half-open time interval. Rule fields are mapped as keyword; noncanonical uppercase rule strings are not selected by this query. No user-provided index, query or source fields are accepted. Missing indices, incomplete shards, timeout, early termination or truncated results are errors, not zero findings.

This is a search snapshot under the requesting user, not a globally complete window or ingestion watermark. Document/field-level security, actual keyword value representation, missing/late events, multi-node permissions and partial index availability must be qualified. Do not schedule this endpoint as an internal service or automatically create incidents from its response. A separate trusted execution principal and policy ledger are still needed. The revised group digest includes the sorted rule allowlist to avoid accidental key reuse when previewing changed policy contents.
