# Correlation preview foundation (not automatic incident creation)

The first deterministic planner groups explicit, allowlisted rule UUIDs by exact Wazuh cluster name, agent ID and UTC time bucket. It only accepts observations produced by trusted authorized callers. Missing time/scope/rule, conflicting rule identities, and conflicting duplicate facts are not guessed. Same finding identity is counted once. Each policy is identified by UUID and version, supports a 5–1440 minute fixed tumbling window and minimum of 2–100 findings. A preview accepts at most 1,000 candidates and at most seven days of input range. Group keys are deterministic across arrival ordering and contain policy and window identity; this is not a proof of real-world identity or a complete correlation search.

## Deliberate limits

- No scheduler, index search, configuration API, persisted grouping ledger, privileged worker, automated case creation, update or reopen has been registered. The planner is pure and not exposed as a REST endpoint.
- Fixed windows split findings at boundaries; a group can be incomplete when the input range or result cap truncates a window. A future execution service must verify full-window coverage and persist a checkpoint before committing outcomes.
- Agent IDs are cluster-scoped, not globally unique. Cluster-name collisions and agent ID reuse across deployments must be ruled out or addressed with stronger deployment identity before automatic execution. No IP-only, username-only or cross-rule grouping by default.
- The group key is stable for a policy/version; any change to its allowed rules must advance the version. Never treat the key as authorization or a secret.
- Preview classification is not a detection verdict; it only identifies candidate groups.

## Execution gates

Implement trusted bounded source discovery, complete-window receipts, late-arrival policy, durable idempotency and group-to-incident ledger; decide automation principal, read/disclosure scope, retention and failure behavior. Use dry-run comparison against manually labelled findings and qualify concurrency/replay, source expiry, retries, false grouping and disabled-by-default activation. No production automatic writes until reviewed.

Correlation identities deliberately reject arrays, malformed alternate rule UUIDs and mixed nested/dotted representations; display extraction remains more permissive. This may exclude valid but unusual source documents and must be measured during qualification.
