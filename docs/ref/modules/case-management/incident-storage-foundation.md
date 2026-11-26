# First-class incident storage (development proposal)

Status: staged, not provisioned or enabled by default. Baseline: Wazuh v5.0.0-rc2.

The existing findings API and findings retention remain unchanged. A standalone incident is authoritative for its workflow; it is never stored in or deleted with a finding. The initial templates use exact index names and strict mappings, not the findings data stream. No automatic expiry or rollover is attached; configurable archival and retention will require a separate reviewed policy.

| Index | Document identity | Purpose |
| --- | --- | --- |
| wazuh-cases-v1 | Server-generated UUID | Current incident aggregate and one pending activity event |
| wazuh-case-activity-v1 | incident UUID + ":" + logical revision | Immutable lifecycle activity |

## Atomic mutation and activity delivery

Every logical mutation must use an OpenSearch sequence-number/primary-term compare-and-set on the aggregate (create-only for new incidents). The same write increments its logical revision and persists the pending activity event. A subsequent mutation must not overwrite an undelivered pending activity event. The writer or recovery worker creates the activity document using op_type=create; on a conflict it must verify identical contents before acknowledging it. Clear the pending event using a new compare-and-set without incrementing the logical revision. A crash at any intermediate step must be recoverable; a failed or partial delivery must not be reported as an uncommitted mutation. No default delete action is permitted.

The activity record captures actor, server timestamp, action kind and before/after changes. It is not a security boundary until permission and direct-index bypass tests are passed.

## Access boundary / activation gate

The templates are intentionally not registered in SetupPlugin until the access model is reviewed. Existing broad index permissions must not silently grant incident access. Use dedicated actions and an authenticated server-derived principal; deny arbitrary direct writes, deletes and field spoofing. Explicitly verify the role configuration in the indexer distribution, cross-tenant visibility, finding access, activity immutability and backup/restore before provisioning any real data.

The first implementation supports a single SOC boundary only; team isolation is not claimed. Do not deploy these assets into production. Evidence links, comments, tasks and automation are subsequent schemas. The legacy case metadata remains available as finding triage until a verified migration is implemented.
