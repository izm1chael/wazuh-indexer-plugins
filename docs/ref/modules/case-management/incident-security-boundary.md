# Incident security boundary (staged)

The indexer, not the dashboard, is the authority for incident mutations. This follows the existing AI-assistant privileged transport action pattern. The TypeScript domain and store in the companion dashboard fork are reference/test scaffolding only; production dashboard routes must call a dedicated indexer action as the authenticated current user. Never register a generic dashboard-to-privileged-index transport proxy.

Initial scope is a single SOC. All approved readers may see all incidents in that SOC, including TLP-labelled data; labels are not access controls. Explicit supervisor reassignment, tenant isolation and finding-level permission projection require further design. The initial indexer mutation rules permit self-assignment and owner-only changes; a caller cannot arbitrarily assign another identity or steal an owned incident.

## Required security actions

- Read/list activity and incident summaries: `cluster:admin/wazuh/incident/read`.
- Creation: `cluster:admin/wazuh/incident/create`.
- Self-assignment / return new incident: `cluster:admin/wazuh/incident/assign`.
- Triage, activation, metadata: `cluster:admin/wazuh/incident/update`.
- Classified closure: `cluster:admin/wazuh/incident/close`.
- Finding relationships: `cluster:admin/wazuh/incident/findings`.
- Reopen: `cluster:admin/wazuh/incident/reopen`.
- Recovery: separate internal worker or administrator-only action, not an analyst grant.

Separate transport actions (or explicit security-plugin-enforced per-command permission checks) must be registered before any route is enabled. A caller holding only one permission must not be able to select another operation through a request field. Resolve the caller from the security thread context before stashing it; missing or shared sentinel identity fails closed. Validate the exact input allowlist in the indexer, not merely the dashboard. Do not grant direct index reads/writes to ordinary analysts until the permission model is qualified; administrative users remain trusted.

## Activation gates

- Verify the actual security role configuration in the Wazuh indexer distribution and prohibit broad `wazuh-*` grants from bypassing the action boundary. Test direct GET/search/index/update/delete/bulk and unauthorized transport actions with real roles.
- Test transport serialization, principal propagation, API denial, optimistic concurrency, create idempotency, ambiguous write outcomes and pending event recovery.
- Read finding evidence under the original caller context before any privilege elevation; do not persist evidence into a broader-readable case without policy review.
- Staged repository/mutation/REST classes do not register actions, provision indices or grant roles. They are not a deployable feature yet.

## Staged write REST contract

- POST `/_plugins/_setup/incidents` with title, severity, optional description/priority/TLP.
- POST `/_plugins/_setup/incidents/{uuid}/{command}?expected_revision=N` with a command-specific JSON object.
- Commands: assign-self, unassign, start-triage, activate, edit, close, reopen, attach-finding, detach-finding.
- Each route maps to a distinct fixed action grant, not an arbitrary action supplied by a caller.
- Success returns `{incident, activity_delivery}`; pending means the mutation committed but delivery is not confirmed. No claim of request idempotency yet.
- The incident projection omits the pending audit payload and individual finding references. The count remains visible within the single-SOC case read boundary. A later link read API must recheck finding visibility under the reader's own permissions; activity containing reference metadata also requires a redaction policy before exposure.
- The current implementation bounds each aggregate at 1,000 active references; a subsequent capacity review can migrate to a separate relation index without exposing partial writes.

## Opt-in and create retry contract

The indexer setting `plugins.setup.incidents.enabled` is false by default. REST handlers and index setup are conditional; transport execution separately fails closed. Enable only on an isolated qualification cluster after reviewing actual roles; this is not an RBAC deployment recipe. Disabling does not delete stored data or revoke any pre-existing direct index grants. All nodes must use the same setting.

Create now requires a client-generated canonical UUID `request_id` in the JSON body, retained by the client for the same logical create attempt. The server derives the incident UUID from authenticated actor + key and persists a fingerprint of the validated normalized creation fields atomically with the aggregate. A matching create conflict returns the current incident with `replayed: true`; a changed payload returns 409. No new creation activity is emitted on replay. Ordinary commands still use expected revision and must reload on ambiguous failure. The internal fingerprint is not exposed in read or mutation responses. Never retry a creation with a newly generated key after an ambiguous outcome.

## Scheduled recovery

When the opt-in setting is enabled, the elected cluster manager runs a bounded asynchronous outbox sweep every 30 seconds. Each pass reads at most 25 pending incident identities in stable ID order, then re-reads their current aggregate before delivery. A create-only audit write and compare-and-set acknowledgement protect against overlapping execution after failover. Individual failures do not stop the page or permanently block later IDs; the cursor wraps after a pass. The worker uses no external service and is cancelled when the plugin closes. Recovery remains unqualified: validate scheduler lifecycle, failover, incomplete search, poison events, partial failures and real concurrent writes. Pending does not imply delivered and an indefinitely failing event must be investigated.
