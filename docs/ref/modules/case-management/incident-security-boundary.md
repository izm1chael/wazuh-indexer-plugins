# Incident security boundary (staged)

The indexer, not the dashboard, is the authority for incident mutations. This follows the existing AI-assistant privileged transport action pattern. The TypeScript domain and store in the companion dashboard fork are reference/test scaffolding only; production dashboard routes must call a dedicated indexer action as the authenticated current user. Never register a generic dashboard-to-privileged-index transport proxy.

Initial scope is a single SOC. All approved readers may see all incidents in that SOC, including TLP-labelled data; labels are not access controls. Explicit supervisor reassignment, tenant isolation and finding-level permission projection require further design. The initial indexer mutation rules permit self-assignment and owner-only changes; a caller cannot arbitrarily assign another identity or steal an owned incident.

## Required security actions

- Read/list activity and incident summaries: `cluster:admin/wazuh/incident/read`.
- Creation: `cluster:admin/wazuh/incident/create`.
- Self-assignment / return new incident: `cluster:admin/wazuh/incident/assign`.
- Triage, activation, metadata: `cluster:admin/wazuh/incident/update`.
- Classified closure: `cluster:admin/wazuh/incident/close`.
- Reopen: `cluster:admin/wazuh/incident/reopen`.
- Recovery: separate internal worker or administrator-only action, not an analyst grant.

Separate transport actions (or explicit security-plugin-enforced per-command permission checks) must be registered before any route is enabled. A caller holding only one permission must not be able to select another operation through a request field. Resolve the caller from the security thread context before stashing it; missing or shared sentinel identity fails closed. Validate the exact input allowlist in the indexer, not merely the dashboard. Do not grant direct index reads/writes to ordinary analysts until the permission model is qualified; administrative users remain trusted.

## Activation gates

- Verify the actual security role configuration in the Wazuh indexer distribution and prohibit broad `wazuh-*` grants from bypassing the action boundary. Test direct GET/search/index/update/delete/bulk and unauthorized transport actions with real roles.
- Test transport serialization, principal propagation, API denial, optimistic concurrency, create idempotency, ambiguous write outcomes and pending event recovery.
- Read finding evidence under the original caller context before any privilege elevation; do not persist evidence into a broader-readable case without policy review.
- Staged repository/mutation classes do not register actions, provision indices or grant roles. They are not a deployable feature yet.
