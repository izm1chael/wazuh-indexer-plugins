# Disposable security qualification

These are test fixtures, not a production role replacement. Do not run securityadmin or overwrite the installed roles file. Create disposable identities in an isolated RC2 cluster; map each to the explicit role fixture plus only the minimal dashboard login and finding read permissions required by the scenario. Inspect the UNION of effective roles (including built-in roles, aliases and backend-role mappings). No ordinary test identity may directly read or write any hidden incident or policy index. Existing privileged administrator identities are outside the analyst threat model.

## Activation and control cases

1. With both flags omitted, verify the original Case Management UI works; incident REST routes are unavailable, incident transport actions deny execution, and fresh clusters have no incident indices.
2. Enable the indexer flag on every node and the dashboard flag only on the isolated deployment. Check setup creates exactly the three enabled hidden strict indices (incident, activity and correlation policy; the execution ledger is staged and must not be provisioned), no findings retention policy is attached, and restart does not wipe data.
3. Confirm the role fixtures resolve to the registered action names, and the current-user dashboard client propagates the authenticated user.
4. Create a test incident as the analyst, record its UUID and revision. Use synthetic findings in two separate document-level security scopes.

## Required role matrix

| Scenario | Reader | Analyst (owner) | Creator-only | No incident access |
| --- | --- | --- | --- | --- |
| Queue/detail/activity/finding references | Allow | Allow | Deny | Deny |
| Create standalone incident | Deny | Allow | Allow (mutation response only) | Deny |
| Claim unassigned incident | Deny | Allow | Deny | Deny |
| Edit, triage, activate, close, reopen | Deny | Allow valid transitions | Deny | Deny |
| Update another owner's incident | Deny | Deny | Deny | Deny |
| Attach/detach visible finding | Deny | Allow valid owner and revision | Deny | Deny |
| Attach/detach forbidden finding | Deny | Deny | Deny | Deny |
| Raw backing index GET/search/mget | Deny | Deny | Deny | Deny |
| Raw index create/update/delete/bulk | Deny | Deny | Deny | Deny |

A creator-only grant returns the created/current incident summary to that caller as part of the mutation response; it is not an arbitrary read grant. Verify a replay after another user has modified an incident does not unintentionally expose data outside the documented single-SOC model. If the policy requires reader permission for any mutation response, tighten the design before deployment.

## Direct bypass and visibility tests

- Use explicit private index names, wildcard patterns (including hidden expansion), aliases if present, mget/msearch, bulk create/index/update/delete and direct transport action invocations. Use disposable records only. Assert 403 for unauthorized actions and no backing-state changes; a 404 from a missing index is not proof of denial.
- A caller with only the create action must not select close, edit or attach through a transport operation field. Try body fields for owner, actor, audit identity and target index. Reject unknown or duplicated fields. Verify username is derived from the authenticated security context.
- For visible/forbidden/expired finding references, verify actual DLS/FLS behavior and no system-privileged fallback. Confirm that all missing or denied links are indistinguishable in the public response and audit history omits reference IDs. Attempt a forged detach and verify no membership oracle or mutation.
- With activity delivery pending, ensure the API reports the observed state without implying delivery. Kill/restart the node between aggregate commit and event delivery, then between event delivery and acknowledgement. Verify one event per revision, no silent overwrite, no erased pending event.
- Race two analysts on the same revision; only one mutation can commit. Repeat a create with the same actor/key/payload; verify one incident and creation event. Different payload with same key must conflict. Repeat with a different actor to check scope.
- Disable the feature again; confirm REST access ceases and transport execution fails closed, while backing records remain. Recheck direct index restrictions independently.

## Evidence required

Record exact artifact SHAs, node settings, role definitions and effective-role inventory (no secrets), request/response status and redacted payloads, before/after state counts and revisions, audit-event identity uniqueness, and failover/restart observations. Report PASS/FAIL/BLOCKED separately per scenario. Do not infer deployment security from unit tests or hidden index names. Full production activation requires a passing real-cluster matrix, including direct-index bypass, and operator approval.

### Collaboration scenarios

- Reader can retrieve notes and tasks via the dedicated collaboration projection but cannot add notes or mutate tasks. Analyst may add an attributed note to an open incident even if not owner; only the owner may change tasks. Creator-only/no-access must not read collaboration or invoke the collaborate action.
- Verify note text never appears in ordinary activity projection or incident summary. Assert no actor spoofing, no edit/delete path, no task mutation on closed incidents, no foreign task ID mutation, and no stale revision overwrite. Test over 20 notes and pagination, pending note delivery recovery, and task cap enforcement.


### Correlation preview scenarios

- Use the dedicated disposable correlation reviewer role, plus narrowly scoped finding search permissions. No default role is changed. Verify reader-only, analyst without preview grant, and no-access identities cannot invoke the preview. A preview grant alone must not bypass finding access.
- Under DLS/FLS, inspect that only permitted matching hits and permitted source fields influence results. In particular test a filtered rule field used in the query, redacted identity fields, hidden data streams and document references. Block rollout if matching/count behavior reveals restricted facts.
- Verify a full aligned interval, an invalid unaligned interval, 1,000 vs 1,001 matches, missing stream, unavailable shard, timeouts, rule UUID case/format, mixed representations and stable replay/group IDs. Confirm zero incident, activity, policy or evidence writes. A successful search does not prove all events arrived.

### Saved policy and staged reservation scenarios

- Verify the separate policy read/save grants. A preview reviewer without policy grants cannot save or load definitions; a policy reader cannot save; an author cannot automatically execute, nor search findings without the separate preview and finding permissions. Test direct access to the policy index with each role, including wildcard/hidden expansion.
- Save a definition, repeat with rule order reversed and verify exactly one version document and the original author/time. Different content with the same UUID/version must return 409. A new version may be saved but never changes the old version or activates it. Reject supplied actor, mode, index, unknown fields, duplicate rule IDs and invalid version/window/threshold. Verify read by exact version and not-found handling. Test parallel conflicting saves.
- No policy mutation or preview may provision the staged execution ledger, write an execution reservation or create an incident. Verify the reserved deterministic identity separately with synthetic groups on a disposable ledger: same group and deployment/membership replay; reordered references replay; changed membership conflicts; different deployment produces a different incident UUID. The ledger is not registered and has no terminal outcome mechanism. Do not infer completion or execution safety from successful reservation.

### SOC operational metrics

Metrics require the dedicated metrics_read grant and single-SOC disclosure approval (owner names and workload counts). No direct backing index grants. Test no-access and ordinary incident reader denial, flag off, invalid/future ranges, 5,000 versus 5,001 union records, timeout and missing shard/index. Verify created-cohort versus all-open denominators; exact-boundary SLA breaches, missing/invalid times, reopened incidents and triage-only closures. No detection-to-identification metric is claimed without an authoritative originating detection timestamp. No finding-source access or mutation should occur.

### Response governance

Validate response_read, response_request, response_approval and response_outcome separately. A requester must be the current incident owner; approvals and rejections must be by a different authenticated actor. Test a user holding both grants attempting self-approval, cross-incident response IDs, stale revisions, duplicate outstanding intent, unknown fields, caller-supplied actor/execution state and attempts to execute commands. The separate outcome grant permits manual reports only after approval. Confirm execution_verified is always false, no manager or endpoint calls occur, pending audit blocks mutations, and outstanding requests block incident closure. Response detail requires separate read grant; ordinary summary/collaboration and general activity omit the response content (event kind, actor and time remain visible). No raw index permission is granted. Validate role combination and direct transport invocation under actual security plugin. All response data is within the explicitly approved single-SOC scope.

- Issued records: verify original caller security context is restored after aggregate and finding lookups. Require response stream search permissions and exact pair of visible source index + document ID (not ID alone); reject ambiguous arrays, mismatched index, and missing FLS reference fields. Test expiry, aliases, missing stream, 100/101 hits, timeouts, forbidden source finding, and no raw executable/arguments in projection. Issued-only records must never update governance outcome or indicate verified execution.

### Investigation playbooks

Verify separate playbook_apply grant, current owner requirement, revision conflict, pending audit block, closed incident rejection, fixed template ID/version validation, condition recheck at apply time, and all-or-nothing capacity. Repeat application of the same version must conflict without new tasks; parallel applies may not allocate duplicate tasks. Compare exact receipt membership against task IDs and audit. No arbitrary task list, condition DSL, command, webhook, manager API or scheduler is accepted. Test both manual and generated task completion and old incidents without playbook history. Read visibility follows existing collaboration/incident read permissions. No default role change or direct index permission.
