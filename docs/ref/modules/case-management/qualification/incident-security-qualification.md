# Disposable security qualification

These are test fixtures, not a production role replacement. Do not run securityadmin or overwrite the installed roles file. Create disposable identities in an isolated RC2 cluster; map each to the explicit role fixture plus only the minimal dashboard login and finding read permissions required by the scenario. Inspect the UNION of effective roles (including built-in roles, aliases and backend-role mappings). No ordinary test identity may directly read or write either hidden incident index. Existing privileged administrator identities are outside the analyst threat model.

## Activation and control cases

1. With both flags omitted, verify the original Case Management UI works; incident REST routes are unavailable, incident transport actions deny execution, and fresh clusters have no incident indices.
2. Enable the indexer flag on every node and the dashboard flag only on the isolated deployment. Check setup creates exactly the two hidden strict indices, no findings retention policy is attached, and restart does not wipe data.
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
