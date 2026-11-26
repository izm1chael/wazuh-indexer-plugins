# Persistent governed response playbooks

Development candidate, default off, not production qualified. Extends the existing native SOAR scan connector and response governance. Distinct from built-in human investigation checklists. No TIP expansion, no core Wazuh changes, no additional endpoint command, no AI calls.

## Delivered scope

Two built-in, immutable version-1 executable workflow templates:

| Template | Response operation |
| --- | --- |
| vulnerability_investigation | scan_vulnerability (exact configured manager UUID:agent:NNN scope) |
| evidence_collection | collect_evidence (manual response, human-readable scope) |

The run orchestrates actual investigation task and response mutations rather than storing an unrelated list of checkboxes. It does not independently approve or execute a native response, create a new external connector, or claim endpoint execution. The incident owner explicitly advances each checkpoint; an independently approved scan still requires the separately configured one-shot runner from incident-soar-scan.md. An evidence collection outcome remains manual.

1. Start: assigned triaging/active incident, no pending handover or audit, exact template/version/scope/reason, at most ten lifetime runs and one active run per incident. Atomically create preparation task and run (run ID and preparation task ID are incident UUID plus new revision).
2. Prepare: complete the exact linked task using existing task permission. Explicit advance checks its current completed status, exact identity, creation actor/time and valid completion attribution. Atomically creates the typed response request using the existing response mutation and records the response step. No other response is substituted. Existing response capacity, duplicate scope and eligibility checks still apply.
3. Response: existing independent response approval/outcome governance, and optional native single-agent scan runner. Requested, approved, dispatch_reserved, manager_accepted and dispatch_unknown all wait; none imply successful completion. Advance only on an actual terminal response. Rejected/cancelled/reported_failed/reported_not_performed transitions to terminal failed with observed response state and no subsequent task. reported_completed creates the linked evidence review task and records the review step. This is a human-attested response outcome, including if the action was manually performed outside the runner; not independent execution evidence.
4. Review: complete the exact review task, then explicitly advance to terminal completed. Completion is an analyst attestation, not verified execution, independent evidence verification or automatic incident closure.
5. Cancel: owner supplies reason during preparation/review or after the linked response is terminal. No cancellation while response is outstanding; use existing response governance to resolve it first. A cancelled workflow does not cancel any native operation or delete/reopen tasks or response records. Completed/failed/cancelled runs cannot restart or advance. New runs require new explicit request and capacity.

Each run contains immutable identity, template/version, scope/reason and up to four attributed transition entries (stage, incident revision, actor, timestamp, exact created task/response reference where applicable, observation). Transition metadata and linked record writes use the existing single aggregate CAS/outbox. All steps persist in workflow_runs; existing immutable activity retains full transition and task/response changes. Public activity exposes only workflow ID and stage. Stored histories validate allowed progression, increasing revisions, unique/nonoverlapping run intervals, exact task creation identity/attribution and response type/scope/reason/actor/time. Current checkpoint readiness derives from current linked task or response state, not caller-supplied state. Task completion is a historical observation when advanced; later reopening a previously completed task does not undo prior transitions. Existing task audit is the historical evidence, not a new independently signed checkpoint receipt.

A stale or lost mutation response is ambiguous; reload incident and exact run before retrying. Existing CAS prevents a duplicate action at the same revision; do not automatically retry with a new revision. No new native dispatch retry or rollback semantics. Active workflow and unresolved response both block case closure. Workflow cancellation retains tasks and response history; no force-close shortcut. Handover may transfer ownership; the current owner can continue only after handover resolves.

## Permission and configuration

New dedicated grant cluster:admin/wazuh/incident/workflow_operate authorizes only start-workflow, advance-workflow and cancel-workflow. This deliberately permits the fixed task creation and typed response request as part of the workflow mutation; it does not grant arbitrary task management, ordinary response request routes, approval, outcome reporting, or scan dispatch. Existing collaborate grant is needed to complete tasks, existing response_read to inspect runs, response_approval/outcome for reviewers, response_request to cancel a linked outstanding response, and soar_dispatch for the separate native runner. Ordinary incident_read exposes only safe activity labels, not full workflow scope/reason or linked response details. Shared single-SOC boundary; no per-case ACL. Operator must be current owner and authenticated.

```yaml
plugins.setup.incidents.enabled: true
plugins.setup.incidents.workflows.enabled: true
```

Both default off; workflow start/advance require both flags. Cancellation remains available with workflows disabled (incidents must still be enabled, normal owner/handover/audit/response guards apply), so the operator can resolve an active run before shutting down functionality. Native scan dispatch has its own independent SOAR gate and actor/target configuration. No UI activation or automatic scheduler introduced. Keep all nodes on matched configuration and builds.

Additive unindexed workflow_runs object field in strict .wazuh-cases-v1 mapping. Existing incidents with absent field use empty history. **Apply/verify additive mapping before upgraded incident writers start, even if workflows remain disabled.** Back up first; do not run mixed old/new writers. No new backing index, no deletion/archival of run records.

Read through existing response_read endpoint: governed_response_tracking adds workflow_runs containing normalized run and derived observed_state/can_advance/can_cancel. Older responses omitting field remain compatible; dashboard hides workflow controls rather than pretending there is empty history. Dashboard response panel shows run history, current checkpoint, exact linked record, start/advance/cancel. Existing task and response UI remains authoritative. No direct dashboard runner/manager execution proxy.

## Disposable integrated qualification

- Build matched RC2 forks and run Gradle, Jest and Python suites. Verify additive strict mapping, normal incident creation and legacy documents with workflows off, backup/restore, no mixed writers. Real action grants and role matrix, exact route/grant binding, owner vs non-owner, no approval or dispatch via workflow grant, no direct index privileges, default-off and cancel during disable.
- Test both templates with invalid scopes/versions, one active/ten lifetime cap, task/response capacity, pending handover, owner change, stale revision, pending audit and clock rollback. Preparation task reopen before advance blocks, reopening after historical advance does not rewind. Confirm exact response identity, no alternate response substitution and no duplication. Validate missing/corrupt references and impossible transitions fail closed.
- Test all response states: requested, approved, reserved, manager_accepted, dispatch_unknown are waiting; terminal failures stop without review task; reported_completed alone allows review creation (unverified). Verify linked response cancellation uses existing guard. Review task completion before workflow completion. Cancellation cannot bypass outstanding response or imply rollback. Closure blocked while workflow active, independently blocked by outstanding response. Test audit projection omits scope/reason.
- Inject concurrent analyst updates, duplicate clicks, CAS conflict, lost response, failed outbox delivery and process restart between each checkpoint. Verify a single task/response per committed step, audit recovery and explicit reload; no automatic redispatch. Browser: exact revision refresh, stale/missing workflow history, unavailable permissions, controls disabled on pending activity/closed/handover, no false success.
- Native execution only in disposable qualified test environment, separately follow incident-soar-scan.md. No claims of verified endpoint completion without independent evidence.

## Cloud qualification evidence

Exact committed Java blobs IncidentWorkflowRuns.java 0c469436a666a7408a460a89526e7440b6cf1e62, IncidentTasks.java 1d72fa297b6747eb6c7a3359cc60478ac03f8d1c and IncidentResponses.java ae3c7a70f4ad400aef82eaa603fa077d36c3d056 reproduced and verified with git hash-object. Compiled with javac 21 using minimal OpenSearch exception/status and mutation enum stubs plus extracted projectTasks; 30 standalone pure Java assertions passed with actual task/response/workflow classes. This does not exercise real IncidentMutation, transport, repository, CAS/outbox or OpenSearch runtime. Exact TypeScript workflow-validation.ts cb43e0daa03ed45310e138fe52dd173d1502c0be and workflow-validation.test.ts 6dfa74b5c4abf480fc773fa901bffca685ad45a5 reproduced and verified, compiled strict with extracted relevant contracts and test globals; all three test groups passed under standalone Node harness (22 validator invocations, 15 explicit assertions). Not full Jest. 34 cross-repository source checks passed. Full Java/Jest/Python plugin builds, live permissions/CAS/outbox, browser and real native calls remain unqualified.

Remaining SOAR: operator-authored workflow definitions, durable automatic trigger/step worker, connector framework, cross-incident target locks, verified result evidence, scoped external integrations, cancellation/rollback only where supported, execution health/SLA. Current templates use explicit checkpoint advancement and existing independently governed response operations. No general script execution, arbitrary integrations, or unattended endpoint response.
