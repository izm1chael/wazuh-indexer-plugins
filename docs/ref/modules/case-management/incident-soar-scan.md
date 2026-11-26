# Governed native response execution: single-agent vulnerability scan

Development candidate, default off, not production qualified. Extends existing incident response governance, not a generic command runner. No TIP expansion.

## RC2 compatibility and scope

The native [Wazuh v5.0.0-rc2 API specification](https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/api/api/spec/spec.yaml), blob d6fd7eb7d2978ce09ae3d262b2e873ec4f981b37, exposes PUT /agents/scan/vulnerability with agents_list and agent:scan_vulnerability permission. GET /agents provides exact agent inventory; agent:read is required. The specification does not expose the legacy /active-response REST path. Existing finding-linked issued active-response records remain read-only and are not changed. Restart, reload, containment, firewall blocking and arbitrary commands are NOT implemented by this phase. No native API was called in development.

## Workflow and safety boundary

1. Incident owner requests typed scan_vulnerability intent on a triaging or active incident with scope exactly manager-uuid:agent:NNN (3–8 numeric characters, nonzero). Manager UUID is operator-assigned configuration identity, not a native manager-attested identity. Approval requires separate reviewer through existing response approval permission. Approval alone does not dispatch.
2. Operator explicitly invokes dedicated one-shot runner with incident ID, response ID, current revision, exact agent and confirmation flag. Runner authenticates to fixed HTTPS manager origin and dedicated indexer origin using separate credentials and trusted CA files. No redirects, proxies, arbitrary commands, URLs, broad target, or automatic scheduling.
3. Indexer checks default-off SOAR gate, incidents enabled, exact configured authenticated dispatcher, manager UUID, exact allowed agent and response scope, fresh approval (one hour), distinct requester/reviewer/runner, current incident revision, valid state and no pending audit. CAS commits dispatch_reserved with attributed immutable activity. Only after outbox delivery is confirmed does the runner receive a reservation receipt. Lost/ambiguous reservation response never authorizes dispatch and cannot be automatically replayed.
4. Runner checks receipt identity, exact revision/actor/scope and false execution_verified, then performs GET /agents with exact agents_list, selected id/dateAdd/status/version and limit 1. Requires exact single active v5 agent and the operator-pinned dateAdd enrollment timestamp. Rechecks reservation freshness (60 seconds; clocks must agree). Sends one PUT /agents/scan/vulnerability?agents_list=NNN. No automatic retry. Manager response counts must reconcile to exactly one selected agent, no failures, error 0; otherwise outcome is ambiguous, including preflight failures. A preflight failure sends no PUT. TLS endpoint binding and dateAdd check reduce accidental mistargeting but do not prove atomic agent identity: re-enrollment between preflight and dispatch remains possible; enrollment pin is local configuration, not part of the approval record. Operators must freeze target/config changes while dispatching.
5. Runner reports manager_accepted or dispatch_unknown through dedicated revision-controlled transport. Receipt and report are **runner attestations**, not independently verified manager evidence. The indexer does not call manager or hold manager credentials. Manager acknowledgement is admission only; execution_verified remains false. A concurrent incident edit or lost report can leave dispatch_reserved even after a native request. No claim of exactly-once remote effects, no automatic retry, no rollback.
6. Until independent human reconciliation, requested/approved/reserved/accepted/unknown responses block incident closure and duplicate same-scope requests in that incident. Cancel allowed before reservation only. Manual outcome permitted to a response-outcome-authorized reviewer distinct from requester and dispatcher; reserved state requires 15 minutes elapsed and operator stopping runner/inspecting actual manager and endpoint state. Reported completed/failed/not_performed remain unverified human attestations. Existing activity preserves reserve/report history. The 15-minute guard is not remote cancellation; no scan cancellation API is introduced.

## Activation and operational boundaries

Apply only to disposable qualified environment first; all nodes must have identical configuration. Example settings (replace placeholders with reviewed values):

```yaml
plugins.setup.incidents.enabled: true
plugins.setup.incidents.soar.enabled: true
plugins.setup.incidents.soar.actor: "wazuh-soar-runner"
plugins.setup.incidents.soar.manager_id: "00000000-0000-4000-8000-000000000002"
plugins.setup.incidents.soar.agents: "001"
```

Grant indexer runner only cluster:admin/wazuh/incident/soar_dispatch (isolated fixture); no direct hidden index rights. Use a separate native manager account with agent:read and agent:scan_vulnerability scoped to exact approved agent IDs, not wildcard, restart/reload or administrator. Restrict protected host/config/credentials and network to actual TLS origins. Manager credentials inherently permit native calls outside the indexer workflow if misused; treat runner host and account as trusted, not an untrusted sandbox. Use a single controlled operator/runner and do not concurrently issue scans against same agent across cases. No global rate limiting or target lock across distinct response requests, and no general scheduled dispatch queue. Do not use example credentials or hostnames. Stop runner and reconcile outstanding states before disabling or changing gates, manager, accounts or allowed agents.

Use examples/soar-scan.example.json as inert template. Install both incident_soar_scan.py and incident_analytics_runner.py (shared parsing/redirect helper). Protect WAZUH_SOAR_INDEXER_PASSWORD and WAZUH_SOAR_MANAGER_PASSWORD outside repository and command line. Explicit invocation only after reviewing live incident and qualification:

```sh
python3 tools/incident_soar_scan.py --config /etc/wazuh-soar/scan.json --incident <uuid> --response <uuid:revision> --revision <current-revision> --agent <exact-id> --confirm-approved-scan
```

No automatic install, no timer. New request is not a retry mechanism: investigate any ambiguous outcome and verify action state before a fresh independently approved request. No durable raw manager response or scan result retained. No source finding data or credentials sent to AI. No new backing index; response_requests is already an unindexed aggregate field. Matched upgraded builds required; governed_response_tracking replaces manual_tracking_only (dashboard supports legacy manual-only projection with no scan intents).

## Qualification

- Build exact final indexer/dashboard heads; execute Java, Jest, Python role and runner regression suites. Verify actual RC2 API semantics on isolated active v5 agent, agent read and scan RBAC scoped to the test target, token schema, dateAdd format, selected fields, manager response shapes, TLS CA/hostname, duplicate JSON, redirect and proxy rejection. No real scan in production.
- Test independent requester/reviewer/runner, default-off, wrong scope/manager/actor/role, wildcard and zero agent, approval expiry, target not allowlisted, current revision and pending activity, no dashboard dispatch proxy. Confirm old manual response workflows unaffected.
- Inject failures before/after CAS and audit, lost reservation acknowledgement, stale reservation, changed agent enrollment/status/version, wrong/partial manager acknowledgement, manager timeout after send, concurrent operator/analyst change and lost report. Confirm no additional PUT on retry, no closure or duplicate until reconciled, no raw response data/credentials, one-shot workflow cannot cancel already queued action. Test independent reconciliation and outbox recovery. Test browser with matched upgrade and live permission matrix.
- Measure scan load and manager/endpoint resource behavior. Document target configuration and re-enrollment procedures; no automatic retries or unattended actions. Verify actual downstream execution via separate evidence before claiming completion.

Cloud evidence: exact committed runner blob 9f9076ee15527195649512282c3cd195aa94085a, dependency 535e84c8dca0d05a890dc5877953e223d46237d2, and test blob 901b24892ab56e70212c28bd382310f03f0d6f92 verified using git hash-object; Python compilation and all eight mocked transport unittest cases passed. 24 source-level cross-repository checks passed. Java/Jest and role regression sources committed but full plugin builds, live manager/indexer API and RBAC, browser and real scan execution unqualified.

Remaining SOAR phase: durable general playbook execution/step ledger, discover supported native response mechanisms beyond the checked API spec, safe external integrations, verified result ingestion, independent audit evidence, failure health views, rollback where native operation supports it, cross-incident target concurrency/rate control. No claim of complete SOAR or Sentinel parity.
