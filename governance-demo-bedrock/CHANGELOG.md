# Changelog

## Unreleased: infrastructure findings from the ASH container scan (2026-10-22)

ASH 3.7.1 ran in its container with every scanner, offline. cdk-nag, cfn-nag and checkov evaluated the synthesized stack for the first time (on Windows cdk-nag and cfn-nag had not run). Every fix is asserted on the synthesized template in `tests/test_scanner_exceptions.py`; each of those tests fails on the code before this change. Nothing was deployed.

### Security fixes
- Every function that wrote evidence held `s3:DeleteObject*` on the evidence buckets, from `grant_read_write`. Object Lock does not stop a simple DELETE: it adds a delete marker, which is not WORM-protected and makes the object look deleted to every reader. `StorageConstruct.grant_objects` now grants only `s3:GetObject`, `s3:PutObject` (and `s3:PutObjectTagging` where approval evidence is tagged) and `s3:ListBucket`, and no function can delete or hide evidence. The data and policy buckets use the same grant.
- The scope enforcer could call `bedrock:InvokeAgent` and `bedrock:InvokeModel` on every resource; it may now invoke only this deployment's agent alias. `bedrock:ApplyGuardrail` covered every guardrail in the account and was granted even with no guardrail configured; it is now granted only with `-c bedrock_guardrail_id`, for that guardrail.
- Buckets did not require TLS (`enforce_ssl`) and none logged access; all now require TLS and deliver server access logs to a new SSE-S3 access log bucket. The trail bucket is versioned.
- The operator alert topic was not encrypted and accepted publishes without TLS. It is now encrypted with a new customer managed key (`DataKey`, rotation on) and requires TLS. The key policy lets CloudWatch alarms publish to it; without that statement every alarm action would fail.
- The data key also encrypts the Lambda environments (except the action group function, whose scope permission boundary grants no KMS action), the log groups and the trail. The key policy lets only this trail use it.

### Reliability and logging
- Eight tables (scope, pending, policy metadata, risk config, framework mapping, runtime drift, agent health, tool authorization) were provisioned at 5 read and 5 write units, including the scope and tool authorization tables on the decision path. All 26 tables are now on-demand with point-in-time recovery.
- EventBridge invokes the post-decision function (decision events) and the engine function (the monthly report) asynchronously, with no dead-letter queue, so a failed decision event and its evidence were dropped after Lambda's retries. Both now send failures to an encrypted dead-letter queue that alarms.
- The Express state machine keeps no execution history and logged nothing; it now logs every event, without execution data, to an encrypted log group. Both API stages write JSON access logs.

### Build
- `governance_constructs/scanner_exceptions.py` records the remaining findings as reviewed exceptions, each with its reason: cdk-nag acknowledgements, and `cfn_nag` and `checkov` metadata in the template. `tests/test_scanner_exceptions.py` runs cdk-nag (`cdk-nag==3.0.2`, added to `requirements.txt`) and fails on any finding without an acknowledgement, on any exception without a reason, and on any `Resource: "*"` statement outside the actions those reasons name.
- `.ash/.ash.yaml` suppresses the detect-secrets matches the container scan found, by rule and file, with reasons: AWS documentation example keys, PEM headers without key material, a sample JWT, placeholder account numbers, generated resource names and encoded test inputs. It also turns off ASH's cdk-nag for repository scans: no template is committed, ASH's cdk-nag wrapper stops on JSON files that are not templates, and the test above checks the stack. `.ruff_cache/` is ignored.

## Unreleased: fixes from the 2026-10-21 security audit

### Security fixes
- Separation of duties on approvals compared IAM principal strings only, so an agent's owner who also held an approver role could approve their own agent's requests under that role. `check_approver_eligibility` now also compares the person behind each principal (`human_identity`: the session name of an STS assumed-role session, the user name of an IAM user), casefolded, and refuses a match. With IAM Identity Center, AWS sets the session name of a permission-set session; check the value in a CloudTrail event before relying on it. For IAM users assuming a role, the role's trust policy must require the session name to be the user name.
- Guardian inspection (`decision_summaries`) scanned the whole decision trace table on every call, so its cost grew with every agent's traffic. It now reads a sparse `ByTraceAgent` index (`trace_agent_id`, `timestamp`) newest first and stops at the requested limit (1 to 100). Delegated-authority traces carry `trace_agent_id` only when the agent id is not empty, since an index key may not be an empty string. The CDK stack and the demo tables define the index. Traces written before this change are not indexed.
- `retrieval_validator` held its invisible-character class as 11 literal invisible characters, including the bidirectional marks U+200E and U+200F (bandit B613). The class is now written with escapes and matches the same code points, and CI no longer skips B613.

### Build
- CI: the workflow token is read-only (`permissions: contents: read`), actions are pinned to commit SHAs, and ruff, bandit, pip-audit, detect-secrets and the CDK CLI are pinned to exact versions.
- The two `urlopen` calls in `tests/test_public_sector_demo_scenarios.py` carry `nosec B310`: they call the loopback demo server the fixture started.
- `.ash/.ash.yaml` replaces `.ash-config.yml`, which ASH 3 does not read and which skipped B310 and B613 everywhere. Each suppression in the new file names one rule, the files it was reviewed in, and the reason; the AWS-internal ASH build's telemetry reporters are disabled so scan results stay local.

## Unreleased: CI runs the whole test suite

### Build
- CI ran only `tests/test_governance_bedrock_stack.py`. It now runs every test file, including the security regression tests, the 12 public-sector demo scenarios and the stack assertions, plus the in-memory state inventory. The live AWS test still skips unless `LIVE_AWS` is set.
- `requirements.txt` lists `hypothesis` and `jsonschema`, which the property-based and schema tests need.
- CI also runs when a workflow file changes.

### Security fixes
- Policies can carry a `binding` that selects the agents they apply to by trusted registry attributes: `policy_bundles`, `risk_tiers`, `agent_types`, `environments`, `agent_ids`. Every dimension present must match. A policy without a binding applies to every agent, as before. Bindings select by attribute rather than listing agents, so one engine serves 2,000 or more agents.
- The pipeline and the authority plane evaluate only the policies bound to the calling agent, using attributes of its registry entry, never of the request. Without attributes only global and deny policies apply.
- A malformed binding can only restrict: a deny policy with a bad binding applies to every agent, an allow or escalate policy with a bad binding applies to none.
- The OPA engine indexes rules by bundle, so selecting the rules for one decision reads the global rules plus the agent's bundle. `MultiAgentManager.get_agent_policy_bindings` used to scan the policy table and return every approved policy for any registered agent; it now uses this index.
- A binding is part of the policy fingerprint, so changing who a policy applies to voids approvals bound to the old version. Bundles without bindings keep their fingerprint.
- The policy definition schema accepts the `binding` block.

### Security fixes
- Source of truth for policies: the deployment owns the baseline under `policies/`, and the policy lifecycle owns `policies/active/`. The policy `BucketDeployment` now excludes `active/*`, `archive/*` and `pending/*` from its sync. Before, it pruned every object not in the source folder on each deploy, which deleted approved versions and put the sample policies back in force. Prune stays on for the baseline, so a baseline file removed from source is still removed.
- Both policy engines load approved lifecycle versions before the baseline, and drop a baseline policy with the same identity. Before, the JSON engine kept whichever copy S3 listed last, so a baseline file named after `active/` replaced an approved version; the OPA engine loaded both rules, so a baseline allow stayed in force next to an approved deny.

### Security fixes
- `scripts/inventory_in_memory_state.py` finds every in-memory container in the engine (45 today) and checks it against a reviewed classification (`scripts/in_memory_state_classification.json`): 6 authoritative, 20 caches, 7 request-scoped, 7 research-only, 3 test-only, 2 configuration. An unclassified container, or an authoritative one without a named durable backing, fails the check, and a test runs it.
- `AIAssetRegistry`, `CostGovernance`, `GovernanceChangeManagement` and `AgentLifecycleManager` accept a DynamoDB table. With one, the table is the source of truth: a revocation, a budget total or an approval made by one Lambda instance is seen by the others. Daily spend is an atomic counter whose returned total decides the budget check. Change-request and lifecycle status changes are conditional writes on the expected current status, so two instances cannot both approve one request, and a stale instance cannot overwrite a suspension.
- These classes, `AgentMemoryManager` and `GovernanceRollbackManager` refuse to start memory-only inside a deployed Lambda function. `AgentTokenExchange` refuses to start in a deployed function at all; it is legacy-only and the hall pass is `delegated_authority`.
- Agent memory recall no longer falls back to the process's local cache when the table read fails. The cache holds only what this process wrote, so it presented a partial history as complete.
- `AgentLifecycleManager.transition` reported the new state as `from_state`; it now reports the previous state.

None of these classes is used by a deployed component today, so this closes latent risk rather than a live one.

### Security fixes
- The scope enforcer takes the agent identity from its deployment binding, the new `GOVERNANCE_AGENT_ID` setting (CDK context `governance_agent_id`, default `demo-agent`), instead of the request's `agent_id`. A request naming another agent is denied (`agent_identity_mismatch`) before governance runs; an enforcer with no binding denies everything (`agent_identity_unbound`).
- The action group Lambda runs only the operation governance evaluated. The scope enforcer records it in the session attributes (`governed_action_groups`, `governance_decision_id`), which the application sets and the model cannot change. A tool call for another action group, or a session with no governance decision, is refused with 403. Before, a conversational request whose keywords classified it as a read could go on to call any action group its scope permitted.
- A session with no `scope_level` attribute now runs at scope 0 instead of scope 1.
- Governance decisions record `policy_bundle_id` (for example `s3://bucket/policies/`) and `policy_version` (each policy id with its declared version) next to `policy_version_hash`. Authority-plane decisions name the agent's assigned bundle, and the signed decision trace and evidence carry both fields.

### Deployment
- Set `-c governance_agent_id=<agent>` when the scope enforcer serves an agent other than `demo-agent`.

### Security fixes
- Agent-to-agent delegation is verified. An allowed request that names `delegate_to_agent_id` gets a delegation receipt, stored server-side in the new `DelegationReceiptTable`. The child presents only `delegation_receipt_id`; its parent, delegation chain and scope cap come from the receipt. A receipt is bound to one child, optionally to a list of operations, expires (15 minutes by default, 1 hour at most) and is single-use by default, enforced with a conditional write. Delegation to self, cycles and chains at the depth limit are refused at issue.
- `calling_agent_id`, `delegation_chain` and `calling_agent_scope` in a request are now claims. Without a receipt they are denied; a claim that disagrees with the receipt is denied as tampering. Before, the pipeline dropped these fields, so the trust-chain checks never saw a delegation, and the validator trusted them when it did: a missing `calling_agent_scope` removed the parent's cap.
- The pipeline no longer uses the request's `scope_level` as authority. The effective scope is the minimum of the registry's approved scope, the Scope Table's operator-authorized scope (which also carries graduated reduction and the kill switch) and the verified delegation cap. A requested scope can only lower it. Before, a scope-1 agent that sent `scope_level: 4` was evaluated at scope 4.
- No trusted scope source denies (`no_trusted_scope`). A registered agent with no Scope Table item, or at scope 0, is denied (`no_authorized_scope`), matching the scope enforcer.
- Each decision response carries `effective_scope`: every ceiling, the requested scope and the ceiling that bound the result.
- The scope enforcer forwards delegation receipts, delegation requests and delegation claims to the governance engine instead of dropping them.

### Deployment
- Adds `DelegationReceiptTable` and the `DELEGATION_RECEIPT_TABLE_NAME` setting on the governance engine Lambda. Without the setting, every delegated request is denied.

### Security and scale fixes
- Caller classification no longer scans the agent registry and the roles table on every authority and approval API request. The registry has a `ByRuntimePrincipal` index and the caller is resolved with one query on it; roles come from a key query on `user_id`. At 2,000 agents the old path read at least 2,000 registry items per request.
- A runtime principal declared by two registered agents now resolves to neither: the caller is classified as unknown and every plane denies it. Before, the scan kept whichever agent it read last.
- Each governance decision no longer scans the tool and model registry. Entries carry `identity_key` (`category#name#version`) and the check is one query on the `ByIdentity` index. A failed query denies.
- Tool-chain detection no longer scans the tool authorization table, which also holds every agent's call history. Chain definitions and an agent's recent calls are read through one overloaded `ByLookupKey` index.
- The seeded `exfiltration_pattern` chain was never checked: seed data writes `sequence` and `chain_name`, and the checker read only `chain_sequence` and `chain_id`. The checker now reads both.
- The pipeline kept no configuration between requests: it scanned the risk configuration table and built a new threat detector and exfiltration detector on each decision, so their 60-second caches never hit. They are now cached per container for 60 seconds, the same window as the OPA policy cache. A failed load is never cached.

### Upgrade notes
- Deploying adds one index to each of three tables. CloudFormation adds at most one index per table per update, which is why the tool authorization table uses a single overloaded index.
- Tool and model registry entries written before this change have no `identity_key` and are denied until backfilled. Run `ToolModelRegistry(table).backfill_identity_keys()` once after deploying.
- Chain records written before this change need `lookup_pk = "CHAIN"` and `lookup_sk = pk`. The seed data sets both.

### Security fixes
- Consuming a human approval and writing its hall pass are now one DynamoDB transaction. Before, the approval was consumed by one write and the grant written by a second; if the second failed, the approval was used up and no grant existed. Now a failed grant write leaves the approval unused, and a replay or an expired approval cancels both writes.
- The approval record stores the ID of the grant it produced.

## Unreleased: policy lifecycle and fail-closed defaults

### Security fixes
- A submitted policy version no longer takes effect before approval. `update_policy` stores versions under `policy-versions/`, outside the prefix the engines load. `approve_policy` activates a pending version with a conditional write, checks separation of duties against the stored author, and marks older approved versions `superseded`.
- Superseded versions no longer stay in force. Both policy loaders now skip archived and pending copies; before, an archived copy under `policies/archive/` replaced the current version in the JSON engine and added its rules to the OPA engine, so a policy tightened from allow to deny kept enforcing the allow.
- `rollback_policy` restores only versions that were approved before, so it cannot activate content nobody approved.
- Submitting a second version of a policy no longer crashes after the write: DynamoDB returns versions as `Decimal`, and the audit log could not serialize them, which also skipped the change-log entry.
- A disabled Cedar engine now denies instead of allowing, and reports policies as not validated instead of valid.
- A guardian check marked `required` fails closed: disabled, failed or unreadable checks return an unsafe verdict that recommends escalation. Every verdict now says whether the guardian actually evaluated.

## Unreleased: internal identifier removal

### Repository hygiene
- Removed the internal AWS account ID, the Bedrock agent, alias and guardrail IDs, and internal tool names from tracked files. Evidence packages, paper result files and test fixtures now use the AWS documentation placeholder account `111122223333`. Git history still contains the earlier values.
- Live scripts read the account from `GOVERNANCE_ACCOUNT_ID` or from the current credentials instead of a hard-coded account. `test_datasets/run_2000_on_isengard.py` is now `test_datasets/run_2000_live.py` and uses the standard AWS credential chain.
- The stack reads the Bedrock Guardrail ID from CDK context (`-c bedrock_guardrail_id=<id>`). Without it, synth prints a warning and the guardrail layer is skipped. Redeploying an existing stack without this value turns that layer off.
- `scripts/pre_push_check.py` blocks any real account ID in an ARN or account field, reads internal-system patterns from an untracked `.pre-push-patterns` file instead of listing them, and now runs in CI.

## Unreleased: delegated authority ("hall pass") demo branch

### Security fixes
- Tool authorization now fails closed: unknown, empty, unloadable and revoked tools were authorized; they are now denied.
- The agent execution entry point no longer accepts `new_scope` (or any authority-changing field); it previously wrote the caller's value straight to the Scope Table.
- Structured requests carry an `operation_id` that governance evaluates; keyword inference from the prompt is a labelled legacy pre-screen only.
- Governance decisions retain the canonical request, the policy version hash and a request digest; approvals bind to that digest plus an absolute expiry.
- One approval record per decision (the scope enforcer's second record is gone); approvals can be approved only while pending and are consumed once.
- `consumed` is a DynamoDB reserved word; the unaliased consume condition made every real consume fail, so an approved request could never execute.
- The approval API takes the approver from the authenticated request context and enforces separation of duties (agents, owners and principals without an approver role are refused).
- `agent_token_exchange.py` no longer has a hard-coded fallback secret and is marked experimental.

### Added
- Delegated Authority Grants: KMS-signed, DynamoDB-persisted, conditionally consumed and revoked; credential broker with AWS STS session policies and mock Entra, ServiceNow and Google adapters; OpenAPI operation registry; budget governance; worker/guardian boundaries; hash-chained signed evidence; a dedicated least-privilege authority Lambda and IAM-only routes.
- `public-sector-canada` deployment profile with a region guard.
- Offline demo (12 scenarios), local UI, live AWS demo script, architecture document.

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project is pre-1.0 and the
API surface is not yet stability-guaranteed (see Versioning below).

## [Unreleased]

### Added
- **Information-flow taint tracking** (`lambdas/governance_engine/information_flow.py`):
  cross-session, provenance-based taint tracking wired into the governance pipeline.
  Labels each input by trust origin (trusted: user/operator/system; untrusted:
  tool response, retrieved doc, web, MCP). When an untrusted source is seen in a
  session and a later action targets a privileged sink, the risk score rises +25
  (escalate) or the action is denied outright (`INFORMATION_FLOW_STRICT=true`).
  Off by default (`INFORMATION_FLOW_ENABLED=false`), fail-open. 16 tests in
  `tests/test_information_flow.py`.
- **Compromised-enforcer experiment harness** (`tests/test_compromised_enforcer.py`):
  11-test harness covering honest baseline (Tier 0), forced-ALLOW decision logic
  (Tier 2), no-op/widen/agent-direct-mutation (Tiers 3a/b/c), and live IAM
  role-separation proof. `FakeIam` + `FakeDynamo` stubs; live test uses direct
  IAM policy inspection (not `simulate_principal_policy`, which has a known
  limitation with role ARN inline policies). Role separation confirmed on live
  AWS test infrastructure.
- **Cedar role-boxing** (`cedar_engine.py`): `HUMAN_ONLY_ACTIONS` frozenset
  prevents AI agents from calling `MakeComplianceDetermination`, `IssueAttestation`,
  `ApproveException`, `OverrideDecision`, and 5 others, regardless of policy content.
  `authorize_agent_role_boxed()` enforces this before Cedar evaluates. 4 tests in
  `test_adversarial_threats.py::TestAgentRoleBoxing`.
- **Benchmark rewrite** (`scripts/benchmark_latency.py`): removed all hardcoded
  ARNs. `_resolve_account()` via STS, `_resolve_function_name()` via
  `list_functions` auto-discovery, `_resolve_sfn_arn()` via `list_state_machines`.
  Artifact detection: infra errors and unseeded-table denials printed as `X` and
  excluded from latency stats. `--mode lambda|sfn|both` flag added.
- **README inside governance-demo-bedrock/**: the subfolder now has its own
  README.md so GitHub renders documentation when browsing into it.
- Multi-account & defense-in-depth reference architecture (`docs/MULTI_ACCOUNT_ARCHITECTURE.md`)
  with a live single-account demonstration: OU tree, escalating SCP guardrails,
  RCP identity perimeter, per-environment VPC segmentation (NACLs/SGs), NAT,
  Gateway endpoints, VPC Flow Logs, Network Firewall, WAF. Teardown script
  included (`scripts/teardown_defense_in_depth.py`).
- Comparative detection benchmark vs live Bedrock baselines
  (`scripts/comparative_benchmark.py`, `docs/COMPARATIVE_BENCHMARK.md`): measured
  detection/false-positive rates against a purpose-built safety model and a
  general LLM-as-guard. NeMo/literal-Llama-Guard explicitly pending (not runnable
  in-env), not fabricated.
- Chaos / failure-injection tests (`tests/test_chaos_failure_injection.py`):
  DynamoDB throttle, OPA crash, S3 evidence-write failure, Bedrock 5xx, KMS
  signing outage; assert fail-closed.
- Signed auditor decision-trace: per-decision, stage-by-stage "why", KMS-signed
  and offline-verifiable; `GET /decisions/{id}/trace` API and
  `scripts/decision_trace_report.py`.
- Operational runbook (`docs/OPERATIONAL_RUNBOOK.md`) and cost model
  (`docs/COST_MODEL.md`).
- Apache-2.0 LICENSE.
- Plane-3 application-security threat model (request forgery, dependency CVEs,
  secrets, AI-accelerated vuln discovery) and CI scanning (pip-audit, detect-secrets).
- Runtime governance spec controls (five verdicts incl. MODIFY/DEFER, intent alignment,
  semantic drift, OTLP telemetry) and side-channel defenses.

### Changed
- Latency documentation corrected to measured numbers (ALLOW ~3.5s single-Lambda
  warm; cold start ~90ms and NOT the dominant cost) replacing an unbenchmarked
  ~200ms target. See runtime-flow.md.
- OPA policy engine cached per warm container (60s TTL), removing ~0.5s per
  request.
- Dependencies bounded (floor + upper-major) for reproducibility.
- Security hardening: fail-closed OPA, approval TOCTOU/replay defense, tool-
  response forgery detection.

### Known limitations (honest scope)
- Semantically-embedded prompt injection: ~0% detection, scoped out of V1.
- Information-flow taint is provenance-based, not semantic: the tracker records
  that a tool response was seen, not that its content influenced later actions.
  False negatives possible when untrusted content is reformatted before re-use.
- Single-Lambda ALLOW latency ~3.5s; async-evidence fix (durable Step Functions
  path) is the recommended production configuration.
- Runtime governance spec: technical requirements implemented; NOT certified/conformant
  (organizational preconditions unmet). Do not claim conformance.
- Multi-account: structure demonstrated in a single account; not a true
  multi-account production deployment.
- Compromised-enforcer paper metrics (RCR, BU, UA, ASR) require a live Bedrock
  run with `LIVE_AWS=1`; structural tests pass but live adversarial measurements
  not yet collected.

## [0.1.0] - 2026-07-10
- Initial public reference architecture: three governance engines (Preventive,
  Detective, Proactive), CDK stack, documentation set.

---

## Versioning

Pre-1.0: the API surface (REST endpoints, event/response schemas, DynamoDB
record shapes) may change between commits without notice. Consumers should pin
to a specific commit, not `main`. A 1.0 tag with a stability guarantee will be
cut when the framework has an external consumer that requires it.
