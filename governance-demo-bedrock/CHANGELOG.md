# Changelog

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
