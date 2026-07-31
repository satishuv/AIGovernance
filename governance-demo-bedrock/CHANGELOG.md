# Changelog

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
  Isengard infrastructure.
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
- AARM R1-R9 controls (five verdicts incl. MODIFY/DEFER, intent alignment,
  semantic drift, OTLP telemetry) and T9 side-channel defenses.

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
- AARM: technical requirements R1-R9 implemented; NOT certified/conformant
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
