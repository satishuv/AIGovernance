# AIGovernance

A runtime governance framework for autonomous AI agents on AWS. Every action an agent
attempts passes through a 20-stage authorization pipeline before it executes. Decisions
are fail-closed, cryptographically signed, and hash-chained for long-term auditability.

The concrete use case is an AI developer agent operating a software deployment pipeline:
read build status, propose changes, deploy to staging, deploy to production. Each step
requires the right scope level, passes every check, and leaves a tamper-evident record.

---

## How it works

Three Lambda functions collaborate on every governed request:

```
Request
  |
  v
[Scope Enforcer]        entry point
                        acquires a distributed DynamoDB lease
                        calls iam:PutRolePermissionsBoundary to set the IAM boundary
                        calls iam:GetRole to verify the boundary applied
                        mismatch or exception -> deny (fail-closed)
  |
  v
[Governance Engine]     20-stage pipeline
  |
  +-- Kill switch check
  +-- Behavioral invariants (output size caps, canary tripwires, time-of-day)
  +-- Privilege escalation detection (self-modification, policy modification)
  +-- Trust chain validation (delegation depth, scope laundering, cross-agent injection)
  +-- Runtime drift detection (behavioral deviation from baseline)
  +-- Input sanitization (unicode normalization, base64/hex/URL decode, ChatML
  |     delimiters, leet-speak normalization, context stuffing detection)
  +-- Bedrock Guardrails (HIPAA PII, content safety)
  +-- Threat pattern detector (regex patterns from DynamoDB)
  +-- Agent identity + registry check
  +-- Environment isolation (dev agent cannot target production resource)
  +-- Data class + sensitivity classification
  +-- Tool / model registry check
  +-- Tool execution authorization (per-tool rate limits, parameter constraints)
  +-- Egress governance (external account creation, public registry uploads)
  +-- OPA policy evaluation (priority-ordered Rego-subset rules, default deny)
  +-- Risk scoring (0-100, five weighted factors)
  +-- Intent alignment + cumulative drift (session-level)
  +-- Side-channel probe detection
  +-- Information-flow taint tracking (cross-session provenance, optional)
  +-- Decision engine -> ALLOW / DENY / ESCALATE / MODIFY / DEFER
  +-- KMS-signed per-stage decision trace (DynamoDB)
  +-- Hash-chained evidence record (S3 Object Lock, 7-year retention in production)
  |
  v
[Action Group]          per-tool-call enforcement
                        enum allowlist, scope-to-action-group check
                        parameter injection scan, invocation cap (25), recursion limit (1)
                        tool response validator (indirect injection in returned data)
                        output sanitization
```

---

## Scope levels

The agent's effective permissions are expressed as an AWS IAM permission boundary
applied to the Action Group Lambda's execution role before each invocation.

| Level | Label | Permitted actions |
|-------|-------|-------------------|
| 1 | Read-only | `getBuildStatus`, `getTestResults` |
| 2 | Propose | + `draftDeploymentPlan`, `draftRollbackStrategy` |
| 3 | Staging | + `deployToStaging`, `triggerTests` |
| 4 | Production | + `deployToProduction`, `rollbackDeployment` |

The scope enforcer holds `iam:PutRolePermissionsBoundary`. The action group role holds
zero `iam:` actions. Role separation is confirmed by live IAM inspection before each
experiment run. A Scope 1 boundary denies production deployment regardless of what
the governance software decides.

---

## Fail-closed guarantees

- Governance tables unreachable at init: **deny**
- Kill switch set: **deny**
- Policy engine exception: **deny** (not skip)
- Risk scoring failure: **score 100** (forces escalation)
- Boundary lease unacquirable: **deny**
- `verify_boundary()` mismatch: **deny**
- Governance Lambda exception: **deny** (Scope Enforcer catches and denies)
- Unrecognized verdict: **deny** (`unknown_verdict` guard)
- Step Functions execution failure: **deny** (fallback payload `verdict: deny`)

Evidence write failure is the one non-blocking path: a temporary S3 outage does not
deny a legitimate action, but it is alarmed and metered.

---

## Evidence and audit trail

Every governed decision produces three records:

**EvidenceRecord** (S3 with Object Lock)
- Fields: `evidence_id`, `agent_id`, `action_requested`, `verdict`, `risk_score`,
  `policy_result`, `scope_level`, `environment`, `delegation_chain`, `timestamp`
- `previous_hash`: SHA-256 of the preceding record (hash chain per agent/environment)
- `record_hash`: SHA-256 over all content fields
- `signature`: KMS ECDSA over `record_hash`
- Retention: 365 days (demo), 2555 days / 7 years (production), enforced by Object Lock

**DecisionTrace** (DynamoDB)
- Ordered list of every pipeline stage: `stage`, `result`, `detail`, `decisive`, `timestamp`
- `decisive_stage`: which stage determined the outcome
- `risk_factors`, `policy_id`, `aarm_decision` (ALLOW / DENY / STEP_UP / MODIFY / DEFER)
- `trace_hash` + KMS ECDSA signature
- Retrievable via `GET /decisions/{decision_id}/trace`; endpoint re-verifies signature online

**ControlTrace** (DynamoDB)
- One record per ISO 42001 control ID and NIST AI RMF function ID that maps to the
  action type, linking `control_id` to `evidence_record_id` and `decision_id`

---

## Cedar role-boxing

`lambdas/governance_engine/cedar_engine.py` maintains a `HUMAN_ONLY_ACTIONS` set:

```
MakeComplianceDetermination  IssueAttestation  ApproveException
OverrideDecision             SignOffControl    CloseFinding
SetVerdict                   AmendPolicy       GrantScope
```

These are denied before Cedar runs, regardless of policy content. An AI agent can
produce evidence and operate governed tools. It cannot issue a compliance determination.

---

## Information-flow taint tracking

`lambdas/governance_engine/information_flow.py` tracks cross-session provenance. Once
an untrusted source (tool response, retrieved document, web content, MCP) appears in a
session, any subsequent privileged action in that session is flagged.

- Default off: set `INFORMATION_FLOW_ENABLED=true` on the Governance Lambda
- Default mode: tainted flow adds +25 to risk score, triggering escalation
- Strict mode (`INFORMATION_FLOW_STRICT=true`): tainted flow is an immediate deny
- Exception in taint tracking: pipeline proceeds unchanged (fail-open; a tracking
  outage never manufactures a denial)

---

## Compromised-enforcer experiment

`tests/test_compromised_enforcer.py` measures residual containment at the IAM plane
while the governance software is progressively subverted.

| Scenario | What is compromised | Containment mechanism |
|----------|--------------------|-----------------------|
| Honest baseline | Nothing | Boundary policy deny |
| Decision logic forced ALLOW | Policy engine, threat detector, sanitizer | Boundary policy deny |
| Enforcer skips boundary swap | Enforcer omits `PutBoundary` | `verify_boundary()` fail-closed |
| Enforcer widens boundary | Enforcer applies Scope 4 | `verify_boundary()` fail-closed |
| Agent self-widens | Agent calls `PutRolePermissionsBoundary` | IAM denies (zero `iam:` actions on role) |

Results across n=400 trials per scenario (5 seeds x 80 attempts):
**RCR = 100.0% [99.1%, 100.0%]** across all five scenarios, zero unauthorized actions.

Run live:
```bash
LIVE_AWS=1 \
ENFORCER_ROLE_ARN=<arn> \
ACTION_GROUP_ROLE_ARN=<arn> \
python -m pytest tests/test_compromised_enforcer.py -k live -v
```

---

## Public attack corpus

`scripts/run_tier1_dataset_experiment.py` runs 1,679 published attack prompts from six
public datasets against the live Scope 1 IAM boundary, assuming worst-case (every prompt
fully jailbreaks the model). Aggregate containment: **RCR = 100.0% [99.8%, 100.0%]**.

| Dataset | n |
|---------|---|
| deepset/prompt-injections | 203 |
| JailbreakBench JBB | 100 |
| AdvBench harmful | 520 |
| TrustAIRLab in-the-wild | 666 |
| Lakera Gandalf | 111 |
| ChatGPT jailbreaks | 79 |

---

## Setup and tests

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/Scripts/activate        # Windows
# source .venv/bin/activate          # Linux / macOS
pip install -r requirements.txt

# Deploy (requires AWS credentials with CDK permissions)
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Validate demo scenarios (must show 21/21 before any demo)
python test_datasets/run_demo_validation.py

# Full offline test suite
python -m pytest tests/ -v           # 344 tests, ~25s, no AWS required
python -m pytest tests/ -q -k "not live"
```

---

## Test coverage

| File | Tests | Covers |
|------|-------|--------|
| `test_governance_engine_units.py` | ~80 | Evidence, signing, hash chain, decision history |
| `test_governance_logic.py` | ~60 | Policy, risk, intent alignment, verdicts, telemetry |
| `test_security_governance.py` | ~50 | Fail-closed, concurrency, boundary, forgery |
| `test_adversarial_threats.py` | ~40 | Injection, jailbreak, drift, role-boxing |
| `test_information_flow.py` | 16 | Taint tracking, cross-session, declassify |
| `test_compromised_enforcer.py` | 11 | Adversary containment, live role separation |
| others | ~87 | Chaos/failure injection, benchmark, multi-agent |

---

## CDK structure

```
governance_constructs/
  storage.py           22 DynamoDB tables + S3 buckets
  governance_engine.py Governance Lambda, env vars, IAM grants
  scope_enforcer.py    Scope Enforcer Lambda, IAM boundary grants
  action_group.py      Action Group Lambda, Bedrock Agent binding
  monitoring.py        CloudWatch alarms, SNS topic
  bedrock_agent.py     Bedrock Agent + alias + guardrail attachment
  api.py               API Gateway for approvals and decision queries
app.py                 CDK stack entrypoint
```

---

## Key environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GOVERNANCE_MODE` | `lambda` | `lambda` or `step_functions` |
| `OPA_MODE` | `embedded` | `embedded` or `external` |
| `INFORMATION_FLOW_ENABLED` | `false` | Cross-session taint tracking |
| `INFORMATION_FLOW_STRICT` | `false` | Tainted flow = deny (vs escalate) |
| `EVIDENCE_ASYNC` | `false` | Async evidence write via EventBridge |
| `EVIDENCE_SIGNING_KEY_ID` | (empty) | KMS key alias for signing |
| `DECISION_TRACE_TABLE_NAME` | (empty) | DynamoDB table for signed decision traces |

---

## Documentation

| Document | What it covers |
|----------|---------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full pipeline flow, execution modes, security model |
| [docs/GOVERNANCE_SPEC_CONFORMANCE.md](docs/GOVERNANCE_SPEC_CONFORMANCE.md) | Requirement mapping and test evidence |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat actors, attack surfaces, fail-safe table |
| [docs/CONTROL_CATALOG.md](docs/CONTROL_CATALOG.md) | 93 implemented controls across 20 domains |
| [docs/OPERATIONAL_RUNBOOK.md](docs/OPERATIONAL_RUNBOOK.md) | Alarm response procedures |
| [docs/COST_MODEL.md](docs/COST_MODEL.md) | Monthly cost estimates at 3 scales |
| [docs/COMPARATIVE_BENCHMARK.md](docs/COMPARATIVE_BENCHMARK.md) | Detection benchmark |
| [lambdas/governance_engine/MODULE_MAP.md](lambdas/governance_engine/MODULE_MAP.md) | All 65 modules by function |
| [CHANGELOG.md](CHANGELOG.md) | Change history |
