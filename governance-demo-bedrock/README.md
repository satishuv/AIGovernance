# governance-demo-bedrock

Runtime governance framework for autonomous AI agents on AWS. Three engines (Preventive, Detective, Proactive), 65 Lambda modules, CDK infrastructure, and a live Bedrock Agent deployment on Isengard (account 917914785227, us-east-1).

This subfolder contains all active code. `../governance-demo/` is frozen and should not be touched.

---

## What is deployed

| Resource | Value |
|----------|-------|
| Bedrock Agent | ID `0YHRUKKENP`, alias `live` (MK9HF5CSAK), model `amazon.nova-micro-v1:0` |
| Governance Lambda | `GovernanceBedrockStack-GovernanceEngineLambda76BBC-BJrhSwyaE07y` |
| Scope Enforcer Lambda | `GovernanceBedrockStack-ScopeEnforcerLambdaServiceRo-gJCeuvTtWsMf` |
| Action Group Lambda | `GovernanceBedrockStack-ActionGroupLambdaRole0015CF3-YSfgpYmNuFid` |
| Bedrock Guardrail | `xilmtxfq02om` (HIPAA PII + content safety) |
| Account | 917914785227 (Isengard, full Bedrock access) |
| Region | us-east-1 |

---

## Quick start

```bash
# Activate environment
source .venv/Scripts/activate
pip install -r requirements.txt

# Get credentials (Windows PowerShell only -- ada is a Windows binary)
ada credentials update --account 917914785227 --provider isengard --role Admin --once

# Deploy
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Validate (must show 21/21 before any demo)
python test_datasets/run_demo_validation.py

# Full test suite
python -m pytest tests/ -v    # 344 tests, ~25s, no AWS required
```

---

## Architecture

Three engines run in sequence on every governed action:

```
Request
  |
  v
[Scope Enforcer Lambda]  <-- entry point; IAM permission boundary swap + verify
  |
  v
[Governance Engine Lambda]  <-- 20-stage pipeline
  |
  +-- Kill switch check
  +-- Behavioral invariants
  +-- Input sanitization (unicode norm, base64, ChatML, leet, stuffing)
  +-- Bedrock Guardrails (HIPAA PII, content safety)
  +-- Threat pattern detector
  +-- Agent identity + registry check
  +-- Environment isolation
  +-- Data class + sensitivity classification
  +-- Tool/model registry
  +-- Tool execution authorization
  +-- OPA policy evaluation
  +-- Risk scoring (0-100, 5 weighted factors)
  +-- Intent alignment + cumulative drift (AARM R7)
  +-- Side-channel probe detection (AARM T9)
  +-- Information-flow taint tracking (cross-session, provenance-based)
  +-- Decision engine (ALLOW / DENY / ESCALATE / MODIFY / DEFER)
  +-- Signed auditor trace (KMS ECDSA, stage-by-stage "why")
  +-- Evidence write (S3 Object Lock, SHA-256 hash chain, async)
  |
  v
[Action Group Lambda]  <-- per-tool-call: scope check, param scan, output sanitize
```

### Execution modes

| Mode | How to select | Notes |
|------|--------------|-------|
| Single Lambda | `GOVERNANCE_MODE=lambda` | All 20 stages sequential; easier to debug |
| Step Functions | `GOVERNANCE_MODE=step_functions` | Input defense and authorization run in parallel; 100K+ concurrent executions |

---

## IAM permission boundary mechanism

The scope enforcer calls `iam:PutRolePermissionsBoundary` to set a per-scope IAM policy on the action-group Lambda's execution role before each governed decision, then calls `iam:GetRole` to verify the boundary actually applied. This is enforced at the AWS IAM layer, not in the agent process.

Key properties:
- The scope enforcer role has `iam:PutRolePermissionsBoundary`; the action-group role does not (role separation, proven by live IAM inspection in `tests/test_compromised_enforcer.py`)
- A DynamoDB lease (`acquire_boundary_lease` / `release_boundary_lease`) prevents race conditions under concurrent decisions
- If `verify_boundary` mismatches, the decision fails closed (deny) rather than proceeding

Code: `lambdas/scope_enforcer/index.py` (`swap_permission_boundary`, `verify_boundary`)

---

## Information-flow taint tracking

`lambdas/governance_engine/information_flow.py` tracks cross-session provenance. Once an untrusted source (tool response, retrieved document, web, MCP) is seen in a session, any subsequent privileged action (production deployment, external write, high-sensitivity read) in that session is flagged. This catches indirect injection chains that per-request checks miss structurally.

- Off by default: set `INFORMATION_FLOW_ENABLED=true` on the governance Lambda
- Default mode: tainted flow adds +25 to the risk score, triggering escalation
- Strict mode (`INFORMATION_FLOW_STRICT=true`): tainted flow is an immediate deny
- Any exception leaves the pipeline unchanged (fail-open; a taint-tracking outage never manufactures a denial)

---

## Cedar role-boxing

`lambdas/governance_engine/cedar_engine.py` maintains a `HUMAN_ONLY_ACTIONS` set (`MakeComplianceDetermination`, `IssueAttestation`, `ApproveException`, `OverrideDecision`, `SignOffControl`, `CloseFinding`, `SetVerdict`, `AmendPolicy`, `GrantScope`). The `authorize_agent_role_boxed()` method denies these before Cedar runs, regardless of policy content. An AI agent can produce evidence and operate governed tools; it cannot issue a compliance determination.

---

## Compromised-enforcer experiment

`tests/test_compromised_enforcer.py` covers four adversary tiers:

| Tier | Adversary | What it tests |
|------|-----------|--------------|
| 0 (baseline) | None | Honest swap + verify passes |
| 2 | Decision logic forced ALLOW | IAM boundary still enforces scope ceiling |
| 3a | Enforcer no-ops the swap | `verify_boundary` catches boundary mismatch |
| 3b | Enforcer widens the boundary | `verify_boundary` catches wrong level |
| 3c | Compromised agent calls `PutRolePermissionsBoundary` directly | IAM denies (role separation) |

Run with `LIVE_AWS=1 ENFORCER_ROLE_ARN=<arn> ACTION_GROUP_ROLE_ARN=<arn> pytest -k live` to execute the live IAM proof.

---

## Tests

```bash
python -m pytest tests/ -q              # 344 tests, 1 skipped (live IAM, needs LIVE_AWS=1)
python -m pytest tests/ -v -k "not live"  # all offline tests
LIVE_AWS=1 ENFORCER_ROLE_ARN=... ACTION_GROUP_ROLE_ARN=... python -m pytest -k live
```

Test files and what they cover:

| File | Tests | Covers |
|------|-------|--------|
| `test_governance_engine_units.py` | ~80 | Evidence, signing, hash chain, decision history |
| `test_governance_logic.py` | ~60 | Policy, risk, intent alignment, verdicts, telemetry |
| `test_security_governance.py` | ~50 | Fail-closed, concurrency, boundary, forgery |
| `test_adversarial_threats.py` | ~40 | Injection, jailbreak, drift, role-boxing |
| `test_information_flow.py` | 16 | Taint tracking, cross-session, declassify |
| `test_compromised_enforcer.py` | 11 | Tier 0/2/3 adversary containment, live role separation |
| others | ~87 | Chaos/failure injection, benchmark, multi-agent, etc. |

---

## CDK structure

```
governance_constructs/
  storage.py          # DynamoDB tables (22 tables) + S3 buckets
  governance_engine.py  # Governance Lambda, env vars, IAM grants
  scope_enforcer.py   # Scope Enforcer Lambda, IAM boundary grants
  action_group.py     # Action Group Lambda, Bedrock Agent binding
  monitoring.py       # CloudWatch alarms, SNS topic
  bedrock_agent.py    # Bedrock Agent + alias + guardrail attachment
app.py                # CDK app entrypoint (~58 lines)
```

---

## Key environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GOVERNANCE_MODE` | `lambda` | `lambda` or `step_functions` |
| `OPA_MODE` | `embedded` | `embedded` or `external` |
| `INFORMATION_FLOW_ENABLED` | `false` | Enable cross-session taint tracking |
| `INFORMATION_FLOW_STRICT` | `false` | Tainted flow = deny (vs escalate) |
| `EVIDENCE_ASYNC` | `false` | Async evidence write via EventBridge |
| `EVIDENCE_SIGNING_KEY_ID` | (empty) | KMS key alias for evidence + trace signing |
| `DECISION_TRACE_TABLE_NAME` | (empty) | DynamoDB table for signed auditor traces |

---

## Lambda import constraint

All imports in `lambdas/governance_engine/` must be flat: `from models import GovernanceDecision`, not `from lambdas.governance_engine.models import ...`. No relative imports. No package-qualified imports. DynamoDB returns `Decimal`; the `DecimalEncoder` monkey-patch handles serialization.

---

## Documentation

| Document | What it covers |
|----------|---------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full pipeline flow, execution modes, security model |
| [docs/AARM_CONFORMANCE.md](docs/AARM_CONFORMANCE.md) | R1-R9 requirement mapping and test evidence |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat actors, attack surfaces, fail-safe table |
| [docs/CONTROL_CATALOG.md](docs/CONTROL_CATALOG.md) | 93 implemented controls across 20 domains |
| [docs/OPERATIONAL_RUNBOOK.md](docs/OPERATIONAL_RUNBOOK.md) | Alarm response procedures |
| [docs/COST_MODEL.md](docs/COST_MODEL.md) | Monthly cost estimates at 3 scales |
| [docs/COMPARATIVE_BENCHMARK.md](docs/COMPARATIVE_BENCHMARK.md) | Head-to-head detection benchmark |
| [lambdas/governance_engine/MODULE_MAP.md](lambdas/governance_engine/MODULE_MAP.md) | All 65 modules by function |
| [CHANGELOG.md](CHANGELOG.md) | What changed and when |

---

## Author

Author, [Affiliation]
