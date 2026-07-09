# AI Agent Runtime Governance Framework

## The Problem

AI agents read data from their environment and that data can become instructions. A tool response, a document, a metadata field can contain hidden commands that reprogram the agent. No security system in history was designed for software that can be hijacked by the data it processes.

Traditional security validates inputs and sanitizes outputs. But an AI agent also CONSUMES tool responses, READS tool descriptions, and CHAINS actions through autonomous reasoning. These three surfaces have no protection in any existing framework, product, or standard.

**This project is the enforcement layer that governs what an AI agent does between receiving a request and taking an action.**

---

## What It Does

Every time an AI agent attempts an action, this framework:

1. **Evaluates** the request against policy, risk scoring, and behavioral analysis
2. **Decides** ALLOW, DENY, or ESCALATE (require human approval)
3. **Enforces** the decision at the AWS infrastructure layer (IAM boundaries, not just prompts)
4. **Validates** data returned from tools before the agent can process it
5. **Records** an immutable, hash-chained evidence record of every decision

All of this happens in under 150 milliseconds. The agent cannot override it.

---

## Why This Exists

| What exists today | What it does | What it cannot do |
|-------------------|-------------|-------------------|
| AWS Bedrock Guardrails | Filters input/output text | Cannot govern tool calls, action sequences, or return-path data |
| OPA / Cedar | Evaluates access policies | Cannot detect prompt injection or sequential attack chains |
| WAFs | Protect HTTP requests | Cannot understand that an AI action emerged from compromised context |
| OWASP / NIST / ISO | Name the risks | Cannot enforce anything at runtime |

This framework combines all of these into a single runtime enforcement engine for the complete attack surface of an autonomous AI agent.

---

## Architecture

```
  REQUEST ──▶ GOVERNANCE CONTROL PLANE ──▶ DECISION ──▶ AGENT EXECUTION
                                                              │
                                                              ▼
                                                    EVIDENCE (immutable)
```

**Control Plane** (evaluates every request):
- Kill switch check (instant shutdown if active)
- Input defense (8 sanitization checks)
- Agent + tool authorization (registry, scope, rate limits)
- Policy evaluation (OPA + Cedar)
- Risk scoring (0-100 composite)
- Drift and behavioral monitoring
- Decision engine (ALLOW / DENY / ESCALATE)

**Execution Plane** (after ALLOW):
- Bedrock Agent with scope-gated action groups (levels 0-4)
- Per-tool security on every tool call (parameter scan, rate limit, chain detection)
- Tool response validation (scans data FROM tools for injection)
- Output guardrails (PII stripping, credential removal, exfiltration blocking)

**Evidence Plane** (async, non-blocking):
- SHA-256 hash chain per decision
- S3 Object Lock (7-year immutable retention)
- Compliance mapping (ISO 42001, NIST AI RMF, EU AI Act, PCI DSS, NIST 800-53)

---

## How Scoring and Decisions Work

Every request gets a **risk score (0-100)** computed from four weighted factors:

```
Risk Score = scope_weight + action_weight + target_weight + history_weight
```

| Factor | What it measures | Weight examples |
|--------|-----------------|-----------------|
| Scope level | How much power the agent has | Level 1 = 10, Level 3 = 50, Level 4 = 75 |
| Action type | How dangerous the action is | Read = 10, Deploy = 50, Emergency = 60 |
| Target resource | What's being acted on | Development = 5, Staging = 15, Production = 30 |
| History | Recent denial patterns | +5 per recent denial |

**Decision logic (what happens with the score):**

| Condition | Verdict | What happens |
|-----------|---------|-------------|
| Policy says DENY | **DENY** | Blocked immediately, regardless of score |
| Policy says ESCALATE | **ESCALATE** | Human approval required, regardless of score |
| Policy says ALLOW but score >= 70 | **ESCALATE** | Too risky for auto-approval, human decides |
| Policy says ALLOW and score < 70 | **ALLOW** | Safe to execute |

**Example:**

```
Agent at Scope 3 requests "deploy to staging"

  Scope weight:     50  (level 3)
  Action weight:    50  (deployment)
  Target weight:    15  (staging)
  History weight:    0  (no recent denials)
  ─────────────────────
  Total:           115 → capped at 100

  Score = 100, threshold = 70
  100 >= 70 → ESCALATE (requires human approval)
```

Deployments are mathematically impossible to auto-approve. This is by design.

---

## Three Novel Contributions

These address attack surfaces that no existing standard, framework, or product covers:

**1. Tool Response Validation (the "Perception Gap")**

Every framework validates what goes INTO tools. Nobody validates what comes BACK. This framework scans all tool responses for injection, anomalies, and sensitive data before the agent can reason over them.

**2. Sequential Chain Governance**

Every access control system evaluates one action at a time. This framework evaluates whether a SEQUENCE of individually-safe actions produces harm when combined.

**3. Tool Metadata Defense**

AI agents read tool descriptions to decide how to use them. Those descriptions can contain hidden adversarial instructions. This framework validates tool metadata against policy before the agent processes it.

---

## Graduated Autonomy

Agents earn trust through demonstrated safe behavior:

| Level | What the agent can do | Enforcement |
|-------|----------------------|-------------|
| 0 | Nothing (kill switch) | Deny-all IAM policy |
| 1 | Read-only queries | S3 GetObject only |
| 2 | Propose changes | + DynamoDB writes to pending |
| 3 | Deploy to staging | + S3 writes to staging path |
| 4 | Deploy to production | + S3 writes to production path |

Each level maps to a dedicated IAM Permission Boundary enforced at the AWS infrastructure layer.

---

## Validation

- **Attack datasets**: 8,470+ payloads from 13 academic benchmarks (JailbreakBench, AdvBench, Deepset, Lakera Gandalf, LMSYS Toxic Chat, AI Safety Institute AgentHarm, and others)
- **Detection rate**: 93.4% on pure attack datasets. Multi-layer defense reduces residual attack success from 73-84% baseline to under 9%
- **End-to-end scenarios**: 21 governance scenarios covering all verdicts, all scope levels, and all attack categories
- **Research foundation**: Informed by 22 peer-reviewed papers (2024-2025) covering tool poisoning, sequential chaining, memory attacks, and supply chain threats
- **Test suite**: 225 automated tests (unit + integration + security)

---

## Quick Start

```bash
cd governance-demo-bedrock
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt

# Deploy
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Validate
python test_datasets/run_demo_validation.py    # 21 scenarios
python -m pytest tests/ -v                     # 225 tests
```

---

## Technology

| Layer | Service |
|-------|---------|
| AI Agent | Amazon Bedrock Agents (Nova Micro) |
| Governance Orchestration | AWS Step Functions Express (100K+ concurrent) |
| Policy Engine | OPA (Rego-subset, embedded or external) |
| State | Amazon DynamoDB (25+ tables) |
| Evidence | Amazon S3 (Object Lock, 7-year WORM) |
| Infrastructure | AWS CDK (Python, 6 modular constructs) |

---

## Documentation

| Document | Audience |
|----------|----------|
| [Architecture Deep-Dives](../governance-demo-bedrock/docs/architecture/) | Platform architects |
| [Security Checklist (93 controls)](../governance-demo-bedrock/docs/AI_AGENT_SECURITY_CHECKLIST.md) | Security reviewers |
| [Control Catalog (377 controls)](../governance-demo-bedrock/docs/CONTROL_CATALOG.md) | Compliance teams |
| [Module Map (72 modules)](../governance-demo-bedrock/lambdas/governance_engine/MODULE_MAP.md) | Developers |
| [Threat Model](../governance-demo-bedrock/docs/THREAT_MODEL.md) | Risk assessors |
| [Evidence Collection Guide](../governance-demo-bedrock/docs/EVIDENCE_COLLECTION_GUIDE.md) | Auditors |

---

## Author

**Author** - [Affiliation]
