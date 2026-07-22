# AI Agent Runtime Governance Framework

## The Problem

AI agents read data from external sources - tool responses, documents, metadata fields - and that data can become instructions. Any of these sources can contain hidden commands that reprogram the agent. Classical application security was not designed for software that can be hijacked by the data it processes.

Traditional security validates inputs and sanitizes outputs. But an AI agent also CONSUMES tool responses, READS tool descriptions, and CHAINS actions through autonomous reasoning. Existing controls are fragmented across prompt filtering, authorization, output inspection, and observability; few provide a unified, infrastructure-enforced governance path that covers tool authorization, returned-data validation, sequential behavior, evidence generation, and graduated autonomy in one place. That gap is what this project targets.

**This project is the enforcement layer that governs what an AI agent does between receiving a request and taking an action.**

---

## What It Does

Every time an AI agent attempts an action, this framework:

1. **Evaluates** the request against policy, risk scoring, and behavioral analysis
2. **Decides** ALLOW, DENY, or ESCALATE (require human approval)
3. **Enforces** the decision at the AWS infrastructure layer (IAM boundaries, not just prompts)
4. **Validates** data returned from tools before the agent can process it
5. **Records** an immutable, hash-chained evidence record of every decision

The governance control path targets a sub-200 ms processing budget in the optimized Step Functions Express configuration; Lambda-oriented or cold-start paths may experience higher end-to-end latency (on the order of 1-2 s). The 200 ms figure is an advisory per-component budget (logged, not aborted); a circuit breaker trips at a separate hard 500 ms threshold. The agent cannot override the verdict, which is enforced at the IAM layer.

---

## Why This Exists

| What exists today | What it does | What it does not focus on |
|-------------------|-------------|-------------------|
| AWS Bedrock Guardrails | Filters input/output text | Governing tool calls, action sequences, or return-path data (it is a content filter, not an action-governance layer) |
| OPA / Cedar | Evaluates access policies | Detecting prompt injection or reasoning over sequential attack chains |
| WAFs | Protect HTTP requests | Understanding that an AI action emerged from compromised context |
| OWASP / NIST / ISO | Name the risks | Enforcing anything at runtime (they are guidance, not controls) |

This framework composes these building blocks (it *uses* Bedrock Guardrails and an OPA-style engine internally) into a single runtime enforcement path covering the agent's action loop end to end.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   User / Operator / Upstream Service                                        │
│                                                                             │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  GOVERNANCE CONTROL PLANE                                          <200ms   │
│                                                                             │
│  ┌─────────────┐                                                            │
│  │ Kill Switch │──── scope = 0? ──── DENY immediately (< 5ms)              │
│  └──────┬──────┘                                                            │
│         │                                                                   │
│         ▼                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Input Defense (sequential pipeline, short-circuits on first fail)  │    │
│  │                                                                     │    │
│  │  1. Unicode normalization (homoglyphs → ASCII)                      │    │
│  │  2. Encoded payload decoding (Base64, hex, URL)                     │    │
│  │  3. Delimiter injection scan (ChatML, Llama tags)                   │    │
│  │  4. Context stuffing check (>5000 chars)                            │    │
│  │  5. Instruction override detection (leet-speak, persona, multilingual)│   │
│  │  6. Bedrock Guardrails (harmful content, PII)                       │    │
│  │  7. Threat pattern matching (regex from DynamoDB)                   │    │
│  │                                                                     │    │
│  │  Any check fails → DENY immediately, remaining checks skipped       │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │                                           │
│         ┌───────────────────────┼───────────────────────┐                   │
│         ▼                       ▼                       ▼                   │
│  ┌─────────────┐      ┌──────────────────┐     ┌──────────────┐            │
│  │ Agent       │      │ Tool             │     │ Policy       │            │
│  │ Registry    │      │ Authorization    │     │ Engine       │            │
│  │             │      │                  │     │              │            │
│  │ Registered? │      │ Allowlisted?     │     │ OPA (Rego)   │            │
│  │ Active?     │      │ Rate limit OK?   │     │ Scope check  │            │
│  │ Scope valid?│      │ Params clean?    │     │ Time-of-day  │            │
│  └──────┬──────┘      └────────┬─────────┘     └──────┬───────┘            │
│         │                      │                       │                    │
│         └──────────────────────┼───────────────────────┘                    │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Risk Scoring (0-100)                                               │    │
│  │  base + scope + action + target + history (5 factors, capped)       │    │
│  │                                                                     │    │
│  │  Score < 70 ─────────── ALLOW                                       │    │
│  │  Score >= 70 ────────── ESCALATE (human approval required)          │    │
│  │  Policy DENY ────────── DENY (blocked, explain why)                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└───────────────────┬──────────────────────┬──────────────────────┬───────────┘
                    │                      │                      │
                    ▼                      ▼                      ▼
         ┌──────────────┐      ┌───────────────────┐     ┌──────────────┐
         │              │      │                   │     │              │
         │    DENY      │      │    ESCALATE       │     │    ALLOW     │
         │              │      │                   │     │              │
         │ Return       │      │ Queue for human   │     │ Proceed to   │
         │ explanation  │      │ SNS alert sent    │     │ execution    │
         │              │      │ Timeout = DENY    │     │              │
         └──────────────┘      └───────────────────┘     └──────┬───────┘
                                                                │
┌───────────────────────────────────────────────────────────────▼──────────────┐
│  AGENT EXECUTION PLANE                                                       │
│                                                                              │
│  Bedrock Agent (Nova Micro)                                                  │
│       │                                                                      │
│       ▼                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Scope-Gated Action Groups                                           │    │
│  │  Level 1: Read  │  Level 2: Propose  │  Level 3: Stage  │  Level 4  │    │
│  └──────────────────────────────────────────────────────────┬───────────┘    │
│                                                             │                │
│       ▼                                                     │                │
│  ┌──────────────────────────────────────┐                   │                │
│  │  Per-Tool Security (every call)      │                   │                │
│  │  - Scope enforcement                 │                   │                │
│  │  - Parameter injection scan          │                   │                │
│  │  - Rate limiting + chain detection   │                   │                │
│  └──────────────────┬───────────────────┘                   │                │
│                     ▼                                       │                │
│  ┌──────────────────────────────────────┐                   │                │
│  │  Enterprise Systems                  │                   │                │
│  │  S3 | DynamoDB | Pipelines           │                   │                │
│  └──────────────────┬───────────────────┘                   │                │
│                     ▼                                       │                │
│  ┌──────────────────────────────────────┐                   │                │
│  │  Tool Response Validator             │◄──────────────────┘                │
│  │  (scans data FROM tools before       │                                    │
│  │   agent can reason over it)          │                                    │
│  └──────────────────┬───────────────────┘                                    │
│                     ▼                                                        │
│  ┌──────────────────────────────────────┐                                    │
│  │  Output Guardrails                   │                                    │
│  │  - PII / credential stripping        │                                    │
│  │  - Exfiltration blocking             │                                    │
│  │  - System prompt leak detection      │                                    │
│  └──────────────────┬───────────────────┘                                    │
│                     │                                                        │
└─────────────────────┼────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────────────────────┐
│  EVIDENCE PLANE (async, non-blocking, adds 0ms to response time)             │
│                                                                              │
│  Every decision and every tool call produces:                                │
│                                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌───────────┐  │
│  │ SHA-256 Hash   │  │ S3 Object Lock │  │ CloudWatch     │  │Compliance │  │
│  │ Chain          │  │ (WORM)         │  │ + CloudTrail   │  │Mapping    │  │
│  │                │  │                │  │                │  │           │  │
│  │ Tamper =       │  │ Even root      │  │ Real-time      │  │ISO 42001  │  │
│  │ chain breaks   │  │ cannot delete  │  │ metrics        │  │NIST RMF   │  │
│  │                │  │                │  │                │  │EU AI Act  │  │
│  └────────────────┘  └────────────────┘  └────────────────┘  └───────────┘  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Three Governance Engines

The architecture runs three engines in concert. Each operates at a different point in time:

| Engine | When it runs | What it does | Key modules |
|--------|-------------|-------------|-------------|
| **Preventive** | BEFORE execution | Blocks unauthorized or dangerous actions before the agent acts | Kill switch, input sanitizer, OPA policy, tool authorization, behavioral invariants, scope enforcement |
| **Detective** | DURING and AFTER | Monitors for anomalies, drift, and degradation while the agent operates | Runtime drift detection, continuous health scoring, anomaly detector, CloudWatch metrics, sequential chain monitoring |
| **Proactive** | BEFORE deployment | Validates that policies and configurations are safe before they go live | Policy contradiction detection, dead rule identification, coverage gap analysis, formal invariant verification |

**How they work together:**

- Preventive stops known-bad actions in real time (< 200ms)
- Detective catches unknown-bad patterns that Preventive missed (baseline deviation, statistical anomalies)
- Proactive ensures the governance rules themselves are correct before they're deployed (no contradictions, no gaps)

A new attack that bypasses Preventive (because no pattern exists yet) is caught by Detective (because it deviates from baseline behavior). Detective flags it, the anomaly gets promoted to a named pattern via `threat_feed_integration.py`, and Preventive catches it from then on. That's the self-improving loop.

---

## How Scoring and Decisions Work

Every request gets a **risk score (0-100)** computed from five weighted factors:

```
Risk Score = base_weight + scope_weight + action_weight + target_weight + history_weight
```

| Factor | What it measures | Weight examples |
|--------|-----------------|-----------------|
| Category base | Inherent risk of action category | Data access = 5, Deployment = 25, Emergency = 35 |
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

  Category base:    25  (deployment category)
  Scope weight:     50  (level 3)
  Action weight:    50  (deployment)
  Target weight:    15  (staging)
  History weight:    0  (no recent denials)
  ─────────────────────
  Total:           140 → capped at 100

  Score = 100, threshold = 70
  100 >= 70 → ESCALATE (requires human approval)
```

Under the default weights, a production deployment saturates the score and cannot be auto-approved; it always escalates to a human. This is by design (and configurable).

---

## Three Under-Served Attack Surfaces

Most governance architectures do not provide a unified, enforceable control boundary across these three surfaces; this framework treats each as a first-class governed channel.

**1. Tool Response Validation (the "Perception Gap")**

Most existing governance architectures do not provide a general, enforceable control boundary for validating tool responses *before* agent reasoning. This framework scans every tool response for injection, anomalies, and sensitive data before the agent can reason over it, and (where an authoritative source exists) can re-fetch ground truth to detect a forged response rather than trusting the echoed payload. The detectors are heuristic (regex + entropy), not semantic - see [limitations](#validation).

**2. Sequential Chain Governance**

Access-control systems typically evaluate one action at a time. This framework maintains per-session state and evaluates whether a *sequence* of individually-safe actions is harmful in combination - via both administrator-declared dangerous sequences and data-flow taint tracking that flags a read-sensitive-then-write-external composition even when it was never enumerated.

**3. Enforcement-Time Tool Authorization**

AI agents read tool descriptions to decide how to use them, and those descriptions can carry hidden adversarial instructions (tool poisoning). This framework enforces a registration, approval, and name/version allowlist so an agent can only invoke vetted tools, plus per-tool parameter validation. Note: this is approval-and-allowlist control, **not** adversarial scanning of tool-description text - that remains future work.

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

All numbers below are produced by running real payloads through the deployed code; a reproducible harness is in [`paper/bench/`](governance-demo-bedrock/paper/bench/).

- **Public benchmarks (full pipeline, live on Isengard)**: across 7 public attack benchmarks (1,663 payloads) the preventive pipeline blocks 79-100%. Per-block *stage attribution* shows no single layer suffices - a pattern sanitizer blocks ~2% of GCG adversarial suffixes while the managed guardrail blocks ~88%, and the relationship inverts on injection sets - which is the empirical case for defense-in-depth.
- **Perception gap (InjecAgent, 2,108 cases)**: the tool-response validator blocks 100% of marker-carrying injections but 0% of semantically embedded ones. We report both honestly; the 0% quantifies the boundary of pattern-based (non-semantic) detection.
- **End-to-end (full 2,000 scenarios, live, no sampling)**: 86.0% correct verdict (1,719/2,000, 0 errors). 100% on every structurally-enforced category (scope, privilege escalation, kill switch, escalation, permitted actions); the misses concentrate in categories needing semantic inference (exfiltration 5%, parameter injection 24%). Mix: 610 allow, 50 escalate, 1,340 deny across 14 categories.
- **False-positive rate**: 0% on a benign set representative of the agent's real traffic (build/pipeline/ops queries). This is scope-dependent - the same strict detectors block much open-domain roleplay, which is appropriate for a locked-down agent but not for a general chatbot.
- **Attack corpus**: 9,465 payloads across 20 datasets (~8,972 unique after deduplication) used during development.
- **Unit/integration tests**: 239 automated tests (runs locally in ~33 seconds, no AWS required), including fail-closed, concurrency-lease, forgery-detection, and data-flow-chain tests.
- **Research foundation**: informed by peer-reviewed work (2023-2026) on tool poisoning, sequential chaining, indirect injection, memory, and supply-chain threats.

> Honest scope: these are strong validation artifacts for an individual open-source project, **not** a peer-reviewed scientific evaluation. There is not yet a head-to-head comparison against a published defense baseline (Llama Guard, CaMeL) on an identical payload set - the clearest next step, and disclosed as such.

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
python -m pytest tests/ -v                     # 239 tests
```

---

## Technology

| Layer | Service |
|-------|---------|
| AI Agent | Amazon Bedrock Agents (Nova Micro) |
| Governance Orchestration | AWS Step Functions Express (100K+ concurrent) |
| Policy Engine | OPA (Rego-subset, embedded or external) |
| State | Amazon DynamoDB (22 tables) |
| Evidence | Amazon S3 (Object Lock, COMPLIANCE mode, configurable retention) |
| Infrastructure | AWS CDK (Python, 6 modular constructs) |

---

## Documentation

| Document | Audience |
|----------|----------|
| [Architecture Deep-Dives](governance-demo-bedrock/docs/architecture/) | Platform architects |
| [Security Checklist (96 controls)](governance-demo-bedrock/docs/AI_AGENT_SECURITY_CHECKLIST.md) | Security reviewers |
| [Control Catalog (377 controls)](governance-demo-bedrock/docs/CONTROL_CATALOG.md) | Compliance teams |
| [Module Map (72 modules)](governance-demo-bedrock/lambdas/governance_engine/MODULE_MAP.md) | Developers |
| [Threat Model](governance-demo-bedrock/docs/THREAT_MODEL.md) | Risk assessors |
| [Evidence Collection Guide](governance-demo-bedrock/docs/EVIDENCE_COLLECTION_GUIDE.md) | Auditors |

---

## Author

**Author** - [Affiliation]
