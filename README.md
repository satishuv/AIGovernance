# Runtime Governance Framework for Agentic AI on AWS

*A production-grade, open-source reference architecture that governs autonomous AI agents with defense-in-depth security, OPA policy enforcement, HIPAA PII detection, and automated compliance evidence generation. Built on Amazon Bedrock Agents, deployed as a single AWS CDK stack.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![AWS CDK](https://img.shields.io/badge/AWS_CDK-v2-orange.svg)](https://docs.aws.amazon.com/cdk/)

---

Run **21 validated demo scenarios**, detect **87.9% of 5,720 real-world attacks**, and deploy a complete governance pipeline with one command.

## Table of Contents

- [What It Does](#what-it-does)
- [Why Use This Framework?](#why-use-this-framework)
- [Architecture](#architecture)
- [Three-Engine Governance Model](#three-engine-governance-model)
- [Attack Resilience](#attack-resilience)
- [HIPAA PII Detection](#hipaa-pii-detection)
- [Quick Start](#quick-start)
- [Scope Levels](#scope-levels)
- [Technology Stack](#technology-stack)
- [Demo Scenarios](#demo-scenarios)
- [Benchmark Results](#benchmark-results)
- [Compliance Coverage](#compliance-coverage)
- [SP-047 Alignment](#sp-047-alignment)
- [Repository Structure](#repository-structure)
- [Key Design Principles](#key-design-principles)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## What It Does

This framework wraps every AI agent action with a governance pipeline that evaluates, approves or denies, and logs decisions in real-time. It provides:

| Challenge | How This Framework Helps |
|-----------|------------------------|
| AI agents invoke tools autonomously | Every tool call is authorized by OPA policy before execution |
| Prompt injection bypasses model safety | 5-layer input defense catches base64, ChatML, leet-speak, multilingual attacks |
| No audit trail for AI decisions | Immutable evidence records (SHA-256, S3 Object Lock, 7-year retention) |
| Compliance requires continuous proof | Automated mapping to ISO 42001, NIST AI RMF, SOC 2, FedRAMP |
| Single guardrail layer is insufficient | 8 independent security modules, none trusts the others |
| HIPAA PHI leaks in responses | Bedrock Guardrails with custom regex (MRN, NPI, DOB, Insurance ID) |
| No emergency shutdown capability | Kill switch disables agent in under 1 second |

**Services assessed:** Amazon Bedrock Agents, Amazon Bedrock Guardrails, AWS Lambda, AWS Step Functions, Amazon DynamoDB, Amazon S3, Amazon EventBridge, Amazon CloudWatch, AWS X-Ray, Amazon SNS, Amazon API Gateway, AWS IAM.

---

## Why Use This Framework?

| If you need... | This framework provides... |
|---------------|--------------------------|
| Runtime governance (not just policy docs) | 20-step pipeline evaluating every action before execution |
| Empirical proof your defenses work | 5,720 attacks tested from 10 academic benchmarks (87.9% detection) |
| HIPAA-grade PII protection | Bedrock Guardrails + custom healthcare regex patterns |
| Policy-as-code (industry standard) | OPA engine with Rego-subset evaluation, priority-based resolution |
| Scalability for production | Step Functions Express supporting 100,000+ concurrent executions |
| Zero false positives | Validated: legitimate requests always pass |

---

## Architecture

![Architecture Diagram](docs/architecture-diagram.png)

*Export your Draw.io diagram as PNG and save to `docs/architecture-diagram.png`*

<details>
<summary>View text-based architecture diagram</summary>

```
                              User Request
                                   |
                                   v
                          +------------------+
                          | Scope Enforcer   |  Reads scope level (0-4)
                          +--------+---------+
                                   |
                                   v
+==========================================================================+
|                    GOVERNANCE SECURITY WRAPPER                            |
|                                                                          |
|  +------------------------------------------------------------------+   |
|  |  LAYER 1: Kill Switch + Behavioral Invariants                     |   |
|  +------------------------------------------------------------------+   |
|                                   |                                      |
|                  +----------------+----------------+                     |
|                  |     PARALLEL EXECUTION          |                     |
|  +---------------------------+  +---------------------------+           |
|  | Input Defense Lambda      |  | Authorization Lambda      |           |
|  | - Unicode normalization   |  | - Agent identity          |           |
|  | - Base64/hex decoding     |  | - Agent registry          |           |
|  | - ChatML/Llama delimiters |  | - Environment isolation   |           |
|  | - Leet-speak detection    |  | - Tool/model approval     |           |
|  | - Context stuffing        |  | - Per-tool rate limits    |           |
|  | - Regex threat patterns   |  | - Tool chain detection    |           |
|  +---------------------------+  +---------------------------+           |
|                  |                                 |                     |
|                  +----------------+----------------+                     |
|                                   |                                      |
|  +------------------------------------------------------------------+   |
|  |  Policy + Risk Decision Lambda                                    |   |
|  |  - OPA policy engine (Rego-subset, priority-based resolution)     |   |
|  |  - Risk scoring (0-100)  - Drift detection                        |   |
|  |  - Verdict: ALLOW / DENY / ESCALATE                               |   |
|  +------------------------------------------------------------------+   |
+==========================================================================+
                                   |
              +--------------------+--------------------+
              |                    |                    |
         DENY |               ESCALATE            ALLOW |
              v                    v                    v
     +-------------+     +----------------+   +------------------+
     | Blocked     |     | Human Approval |   | Bedrock Agent    |
     | (explain)   |     | Queue (SNS)    |   | (Nova Micro)     |
     +-------------+     +----------------+   +--------+---------+
                                                       |
                                              +--------+--------+
                                              |   |   |   |
                                             S1  S2  S3  S4
                                              |   |   |   |
                                              v   v   v   v
                                          Read Propose Stage Prod
                                              |
                                              v
                  +------------------------------------------------------------------+
                  |  Output Guardrails + HIPAA PII Detection                         |
                  +------------------------------------------------------------------+
                                              |
                                              v
                  +------------------------------------------------------------------+
                  |  Async Evidence (EventBridge, non-blocking)                      |
                  |  SHA-256 + ISO 42001 + NIST AI RMF mapping                      |
                  +------------------------------------------------------------------+
```

</details>

---

## Three-Engine Governance Model

| Engine | When | Purpose | Components |
|--------|------|---------|-----------|
| **Preventive** | Before execution | Block unauthorized or dangerous actions | OPA policy engine, input sanitizer, Bedrock Guardrails, scope enforcement, behavioral invariants, per-tool authorization |
| **Detective** | During and after | Monitor behavior, detect anomalies, alert | Runtime drift detection, continuous health monitoring, statistical anomaly detection, CloudWatch metrics |
| **Proactive** | Before config changes | Validate governance policies are correct | Policy contradiction detection, dead rule identification, coverage gap analysis, unsafe change validation |

---

## Attack Resilience

### Multi-Layer Defense Stack

| Layer | What It Catches | Detection Method |
|-------|----------------|-----------------|
| Input Sanitizer | Encoding attacks (base64, hex, URL), ChatML/Llama delimiters, unicode homoglyphs, leet-speak, context stuffing, multilingual injection | Pattern matching + decoding |
| Bedrock Guardrails | Harmful content, violence, hate, jailbreaks, illegal activities, misinformation | AI content classification |
| Threat Detector | SQL injection, prompt injection (regex), destructive commands | Configurable DynamoDB patterns |
| Per-tool enforcement | SQL injection in parameters, unauthorized tools, rate limit abuse, tool chaining | Inline checks (~15ms) |
| Statistical anomaly | High entropy, script mixing, repetition patterns, unusual character distribution | Shannon entropy + z-score |
| Guardian Monitor | Semantic safety evaluation beyond pattern matching | Parallel AI model (LLM-based) |
| Output Guardrails | System prompt leakage, credential exposure, ARN leaks, canary tripwire | Regex + Bedrock Guardrails |

### Tested Against Real-World Attacks

Validated against **5,720 unique attack payloads** from 10 published academic benchmarks:

| Dataset | Source | Attacks | Detection |
|---------|--------|---------|-----------|
| AdvBench | ICML 2024 | 520 | **98.8%** |
| ChatGPT Jailbreaks | rubend18 | 79 | **100.0%** |
| JailbreakBench | NeurIPS 2024 | 100 | **95.0%** |
| HarmfulQA | Declare Lab | 1,000 | 87%+ |
| LLM-LAT Harmful | LLM-LAT | 1,000 | 85%+ |
| BeaverTails | PKU Alignment | 604 | 85%+ |
| In-the-Wild Jailbreaks | TrustAI Lab | 666 | 80%+ |
| Deepset Injections | Deepset | 203 | 75.9% |
| Gandalf Ignore | Lakera | 111 | 81.1% |
| Do-Not-Answer | LibrAI | 939 | 80%+ |
| **Total** | | **5,720** | **87.9%** |

---

## HIPAA PII Detection

Healthcare-specific PII detection and redaction using Amazon Bedrock Guardrails:

| PII Type | Action | Example |
|----------|--------|---------|
| SSN | **BLOCK** (entire response) | `123-45-6789` |
| Credit Card | **BLOCK** (entire response) | `4111-1111-1111-1111` |
| Name | ANONYMIZE | `John Smith` to `{NAME}` |
| Medical Record Number | ANONYMIZE | `MRN-4829301` to `{Medical_Record_Number}` |
| National Provider ID | ANONYMIZE | `NPI 1234567890` to `{NPI_Number}` |
| Date of Birth | ANONYMIZE | `DOB: 03/15/1985` to `{Date_of_Birth}` |
| Insurance ID | ANONYMIZE | `Member ID: XYZ789` to `{Insurance_ID}` |
| Email, Phone, Address | ANONYMIZE | Replaced with placeholders |

**BLOCK** = entire response suppressed (critical PHI). **ANONYMIZE** = identifiers replaced with placeholders, clinical data passes through (minimum necessary principle).

---

## Quick Start

```bash
cd governance-demo-bedrock

# Install
python -m venv .venv
source .venv/Scripts/activate   # Windows
pip install -r requirements.txt

# Deploy (single command, ~3 minutes)
export AWS_PROFILE=your-profile
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Validate demo works
python test_datasets/run_demo_validation.py
# Expected: "ALL SCENARIOS PASS. SAFE TO DEMO LIVE."
```

---

## Scope Levels

| Level | Action Groups Permitted | Description |
|-------|------------------------|-------------|
| **0** | None (kill switch) | Agent fully disabled |
| **1** | ReadPipelineStatus | Read-only: query build status and test results |
| **2** | + ProposeChanges | Draft deployment plans and rollback strategies |
| **3** | + StagingDeployment | Deploy to staging, run integration tests |
| **4** | + ProductionDeployment | Full autonomy: production deploys and rollbacks |

Each scope maps to a dedicated **IAM Permission Boundary** enforced by AWS (not just application logic).

---

## Technology Stack

| Component | Service |
|-----------|---------|
| AI Agent Runtime | Amazon Bedrock Agents (Nova Micro) |
| Policy Engine | OPA (Open Policy Agent) Rego-subset, embedded or external |
| Content Safety | Amazon Bedrock Guardrails (HIPAA PII + content filters) |
| Governance Orchestration | AWS Step Functions Express Workflows |
| Per-Layer Lambdas | AWS Lambda (Python 3.12) |
| Event-Driven Post-Processing | Amazon EventBridge |
| State Management | Amazon DynamoDB (22+ tables) |
| Policy Storage | Amazon S3 (versioned, reload in 60s) |
| Evidence Storage | Amazon S3 (Object Lock, 7-year retention) |
| Monitoring | Amazon CloudWatch (dashboard + alarms) |
| Distributed Tracing | AWS X-Ray |
| Alerts | Amazon SNS |
| API Endpoints | Amazon API Gateway (kill switch + approvals) |
| Infrastructure | AWS CDK (Python, single stack) |

---

## Demo Scenarios

21 validated scenarios covering the full demo flow:

| # | Scenario | Expected | Status |
|---|----------|----------|--------|
| 1 | Bedrock Agent: build-47 status | Agent responds with data | PASS |
| 2 | Bedrock Agent: test results | Agent responds with results | PASS |
| 3 | Normal governance request | ALLOW | PASS |
| 4 | Production deploy at scope 2 | DENY (OPA policy) | PASS |
| 5 | Direct prompt injection | DENY (input sanitizer) | PASS |
| 6 | Base64 encoded jailbreak | DENY (decoded + caught) | PASS |
| 7 | ChatML delimiter injection | DENY (delimiter detected) | PASS |
| 8 | Leet-speak bypass | DENY (1=i decoded) | PASS |
| 9 | DAN persona attack | DENY (jailbreak pattern) | PASS |
| 10 | Context stuffing (6000 chars) | DENY (length exceeded) | PASS |
| 11 | German language injection | DENY (multilingual) | PASS |
| 12 | Developer mode override | DENY (authority pattern) | PASS |
| 13 | Phishing email request | DENY (content safety) | PASS |
| 14 | Malware creation request | DENY (content safety) | PASS |
| 15 | Violence instructions | DENY (content safety) | PASS |
| 16-21 | Step Functions pipeline, additional | PASS | PASS |

---

## Benchmark Results

### Performance Characteristics

| Metric | Value |
|--------|-------|
| Governance evaluation latency (p50) | 150ms |
| Per-tool-call overhead | 15ms |
| Maximum concurrent executions | 100,000+ |
| Policy reload time (no deploy) | < 60 seconds |
| Evidence write latency (async) | 1-2 seconds |
| False positive rate | 0% |

### Detection Improvement by Layer

| Defense Layer | Cumulative Detection |
|--------------|---------------------|
| Input Sanitizer (regex only) | 34.4% |
| + Bedrock Guardrails (AI classifier) | 87.9% |
| + Guardian Monitor (LLM evaluation) | 95%+ projected |

---

## Compliance Coverage

| Framework | Architecture Component |
|-----------|----------------------|
| ISO 42001 A.2 (AI Policy) | OPA Policy Engine |
| ISO 42001 A.6 (Lifecycle) | Three-Engine Model |
| ISO 42001 A.9 (Performance) | Continuous Monitoring |
| NIST AI RMF GOVERN | Policy-as-Code |
| NIST AI RMF MEASURE | Risk Scoring, CloudWatch Metrics |
| NIST AI RMF MANAGE | Decision Engine, Kill Switch |
| SOC 2 (Security) | Per-Tool Enforcement, Evidence Pipeline |
| FedRAMP (Monitoring) | Continuous Assurance Layer |
| HIPAA 164.312 | PII Detection, Audit Controls, Access Controls |
| OWASP LLM Top 10 | Input/Output Defense Layers |

---

## SP-047 Alignment

This architecture satisfies all 7 control areas defined by the [Open Security Architecture SP-047 pattern](https://www.opensecurityarchitecture.org/patterns/sp-047/) for Secure Agentic AI Frameworks:

| SP-047 Control Area | Implementation |
|--------------------|---------------|
| Agent Execution Isolation | Lambda isolation + IAM permission boundaries (scope 1-4) |
| Tool Registry & Plugin Governance | `agent_registry.py`, `tool_model_registry.py`, `tool_execution_auth.py` |
| Guardrails Architecture | 5-layer input defense + Bedrock Guardrails + output sanitization |
| RAG Pipeline Security | `retrieval_validator.py` + `cache_governance.py` |
| Multi-Agent Trust | `multi_agent.py` + `privilege_escalation.py` |
| Cost & Resource Governance | Rate limiting, invocation caps, recursion prevention |
| Agent Lifecycle & Deployment | CDK IaC, OPA policies (versioned), proactive engine |

---

## Repository Structure

```
governance-demo-bedrock/
├── app.py                          CDK app entry point
├── governance_bedrock_stack.py     Full CDK stack (single file, ~2000 lines)
├── lambdas/
│   ├── governance_engine/          20+ governance modules
│   │   ├── index.py               Main handler (20-step pipeline)
│   │   ├── opa_engine.py          OPA policy evaluation
│   │   ├── input_sanitizer.py     Multi-layer input defense
│   │   ├── output_guardrails.py   Response validation
│   │   ├── bedrock_guardrails.py  AWS content safety integration
│   │   ├── behavioral_invariants.py  Hard limits + canary tokens
│   │   ├── runtime_drift_detection.py  Behavioral baseline comparison
│   │   ├── continuous_monitoring.py  Health scoring + anomaly detection
│   │   ├── tool_execution_auth.py  Per-tool authorization
│   │   ├── guardian_monitor.py    Parallel AI safety evaluator
│   │   ├── anomaly_detector.py    Statistical anomaly detection
│   │   ├── retrieval_validator.py  RAG content validation
│   │   ├── cache_governance.py    Semantic cache security
│   │   ├── proactive_engine.py    Policy self-validation
│   │   └── ...                    (25+ modules total)
│   ├── scope_enforcer/            Request orchestrator + output guardrails
│   ├── action_group/              Bedrock Agent tool handler (per-call security)
│   └── kill_switch/               Emergency shutdown
├── state_machine/                  Step Functions ASL definition
├── schemas/                        OpenAPI action group schemas
├── sample_data/
│   ├── policies/                   OPA policy files (JSON + Rego)
│   ├── configs/                    Governance configurations
│   └── compliance/                 ISO 42001 + NIST mappings
├── test_datasets/                  5,720 attacks from 10 benchmarks
├── tests/                          CDK + unit + security tests
└── docs/
    ├── ARCHITECTURE.md             Detailed architecture + threat coverage
    ├── IMPLEMENTATION_GUIDE.md     Enterprise adoption guide (920 lines)
    ├── HIPAA_DEMO_GUIDE.md         HIPAA PII demo with 3 scenarios
    └── ieee_paper.tex              IEEE paper (LaTeX)
```

---

## Key Design Principles

1. **Fail-safe deny** — Every failure path returns DENY. Never fails open.
2. **Defense-in-depth** — 8 independent security layers. Bypassing one doesn't bypass all.
3. **Progressive trust** — Agents earn autonomy through demonstrated safe behavior.
4. **Policy-as-code** — OPA rules are machine-readable JSON, updated without deployments.
5. **Continuous evidence** — Every decision logged, hashed, and traceable to compliance controls.
6. **Physical constraints** — IAM boundaries and scope enforcement cannot be overridden by model output.
7. **Dual-mode scalability** — Single Lambda for dev, Step Functions for production. One feature flag.
8. **Async by default** — Evidence writing and monitoring never block the governance response.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](governance-demo-bedrock/docs/ARCHITECTURE.md) | SDLC flow, three engines, threat coverage, design decisions |
| [Implementation Guide](governance-demo-bedrock/docs/IMPLEMENTATION_GUIDE.md) | Enterprise adoption: ADRs, deployment patterns, OWASP mapping, operational runbook |
| [HIPAA Demo Guide](governance-demo-bedrock/docs/HIPAA_DEMO_GUIDE.md) | 3 realistic HIPAA scenarios with step-by-step demo actions |
| [IEEE Paper](governance-demo-bedrock/docs/ieee_paper.tex) | Academic paper with empirical validation results |

---

## Contributing

Contributions welcome. Please open an issue or pull request.

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

This project is licensed under the MIT License.

---

**Built by the [Affiliation] team.**

**Author**, Assurance Consultant
