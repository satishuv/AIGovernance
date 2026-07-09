# Runtime Governance Framework for Agentic AI on AWS

*A production-grade, open-source reference architecture that governs autonomous AI agents with defense-in-depth security, OPA policy enforcement, HIPAA PII detection, tool response validation, and automated compliance evidence generation. Built on Amazon Bedrock Agents, deployed via modular AWS CDK constructs.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![AWS CDK](https://img.shields.io/badge/AWS_CDK-v2-orange.svg)](https://docs.aws.amazon.com/cdk/)
[![Controls](https://img.shields.io/badge/Security_Controls-93-green.svg)](governance-demo-bedrock/docs/AI_AGENT_SECURITY_CHECKLIST.md)
[![Tests](https://img.shields.io/badge/Demo_Scenarios-21%2F21_PASS-brightgreen.svg)](governance-demo-bedrock/test_datasets/run_demo_validation.py)

---

Run **21 validated demo scenarios**, detect **93.4% of 8,470+ real-world attacks** from 13 academic benchmarks, and deploy a complete governance pipeline with one command.

**Live site:** [satishuv.github.io/AIGovernance](https://satishuv.github.io/AIGovernance/)

## Table of Contents

- [What It Does](#what-it-does)
- [Why Use This Framework?](#why-use-this-framework)
- [Architecture](#architecture)
- [Three-Engine Governance Model](#three-engine-governance-model)
- [Attack Resilience](#attack-resilience)
- [Governed vs Ungoverned AI Development](#governed-vs-ungoverned-ai-development)
- [HIPAA PII Detection](#hipaa-pii-detection)
- [Quick Start](#quick-start)
- [Scope Levels](#scope-levels)
- [Technology Stack](#technology-stack)
- [Security Controls (93)](#security-controls)
- [Compliance Coverage](#compliance-coverage)
- [Documentation](#documentation)
- [License](#license)

---

## What It Does

This framework wraps every AI agent action with a governance pipeline that evaluates, approves or denies, and logs decisions in real-time. It provides:

| Challenge | How This Framework Helps |
|-----------|------------------------|
| AI agents invoke tools autonomously | Every tool call is authorized by OPA policy before execution |
| Prompt injection bypasses model safety | 6-layer input defense catches base64, ChatML, leet-speak, multilingual attacks |
| Tool responses contain hidden instructions | Tool response validator detects injection in data returned FROM tools |
| No audit trail for AI decisions | Immutable evidence records (SHA-256, S3 Object Lock, 7-year retention) |
| Compliance requires continuous proof | Automated evidence collection across 6 frameworks (ISO 42001, NIST AI RMF, 800-53, PCI DSS, EU AI Act) |
| Single guardrail layer is insufficient | 8 independent security modules, none trusts the others |
| HIPAA PHI leaks in responses | Bedrock Guardrails with custom regex (MRN, NPI, DOB, Insurance ID) |
| No emergency shutdown capability | Kill switch disables agent in under 1 second |
| Cannot prove governance effectiveness | `python scripts/collect_evidence.py` generates a complete audit package |

---

## Why Use This Framework?

| If you need... | This framework provides... |
|---------------|--------------------------|
| Runtime governance (not just policy docs) | 20-step pipeline evaluating every action before execution |
| Empirical proof your defenses work | 8,470+ attacks tested from 13 academic benchmarks (93.4% detection) |
| Tool response security (perception gap) | Validates data returned FROM tools before agent processes it |
| HIPAA-grade PII protection | Bedrock Guardrails + custom healthcare regex patterns |
| Policy-as-code (industry standard) | OPA engine with Rego-subset evaluation, priority-based resolution |
| Scalability for production | Step Functions Express supporting 100,000+ concurrent executions |
| Automated compliance evidence | One command generates a full audit package across 6 frameworks |
| Zero false positives | Validated: legitimate requests always pass (21/21 scenarios) |

---

## Architecture

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
|                    (runs IN PARALLEL with agent actions)                  |
|                                                                          |
|  +------------------------------------------------------------------+   |
|  |  LAYER 1: Kill Switch + Behavioral Invariants                     |   |
|  |  (hard limits no model can override)                              |   |
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
                                              v   v   v   v
                                          Read Propose Stage Prod
                                              |
                                              v
                  +------------------------------------------------------------------+
                  |  Tool Response Validator (scans data FROM tools for injection)    |
                  +------------------------------------------------------------------+
                                              |
                                              v
                  +------------------------------------------------------------------+
                  |  Output Guardrails + HIPAA PII Detection                         |
                  +------------------------------------------------------------------+
                                              |
                                              v
                  +------------------------------------------------------------------+
                  |  Async Evidence (EventBridge, non-blocking)                      |
                  |  SHA-256 + ISO 42001 + NIST AI RMF + 4 more frameworks          |
                  +------------------------------------------------------------------+
```

---

## Three-Engine Governance Model

| Engine | When | Purpose | Components |
|--------|------|---------|-----------|
| **Preventive** | Before execution | Block unauthorized or dangerous actions | OPA policy engine, input sanitizer, Bedrock Guardrails, scope enforcement, behavioral invariants, per-tool authorization, tool response validation |
| **Detective** | During and after | Monitor behavior, detect anomalies, alert | Runtime drift detection, continuous health monitoring, statistical anomaly detection, CloudWatch metrics |
| **Proactive** | Before config changes | Validate governance policies are correct | Policy contradiction detection, dead rule identification, coverage gap analysis |

---

## Attack Resilience

### Multi-Layer Defense Stack

| Layer | What It Catches | Detection Method |
|-------|----------------|-----------------|
| Input Sanitizer | Encoding attacks (base64, hex, URL), ChatML/Llama delimiters, unicode homoglyphs, leet-speak, context stuffing, multilingual injection | Pattern matching + decoding |
| Bedrock Guardrails | Harmful content, violence, hate, jailbreaks, illegal activities, misinformation | AI content classification |
| Threat Detector | SQL injection, prompt injection (regex), destructive commands | Configurable DynamoDB patterns |
| Per-tool enforcement | SQL injection in parameters, unauthorized tools, rate limit abuse, tool chaining | Inline checks (~15ms) |
| Tool Response Validator | Injection in S3/DynamoDB data, action directives in tool output, sensitive data in responses | Pattern + entropy + format analysis |
| Statistical anomaly | High entropy, script mixing, repetition patterns, unusual character distribution | Shannon entropy + z-score |
| Output Guardrails | System prompt leakage, credential exposure, ARN leaks, canary tripwire, PII | Regex + Bedrock Guardrails |

### Tested Against Real-World Attacks

Validated against **8,470+ unique attack payloads** from 13 published academic benchmarks:

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
| + 3 additional benchmarks | Various 2024-2025 | 3,248 | 93%+ |
| **Total** | **13 sources** | **8,470+** | **93.4%** |

---

## Governed vs Ungoverned AI Development

Live comparison from running a production user story through both approaches:

### Ungoverned (AI coding directly)

| Step | What Happened | Protection |
|------|--------------|-----------|
| Read codebase | Accessed all files freely | None |
| Process user story | Pasted raw API signatures as input | None |
| Write 6 files | Created components, hooks, tests in one shot | None |
| Push to production | Only blocked by accidental IAM permission | Coincidence |
| Evidence trail | Git commit message only | Cannot prove what checks ran |

**Total governance decisions: 0. Risk visibility: 0. Audit evidence: 0.**

### Governed (same task, wrapped by governance pipeline)

| Step | Action | Scope | Verdict | Risk Score |
|------|--------|-------|---------|-----------|
| Read codebase | ReadPipelineStatus | 1 | ALLOW | 35 |
| Process user story | ReadPipelineStatus | 1 | ALLOW | 35 |
| Propose changes | ProposeChanges | 2 | ALLOW | 50 |
| Write code (staging) | StagingDeployment | 3 | ESCALATE | 100 |
| Deploy to prod (scope 2) | ProductionDeployment | 2 | DENY | 100 |
| Deploy to prod (scope 4) | ProductionDeployment | 4 | ESCALATE | 100 |

**Total governance decisions: 6. Denied: 1. Escalated: 2. Evidence: 6 immutable records.**

---

## HIPAA PII Detection

| PII Type | Action | Example |
|----------|--------|---------|
| SSN | **BLOCK** (entire response) | `123-45-6789` |
| Credit Card | **BLOCK** (entire response) | `4111-1111-1111-1111` |
| Name | ANONYMIZE | `John Smith` to `{NAME}` |
| Medical Record Number | ANONYMIZE | `MRN-4829301` to `{Medical_Record_Number}` |
| National Provider ID | ANONYMIZE | `NPI 1234567890` to `{NPI_Number}` |
| Date of Birth | ANONYMIZE | `DOB: 03/15/1985` to `{Date_of_Birth}` |
| Insurance ID | ANONYMIZE | `Member ID: XYZ789` to `{Insurance_ID}` |

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

# Validate demo (must show 21/21 PASS)
python test_datasets/run_demo_validation.py

# Collect evidence package
python scripts/collect_evidence.py --scope monthly

# Run governed development demo
python scripts/governed_dev_demo.py
```

---

## Scope Levels

| Level | Action Groups Permitted | Risk Score Weight |
|-------|------------------------|-------------------|
| **0** | None (kill switch) | 0 |
| **1** | ReadPipelineStatus | 10 |
| **2** | + ProposeChanges | 25 |
| **3** | + StagingDeployment | 50 |
| **4** | + ProductionDeployment | 75 |

Each scope maps to a dedicated **IAM Permission Boundary** enforced by AWS (not just application logic).

---

## Technology Stack

| Component | Service |
|-----------|---------|
| AI Agent Runtime | Amazon Bedrock Agents (Nova Micro) |
| Policy Engine | OPA (Open Policy Agent) Rego-subset + Cedar formal verification |
| Content Safety | Amazon Bedrock Guardrails (HIPAA PII + 8 topic denials) |
| Governance Orchestration | AWS Step Functions Express Workflows |
| Per-Layer Lambdas | AWS Lambda (Python 3.12, 5 Lambda packages, 65 modules) |
| Event-Driven Post-Processing | Amazon EventBridge |
| State Management | Amazon DynamoDB (22 tables) |
| Policy Storage | Amazon S3 (versioned, OPA + Rego files) |
| Evidence Storage | Amazon S3 (Object Lock COMPLIANCE mode, SHA-256 hash chains) |
| Monitoring | Amazon CloudWatch (dashboard + 3 alarms + 10 custom metrics) |
| Distributed Tracing | AWS X-Ray |
| Alerts | Amazon SNS |
| API Endpoints | Amazon API Gateway (kill switch + approvals) |
| Infrastructure | AWS CDK (Python, 6 modular constructs) |
| CI/CD | GitHub Actions (lint, test, security scan, CDK synth) |

---

## Security Controls

**93 controls across 12 domains.** Full checklist with evidence requirements:

- [AI Agent Security Checklist](governance-demo-bedrock/docs/AI_AGENT_SECURITY_CHECKLIST.md) (threat-informed, 22 papers cited)
- [Evidence Collection Guide](governance-demo-bedrock/docs/EVIDENCE_COLLECTION_GUIDE.md) (per-control evidence + automation scripts)

Domains: Input Defense, Tool Response Validation, Output Defense, Policy Enforcement, Per-Tool Security, Agent Identity, Memory/RAG Security, Data Governance, Monitoring, Incident Response, Evidence/Compliance, Architecture.

---

## Compliance Coverage

| Framework | Controls Mapped |
|-----------|----------------|
| ISO/IEC 42001 | 9 Annex A controls (A.2 through A.10) |
| NIST AI RMF | 12 functions (GOVERN, MAP, MEASURE, MANAGE) |
| NIST 800-53 | 17 controls (AC, AU, CA, CM, IA, IR, RA, SA, SC, SI) |
| PCI DSS v4.0 | 10 requirements |
| EU AI Act | 10 articles (high-risk system requirements) |
| SP-047 | 7/7 control areas (Open Security Architecture) |

Evidence stored in S3 with Object Lock (configurable: 365 days demo / 2555 days production) and SHA-256 hash chains.

---

## Repository Structure

```
governance-demo-bedrock/
  governance_constructs/              6 modular CDK constructs
    storage.py                        S3, DynamoDB, IAM boundaries, SNS
    bedrock_agent.py                  Agent, action groups, scope enforcer
    governance_engine.py              Lambda, Step Functions, EventBridge
    monitoring.py                     CloudWatch dashboard, alarms, CloudTrail
    api.py                            API Gateway (kill switch + approvals)
    seed_data.py                      Seed Lambda + all table data
  governance_bedrock_stack.py         Thin orchestrator (~55 lines)
  lambdas/
    governance_engine/                65 governance modules
      index.py                        Thin entrypoint (routes to orchestrator/API)
      pipeline_orchestrator.py        20-step governance pipeline
      api_router.py                   API Gateway event handling
      tool_response_validator.py      Validates data FROM tools (perception gap)
      input_sanitizer.py              6-layer input defense
      opa_engine.py                   OPA policy evaluation
      output_guardrails.py            Response validation + PII
      ...
    action_group/                     Bedrock Agent tools (per-call security)
    scope_enforcer/                   Request orchestrator
    kill_switch/                      Emergency shutdown
  scripts/
    collect_evidence.py               Automated compliance evidence package
    governed_dev_demo.py              Live governance demo (6 decisions)
  config/
    demo.yaml                         Demo environment settings
    production.yaml                   Production environment settings
  tests/                              20 CDK tests (all passing)
  test_datasets/                      8,470+ attacks from 13 benchmarks
  docs/
    AI_AGENT_SECURITY_CHECKLIST.md    93 controls (threat-informed)
    EVIDENCE_COLLECTION_GUIDE.md      Per-control evidence requirements
    ARCHITECTURE.md                   Detailed architecture
    HIPAA_DEMO_GUIDE.md               HIPAA PII demo scenarios
```

---

## Research Foundations

| Source | Contribution |
|--------|-------------|
| **AWS Bedrock Guardrails** | Content filtering, PII detection, contextual grounding |
| **AWS AI Service Cards** | Responsible AI transparency and intended use boundaries |
| **NVIDIA NeMo Guardrails** | Programmable rails pattern: input/output/dialog rails |
| **OWASP LLM Top 10 (2025)** | Attack taxonomy: prompt injection, insecure output, supply chain |
| **OWASP Top 10 for Agentic Applications** | Agent-specific risks: excessive agency, tool poisoning |
| **NIST AI RMF (AI 100-1)** | Risk management lifecycle: GOVERN, MAP, MEASURE, MANAGE |
| **ISO/IEC 42001** | AI management system controls (Annex A.2 through A.10) |
| **MITRE ATLAS** | Adversarial threat landscape for AI systems |
| **CrowdStrike 2026 Global Threat Report** | 89% increase in AI attacks, 550% ChatGPT on criminal forums |
| **22 Academic Papers (2024-2025)** | MCPTox, STAC, MemoryGraft, ASB, ART, IPIGuard, and more |

---

## Documentation

| Document | Description |
|----------|-------------|
| [GitHub Pages Site](https://satishuv.github.io/AIGovernance/) | Full architecture, checklist, glossary, governed dev demo |
| [Security Checklist](governance-demo-bedrock/docs/AI_AGENT_SECURITY_CHECKLIST.md) | 93 controls with citations and attack success rates |
| [Evidence Guide](governance-demo-bedrock/docs/EVIDENCE_COLLECTION_GUIDE.md) | What to collect, where it lives, how to automate |
| [Architecture](governance-demo-bedrock/docs/ARCHITECTURE.md) | SDLC flow, three engines, threat coverage |
| [HIPAA Demo](governance-demo-bedrock/docs/HIPAA_DEMO_GUIDE.md) | 3 realistic HIPAA scenarios |
| [SECURITY.md](governance-demo-bedrock/SECURITY.md) | Vulnerability reporting + IAM exception documentation |
| [CONTRIBUTING.md](governance-demo-bedrock/CONTRIBUTING.md) | Development workflow and code style |

---

## License

MIT License. See [LICENSE](governance-demo-bedrock/LICENSE).

---

**Built by Author**, Associate Assurance Consultant, [Affiliation]
