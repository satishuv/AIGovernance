# AIGovernance

**Runtime governance framework for agentic AI on AWS**

A production-grade reference implementation demonstrating how to govern AI agents with defense-in-depth security, policy-as-code enforcement, continuous monitoring, and compliance evidence generation. Built on Amazon Bedrock Agents, deployed via AWS CDK.

Accompanies the AWS whitepaper: *"Building Trustworthy Agentic AI: A Governance Framework for Public Sector and Regulated Organizations"*

---

## The Problem

AI agents that reason and act autonomously introduce risks traditional software controls don't address. An agent with production access could deploy untested code, exfiltrate data, escalate its own permissions, or be jailbroken through prompt injection without human awareness.

This project provides a working answer: **How do you let AI agents be useful while keeping them safe, auditable, and compliant?**

---

## Architecture

AIGovernance supports two execution modes, switchable via the `GOVERNANCE_MODE` environment variable:

| Mode | Use Case | Engine | Latency | Concurrency |
|------|----------|--------|---------|-------------|
| `lambda` | Development, testing, low-traffic | Single Lambda (monolithic) | ~200ms | 1,000 concurrent |
| `stepfunctions` | Production, high-traffic, regulated | Step Functions Express Workflow | ~150ms (parallel) | 100,000+ concurrent |

### Production Architecture (Step Functions)

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
|                  |                                 |                     |
|  +---------------------------+  +---------------------------+           |
|  | Input Defense Lambda      |  | Authorization Lambda      |           |
|  |                           |  |                           |           |
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
|                                                                          |
+==========================================================================+
                                   |
              +--------------------+--------------------+
              |                    |                    |
         DENY |               ESCALATE            ALLOW |
              v                    v                    v
     +-------------+     +----------------+   +------------------+
     | Blocked     |     | Human Approval |   | Bedrock Agent    |
     | (explain    |     | Queue (SNS +   |   | (Amazon Nova     |
     |  why)       |     |  API Gateway)  |   |  Micro)          |
     +-------------+     +----------------+   +--------+---------+
                                                       |
                                              Scope determines which
                                              action groups are available:
                                                       |
                          +----------------------------+----------------------------+
                          |              |              |              |             |
                     Scope 1        Scope 2        Scope 3        Scope 4          |
                          |              |              |              |             |
                          v              v              v              v             |
                  +-------------+ +-------------+ +-------------+ +-------------+  |
                  | ReadPipeline| | Propose     | | Staging     | | Production  |  |
                  | Status      | | Changes     | | Deployment  | | Deployment  |  |
                  |             | |             | |             | |             |  |
                  | - Build     | | - Draft     | | - Deploy to | | - Deploy to |  |
                  |   status    | |   deploy    | |   staging   | |   prod      |  |
                  | - Test      | |   plans     | | - Run       | | - Canary    |  |
                  |   results   | | - Rollback  | |   integ     | |   analysis  |  |
                  | - Config    | |   strategy  | |   tests     | | - Auto      |  |
                  |   state     | |             | | - Promote   | |   rollback  |  |
                  +------+------+ +------+------+ +------+------+ +------+------+  |
                         |               |               |               |          |
                         +-------+-------+-------+-------+-------+------+          |
                                 |                                                  |
                                 v                                                  |
                  +------------------------------------------------------------------+
                  |  Output Guardrails (validates EVERY response before returning)   |
                  |  - System prompt leak detection    - Canary tripwire             |
                  |  - ARN/credential exposure         - Response size limits        |
                  +------------------------------------------------------------------+
                                 |
                                 v
                  +------------------------------------------------------------------+
                  |  Async Post-Decision (EventBridge, non-blocking)                 |
                  |  - Immutable evidence (S3 + SHA256)  - Decision history          |
                  |  - Control traces (ISO 42001, NIST)  - CloudWatch metrics        |
                  |  - Continuous health monitoring       - Drift baseline update    |
                  +------------------------------------------------------------------+
```

**Key insight:** The governance security wrapper runs as a sidecar around the agent's SDLC actions. Security is not a blocker that sits in front of the agent; it wraps every action, validating inputs before and outputs after. The agent's 4 action groups (the actual CI/CD pipeline work) execute inside this security envelope.

### Development Mode (Single Lambda)

In `lambda` mode, all 20 security modules execute sequentially within a single Governance Engine Lambda. Same checks, simpler topology. Best for debugging and low-traffic environments.

---

## Scalability

The dual-mode architecture enables organizations to start simple and scale without rearchitecting:

**Parallel Execution** -- Input defense and authorization checks run concurrently in separate Lambda functions. This halves the latency of the two heaviest governance layers compared to sequential execution.

**Async Evidence Writing** -- Post-decision processing (evidence hashing, compliance mapping, metrics) fires via EventBridge and does not block the governance response. The caller receives the verdict immediately.

**Independent Scaling** -- Each security layer is its own Lambda function with independent concurrency limits, memory allocation, and timeout settings. A spike in threat detection load does not affect policy evaluation capacity.

**100K+ Concurrent Executions** -- Step Functions Express Workflows support up to 100,000 concurrent executions per account per region. Combined with Lambda's scaling, the pipeline handles burst traffic without throttling.

**Feature Flag Switching** -- Set `GOVERNANCE_MODE=stepfunctions` or `GOVERNANCE_MODE=lambda` on the Scope Enforcer. No code changes, no redeployment of business logic. Both modes share the same security modules and policy definitions.

**Fail-Safe by Design** -- If Step Functions or any Lambda fails, the pipeline returns DENY. The kill switch check uses a native DynamoDB SDK integration (no Lambda cold start) to ensure emergency shutdown is always available.

---

## Research Foundations

The governance architecture draws from established AI safety frameworks and industry patterns:

| Source | Contribution |
|--------|-------------|
| **NVIDIA NeMo Guardrails** | Programmable rails pattern: input/output/dialog rails with configurable actions |
| **AWS Bedrock Guardrails** | Content filtering layers, denied topics, word filters as pre/post processing |
| **Microsoft Azure AI Content Safety** | Multi-category threat scoring, severity-based routing |
| **OWASP LLM Top 10 (2025)** | Attack taxonomy: prompt injection, insecure output handling, supply chain risks |
| **NIST AI RMF (AI 100-1)** | Risk management lifecycle: GOVERN, MAP, MEASURE, MANAGE functions |
| **ISO/IEC 42001** | AI management system controls (Annex A.2 through A.10) |

---

## Defense-in-Depth Security Layers

| Layer | Module | Attacks Caught |
|-------|--------|---------------|
| Input Sanitizer | `input_sanitizer.py` | Base64-encoded jailbreaks, ChatML/Llama delimiter injection, unicode homoglyphs, leet-speak obfuscation, context stuffing |
| Behavioral Invariants | `behavioral_invariants.py` | Time-of-day policy violations, output size exploits, agent compromise (canary tripwire) |
| Threat Detector | `threat_detector.py` | SQL injection, prompt injection (regex), destructive commands |
| Tool Execution Auth | `tool_execution_auth.py` | SQL injection in parameters, unauthorized tools, rate limit abuse, dangerous tool chains |
| Runtime Drift | `runtime_drift_detection.py` | Behavioral deviation from baseline, scope creep, unusual action patterns |
| OPA Policy Engine | `opa_engine.py` | Policy violations, scope-exceeding actions (Rego-subset evaluation with priority resolution) |
| Output Guardrails | `output_guardrails.py` | System prompt leakage, ARN/credential exposure, canary token leakage |
| Continuous Monitoring | `continuous_monitoring.py` | Health degradation, statistical anomalies, sustained risk patterns |

---

## Governance Verdicts

Every agent action request receives one of three verdicts:

| Verdict | Meaning | What Happens |
|---------|---------|-------------|
| **ALLOW** | Safe to execute | Bedrock Agent runs the action |
| **DENY** | Blocked by policy or security layer | Request rejected with explanation |
| **ESCALATE** | Requires human approval | Pending record created, SNS notification sent |

---

## Use Case: Software Deployment Pipeline

The demo simulates an AI agent managing a CI/CD pipeline with graduated autonomy:

| Scope | Permissions | Example |
|-------|------------|---------|
| 0 | None (kill switch) | Agent disabled |
| 1 | Read pipeline status | "Show me build-47 status" |
| 2 | + Propose changes | "Draft a deployment plan" |
| 3 | + Staging deployment | "Deploy to staging" |
| 4 | + Production deployment | "Release to production" |

---

## Quick Start

```bash
cd governance-demo-bedrock

# Install
python -m venv .venv
source .venv/Scripts/activate   # Windows Git Bash
pip install -r requirements.txt

# Deploy (Step Functions mode is the default)
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
npx cdk deploy -c skip_cloudtrail=true

# Switch to single-Lambda mode for development
# Set GOVERNANCE_MODE=lambda on the Scope Enforcer Lambda

# Test (governance engine directly)
aws lambda invoke \
  --function-name GovernanceBedrockStack-GovernanceEngineLambda* \
  --payload '{"agent_id":"demo-agent","action_group":"ReadPipelineStatus","target_resource":"default","input_text":"Show me build status","scope_level":1}' \
  --cli-binary-format raw-in-base64-out \
  output.json
```

---

## Attack Resilience (tested and validated)

| # | Attack | Defense Layer | Result |
|---|--------|--------------|--------|
| 1 | Base64-encoded jailbreak | Input Sanitizer | DENIED |
| 2 | ChatML delimiter injection (`<|im_start|>system`) | Input Sanitizer | DENIED |
| 3 | Leet-speak bypass (`1gnore prev1ous 1nstructions`) | Input Sanitizer | DENIED |
| 4 | Context stuffing (6000+ chars) | Input Sanitizer | DENIED |
| 5 | Direct prompt injection | Input Sanitizer | DENIED |
| 6 | Production deploy at wrong scope | Policy Engine | DENIED |
| 7 | SQL injection in tool parameter | Tool Execution Auth | DENIED |
| 8 | Unauthorized tool access | Tool/Model Registry | DENIED |
| 9 | Normal legitimate request | All layers | ALLOWED |
| 10 | Valid tool with correct parameters | All layers | ALLOWED |

---

## Compliance Coverage

Every governance decision generates evidence records mapped to:

- **ISO/IEC 42001** Annex A controls (A.2 through A.10)
- **NIST AI RMF** functions (GOVERN, MAP, MEASURE, MANAGE)

Evidence is stored in S3 with Object Lock (7-year retention) and SHA-256 hash chains for integrity verification.

---

## Technology Stack

| Component | Service |
|-----------|---------|
| AI Agent Runtime | Amazon Bedrock Agents (Nova Micro) |
| Governance Orchestration | AWS Step Functions Express Workflows |
| Governance Engine (dev mode) | AWS Lambda (Python 3.12, monolithic) |
| Security Layer Lambdas | AWS Lambda (Python 3.12, one per layer) |
| Event-Driven Post-Processing | Amazon EventBridge |
| Policy Engine | OPA (Open Policy Agent) Rego-subset, embedded or external |
| Policy Storage | Amazon S3 (versioned, JSON + Rego files) |
| State Management | Amazon DynamoDB (25+ tables) |
| Evidence Storage | Amazon S3 (Object Lock) |
| API Endpoints | Amazon API Gateway |
| Alerts | Amazon SNS |
| Metrics + Alarms | Amazon CloudWatch |
| Infrastructure | AWS CDK (Python) |

---

## Repository Structure

```
governance-demo-bedrock/              Active codebase
  lambdas/
    governance_engine/                20+ security modules (monolithic mode)
    scope_enforcer/                   Request orchestrator + mode selector
    input_defense/                    Input sanitization Lambda (Step Functions)
    authorization/                    Identity + auth Lambda (Step Functions)
    policy_risk/                      Policy eval + risk scoring Lambda (Step Functions)
    post_decision/                    Async evidence + metrics (EventBridge target)
    action_group/                     Bedrock Agent business logic
    kill_switch/                      Emergency shutdown
    seed_tables/                      DynamoDB initialization
  state_machine/
    governance_pipeline.asl.json      Step Functions ASL definition
  schemas/                            OpenAPI action group schemas
  sample_data/                        Policies, configs, compliance mappings
  tests/                              CDK + governance tests
  governance_bedrock_stack.py         CDK infrastructure (single stack)

governance-demo/                      Frozen reference (OWASP test suite only)
```

---

## Key Design Principles

1. **Fail-safe defaults** -- System denies on failure. Never fails open.
2. **Defense-in-depth** -- 6 independent security layers. Bypassing one doesn't bypass all.
3. **Progressive trust** -- Agents earn autonomy through demonstrated safe behavior.
4. **Policy-as-code** -- Governance rules are machine-readable JSON, updated without deployments.
5. **Continuous evidence** -- Every decision logged, hashed, and traceable to compliance controls.
6. **Physical constraints** -- IAM boundaries and output caps cannot be overridden by model output.
7. **Dual-mode scalability** -- Same security logic, different execution topology. Dev simplicity or production scale.
8. **Async by default** -- Evidence and metrics never block the governance verdict.

---

## Authors

Built by the [Affiliation] team:

- **Author**, Associate Assurance Consultant

---

## License

This repository is a reference implementation for educational and demonstration purposes. Organizations should adapt the patterns to their specific regulatory and operational requirements.

---

## AI Agentic Workload Security Checklist

Complete security checklist for AI agent deployments on AWS. Every item is implemented in this architecture.

### Input Defense
- Base64/hex/URL encoding detection and decoding
- ChatML/Llama delimiter injection blocking
- Unicode homoglyph normalization
- Leet-speak pattern decoding
- Context window stuffing detection (>5000 chars)
- Multilingual injection detection (German, Spanish, French, Croatian)
- Persona/roleplay jailbreak blocking (DAN, developer mode)
- Harmful content request blocking (violence, malware, fraud)
- Bedrock Guardrails content classification (8 topic denials)

### Output Defense
- System prompt leakage detection
- AWS ARN/credential/JWT stripping from responses
- PII detection and redaction (HIPAA: SSN, MRN, NPI, DOB)
- Canary token tripwire (agent compromise detection)
- Response size hard cap (output truncation)

### Policy Enforcement
- OPA policy engine (Rego-subset, priority-based resolution)
- Cedar formal verification (mathematically proven policies)
- Scope-based progressive autonomy (levels 0-4)
- IAM permission boundaries per scope level
- Default-deny posture (no matching rule = deny)
- Policy contradiction detection (proactive engine)
- Dead rule identification
- Coverage gap analysis

### Per-Tool Security
- Enum-based action group allowlisting
- Parameter injection scanning (SQL, XSS, path traversal)
- Per-invocation tool call cap (max 25)
- Recursion depth prevention (max 1)
- Tool chain attack detection
- Per-tool rate limiting

### Agent Identity and Lifecycle
- Formal agent registration required
- Agent status tracking (active/suspended)
- Cryptographic token exchange for data access
- Token scoping (data classes, TTL, revocable)
- Non-repudiation (SHA-256 hash chains)
- Cross-agent rule enforcement

### Data Governance
- Data classification enforcement (Cedar PHI authorization)
- Tokenized data-lake access (check-in/check-out)
- Retrieval content validation (RAG poisoning prevention)
- Semantic cache governance (PII never cached)
- Exfiltration detection (output size limits, endpoint allowlisting)

### Monitoring and Detection
- Runtime behavioral drift detection
- Continuous agent health scoring (0-100)
- Statistical anomaly detection (Shannon entropy, script mixing)
- CloudWatch dashboard (real-time metrics)
- PHI attestation dashboard (CISO deliverable)
- X-Ray distributed tracing
- Model invocation logging (CloudTrail)

### Incident Response
- Kill switch (instant agent shutdown, <1 second)
- Automated scope reduction on bad behavior
- SNS operator alerts
- Graduated escalation (deny > reduce scope > kill)

### Evidence and Compliance
- Immutable evidence (S3 Object Lock, 7-year retention)
- SHA-256 hash chain integrity
- ISO 42001 control mapping (9 Annex A controls)
- NIST AI RMF mapping (12 functions)
- NIST 800-53 mapping (17 controls)
- PCI DSS v4.0 mapping (10 requirements)
- EU AI Act mapping (10 articles)
- SP-047 alignment (7/7 control areas)

### Architecture
- Dual-mode execution (Lambda dev / Step Functions prod)
- Parallel execution (halves latency)
- Async evidence writing (non-blocking)
- 100,000+ concurrent executions
- Fail-safe deny (never fails open)
- Zero false positives on legitimate requests

### Validation
- 8,470+ attack payloads from 13 academic benchmarks
- 93.4% detection on pure attack datasets
- 21/21 demo scenarios validated
- Holmes security scan: 0 findings
- ASH automated scan: passed (false positives only)
- AWS AIML Security Assessment: key checks passed

---

**Total: 67 security controls implemented and validated.**
