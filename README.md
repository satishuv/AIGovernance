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

```
User Request
     |
     v
+------------------+
| Scope Enforcer   |  Entry point: reads scope, invokes governance pipeline
+--------+---------+
         |
         v
+------------------+     20-Step Governance Pipeline
| Governance       |     ================================
| Engine           |     LAYER 1: Hard Invariants
|                  |       Kill switch, time-of-day blocks, canary injection
| (20 security     |     LAYER 2: Input Defense
|  modules)        |       Unicode normalization, base64 decoding, delimiter
|                  |       detection, leet-speak, context stuffing, regex threats
|                  |     LAYER 3: Identity + Authorization
|                  |       Agent registry, environment isolation, tool auth,
|                  |       parameter validation, rate limiting, chain detection
|                  |     LAYER 4: Policy + Risk
|                  |       Policy-as-code evaluation, risk scoring (0-100),
|                  |       drift detection, anomaly detection
|                  |     LAYER 5: Evidence + Response Validation
|                  |       Immutable evidence, output guardrails, canary tripwire
|                  |     LAYER 6: Post-Decision Monitoring
|                  |       Health scoring, drift recording, metrics publishing
+--------+---------+
         |
         v (if ALLOW)
+------------------+
| Bedrock Agent    |  Amazon Nova Micro, 4 action groups
| (governed)       |  IAM boundary swapped per scope level
+--------+---------+
         |
         v
+------------------+
| Output           |  Validates response before returning to user
| Guardrails       |  Blocks ARN leaks, credential exposure, canary leakage
+------------------+
```

---

## Defense-in-Depth Security Layers

| Layer | Module | Attacks Caught |
|-------|--------|---------------|
| Input Sanitizer | `input_sanitizer.py` | Base64-encoded jailbreaks, ChatML/Llama delimiter injection, unicode homoglyphs, leet-speak obfuscation, context stuffing |
| Behavioral Invariants | `behavioral_invariants.py` | Time-of-day policy violations, output size exploits, agent compromise (canary tripwire) |
| Threat Detector | `threat_detector.py` | SQL injection, prompt injection (regex), destructive commands |
| Tool Execution Auth | `tool_execution_auth.py` | SQL injection in parameters, unauthorized tools, rate limit abuse, dangerous tool chains |
| Runtime Drift | `runtime_drift_detection.py` | Behavioral deviation from baseline, scope creep, unusual action patterns |
| Policy Engine | `policy_engine.py` | Policy violations, scope-exceeding actions |
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

# Deploy
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
npx cdk deploy -c skip_cloudtrail=true

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
| 2 | ChatML delimiter injection (`<\|im_start\|>system`) | Input Sanitizer | DENIED |
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
| Governance Engine | AWS Lambda (Python 3.12) |
| Policy Storage | Amazon S3 (versioned) |
| State Management | Amazon DynamoDB (25+ tables) |
| Evidence Storage | Amazon S3 (Object Lock) |
| API Endpoints | Amazon API Gateway |
| Alerts | Amazon SNS |
| Metrics + Alarms | Amazon CloudWatch |
| Scheduled Reports | Amazon EventBridge |
| Infrastructure | AWS CDK (Python) |

---

## Repository Structure

```
governance-demo-bedrock/          Active codebase
  lambdas/
    governance_engine/            20+ security modules (the core)
    scope_enforcer/               Request orchestrator + output guardrails
    action_group/                 Bedrock Agent business logic
    kill_switch/                  Emergency shutdown
    seed_tables/                  DynamoDB initialization
  schemas/                        OpenAPI action group schemas
  sample_data/                    Policies, configs, compliance mappings
  tests/                          CDK + governance tests
  governance_bedrock_stack.py     CDK infrastructure (single stack)

governance-demo/                  Frozen reference (OWASP test suite only)
```

---

## Key Design Principles

1. **Fail-safe defaults** - System denies on failure. Never fails open.
2. **Defense-in-depth** - 6 independent security layers. Bypassing one doesn't bypass all.
3. **Progressive trust** - Agents earn autonomy through demonstrated safe behavior.
4. **Policy-as-code** - Governance rules are machine-readable JSON, updated without deployments.
5. **Continuous evidence** - Every decision logged, hashed, and traceable to compliance controls.
6. **Physical constraints** - IAM boundaries and output caps cannot be overridden by model output.

---

## Authors

Built by the [Affiliation] team:

- **Paul Keastead**, Assurance Consultant
- **Author**, Associate Assurance Consultant

---

## License

This repository is a reference implementation for educational and demonstration purposes. Organizations should adapt the patterns to their specific regulatory and operational requirements.
