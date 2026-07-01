# AIGovernance Project Status

## Project Overview
Building a whitepaper on agentic AI governance for public sector, plus a deployable code demo that demonstrates the governance framework in practice.

## Track A: Whitepaper Content Uplift

| Task | Status |
|------|--------|
| Original text reviewed | Done |
| Writing analysis (passive voice, weasel words, compliance) | Done |
| Change guide created (42 changes) | Done |
| All 42 changes applied to text | Done |
| Diagram improvement suggestions | Pending (future v3) |

## Track B: Code Governance Demo

### Phase 1a-1c: Core Governance Engine (DONE)
- Scope enforcement, kill switch, policy evaluation, risk scoring, decision engine
- Agent identity, registry, environment isolation, separation of duties
- Evidence pipeline (SHA-256 hash chains), control traces (ISO 42001 + NIST AI RMF)
- Threat detection, compliance mapping, validation suite

### Phase 2: Human-in-the-Loop (DONE)
- Approval workflow with SNS notifications
- Change logging with 7-year retention
- Queryable decision history
- API Gateway endpoints for approvals

### Phase 3: Advanced Detection (DONE)
- CloudWatch metrics and alarms
- Privilege escalation hardening
- Data exfiltration prevention
- Graduated scope reduction
- Multi-agent governance

### Phase 4: Defense-in-Depth Security (DONE)
- Input sanitizer (base64, ChatML, leet-speak, unicode, context stuffing)
- Output guardrails (ARN exposure, credential leaks, canary tripwire)
- Behavioral invariants (time-of-day, output caps, canary injection)
- Runtime drift detection (behavioral baseline comparison)
- Continuous monitoring (health scoring, anomaly detection)
- Tool execution authorization (parameter validation, rate limiting, chain detection)

### Phase 5: Scalable Architecture (DONE)
- Step Functions Express pipeline with parallel execution
- 4 focused Lambdas (InputDefense, Authorization, PolicyRisk, PostDecision)
- Async evidence writing via EventBridge (non-blocking)
- GOVERNANCE_MODE feature flag (lambda vs step_functions)
- OPA policy engine (Rego-subset, embedded + external modes)
- Per-tool-call inline security in Action Group Lambda (~15ms overhead)
- CloudWatch monitoring dashboard (AIGovernance-Monitoring)

### Pending
- Bedrock quota increase (support case filed, awaiting resolution)
- Full end-to-end agent invocation test (blocked by quota)

## Deployment

| Account | Region | Status |
|---------|--------|--------|
| 831926627799 (personal) | us-east-1 | Deployed, governance working, agent throttled |
| 917914785227 (Isengard) | us-east-1 | Deployed, SCP blocks Bedrock InvokeModel |

## Architecture

Three governance engines:
- **Preventive**: OPA policy engine, input sanitizer, scope enforcement, per-tool auth
- **Detective**: Drift detection, continuous monitoring, CloudWatch metrics
- **Proactive**: (Planned) Policy validation, config drift prevention

Dual execution modes:
- **Lambda mode**: All 20 steps in single Lambda (~200ms)
- **Step Functions mode**: Parallel branches, async evidence (100K+ concurrent)

## Rules for AI Assistants
1. Never modify original files (the .docx is untouchable)
2. Never use em dashes anywhere
3. Never store secrets, tokens, or passwords in any file
4. Work step by step, explain everything clearly
5. All code changes go in the `governance-demo-bedrock/` folder (governance-demo/ is frozen)
6. Commit often with conventional commit messages
