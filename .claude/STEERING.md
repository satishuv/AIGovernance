# Steering Document - AIGovernance Enterprise Architecture Uplift

## What This Project Is

A production-grade AI governance framework for agentic AI on AWS. Demonstrates runtime governance controls (20-step pipeline), defense-in-depth security, and compliance evidence generation. Built for conference demos AND enterprise adoption.

## Current State (as of 2026-07-01)

### What's Done
- 20-step governance pipeline deployed and validated (account 831926627799, us-east-1)
- 6 Phase 4 security modules: input sanitizer, output guardrails, behavioral invariants, runtime drift, continuous monitoring, tool execution auth
- 10/10 attack scenarios pass (base64, ChatML, leet-speak, context stuffing, prompt injection, policy deny, SQL injection in params, blocked tools, normal ALLOW x2)
- Model: Amazon Nova Micro v1:0 (Bedrock Agent throttled due to quota; support case filed)
- CDK stack deploys in ~90s, all 20 tests pass
- Repo cleaned: 53 junk files removed, .gitignore updated, datetime.utcnow fixed globally

### What's Pending
- **Bedrock quota increase** (AWS support case filed 2026-06-30, expect 24-48h). Once approved, full end-to-end agent invocation works.
- **Enterprise architecture uplift** (next session goal)
- **Implementation guide for enterprises** (next session goal)

## Next Session Goal: Enterprise-Grade Architecture

The user wants this to be world-class, implementable by enterprises, not just a conference showpiece. Two deliverables:

### Deliverable 1: Implementation Guide
A detailed guide that enterprises can follow to implement this governance framework in their own environment. Should cover:
- Architecture Decision Records (ADRs) for each design choice
- Deployment patterns (single account, multi-account, org-wide)
- Customization guide (how to add custom policies, threat patterns, tool rules)
- OWASP LLM Top 10 mapping (which layer covers which threat)
- Integration patterns (how to wrap existing agents, how to add to CI/CD)
- Operational runbook (monitoring, alerting, incident response)

### Deliverable 2: Architecture Refactor
Evolve from "single Lambda with 20 modules" to production microservices:
- Each defense layer should be independently deployable/scalable
- Configuration-driven (no hardcoded rules; all from DynamoDB/S3)
- Plugin architecture for custom validators
- X-Ray tracing for full request observability
- Multi-account support (governance engine as a shared service)
- API-first (governance decisions available via REST API for any agent framework)

## Key Context

- **Account**: Personal 831926627799 (full Bedrock access, no SCP)
- **Also deployed to**: Isengard 917914785227 (SCP blocks Bedrock InvokeModel)
- **AWS credentials**: Profile `personal` (WARNING: old static keys were exposed in a prior session, user needs to rotate)
- **Model**: Amazon Nova Micro v1:0 (changed from Claude 3 Haiku)
- **CDK**: Python, single stack `GovernanceBedrockStack`, app.py entry point
- **Tests**: `python -m pytest tests/ -v` (20 CDK tests pass)
- **Deploy**: `npx cdk deploy -c skip_cloudtrail=true` with AWS_PROFILE=personal
- **The governance-demo/ folder is FROZEN** (never modify)

## User Preferences

- Satish is an Associate Assurance Consultant at [Affiliation]
- Wants practical, enterprise-grade architecture (not toy demos)
- Cares about defense-in-depth, continuous monitoring, drift detection
- Conference presentation context: AI agentic SDLC governance
- Prefers direct action over long explanations
- OK to spend money on personal account for demo reliability
- Uses Windows 11 with Git Bash, Python 3.12, VS Code

## File Locations

| What | Where |
|------|-------|
| CDK stack | `governance-demo-bedrock/governance_bedrock_stack.py` |
| Governance handler | `governance-demo-bedrock/lambdas/governance_engine/index.py` |
| Phase 4 modules | `governance-demo-bedrock/lambdas/governance_engine/{input_sanitizer,output_guardrails,behavioral_invariants,runtime_drift_detection,continuous_monitoring,tool_execution_auth}.py` |
| Scope enforcer | `governance-demo-bedrock/lambdas/scope_enforcer/index.py` |
| Policies | `governance-demo-bedrock/sample_data/policies/` |
| Tests | `governance-demo-bedrock/tests/` |
| Demo guides | `governance-demo-bedrock/DEMO_CONSOLE_GUIDE*.md` |
| Plan file | `.claude/plans/playful-wibbling-panda.md` |

## How to Validate Everything Works

```bash
cd governance-demo-bedrock
export AWS_PROFILE=personal
export AWS_REGION=us-east-1

# Synth
npx cdk synth -c skip_cloudtrail=true > /dev/null && echo OK

# Tests
python -m pytest tests/test_governance_bedrock_stack.py -v

# Deploy
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Attack battery (run from repo root)
# See the python script pattern used in this session's final test (10 scenarios)
```

## Lambda Function Names (deployed)

| Function | Name |
|----------|------|
| Governance Engine | GovernanceBedrockStack-GovernanceEngineLambda76BBC-aZUy3DLvBpVS |
| Scope Enforcer | GovernanceBedrockStack-ScopeEnforcerLambda6E908DFB-zkP8akqaUzI9 |
| Kill Switch | GovernanceBedrockStack-KillSwitchLambdaC7575B3E-VcNmZ8NbdyWy |
| Action Group | GovernanceBedrockStack-ActionGroupLambdaDAF0E21B-6fTISHkyUsRJ |
