# Steering Document - AIGovernance Enterprise Architecture

## What This Project Is

A production-grade AI governance framework for agentic AI on AWS. Demonstrates runtime governance controls (20-step pipeline, dual-mode execution), defense-in-depth security, and compliance evidence generation. Built for conference demos AND enterprise adoption.

## Current State (as of 2026-06-30, end of session)

### What's Done

**Phase 1-3: Core Governance Pipeline**
- 20-step governance pipeline deployed and validated (account 831926627799, us-east-1)
- Scope enforcement, kill switch, policy evaluation, risk scoring, decision engine
- Evidence write with SHA-256 hashing, control traces (ISO 42001 + NIST AI RMF)

**Phase 4: Defense-in-Depth Security Modules**
- 6 security modules: input sanitizer, output guardrails, behavioral invariants, runtime drift, continuous monitoring, tool execution auth
- 10/10 attack scenarios pass (base64, ChatML, leet-speak, context stuffing, prompt injection, policy deny, SQL injection in params, blocked tools, normal ALLOW x2)

**Phase 5: Step Functions Scalable Pipeline (DONE)**
- 4 new focused Lambdas created: InputDefense, Authorization, PolicyRisk, PostDecision
- Step Functions Express state machine deployed: `governance-pipeline`
- State machine ARN: `arn:aws:states:us-east-1:831926627799:stateMachine:governance-pipeline`
- Parallel execution: InputDefense and Authorization run concurrently in the state machine
- EventBridge rule for async post-decision processing (evidence write no longer blocks response)
- GOVERNANCE_MODE feature flag on Scope Enforcer (values: `lambda` or `step_functions`)
- Both modes validated: single-Lambda (backward compat, 5/5 tests) + Step Functions (scalable, 5/5 tests)
- Architecture supports 1000+ concurrent executions

**Infrastructure and Operations**
- Model: Amazon Nova Micro v1:0 (Bedrock Agent throttled due to quota; support case filed)
- CDK stack deploys in ~90s
- Repo cleaned: 53 junk files removed, .gitignore updated, datetime.utcnow fixed globally

**Research Completed**
- NVIDIA NeMo Guardrails (programmable rails architecture)
- AWS Bedrock Guardrails (content filters, denied topics, PII detection)
- Google Vertex AI Safety (responsible AI toolkit, model cards)
- Azure AI Content Safety (severity-based filtering, custom categories)
- OWASP LLM Top 10 (threat taxonomy, mitigation mapping)
- NIST AI RMF (governance, map, measure, manage functions)
- Anthropic Constitutional AI (principle-based self-critique)

### What's Pending

- **Bedrock quota increase** (AWS support case filed 2026-06-30, expect 24-48h). Once approved, full end-to-end agent invocation works.
- **Implementation guide for enterprises** - detailed guide covering ADRs, deployment patterns (single/multi-account/org-wide), customization, OWASP mapping, integration patterns, operational runbook
- **Monitoring dashboard** - CloudWatch dashboard with latency breakdowns per governance step, error rates, decision distribution

## Session Commit History

| Commit | Description |
|--------|-------------|
| `807a50e` | Phase 4 security modules + repo cleanup (45 files) |
| `d9ce0a3` | README rewrite |
| `efb823e` | Steering document |
| `99b5895` | Step Functions scalable pipeline (10 files) |

## Key Context

- **Account**: Personal 831926627799 (full Bedrock access, no SCP)
- **Also deployed to**: Isengard 917914785227 (SCP blocks Bedrock InvokeModel)
- **AWS credentials**: Profile `personal`
- **Model**: Amazon Nova Micro v1:0 (changed from Claude 3 Haiku)
- **CDK**: Python, single stack `GovernanceBedrockStack`, app.py entry point
- **Tests**: `python -m pytest tests/ -v` (20 CDK tests + 110 unit tests pass)
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
| Phase 5 handlers (in-engine) | `governance-demo-bedrock/lambdas/governance_engine/handler_{input_defense,authorization,policy_risk,post_decision}.py` |
| InputDefense Lambda | `governance-demo-bedrock/lambdas/input_defense/index.py` |
| Authorization Lambda | `governance-demo-bedrock/lambdas/authorization/index.py` |
| PolicyRisk Lambda | `governance-demo-bedrock/lambdas/policy_risk/index.py` |
| PostDecision Lambda | `governance-demo-bedrock/lambdas/post_decision/index.py` |
| State machine definition | `governance-demo-bedrock/state_machine/governance_pipeline.asl.json` |
| Scope enforcer | `governance-demo-bedrock/lambdas/scope_enforcer/index.py` |
| Policies | `governance-demo-bedrock/sample_data/policies/` |
| Tests | `governance-demo-bedrock/tests/` |
| Demo guides | `governance-demo-bedrock/DEMO_CONSOLE_GUIDE*.md` |

## Lambda Function Names (deployed)

| Function | Name |
|----------|------|
| Governance Engine | GovernanceBedrockStack-GovernanceEngineLambda76BBC-aZUy3DLvBpVS |
| Scope Enforcer | GovernanceBedrockStack-ScopeEnforcerLambda6E908DFB-zkP8akqaUzI9 |
| Kill Switch | GovernanceBedrockStack-KillSwitchLambdaC7575B3E-VcNmZ8NbdyWy |
| Action Group | GovernanceBedrockStack-ActionGroupLambdaDAF0E21B-6fTISHkyUsRJ |
| Input Defense | (CDK-generated, check CloudFormation outputs) |
| Authorization | (CDK-generated, check CloudFormation outputs) |
| Policy Risk | (CDK-generated, check CloudFormation outputs) |
| Post Decision | (CDK-generated, check CloudFormation outputs) |

## State Machine

| Resource | Value |
|----------|-------|
| Name | governance-pipeline |
| Type | EXPRESS |
| ARN | arn:aws:states:us-east-1:831926627799:stateMachine:governance-pipeline |

## How to Validate Everything Works

```bash
cd governance-demo-bedrock
export AWS_PROFILE=personal
export AWS_REGION=us-east-1

# Synth
npx cdk synth -c skip_cloudtrail=true > /dev/null && echo OK

# Unit tests (110 tests)
python -m pytest tests/test_governance_engine_units.py -v

# CDK stack tests (20 tests)
python -m pytest tests/test_governance_bedrock_stack.py -v

# All tests
python -m pytest tests/ -v

# Deploy
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Invoke in Step Functions mode (default after Phase 5 deploy)
aws lambda invoke --function-name "GovernanceBedrockStack-ScopeEnforcerLambda6E908DFB-zkP8akqaUzI9" \
  --payload '{"agent_id":"demo-agent","input_text":"Show me the build status for build-47"}' \
  --cli-binary-format raw-in-base64-out output.json
```

## Architecture Diagram (Logical)

```
Request --> Scope Enforcer
              |
              |--> [GOVERNANCE_MODE=lambda] --> Governance Engine (20 steps, single Lambda)
              |
              |--> [GOVERNANCE_MODE=step_functions] --> Step Functions Express:
                      |
                      |--> Kill Switch Check (DynamoDB direct)
                      |--> PARALLEL:
                      |      |--> InputDefense Lambda (threat detection, sanitization)
                      |      |--> Authorization Lambda (identity, registry, env isolation)
                      |--> PolicyRisk Lambda (policy eval, risk scoring, decision)
                      |--> EventBridge --> PostDecision Lambda (evidence, traces, metrics) [ASYNC]
                      |
                      |--> Return decision to caller
```
