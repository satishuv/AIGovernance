# AIGovernance Project Status

This file tracks what has been done and what is pending.
Kiro (or any future AI assistant) should read this file first to understand project context.

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

Files:
- `text in the blog.md` - current working copy with v2 changes applied
- `change-guide-v2.md` - reference of all changes made
- `blog-v2.md` - full rewrite version (reference only)

## Track B: Code Governance Demo

| Task | Status |
|------|--------|
| Architecture decided | Done |
| Use case scenario defined | Done |
| Requirements document created | Done |
| Design document created | Done |
| Task list created | Done |
| CDK project scaffolded (Task 1) | Done |
| S3 buckets + sample data (Task 2) | Done |
| DynamoDB tables + scope init (Task 3) | Done |
| IAM permission boundaries Scope 1-4 (Task 4) | Done |
| Scope enforcement Lambda (Task 6.4) | Done |
| Agent Lambda / Bedrock-based (Task 6.2) | Done |
| Kill-switch Lambda (Task 6.6) | Done |
| Lambda IAM roles + wiring (Task 6) | Done |
| CloudWatch audit logging (Task 7.1) | Done |
| CloudTrail trail (Task 7.2) | Skipped (Isengard region limitation) |
| CDK stack assertion tests (Task 9) | Done (24 assertions) |
| Property-based tests / Hypothesis (Task 10) | Done (7 tests, 100 examples each) |
| Edge case unit tests (Task 11) | Done (4 error handling scenarios) |
| Full test suite | Done (38 tests passing) |
| Deployed to us-east-1 | Done (Isengard account 917914785227) |
| Live-tested | Done (full end-to-end verified) |

Live Test Results (March 22, 2026):
1. Scope Enforcer (Scope 1, read): Agent invoked, Bedrock denied by permission boundary (governance working as designed)
2. Kill Switch activated: scope set to 0 + deny-all policy attached (both actions confirmed)
3. Scope Enforcer after kill switch: "agent_disabled" / "Agent has been disabled via kill switch (scope 0)"

Lambda Function Names (deployed):
- Scope Enforcer: `AgenticGovernanceDemo-ScopeEnforcerFunction3C35FCC-1dcAAsSNyFeL`
- Agent: `AgenticGovernanceDemo-AgentFunction4E676656-YnTAgJTBCPHM`
- Kill Switch: `AgenticGovernanceDemo-KillSwitchFunction1CE942D4-276rF012aAoF`

Test Breakdown:
- 24 CDK stack assertion tests (resource counts, Lambda config, bucket settings, DynamoDB keys, permission boundaries)
- 7 Hypothesis property-based tests (scope validation, access control matrix, boundary swap, pending records, agent logs, kill switch dual action, kill switch logs)
- 4 edge case unit tests (Scope Table unreachable, Bedrock failure, IAM retry success, IAM double failure)
- 3 agent/kill-switch property tests (in separate test file)

Deployment Notes:
- Isengard account: 917914785227
- Region: us-east-1
- Credentials: `ada credentials update --account 917914785227 --provider isengard --role Admin`
- CDK uses `python` not `python3` on Windows (updated in cdk.json)
- CloudTrail not supported in this Isengard account; deploy with: `npx cdk deploy -c skip_cloudtrail=true`
- Lambda invoke on PowerShell: write payload to file first, use `fileb://payload.json`
- Cleanup: `npx cdk destroy -c skip_cloudtrail=true`

Architecture:
- Language: Python
- IaC: AWS CDK (Python)
- Region: us-east-1
- Agent: Amazon Bedrock-based Lambda
- Scope enforcement: DynamoDB state + IAM boundaries
- Audit: CloudTrail + CloudWatch
- Kill-switch: Lambda that revokes agent permissions immediately

Folder: `governance-demo/`

Use Case Scenario: Software Deployment Pipeline Agent
- Industry: Technology / Software Development
- Application: An AI agent that assists a dev team in shipping features from code to production
- Data: Mock build artifacts, test results, deployment configs, change requests, rollback plans (all in S3)
- Scope 1: Read pipeline state (builds, test results, configs)
- Scope 2: Draft deployment plans and rollback strategies for human approval
- Scope 3: Auto-deploy to staging, run integration tests, promote to pre-prod within guardrails
- Scope 4: Full autonomous CI/CD including production deployments
- Kill switch scenario: Halt agent that is deploying a build that failed a security scan
- Full scenario details in `.kiro/steering/blog-uplift-project.md`

## Rules for AI Assistants
1. Never modify original files (`text in the blog.md` is now the working copy, but the .docx is untouchable)
2. Never use em dashes anywhere
3. Never store secrets, tokens, or passwords in any file
4. Work step by step, explain everything clearly
5. All code changes go in the `governance-demo/` folder
6. Commit often with conventional commit messages
