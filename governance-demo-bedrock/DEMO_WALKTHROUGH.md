# Governance Demo Walkthrough
## Testing the Bedrock Agent via Console

This document captures the live demo of the governance framework using the
Amazon Bedrock Agent console Test panel. Each scenario maps to one SDLC phase
and one action group.

---

## Stack Details

| Item | Value |
|---|---|
| Agent Name | governance-demo-pipeline-agent |
| Agent ID | ENPWN03B8X |
| Agent Alias | live (KPRIIWN63Z) |
| Foundation Model | amazon.nova-micro-v1:0 |
| Region | us-east-1 |
| Stack | GovernanceBedrockStack |

---

## Scenario 1: Read - Check Build Status (Scope 1)

**SDLC Phase:** Plan / Monitor
**Action Group:** ReadPipelineStatus
**Scope:** 1 (Read Only)

**What to type in the Test panel:**
```
Show me the build status and test results for build-47
```

**Expected:** Agent reads from S3 and returns build manifest and test results.

### Screenshot
<!-- Add screenshot here -->

---

## Scenario 2: Propose - Draft a Deployment Plan (Scope 2)

**SDLC Phase:** Design / Review
**Action Group:** ProposeChanges
**Scope:** 2 (Propose Changes)

**What to type in the Test panel:**
```
Propose and update the change plan for build-47
```

**Expected:** Agent drafts a deployment plan and writes it to the pending approval queue.

### Screenshot
<!-- Add screenshot here -->

---

## Scenario 3: Act - Deploy to Staging (Scope 3)

**SDLC Phase:** Test / Deploy to Staging
**Action Group:** StagingDeployment
**Scope:** 3 (Act Within Boundaries)

**What to type in the Test panel:**
```
Push build-47 to staging and trigger the integration tests
```

**Expected:** Agent deploys to staging and triggers tests. Cannot touch production.

### Screenshot
<!-- Add screenshot here -->

---

## Scenario 4: Full Autonomy - Deploy to Production (Scope 4)

**SDLC Phase:** Release to Production
**Action Group:** ProductionDeployment
**Scope:** 4 (Full Autonomy)

**What to type in the Test panel:**
```
Deploy build-47 to production
```

**Expected:** Agent deploys to production. Full autonomy. Kill switch still active.

### Screenshot
<!-- Add screenshot here -->

---

## DynamoDB - Scope Table

Shows the live scope level of the agent.

### Screenshot
<!-- Add screenshot here -->

---

## CloudWatch - Governance Audit Log

Shows the structured JSON decision log for each action.

### Screenshot
<!-- Add screenshot here -->

---

## Kill Switch

Shows scope set to 0 and deny-all IAM policy attached.

### Screenshot
<!-- Add screenshot here -->
