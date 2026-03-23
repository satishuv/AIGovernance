# Agentic AI Governance Demo

A deployable demo that demonstrates the scope-based governance framework from the whitepaper "Building Trustworthy Agentic AI."

## What This Deploys

- A simple AI agent (Lambda + Bedrock) that can read S3 and write to DynamoDB
- Scope enforcement (Scope 1 = read-only, Scope 2 = propose changes, Scope 3 = act within boundaries, Scope 4 = full autonomy)
- IAM permission boundaries that technically enforce each scope level
- CloudTrail + CloudWatch audit logging for every agent action
- A kill-switch Lambda that immediately revokes agent permissions
- A DynamoDB table that tracks agent scope state

## Architecture

```
User Request
    |
    v
Scope Enforcer (Lambda)
    |
    v
[Check DynamoDB: what scope is this agent at?]
    |
    v
Agent (Lambda + Bedrock)
    |
    +-- Scope 1: read-only (S3 GetObject only)
    +-- Scope 2: propose changes (write to "pending" table, human approves)
    +-- Scope 3: act within boundaries (write to S3/DynamoDB within limits)
    +-- Scope 4: full access (all actions, no human gate)
    |
    v
CloudWatch Logs (every action logged)
    |
    v
Kill Switch (Lambda) -- can revoke permissions at any time
```

## Prerequisites

- Python 3.9+
- AWS CDK v2 (`npm install -g aws-cdk`)
- AWS CLI configured with credentials for your account
- An AWS account with Bedrock model access enabled in us-east-1

## Setup

```bash
cd governance-demo
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
cdk bootstrap             # first time only
cdk deploy
```

## Cleanup

```bash
cdk destroy
```
