# Agentic AI Governance Demo — Amazon Bedrock Edition

A production-ready reference architecture demonstrating **scope-based governance** for autonomous AI agents built on [Amazon Bedrock Agents](https://aws.amazon.com/bedrock/agents/).

This project accompanies the whitepaper *"Building Trustworthy Agentic AI"* and shows how to enforce graduated autonomy, real-time scope control, and an emergency kill switch — all deployed as a single AWS CDK stack.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User / Operator                        │
└──────────────┬──────────────────────────────┬───────────────┘
               │ invoke                       │ emergency stop
               ▼                              ▼
┌──────────────────────┐        ┌──────────────────────────┐
│   Scope Enforcer λ   │        │     Kill Switch λ        │
│                      │        │  • scope → 0             │
│  1. Read scope level │        │  • deny-all IAM policy   │
│  2. Swap IAM boundary│        └──────────────────────────┘
│  3. Invoke Agent     │
└──────────┬───────────┘
           │ bedrock-agent-runtime:InvokeAgent
           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Bedrock Agent (Claude 3 Haiku)             │
│                                                              │
│  Action Groups (graduated by scope level):                   │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ ReadPipeline     │  │ ProposeChanges   │  Scope 1-2      │
│  │ Status (scope≥1) │  │ (scope≥2)        │                 │
│  └──────────────────┘  └──────────────────┘                 │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ Staging          │  │ Production       │  Scope 3-4      │
│  │ Deployment (≥3)  │  │ Deployment (≥4)  │                 │
│  └──────────────────┘  └──────────────────┘                 │
│                              │                               │
│                    Action Group Lambda                        │
└──────────────────────────────┬───────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌────────────┐   ┌────────────┐
        │ S3 Data  │   │ DynamoDB   │   │ CloudWatch │
        │ Bucket   │   │ Tables     │   │ + Trail    │
        └──────────┘   └────────────┘   └────────────┘
```


## Scope Levels

| Level | Action Groups Permitted | Description |
|-------|------------------------|-------------|
| **0** | None (kill switch) | Agent fully disabled — all requests denied |
| **1** | ReadPipelineStatus | Read-only: query build status and test results |
| **2** | + ProposeChanges | Can draft deployment plans and rollback strategies |
| **3** | + StagingDeployment | Can deploy to staging and trigger test suites |
| **4** | + ProductionDeployment | Full autonomy: production deploys and rollbacks |

Each scope level maps to a dedicated **IAM Permission Boundary** that restricts the Action Group Lambda's AWS permissions at the IAM layer — defense in depth beyond just prompt-level filtering.

---

## Project Structure

```
governance-demo-bedrock/
├── app.py                        # CDK app entry point
├── governance_bedrock_stack.py    # Full CDK stack definition
├── cdk.json                      # CDK configuration
├── requirements.txt              # Python dependencies
│
├── lambdas/
│   ├── action_group/             # Bedrock Agent action group handler
│   │   └── index.py              #   8 operations across 4 action groups
│   ├── scope_enforcer/           # Governance orchestrator
│   │   └── index.py              #   Scope check → boundary swap → invoke agent
│   └── kill_switch/              # Emergency stop
│       └── index.py              #   Scope→0 + deny-all IAM policy
│
├── schemas/                      # OpenAPI 3.0 specs for each action group
│   ├── read_pipeline_status.json
│   ├── propose_changes.json
│   ├── staging_deployment.json
│   └── production_deployment.json
│
├── sample_data/                  # Mock pipeline data (deployed to S3)
│   ├── builds/                   #   Build manifests
│   ├── test-results/             #   Test result reports
│   ├── configs/                  #   Staging & production configs
│   └── rollback-plans/           #   Rollback strategies
│
├── tests/
│   └── test_governance_bedrock_stack.py  # CDK assertion tests
│
└── docs/
    └── ARCHITECTURE.md           # Detailed architecture notes
```

---

## Prerequisites

- Python 3.9+
- [AWS CDK v2](https://docs.aws.amazon.com/cdk/v2/guide/getting-started.html) (`npm install -g aws-cdk`)
- AWS account with Bedrock model access enabled for `anthropic.claude-3-haiku-20240307-v1:0`
- AWS CLI configured with appropriate credentials

---

## Quick Start

```bash
# Clone and enter the project
cd governance-demo-bedrock

# Create virtual environment and install dependencies
python -m venv .venv
source .venv/Scripts/activate   # Windows (Git Bash)
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt

# Synthesize the CloudFormation template
cdk synth

# Deploy the stack
cdk deploy

# Run tests
python -m pytest tests/ -v
```

---

## How It Works

### 1. Scope Enforcer (Entry Point)

Every user request flows through the **Scope Enforcer Lambda**, which:
1. Reads the agent's current scope level from DynamoDB
2. Swaps the IAM Permission Boundary on the Action Group Lambda role to match the scope
3. Invokes the Bedrock Agent via `InvokeAgent` API, passing scope metadata as session attributes
4. Returns the agent's response to the caller

### 2. Bedrock Agent (Decision Maker)

The agent uses Claude 3 Haiku to interpret natural language requests and route them to the appropriate action group. Session attributes tell the agent which action groups are permitted at the current scope level.

### 3. Action Group Lambda (Executor)

A single Lambda handles all 8 operations across 4 action groups:
- **ReadPipelineStatus**: `getBuildStatus`, `getTestResults`
- **ProposeChanges**: `draftDeploymentPlan`, `draftRollbackStrategy`
- **StagingDeployment**: `deployToStaging`, `triggerTests`
- **ProductionDeployment**: `deployToProduction`, `rollbackDeployment`

### 4. Kill Switch (Emergency Stop)

Instantly disables the agent by:
- Setting scope to 0 in DynamoDB
- Attaching a deny-all inline IAM policy to the Action Group Lambda role

---

## Governance Controls

| Control | Mechanism | Layer |
|---------|-----------|-------|
| Scope-based filtering | DynamoDB scope table + session attributes | Application |
| Permission boundaries | IAM managed policies swapped per scope level | IAM |
| Kill switch | Scope→0 + deny-all inline policy | IAM + Application |
| Audit trail | Structured JSON logs + CloudTrail data events | Observability |
| Pending approvals | DynamoDB pending table for proposed changes | Application |

---

## Configuration

### CDK Context Flags

| Flag | Default | Description |
|------|---------|-------------|
| `skip_cloudtrail` | `false` | Set to `true` to skip CloudTrail trail creation (saves cost in dev) |

### Environment Variables (set automatically by CDK)

| Lambda | Variables |
|--------|-----------|
| Action Group | `DATA_BUCKET_NAME`, `PENDING_TABLE_NAME`, `LOG_GROUP_NAME` |
| Scope Enforcer | `AGENT_ID`, `AGENT_ALIAS_ID`, `SCOPE_TABLE_NAME`, `ACTION_GROUP_LAMBDA_ROLE_NAME`, `SCOPE_BOUNDARY_ARNS` |
| Kill Switch | `SCOPE_TABLE_NAME`, `ACTION_GROUP_LAMBDA_ROLE_NAME` |

---

## Testing

```bash
# Run CDK assertion tests
python -m pytest tests/ -v

# Synthesize and validate the template
cdk synth --quiet
```

The test suite validates:
- Bedrock Agent resource with correct foundation model and 4 action groups
- All three Lambda functions with correct runtime, timeout, and memory
- Four IAM Permission Boundary policies with correct actions per scope
- CloudWatch log group and CloudTrail trail configuration

---

## Cleanup

```bash
cdk destroy
```

---

## License

This project is provided as a reference implementation for educational purposes. See the accompanying whitepaper for full context on the governance framework design.
