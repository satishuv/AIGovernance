# Agentic AI Governance Demo — Amazon Bedrock Edition

> **This is the primary demo.** Deploy this, present this, share this.
>
> The folder `governance-demo/` in this repo is a separate, minimal Lambda reference implementation. It is NOT a second demo. It exists solely as a clean reference that the OWASP LLM security test suite (`tests/test_security_governance.py`) validates against. You do not need to deploy or explain it.

A production-ready reference architecture demonstrating **scope-based governance** for autonomous AI agents built on [Amazon Bedrock Agents](https://aws.amazon.com/bedrock/agents/).

This project accompanies the whitepaper *"Building Trustworthy Agentic AI"* and shows how to enforce graduated autonomy, real-time scope control, and an emergency kill switch — all deployed as a single AWS CDK stack.

---

## Enterprise AI Runtime Governance Control Plane

*How does an AI agent request get governed before it acts?*

```
╔══════════════════════════════════════════════════════════════════════════╗
║  LAYER 1: REQUEST                                                       ║
║                                                                         ║
║    User / Operator / Upstream Service                                   ║
║         │                                                               ║
║         ▼                                                               ║
║    API Gateway / Scope Enforcer Lambda                                  ║
╚════════════════════════════╤═════════════════════════════════════════════╝
                             │
         ┌───────────────────┴─────────────── TRUST BOUNDARY ──────┐
         │                                                          │
╔════════▼═════════════════════════════════════════════════════════════════╗
║  LAYER 2: GOVERNANCE CONTROL PLANE (Blue)                               ║
║                                                                         ║
║  ┌─────────────┐   ┌──────────────────────────────────────────────────┐ ║
║  │ Kill Switch │──▶│             Governance Engine                     │ ║
║  │ (scope = 0  │   │                                                  │ ║
║  │  = instant  │   │  1. Agent Registry + Scope Table lookup          │ ║
║  │  shutdown)  │   │  2. Input Defense (8 sanitization checks)        │ ║
║  └─────────────┘   │  3. Agent + Tool Authorization                   │ ║
║                     │  4. OPA + Cedar Policy Evaluation                │ ║
║                     │  5. Risk Scoring + Trust Assessment              │ ║
║                     │  6. Drift / Behavioral Monitoring                │ ║
║                     │  7. Decision Engine                              │ ║
║                     └─────────────────────┬───────────────────────────┘ ║
║                                           │                             ║
╚═══════════════════════════════════════════╤══════════════════════════════╝
                                            │
              ┌─────────────────────────────┼──────────────────────┐
              │                             │                      │
              ▼                             ▼                      ▼
┌──────────────────────┐   ┌───────────────────────┐   ┌────────────────────┐
│    ## DENY ##        │   │   ^^ ESCALATE ^^      │   │   ** ALLOW **      │
│                      │   │                       │   │                    │
│ Return explanation   │   │ Human approval queue  │   │ Proceed to agent   │
│ Log + evidence       │   │ SNS operator alert    │   │ execution          │
└──────────────────────┘   └───────────────────────┘   └─────────┬──────────┘
                                                                  │
         ┌────────────────────────────────────────── TRUST BOUNDARY ──────┐
         │                                                                 │
╔════════▼═════════════════════════════════════════════════════════════════════╗
║  LAYER 3: AGENT EXECUTION PLANE (Green)                                     ║
║                                                                             ║
║    Bedrock Agent (Nova Micro) ──▶ Action Groups (scope-gated)               ║
║         │                              │                                    ║
║         │                   ┌──────────┼──────────┐                         ║
║         │                   ▼          ▼          ▼                         ║
║         │            ReadPipeline  Staging    Production                     ║
║         │            Propose       Deploy     Deploy                         ║
║         │                   │          │          │                          ║
║         │                   └──────────┼──────────┘                         ║
║         │                              ▼                                    ║
║         │              ┌───────────────────────────────┐                    ║
║         │              │ Per-Tool Security (15ms each) │                    ║
║         │              │  - Scope enforcement          │                    ║
║         │              │  - Parameter injection scan   │                    ║
║         │              │  - Rate limiting + chain det. │                    ║
║         │              └───────────────┬───────────────┘                    ║
║         │                              ▼                                    ║
║         │              ┌───────────────────────────────┐                    ║
║         │              │ Enterprise Systems            │                    ║
║         │              │  S3 | DynamoDB | Pipelines    │                    ║
║         │              └───────────────┬───────────────┘                    ║
║         │                              │                                    ║
║         │                              ▼                                    ║
║         │              ┌───────────────────────────────┐                    ║
║         │              │ Tool Response Validator       │                    ║
║         │              │  - Injection detection        │                    ║
║         │              │  - Data classification        │                    ║
║         │              │  - Anomaly scoring            │                    ║
║         │              └───────────────┬───────────────┘                    ║
║         │                              ▼                                    ║
║         │              ┌───────────────────────────────┐                    ║
║         │              │ Output Guardrails             │                    ║
║         │              │  - PII/credential stripping   │                    ║
║         │              │  - Exfiltration blocking      │                    ║
║         │              │  - Content safety             │                    ║
║         │              └───────────────┬───────────────┘                    ║
║         │                              │                                    ║
╚═════════╪══════════════════════════════╪════════════════════════════════════╝
          │                              │
          │         ┌────────────────────┘
          │         │
╔═════════▼═════════▼══════════════════════════════════════════════════════════╗
║  LAYER 4: EVIDENCE & COMPLIANCE PLANE (async, non-blocking side-stream)     ║
║                                                                             ║
║  Every decision and action flows here automatically:                        ║
║                                                                             ║
║  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐   ║
║  │ S3 Object    │  │ Evidence     │  │ CloudWatch   │  │ Compliance    │   ║
║  │ Lock (7yr)   │  │ Graph        │  │ + CloudTrail │  │ Mapping       │   ║
║  │              │  │              │  │              │  │               │   ║
║  │ Immutable    │  │ SHA-256      │  │ Real-time    │  │ ISO 42001     │   ║
║  │ WORM storage │  │ hash chains  │  │ metrics      │  │ NIST AI RMF   │   ║
║  │              │  │              │  │              │  │ EU AI Act     │   ║
║  └──────────────┘  └──────────────┘  └──────────────┘  └───────────────┘   ║
║                                                                             ║
╚═════════════════════════════════════════════════════════════════════════════╝
```

> **Detailed architecture:** [docs/architecture/](docs/architecture/) has deep-dives on runtime flow, control plane internals, threat-defense mapping, evidence pipeline, shadow AI discovery, and supply chain governance.


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
- AWS account with Bedrock model access enabled for `amazon.nova-micro-v1:0`
- AWS CLI configured with appropriate credentials

---

## Quick Start

```bash
# Clone and enter the project
cd governance-demo-bedrock

# Create virtual environment and install ies
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

The agent uses Amazon Nova Micro to interpret natural language requests and route them to the appropriate action group. Session attributes tell the agent which action groups are permitted at the current scope level.

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
