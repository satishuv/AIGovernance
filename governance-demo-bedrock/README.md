# AI Agent Runtime Governance Framework

A runtime enforcement engine for autonomous AI agents. Evaluates every agent action in <150ms, decides ALLOW / DENY / ESCALATE, enforces the decision at the infrastructure layer, and records immutable evidence of every decision.

**The problem this solves:** AI agents read and reason over data that can reprogram them. No existing security framework governs what an agent does between receiving a prompt and executing an action. This framework fills that gap.

**What it is NOT:** A set of guidelines, principles, or policies. This is running code that physically blocks unauthorized AI agent actions at the AWS infrastructure layer.

Built on [Amazon Bedrock Agents](https://aws.amazon.com/bedrock/agents/). Deployed as a single AWS CDK stack.

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
│
├── app.py                          # CDK app entry point
├── governance_bedrock_stack.py     # CDK stack (~58 lines, 6 modular constructs)
├── governance_constructs/          # CDK constructs (infrastructure-as-code)
│   ├── api.py                      #   API Gateway + Lambda integration
│   ├── bedrock_agent.py            #   Bedrock Agent + Action Groups
│   ├── governance_engine.py        #   Governance Lambda + Step Functions
│   ├── monitoring.py               #   CloudWatch dashboards + alarms
│   ├── seed_data.py                #   Sample data deployment
│   └── storage.py                  #   DynamoDB + S3 + Object Lock
│
├── lambdas/
│   ├── governance_engine/          # 72 modules (see MODULE_MAP.md inside)
│   │   ├── index.py                #   Lambda entrypoint
│   │   ├── pipeline_orchestrator.py#   20-step governance pipeline
│   │   ├── decision_engine.py      #   ALLOW / DENY / ESCALATE
│   │   ├── input_sanitizer.py      #   8-layer input defense
│   │   ├── tool_response_validator.py # Return-path validation
│   │   ├── opa_engine.py           #   Policy-as-code evaluation
│   │   └── MODULE_MAP.md           #   ← READ THIS to understand the 72 modules
│   ├── action_group/               # Bedrock Agent tool execution
│   ├── scope_enforcer/             # Entry point (scope check + agent invoke)
│   ├── kill_switch/                # Emergency shutdown (<1s)
│   └── seed_tables/                # Initial data seeding
│
├── tests/                          # 225 tests (9 test files)
├── test_datasets/                  # Attack payloads (8,470+ from 13 benchmarks)
├── test_payloads/                  # Manual test payloads and outputs
├── scripts/                        # Operational scripts
│   ├── collect_evidence.py         #   Export compliance evidence packages
│   ├── governed_dev_demo.py        #   End-to-end governance demonstration
│   └── benchmark_latency.py        #   Latency benchmarking
│
├── config/                         # Environment configs (demo, production)
├── schemas/                        # OpenAPI 3.0 action group schemas
├── sample_data/                    # Policies, compliance mappings, mock data
├── state_machine/                  # Step Functions ASL definition
│
└── docs/                           # ← START HERE for documentation
    ├── README.md                   #   Documentation index
    ├── architecture/               #   6 technical deep-dives
    ├── AI_AGENT_SECURITY_CHECKLIST.md  # 93 controls from 22 papers
    ├── CONTROL_CATALOG.md          #   377 controls across 20 domains
    └── internal/                   #   Development notes (not for external)
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
