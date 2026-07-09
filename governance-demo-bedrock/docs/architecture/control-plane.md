# Control Plane Architecture

The governance control plane is the decision-making layer that sits between user requests and agent execution. It never touches enterprise data directly - it only decides whether an action is ALLOWED, DENIED, or ESCALATED.

---

## Control Plane Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GOVERNANCE CONTROL PLANE                          │
│                                                                         │
│  ┌─────────────────┐     ┌─────────────────────────────────────────┐   │
│  │ Agent Registry  │     │            Policy Engine                 │   │
│  │                 │     │                                         │   │
│  │ - Registration  │     │  ┌─────────────┐  ┌─────────────────┐  │   │
│  │ - Status track  │     │  │ OPA (Rego)  │  │ Cedar (formal)  │  │   │
│  │ - Identity      │     │  │             │  │                 │  │   │
│  │ - Capabilities  │     │  │ Priority    │  │ Mathematical    │  │   │
│  └────────┬────────┘     │  │ resolution  │  │ proof of safety │  │   │
│           │              │  └─────────────┘  └─────────────────┘  │   │
│           │              │                                         │   │
│           │              │  Policy contradiction detection          │   │
│           │              │  Dead rule identification                │   │
│           │              └─────────────────────────────────────────┘   │
│           │                                                            │
│  ┌────────▼────────┐     ┌─────────────────────────────────────────┐   │
│  │ Scope Table     │     │            Risk Engine                   │   │
│  │                 │     │                                         │   │
│  │ Level 0-4      │     │  - Action severity scoring               │   │
│  │ Per-agent      │     │  - Time-of-day risk factor               │   │
│  │ DynamoDB       │     │  - Recent denial history                  │   │
│  │ Mutable by     │     │  - Drift magnitude                       │   │
│  │ operators only │     │  - Composite score (0-100)                │   │
│  └────────┬────────┘     │  - Thresholds: >70 ESCALATE, >90 DENY   │   │
│           │              └─────────────────────────────────────────┘   │
│           │                                                            │
│  ┌────────▼────────┐     ┌─────────────────────────────────────────┐   │
│  │ Trust Score     │     │         Drift Detector                   │   │
│  │                 │     │                                         │   │
│  │ Health: 0-100  │     │  - Behavioral baseline comparison        │   │
│  │ Updated every  │     │  - Tool usage pattern analysis            │   │
│  │ request        │     │  - Request frequency anomalies            │   │
│  │ Feeds risk     │     │  - Scope access patterns                  │   │
│  │ engine         │     │  - Output characteristic tracking         │   │
│  └─────────────────┘     └─────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────┐     ┌─────────────────────────────────────────┐   │
│  │ Human Approval  │     │         Evidence Writer                  │   │
│  │                 │     │                                         │   │
│  │ - SNS alerts   │     │  - SHA-256 hash per decision             │   │
│  │ - Approval     │     │  - S3 Object Lock (7-year WORM)          │   │
│  │   queue        │     │  - ISO 42001 / NIST mapping              │   │
│  │ - Timeout      │     │  - Async (EventBridge, non-blocking)     │   │
│  │   = DENY       │     │  - Evidence graph relationships          │   │
│  └─────────────────┘     └─────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      Kill Switch                                 │   │
│  │                                                                  │   │
│  │  Instant shutdown (<1 second). Sets scope=0, attaches deny-all   │   │
│  │  IAM policy. Triggered by: operator, canary tripwire, health=0   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### Agent Registry

| Field | Purpose |
|-------|---------|
| agent_id | Unique identifier |
| status | active / suspended / quarantined / decommissioned |
| registered_at | Registration timestamp |
| capabilities | List of permitted action groups |
| owner | Responsible operator |
| last_health_check | Most recent health score timestamp |

Unregistered agents are denied at step 2 of the pipeline. No exceptions.

### Scope Table

| Level | Meaning | IAM Boundary |
|-------|---------|-------------|
| 0 | Kill switch active | deny-all |
| 1 | Read-only | S3 GetObject only |
| 2 | Read + propose | + DynamoDB PutItem to pending |
| 3 | + staging deploy | + S3 PutObject to staging path |
| 4 | + production deploy | + S3 PutObject to production path |

Scope can only be modified by operators via the Scope Enforcer Lambda or Kill Switch Lambda. The agent cannot modify its own scope.

### Policy Engine

Two complementary systems:

**OPA (Rego-subset)** - Rule evaluation with priority resolution:
- Lowest priority number wins when multiple rules match
- Default-deny rule at priority 9999 (catches everything not explicitly allowed)
- Supports: time-of-day, scope-action mapping, risk thresholds, data classification

**Cedar (formal verification)** - Mathematical proofs:
- Proves policy combinations cannot create contradictions
- Detects "dead rules" that can never match
- Verifies no path allows unauthorized access

### Risk Engine

Composite scoring formula:
```
risk_score = (
    action_severity * 0.4 +
    time_risk_factor * 0.15 +
    recent_denial_rate * 0.2 +
    drift_magnitude * 0.15 +
    inverse_health * 0.1
)
```

Thresholds:
- 0-70: Normal operation (ALLOW if policy passes)
- 71-89: ESCALATE to human approval
- 90-100: DENY regardless of policy

### Trust / Health Score

Continuous score (0-100) updated on every request:
- Starts at 100 for newly registered agents
- Decreases on: policy violations, anomalous behavior, drift detection
- Increases on: successful operations within scope, consistent patterns
- At 0: Kill switch triggers automatically

### Human Approval Workflow

When verdict is ESCALATE:
1. Request queued in DynamoDB pending table
2. SNS notification to operator
3. Operator reviews in console or via API
4. APPROVE proceeds to execution with evidence trail
5. REJECT returns DENY to caller
6. TIMEOUT (configurable, default 30 min) = automatic DENY

---

## Separation from Execution Plane

The control plane NEVER:
- Reads enterprise data (S3 buckets, databases)
- Executes tool calls
- Invokes the Bedrock Agent
- Modifies enterprise systems

It ONLY:
- Reads its own state (scope table, registry, policies, evidence)
- Writes decisions (evidence records, health scores)
- Routes to: ALLOW (hand off to execution) / DENY (return) / ESCALATE (queue)

This separation means a compromised execution plane cannot modify governance decisions.
