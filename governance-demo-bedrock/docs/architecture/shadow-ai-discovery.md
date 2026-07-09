# Shadow AI Discovery Architecture

Shadow AI refers to AI agents, models, or MCP servers operating within an organization's infrastructure without formal registration or governance oversight. This module discovers, classifies, and brings them under governance.

---

## Discovery Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  DISCOVERY (continuous scanning)                                     │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Network Scan     │  │ API Call Audit    │  │ Cost Anomaly     │  │
│  │                  │  │                  │  │                  │  │
│  │ CloudTrail for   │  │ Bedrock/SageMaker│  │ Unexpected model │  │
│  │ InvokeModel      │  │ InvokeEndpoint   │  │ invocation costs │  │
│  │ calls from       │  │ calls not from   │  │ from accounts    │  │
│  │ unregistered     │  │ registered       │  │ without approved │  │
│  │ sources          │  │ agents           │  │ AI workloads     │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │
│           │                     │                     │             │
│           └─────────────────────┼─────────────────────┘             │
│                                 │                                    │
└─────────────────────────────────┼────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  INVENTORY (classification)                                          │
│                                                                     │
│  For each discovered AI usage:                                      │
│    - Source account / role / principal                                │
│    - Model being invoked (Bedrock, SageMaker, external)              │
│    - Invocation frequency                                            │
│    - Data classification of inputs/outputs                           │
│    - MCP servers connected (if detectable)                           │
│    - Tool/action groups being used                                   │
│    - Whether it has governance wrapping                              │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RISK CLASSIFICATION                                                │
│                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐   │
│  │ HIGH RISK     │  │ MEDIUM RISK   │  │ LOW RISK              │   │
│  │               │  │               │  │                       │   │
│  │ - Accesses    │  │ - Internal    │  │ - Read-only           │   │
│  │   PII/PHI     │  │   data only   │  │ - No sensitive data   │   │
│  │ - Production  │  │ - Non-prod    │  │ - Dev/test only       │   │
│  │   access      │  │   environment │  │ - Low invocation rate │   │
│  │ - External    │  │ - Moderate    │  │                       │   │
│  │   model calls │  │   frequency   │  │                       │   │
│  │ - No govnance │  │               │  │                       │   │
│  └───────┬───────┘  └───────┬───────┘  └───────────┬───────────┘   │
│          │                  │                      │                │
└──────────┼──────────────────┼──────────────────────┼────────────────┘
           │                  │                      │
           ▼                  ▼                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RESPONSE                                                           │
│                                                                     │
│  HIGH RISK:                                                         │
│    1. Immediate quarantine (block invocations)                       │
│    2. Alert security team                                            │
│    3. Evidence preservation                                          │
│    4. Mandatory registration within 24 hours or permanent block      │
│                                                                     │
│  MEDIUM RISK:                                                        │
│    1. Flag for registration                                          │
│    2. Alert team owner                                               │
│    3. 7-day registration deadline                                    │
│    4. Monitoring enabled immediately                                 │
│                                                                     │
│  LOW RISK:                                                           │
│    1. Log for awareness                                              │
│    2. Suggest registration                                           │
│    3. Add to inventory (unregistered)                                │
│    4. Monthly review                                                 │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  REGISTER OR QUARANTINE                                             │
│                                                                     │
│  Registration path:                                                  │
│    1. Owner identified                                               │
│    2. Purpose documented                                             │
│    3. Data classification confirmed                                  │
│    4. Governance wrapper applied                                     │
│    5. Scope level assigned                                           │
│    6. Added to agent registry                                        │
│    7. Monitoring begins                                              │
│                                                                     │
│  Quarantine path:                                                    │
│    1. Invocations blocked at IAM level                               │
│    2. Evidence preserved                                             │
│    3. Owner notified                                                 │
│    4. Remains blocked until registered                               │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CONTINUOUS MONITORING                                               │
│                                                                     │
│  After registration:                                                 │
│    - Standard governance pipeline applies                            │
│    - Health scoring active                                           │
│    - Drift detection enabled                                         │
│    - Evidence pipeline captures all decisions                        │
│    - Periodic re-scan confirms no new shadow AI                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detection Signals

| Signal | Source | Indicates |
|--------|--------|-----------|
| InvokeModel from unknown principal | CloudTrail | Unregistered AI usage |
| Bedrock model access from non-governed Lambda | CloudTrail | Shadow agent |
| Unexpected bedrock:* API calls | VPC Flow Logs | External model calls |
| Cost spike in Bedrock/SageMaker | Cost Explorer | New AI workload |
| MCP server endpoint not in registry | Network scan | Rogue tool server |
| Model download from HuggingFace/external | Egress monitoring | Unvetted model |

---

## Why This Matters

NIST AI RMF says "inventory AI assets." But it does not say how to FIND assets you do not know about. Shadow AI is the gap between "what we think we have" and "what is actually running." This module closes that gap through continuous automated discovery rather than self-reported inventories.
