# Evidence Pipeline Architecture

Every governance decision and agent action produces an immutable evidence record. This is not an afterthought - evidence flows as a parallel stream from every point in the system.

---

## Evidence Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ANY GOVERNANCE EVENT                              │
│                                                                     │
│  Sources:                                                           │
│    - Governance decision (ALLOW / DENY / ESCALATE)                  │
│    - Tool invocation (with params and response)                     │
│    - Kill switch activation                                         │
│    - Scope change                                                   │
│    - Policy evaluation                                              │
│    - Drift detection alert                                          │
│    - Human approval / rejection                                     │
│    - Agent registration / suspension                                │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ EventBridge (async, non-blocking)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Evidence Record Creation                                   │
│                                                                     │
│  {                                                                  │
│    "evidence_id": "uuid",                                           │
│    "timestamp": "ISO-8601",                                         │
│    "event_type": "governance_decision",                             │
│    "agent_id": "agent-001",                                         │
│    "action": "ProductionDeployment",                                │
│    "verdict": "DENY",                                               │
│    "reason": "scope_insufficient",                                  │
│    "scope_level": 2,                                                │
│    "required_scope": 4,                                             │
│    "risk_score": 85,                                                │
│    "policy_rules_evaluated": ["deny_prod_below_3", "default_deny"], │
│    "input_hash": "sha256:abc...",                                   │
│    "session_id": "sess-xyz"                                         │
│  }                                                                  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: Hash Chain                                                 │
│                                                                     │
│  current_hash = SHA-256(                                            │
│    previous_hash +                                                  │
│    evidence_record_json +                                           │
│    timestamp                                                        │
│  )                                                                  │
│                                                                     │
│  This creates an immutable chain: modifying any past record         │
│  breaks all subsequent hashes. Tampering is instantly detectable.   │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: S3 Object Lock Write (WORM)                                │
│                                                                     │
│  Bucket: governance-evidence-{account-id}                           │
│  Key: evidence/{year}/{month}/{day}/{evidence_id}.json              │
│  Object Lock: GOVERNANCE mode, configurable retention (default 1 year, 7 years in production)                     │
│                                                                     │
│  Once written:                                                      │
│    - Cannot be deleted (even by root account)                       │
│    - Cannot be overwritten                                          │
│    - Cannot have retention shortened                                │
│    - Survives account compromise                                    │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: Evidence Graph                                             │
│                                                                     │
│  Relationships stored:                                              │
│    decision --caused_by--> input                                    │
│    decision --evaluated_by--> policy_rules[]                        │
│    decision --led_to--> agent_action (if ALLOW)                     │
│    agent_action --produced--> tool_response                         │
│    tool_response --validated_by--> response_validator               │
│    kill_switch --triggered_by--> {canary_leak | operator | health}  │
│                                                                     │
│  Enables: "Show me every decision that led to this production       │
│  deployment" - full causal chain from request to action.            │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: Compliance Mapping                                         │
│                                                                     │
│  Each evidence record is tagged with:                               │
│                                                                     │
│  ISO 42001 controls:                                                │
│    - 6.1.2 (AI risk assessment)                                     │
│    - 8.4 (AI system operation and monitoring)                       │
│    - 9.2 (Internal audit)                                           │
│                                                                     │
│  NIST AI RMF functions:                                             │
│    - GOVERN 1.1 (Legal and regulatory requirements)                 │
│    - MAP 3.5 (Scientific integrity and reproducibility)             │
│    - MEASURE 2.6 (AI system performance metrics)                    │
│    - MANAGE 2.2 (Mechanisms for AI risk treatment)                  │
│                                                                     │
│  EU AI Act articles:                                                │
│    - Art. 9 (Risk management system)                                │
│    - Art. 12 (Record-keeping)                                       │
│    - Art. 13 (Transparency and provision of information)            │
│                                                                     │
│  NIST 800-53 controls:                                              │
│    - AU-2 (Event Logging)                                           │
│    - AU-10 (Non-repudiation)                                        │
│    - SI-4 (System Monitoring)                                       │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 6: CloudWatch / CloudTrail                                    │
│                                                                     │
│  CloudWatch Metrics:                                                │
│    - GovernanceDecisions (ALLOW/DENY/ESCALATE counts)               │
│    - RiskScoreDistribution                                          │
│    - LatencyPercentiles                                             │
│    - DenialRate                                                     │
│                                                                     │
│  CloudTrail:                                                        │
│    - Every Bedrock InvokeModel / InvokeAgent call                   │
│    - Every DynamoDB read/write                                      │
│    - Every S3 access                                                │
│    - IAM boundary swaps                                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Evidence Package Generation

Monthly compliance packages are generated by `scripts/collect_evidence.py`:

```
evidence_packages/
└── 2026-07/
    ├── summary.json              # Totals: decisions, denials, escalations
    ├── decisions/                 # All governance decisions this month
    ├── hash_chain_verification/  # Hash chain integrity proof
    ├── compliance_mapping/       # ISO/NIST/EU AI Act cross-reference
    ├── risk_scores/              # Risk score distribution
    └── anomalies/                # Drift detections and alerts
```

---

## Non-Repudiation Guarantees

| Property | Mechanism |
|----------|-----------|
| Cannot deny a decision was made | SHA-256 hash + timestamp in Object Lock |
| Cannot alter a past record | Hash chain breaks on any modification |
| Cannot delete evidence | S3 Object Lock GOVERNANCE mode (configurable retention) |
| Cannot claim different sequence | Hash chain encodes ordering |
| Cannot backdate | Timestamp from Lambda execution context (AWS-signed) |
| Cannot forge | Evidence written by governance Lambda only (IAM-restricted) |

---

## Performance Impact

Evidence writing is fully asynchronous:

| Metric | Value |
|--------|-------|
| Added latency to user response | 0ms (EventBridge async) |
| Time to evidence availability | 1-2 seconds |
| Storage cost per decision | ~0.5 KB (JSON) |
| Monthly volume (1000 decisions/day) | ~15 MB |
| configurable retention (default 1 year, 7 years in production) cost | ~$0.01/month (S3 Glacier after 90 days) |
