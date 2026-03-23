# Architecture Notes

## Design Principles

1. **Defense in Depth** — Governance is enforced at multiple layers: application logic (scope filtering), IAM (permission boundaries), and observability (CloudTrail + structured logs). No single layer is trusted alone.

2. **Graduated Autonomy** — The agent starts at scope 1 (read-only) and can be promoted to higher scopes as trust is established. Each scope level is a strict superset of the previous one.

3. **Fail-Closed** — If the scope table returns no record or scope 0, the agent is fully denied. The kill switch is designed to succeed even under partial failure (scope update + IAM policy are independent).

4. **Separation of Concerns** — Three distinct Lambdas handle three distinct responsibilities:
   - **Scope Enforcer**: Orchestration and governance enforcement
   - **Action Group Lambda**: Business logic execution
   - **Kill Switch**: Emergency shutdown (minimal dependencies)

---

## Key Design Decisions

### Why Permission Boundaries (not just session attributes)?

Session attributes tell the agent which action groups to use, but a compromised or hallucinating agent could ignore them. Permission boundaries enforce restrictions at the IAM layer — even if the agent tries to call a restricted API, AWS will deny it.

### Why a single Action Group Lambda?

All 8 operations share the same S3 bucket and DynamoDB table. A single Lambda simplifies IAM grants and permission boundary management. The routing logic is a simple dict lookup.

### Why L1 constructs for Bedrock?

At the time of writing, AWS CDK does not have L2 constructs for Bedrock Agents. We use `CfnAgent` and `CfnAgentAlias` directly.

### Why conditional CloudTrail?

CloudTrail with data events can be expensive in dev/test. The `skip_cloudtrail` CDK context flag lets you skip it locally while keeping it enabled for production deployments.

---

## Data Flow

```
User Request
    │
    ▼
Scope Enforcer Lambda
    │
    ├─ DynamoDB: Read scope level
    ├─ IAM: Swap permission boundary
    ├─ Bedrock: InvokeAgent (with session attributes)
    │       │
    │       ▼
    │   Bedrock Agent (Claude 3 Haiku)
    │       │
    │       ▼
    │   Action Group Lambda
    │       │
    │       ├─ S3: Read/write pipeline data
    │       ├─ DynamoDB: Write pending proposals
    │       └─ CloudWatch: Structured audit logs
    │
    └─ Return agent response to caller
```

---

## Security Model

| Threat | Mitigation |
|--------|------------|
| Agent ignores scope restrictions | IAM permission boundaries block unauthorized API calls |
| Prompt injection escalates scope | Scope is read from DynamoDB (server-side), not from user input |
| Runaway agent | Kill switch sets scope→0 and attaches deny-all policy |
| Unauthorized scope changes | Only Scope Enforcer Lambda has DynamoDB write access to scope table |
| Missing audit trail | CloudTrail captures all S3 and DynamoDB data events |
