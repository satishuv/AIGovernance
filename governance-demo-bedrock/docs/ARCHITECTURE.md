# Architecture

## SDLC Governance Flow

An AI agent assists a development team in deploying software from code to production. Every action the agent takes is governed by three engines running in concert:

```
Developer: "Deploy build-47 to staging and run tests"
                            |
                            v
+===================================================================+
|                  GOVERNANCE SECURITY WRAPPER                       |
|                                                                   |
|  +-------------------------------------------------------------+ |
|  | PREVENTIVE ENGINE (blocks before execution)                  | |
|  |                                                              | |
|  |  Kill Switch Check -----> scope 0? DENY immediately         | |
|  |       |                                                      | |
|  |       v                                                      | |
|  |  Input Sanitization ----> base64? ChatML? leet? DENY         | |
|  |       |                                                      | |
|  |       v                                                      | |
|  |  OPA Policy Engine -----> scope too low? DENY                | |
|  |       |                   after hours? DENY                  | |
|  |       |                   risk too high? ESCALATE            | |
|  |       v                                                      | |
|  |  Tool Authorization ----> params valid? rate ok? ALLOW       | |
|  +-------------------------------------------------------------+ |
|                            |                                      |
|                     ALLOW  |  DENY returns explanation             |
|                            |  ESCALATE creates approval request   |
|                            v                                      |
|  +-------------------------------------------------------------+ |
|  | AGENT EXECUTION (inside security boundary)                   | |
|  |                                                              | |
|  |  Bedrock Agent (Nova Micro) reasons about the request        | |
|  |       |                                                      | |
|  |       v  picks action group based on scope:                  | |
|  |                                                              | |
|  |  Scope 1: ReadPipelineStatus                                 | |
|  |    - getBuildStatus (S3 read)                                | |
|  |    - getTestResults (S3 read)                                | |
|  |                                                              | |
|  |  Scope 2: ProposeChanges                                     | |
|  |    - draftDeploymentPlan (DynamoDB write to pending table)   | |
|  |    - draftRollbackStrategy (DynamoDB write)                  | |
|  |                                                              | |
|  |  Scope 3: StagingDeployment                                  | |
|  |    - deployToStaging (S3 write to staging path)              | |
|  |    - triggerTests (S3 write test execution record)           | |
|  |                                                              | |
|  |  Scope 4: ProductionDeployment                               | |
|  |    - deployToProduction (S3 write to production path)        | |
|  |    - rollbackDeployment (S3 write rollback record)           | |
|  |                                                              | |
|  |  EACH tool call is wrapped with:                             | |
|  |    1. Scope enforcement (scope 1 cannot call Scope 3 tools)  | |
|  |    2. Parameter injection scan (SQL, XSS, path traversal)    | |
|  |    3. Output sanitization (strip ARNs, credentials, JWTs)    | |
|  +-------------------------------------------------------------+ |
|                            |                                      |
|                            v                                      |
|  +-------------------------------------------------------------+ |
|  | DETECTIVE ENGINE (monitors during and after)                 | |
|  |                                                              | |
|  |  Runtime Drift Detection ---> behavior deviates? flag it     | |
|  |  Continuous Health Score ---> health dropping? alert         | |
|  |  CloudWatch Metrics -------> latency, denial rates, risk     | |
|  |  Decision History ----------> queryable audit trail          | |
|  +-------------------------------------------------------------+ |
|                            |                                      |
|                            v                                      |
|  +-------------------------------------------------------------+ |
|  | EVIDENCE (immutable, async, non-blocking)                    | |
|  |                                                              | |
|  |  SHA-256 hashed evidence record --> S3 (Object Lock 7yr)    | |
|  |  Control trace --> ISO 42001 + NIST AI RMF mapping          | |
|  |  Canary tripwire check --> if leaked, auto kill switch      | |
|  +-------------------------------------------------------------+ |
|                                                                   |
+===================================================================+
                            |
                            v
Developer receives: "Build-47 deployed to staging. Integration
tests triggered. Results will be available in 10 minutes."
```

## Three Governance Engines

| Engine | When | Purpose | Components |
|--------|------|---------|-----------|
| **Preventive** | Before execution | Block unauthorized or dangerous actions | OPA policy engine, input sanitizer, threat detector, tool auth, scope enforcement, behavioral invariants |
| **Detective** | During and after | Monitor for anomalies, track health | Runtime drift detection, continuous monitoring, CloudWatch metrics, decision history |
| **Proactive** | Before config changes | Validate policies and configs are safe | (Planned: policy validation, config drift prevention) |

## Execution Modes

The governance pipeline supports two execution topologies:

### Step Functions Express (Production)

```
Kill Switch (DynamoDB direct)
    |
    v
[InputDefense Lambda] || [Authorization Lambda]   <-- PARALLEL
    |                          |
    v                          v
       PolicyRisk Lambda (sequential)
    |
    v
EventBridge --> [PostDecision Lambda]   <-- ASYNC (non-blocking)
```

- Parallel: Input defense and authorization run simultaneously
- Async: Evidence writing does not block the response
- Scale: 100,000+ concurrent executions
- Latency: ~150ms for ALLOW, <50ms for DENY (short-circuits early)

### Single Lambda (Development)

All 20 steps run sequentially in one Governance Engine Lambda invocation. Same checks, simpler to debug. Switch via `GOVERNANCE_MODE=lambda` on Scope Enforcer.

## Per-Tool-Call Security

Even after the governance pipeline approves a session, the Action Group Lambda enforces security on EVERY individual tool call:

| Check | What it does | Overhead |
|-------|-------------|----------|
| Scope enforcement | Verifies this tool is permitted at current scope level | <1ms |
| Parameter injection | Regex scan for SQL injection, XSS, path traversal, LLM delimiters in parameter values | ~5ms |
| Output sanitization | Strips leaked ARNs, AWS credentials, JWTs, internal resource names from response | ~5ms |

Total per-tool overhead: ~15ms. No external Lambda calls. Inline checks only.

This means: even if the Bedrock Agent model is jailbroken and tries to call a production deployment tool at scope 1, the physical scope check in the Action Group Lambda blocks it. The IAM permission boundary ALSO blocks it. Two independent layers, neither trusts the other.

## Policy Resolution

OPA-style policy engine with priority-based resolution:

```
Request: ProductionDeployment at scope 2
  |
  v
Rule: deny_production_below_scope_3 (priority 10)
  Conditions: action_group == "ProductionDeployment" AND scope_level < 3
  Match: YES (scope 2 < 3)
  |
Rule: allow_production_at_scope_3_plus (priority 20)
  Conditions: action_group == "ProductionDeployment" AND scope_level >= 3
  Match: NO (scope 2 is not >= 3)
  |
Rule: default_deny (priority 9999)
  Conditions: (none, matches everything)
  Match: YES
  |
Winner: deny_production_below_scope_3 (lowest priority number = highest precedence)
Verdict: DENY
```

## Security Model

| Threat | Layer 1 (Preventive) | Layer 2 (Per-Tool) | Layer 3 (Infrastructure) |
|--------|---------------------|-------------------|-------------------------|
| Prompt injection | Input sanitizer (base64, ChatML, leet-speak) | N/A | N/A |
| Scope escalation | OPA policy denies | Scope-action-group check | IAM permission boundary |
| SQL injection in params | Threat detector (regex) | Parameter injection scan | N/A |
| Data exfiltration | Exfiltration detector (output size) | Output sanitization | S3 bucket policies |
| Credential leakage | N/A | Output sanitization strips secrets | IAM role isolation |
| Agent compromise | Canary tripwire detection | N/A | Kill switch (instant) |
| Unauthorized tools | Tool/model registry | Scope enforcement | IAM actions restricted |
| After-hours deploy | Behavioral invariants | N/A | N/A |

## Key Design Decisions

### Why OPA over custom policy logic?

OPA (Open Policy Agent) is the industry standard for policy-as-code. Rego is purpose-built for policy evaluation. Organizations with existing OPA infrastructure can point `OPA_ENDPOINT` at their service. Organizations without OPA get an embedded Rego-subset evaluator that handles governance use cases natively.

### Why per-tool checks instead of trusting the session?

A session-level approval says "this agent is allowed to act." But between approval and execution, the agent reasons autonomously. It might:
- Call tools it shouldn't (hallucination)
- Pass injection payloads as parameters
- Leak internal data in responses

Per-tool checks are the last line of defense. They're physical constraints that no model output can override.

### Why async evidence writing?

Evidence records are critical for compliance but not for the developer waiting for a response. Blocking the response for 300ms to write evidence is wrong. EventBridge fires the write asynchronously; the developer gets their answer immediately; the evidence appears in S3 within 1-2 seconds.

### Why dual-mode execution?

Development teams need simple debugging (single Lambda, CloudWatch logs in one place). Production needs scale (100K concurrent). The feature flag lets you run both from the same codebase without forking.

### Why fail-safe deny?

If DynamoDB is unreachable, the system denies all requests. If the policy engine throws an exception, the system denies. If the kill switch check fails, the system denies. The only path to ALLOW is every check explicitly passing. This is the opposite of "fail-open" which many systems default to.
