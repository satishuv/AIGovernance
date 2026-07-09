# Runtime Flow: 20-Step Governance Pipeline

The complete sequence from user request to governed response. Every step runs in <150ms total for ALLOW, <50ms for DENY (short-circuits early).

---

## Pipeline Sequence

```
User Request
     │
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Kill Switch Check                                          │
│  Source: DynamoDB direct read (no Lambda cold start)                 │
│  Action: If scope == 0, return DENY immediately (<5ms)              │
│  Short-circuit: YES - nothing else runs                             │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ scope > 0
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: Agent Registry Lookup                                      │
│  Source: agent_registry module                                       │
│  Action: Verify agent is registered, status == active                │
│  Short-circuit: Unregistered or suspended agent = DENY               │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: Scope Table Lookup                                         │
│  Source: DynamoDB scope table                                        │
│  Action: Read current scope level (0-4) for this agent               │
│  Data: scope_level, last_modified, modified_by                       │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEPS 4-11: Input Defense (8 checks, parallel in Step Functions)    │
│                                                                     │
│  4. Base64/hex/URL encoding detection and decode                     │
│  5. ChatML/Llama delimiter injection scan                            │
│  6. Unicode homoglyph normalization (NFKD)                           │
│  7. Leet-speak pattern decode and scan                               │
│  8. Context window stuffing check (>5000 chars = DENY)               │
│  9. Persona/roleplay/DAN jailbreak detection                         │
│  10. Harmful content classification                                  │
│  11. Shannon entropy anomaly detection                               │
│                                                                     │
│  Short-circuit: Any check fails = DENY with specific reason          │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ all pass
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 12: Tool/Action Group Authorization                           │
│  Source: tool_execution_auth module                                   │
│  Action: Verify requested action group is permitted at current scope │
│  Check: Enum allowlist, rate limit, invocation cap                   │
│  Short-circuit: Unauthorized tool = DENY                             │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 13: OPA Policy Evaluation                                     │
│  Source: policy_engine module (embedded Rego-subset)                  │
│  Action: Evaluate all matching rules, resolve by priority            │
│  Outcomes: ALLOW / DENY / ESCALATE                                   │
│  Rules: Time-of-day, scope-action mapping, risk thresholds           │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 14: Cedar Formal Verification (if enabled)                    │
│  Source: cedar_verification module                                    │
│  Action: Mathematical proof that policy combination is safe          │
│  Outcomes: VERIFIED / CONTRADICTION_DETECTED                         │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 15: Risk Scoring                                              │
│  Source: risk_engine module                                          │
│  Action: Compute composite risk score (0-100)                        │
│  Inputs: action severity, time-of-day, recent denials, drift score   │
│  Threshold: >70 = ESCALATE, >90 = DENY                              │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 16: Behavioral Invariant Check                                │
│  Source: behavioral_invariants module                                 │
│  Action: Hard physical limits no model output can override           │
│  Checks: Max tool calls (25), after-hours block, output size cap     │
│  Short-circuit: Invariant violated = DENY (cannot be overridden)     │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 17: Trust / Drift Assessment                                  │
│  Source: runtime_drift_detection + continuous_monitoring              │
│  Action: Compare current behavior against baseline                   │
│  Signal: Health score, drift magnitude, anomaly flags                 │
│  Outcome: Informational (feeds into risk score for next request)      │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 18: Decision Engine (final verdict)                           │
│  Source: pipeline_orchestrator module                                 │
│  Action: Aggregate all signals into ALLOW / DENY / ESCALATE          │
│  Logic: Any DENY in chain = DENY. Any ESCALATE = ESCALATE.          │
│          All pass = ALLOW.                                           │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌─────────┐  ┌──────────┐  ┌─────────┐
              │  DENY   │  │ ESCALATE │  │  ALLOW  │
              └─────────┘  └──────────┘  └────┬────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 19: Agent Execution (post-approval)                           │
│  Bedrock Agent invoked with scope-gated action groups                │
│  Per-tool: scope check + param injection + output sanitization       │
│  Tool Response Validator scans all data returned from enterprise      │
│  Output Guardrails strip PII, credentials, exfiltration attempts     │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 20: Evidence Writing (async, non-blocking)                    │
│  Source: EventBridge -> evidence_pipeline                             │
│  Action: SHA-256 hash, Object Lock write, compliance mapping         │
│  Latency: 0ms added to response (fires asynchronously)               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Execution Modes

### Step Functions Express (Production)

```
Kill Switch (DynamoDB direct)
    │
    ▼
[InputDefense Lambda] || [Authorization Lambda]   <-- PARALLEL
    │                          │
    ▼                          ▼
       PolicyRisk Lambda (sequential)
    │
    ▼
EventBridge --> [PostDecision Lambda]   <-- ASYNC (non-blocking)
```

- Parallel: Input defense and authorization run simultaneously (halves latency)
- Async: Evidence writing does not block the response
- Scale: 100,000+ concurrent executions
- Latency: ~150ms for ALLOW, <50ms for DENY (short-circuits early)

### Single Lambda (Development)

All 20 steps run sequentially in one Governance Engine Lambda invocation. Same checks, simpler to debug. Switch via `GOVERNANCE_MODE=lambda` on Scope Enforcer.

---

## Per-Tool-Call Security (Inside Agent Execution)

Even after the governance pipeline approves a session, the Action Group Lambda enforces security on EVERY individual tool call:

| Check | What it does | Overhead |
|-------|-------------|----------|
| Scope enforcement | Verifies this tool is permitted at current scope level | <1ms |
| Parameter injection | Regex scan for SQL, XSS, path traversal, LLM delimiters | ~5ms |
| Rate limiting | Per-tool invocation cap (25/session), recursion limit (1) | <1ms |
| Tool response validation | Scan data FROM tools for injection, anomalies | ~3ms |
| Output sanitization | Strip ARNs, credentials, JWTs, internal resource names | ~5ms |

Total per-tool overhead: ~15ms. No external Lambda calls. Inline checks only.

---

## Short-Circuit Behavior

The pipeline is designed to fail fast:

| Condition | Short-circuits at | Total latency |
|-----------|-------------------|---------------|
| Kill switch active (scope 0) | Step 1 | <5ms |
| Agent not registered | Step 2 | <10ms |
| Input injection detected | Steps 4-11 | <30ms |
| Tool not in allowlist | Step 12 | <40ms |
| Policy DENY | Step 13 | <50ms |
| Behavioral invariant violated | Step 16 | <60ms |
| Full ALLOW path | Step 18 | ~150ms |
