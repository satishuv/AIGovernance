# Runtime Flow: 20-Step Governance Pipeline

The complete sequence from user request to governed response.

**Measured latency (single-Lambda mode, warm, us-east-1, 2026-07-24):** ALLOW
~3.5s server-side (billed Duration) p50, of which ~2.0s is tracked governance
work; DENY short-circuits early (~0.8s client round-trip). Cold start adds only
~90ms (Init Duration), so cold start is NOT the dominant cost. The dominant
costs are synchronous evidence write to the WORM bucket (~1.4s, includes KMS
signing) and S3 policy load (~0.5s). See the latency breakdown below and
[Latency and performance](#latency-and-performance) for the honest picture and
the paths to reduce it (Step Functions Express mode, async evidence, policy
caching). Earlier docs cited a ~200ms target; that was an unbenchmarked design
goal, not a measured figure, and is corrected here.

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
│  STEPS 4-11: Input Defense (7 checks, sequential - short-circuits on first fail)    │
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

- Parallel: Input defense and authorization run simultaneously
- Async: Evidence writing does not block the response (the ~1.4s evidence write
  that dominates single-Lambda mode moves off the hot path here)
- Scale: 100,000+ concurrent executions
- Latency: **design target ~200ms for ALLOW; NOT yet benchmarked in this mode.**
  Only single-Lambda mode has been measured (see below). The parallel +
  async-evidence design should be materially faster than single-Lambda's ~3.5s,
  but that figure is a target until measured, not a verified result.

### Single Lambda (Development)

All 20 steps run sequentially in one Governance Engine Lambda invocation. Same checks, simpler to debug. Switch via `GOVERNANCE_MODE=lambda` on Scope Enforcer.

---

## Latency and performance

Honest, measured numbers (deployed on Isengard, single-Lambda mode, warm,
us-east-1, 2026-07-24). These replace an earlier unbenchmarked "~200ms" design
target that was off by roughly 10-17x.

| Metric | Measured |
|--------|----------|
| ALLOW, server-side billed Duration, p50 | ~3.5s |
| ALLOW, tracked governance work, p50 | ~2.0s |
| DENY (injection), client round-trip | ~0.8s |
| Cold start (Init Duration) | ~90ms |

**Where the ALLOW time goes** (tracked spans, p50):

| Stage | Time |
|-------|------|
| Evidence write to WORM bucket (incl. KMS signing) | ~1.4s |
| Policy evaluation (S3 policy load) | ~0.5s |
| Decision engine | ~0.14s |
| Risk scoring | <0.01s |

**Key finding:** cold start is negligible (~90ms), so provisioned concurrency is
NOT the fix. The dominant costs are the synchronous evidence write and the S3
policy load on the hot path. Honest paths to reduce ALLOW latency, in order of
impact:

1. **Move evidence write off the hot path (~1.4s). DONE (opt-in):** set
   `EVIDENCE_ASYNC=true` and single-Lambda mode emits the decision to EventBridge
   (a DURABLE queue, EventBridge retries), and the PostDecision Lambda writes
   evidence off the hot path. **Measured live: ALLOW tracked governance latency
   dropped from ~2,016ms to ~287ms p50 (~7x), evidence stage ~1,389ms -> ~129ms
   (just the event emit).** Verified evidence is still written durably
   (PostDecision runs on every event) and the emit falls back to a synchronous
   inline write if EventBridge is unreachable, so evidence is never silently
   dropped. Default is `false` (inline, synchronous) for the strongest guarantee.
   TRADE-OFF (honest): the PostDecision evidence write is currently a plain write
   and does NOT KMS-sign the record, unlike the inline path. So async mode trades
   ~1.4s latency for unsigned evidence via that path until PostDecision is updated
   to sign. A naive in-process "fire-and-forget" was deliberately NOT used
   (Lambda freezes post-response and would drop the write).
2. **Cache policies in memory (~0.5s). DONE:** the OPA engine is now cached per
   warm container with a 60s TTL (`_get_cached_opa_engine` in
   pipeline_orchestrator.py), removing the per-request S3 policy load while still
   honoring the 60s policy-refresh requirement. First (cold) request still pays
   the load.
3. **Use Step Functions Express mode** for the parallel path (design target
   ~200ms, not yet benchmarked).

Until those land, single-Lambda mode is honestly suited to lower-throughput or
non-latency-critical governed workloads (e.g. CI/CD gating, batch review), not
sub-second interactive agent loops.

## Per-Tool-Call Security (Inside Agent Execution)

Even after the governance pipeline approves a session, the Action Group Lambda enforces security on EVERY individual tool call:

| Check | What it does | Overhead |
|-------|-------------|----------|
| Scope enforcement | Verifies this tool is permitted at current scope level | <1ms |
| Parameter injection | Regex scan for SQL, XSS, path traversal, LLM delimiters | ~5ms |
| Rate limiting | Per-tool invocation cap (25/session), recursion limit (1) | <1ms |
| Tool response validation | Scan data FROM tools for injection, anomalies | ~3ms |
| Output sanitization | Strip ARNs, credentials, JWTs, internal resource names | ~5ms |

Total per-tool overhead: ~15ms (engineering estimate; these are pure in-process
regex/dict checks with no external calls, so the estimate is plausible, but the
per-check millisecond values here are not individually benchmarked). No external
Lambda calls. Inline checks only.

---

## Short-Circuit Behavior

The pipeline is designed to fail fast: DENY paths short-circuit early and skip
the expensive evidence write, so they are much faster than ALLOW. Measured DENY
(injection, single-Lambda, warm) is ~0.8s client round-trip. The relative
ordering below is by design; the per-row millisecond values are engineering
estimates of the *internal* short-circuit point, not individually benchmarked.

| Condition | Short-circuits at | Relative cost (est.) |
|-----------|-------------------|----------------------|
| Kill switch active (scope 0) | Step 1 | fastest (DynamoDB read only) |
| Agent not registered | Step 2 | very fast |
| Input injection detected | Steps 4-11 | fast (no policy/evidence) |
| Tool not in allowlist | Step 12 | fast |
| Policy DENY | Step 13 | fast (skips evidence write) |
| Behavioral invariant violated | Step 16 | fast |
| Full ALLOW path | Step 18 | **~3.5s measured (single-Lambda, warm); evidence write dominates** |
