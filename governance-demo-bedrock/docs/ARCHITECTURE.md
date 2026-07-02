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

## GenAI Threat Matrix Coverage

This architecture addresses the complete Amazon GenAI Security Threat Matrix (GAIS). Every threat, vulnerability, and attack technique maps to a deployed governance module.

### Threats Covered

| Threat ID | Threat | Governance Module |
|-----------|--------|-------------------|
| GAIS-TH001 | Guardrail Evasion | input_sanitizer (encoding, unicode, delimiters) + behavioral_invariants (physical limits) |
| GAIS-TH001.001 | Overreliance on system instruction | behavioral_invariants (hard limits no model output can override) |
| GAIS-TH001.002 | Output Guardrail Evasion | output_guardrails + per-tool _sanitize_output |
| GAIS-TH002.001-004 | Customer data exfiltration (PII, credentials, prompt history) | output_guardrails + cache_governance (PII detection and redaction) |
| GAIS-TH002.005-007 | System info disclosure (runtime, errors, metadata) | output_guardrails (ARN, Lambda name, account ID stripping) |
| GAIS-TH002.010 | System context exposure | output_guardrails (system prompt leak detection) |
| GAIS-TH002.013-016 | RAG data extraction and auth bypass | retrieval_validator + exfiltration_detector |
| GAIS-TH003.002 | Model drift | runtime_drift_detection + continuous_monitoring |
| GAIS-TH004.002-004 | Knowledge base poisoning (vector store, embedding backdoor) | retrieval_validator (validates all retrieved content before context injection) |
| GAIS-TH004.005 | Retrieval flooding | tool_execution_auth (rate limiting per tool per agent) |
| GAIS-TH004.006 | Insecure deserialization of outputs | output_guardrails (XSS, script tag detection) |
| GAIS-TH004.007 | Session hijacking | Scope enforcement + per-agent session attributes |
| GAIS-TH005 | Unauthorized access | agent_identity + agent_registry + IAM permission boundaries |
| GAIS-TH005.001 | Cross-Agent Privilege Escalation | privilege_escalation + multi_agent (cross-agent rules) |
| GAIS-TH006.002 | Hallucinations | Evidence grounding + output guardrails (coherence check) |
| GAIS-TH006.006 | Out of band response | Scope enforcement (agent can only call permitted action groups) |
| GAIS-TH007.001 | Autonomous Tool-Misuse Loop | tool_execution_auth (rate limiting + chain detection) |
| GAIS-TH007.005 | Unbounded invocations | tool_execution_auth (rate_limit_per_minute) |
| GAIS-TH007.006 | Decision drifts | runtime_drift_detection (behavioral baseline comparison) |
| GAIS-TH007.007 | Context manipulation | input_sanitizer (context stuffing >5000 chars = DENY) |
| GAIS-TH007.008 | Multi-agent collaborative compromise | multi_agent (cross-agent rules prevent one agent modifying another) |
| GAIS-TH007.009 | Improper lifecycle management | agent_registry (formal registration required, status tracked) |
| GAIS-TH007.010 | Agent Self Modification | privilege_escalation (blocks self-modification, auto-reduces scope) |

### Attack Techniques Covered

| Technique ID | Attack | Governance Module |
|-------------|--------|-------------------|
| GAIS-T001 | Character manipulation (homoglyphs, invisible chars) | input_sanitizer (unicode NFKD normalization, homoglyph map) |
| GAIS-T003 | Encoding (base64, hex, URL, steganography) | input_sanitizer (decodes and scans all encoded payloads) |
| GAIS-T004 | Mixed-language evasion | input_sanitizer (instruction patterns detected post-normalization) |
| GAIS-T005 | Jailbreak | input_sanitizer + behavioral_invariants (physical limits survive jailbreak) |
| GAIS-T006 | Multiturn attacks | continuous_monitoring (tracks patterns across requests, health degrades) |
| GAIS-T011-013 | Denial of Service (complex problems, resource exhaustion) | tool_execution_auth (rate limiting) + behavioral_invariants (output caps) |
| GAIS-T014 | Context overflow | input_sanitizer (context stuffing detection at 5000 chars) |
| GAIS-T016 | Confused deputy | Scope enforcement + per-tool auth (agent cannot act above its scope) |
| GAIS-T017 | Retrieval source poisoning | retrieval_validator (scans all retrieved content for injection) |
| GAIS-T019 | Indirect PI via agent response | retrieval_validator + output_guardrails |
| GAIS-T021 | Capability forging | Scope-action-group enforcement (physical check in Action Group Lambda) |
| GAIS-T023 | No isolated sessions | Per-agent scope table + environment isolation |
| GAIS-T027-029 | KB discovery, poisoning, spoofing | retrieval_validator (validates content from all data sources) |

### Vulnerabilities Covered

| Vulnerability ID | Vulnerability | Governance Module |
|-----------------|---------------|-------------------|
| GAIS-V001 | Insufficient Guardrails | 8 security modules + OPA + per-tool checks (defense-in-depth) |
| GAIS-V001.001 | Function call validation gaps | tool_execution_auth (per-tool parameter validation on every call) |
| GAIS-V001.002 | RAG content filtering bypass | retrieval_validator (validates before context injection) |
| GAIS-V002.001 | Least privilege misconfigured | IAM permission boundaries (scope 1-4, enforced by AWS) |
| GAIS-V002.004 | Insecure logging practices | evidence_pipeline (S3 Object Lock, encrypted, 7-year retention) |
| GAIS-V002.006 | Orchestration logic flaws | proactive_engine (validates policy contradictions before deploy) |
| GAIS-V003.003 | API credential exposure | output_guardrails (AKIA pattern detection + redaction) |
| GAIS-V003.004 | Agent privilege boundaries | Scope enforcement + IAM boundaries (two independent layers) |
| GAIS-V005.001-003 | Retrieval system vulnerabilities | retrieval_validator + cache_governance + rate limiting |
| GAIS-V006.001 | Uncontrolled recursion | tool_execution_auth (rate limiting prevents loops) |
| GAIS-V006.002 | Inter-agent trust issues | multi_agent (cross-agent rules, no implicit trust) |
| GAIS-V006.003 | Memory manipulation | retrieval_validator (validates all content entering agent context) |

### ASR GenAI Security Review Tasks

This architecture satisfies all GenAI Critical tasks required by Amazon Security Reviews (ASR):

| ASR Task | Implementation |
|----------|---------------|
| Protect Against Data Leakage | output_guardrails + cache_governance + exfiltration_detector |
| Prompt Data Input Validation | input_sanitizer (6 validation checks) |
| Review Response Data Usage | evidence_pipeline (every response logged with SHA-256 hash) |
| Create/Review Andon Cord System | kill_switch + behavioral_invariants (auto-trigger on canary leak) |
| Auth check | agent_identity + agent_registry + tool_execution_auth |
| Capture Prompts and Responses | evidence_pipeline (S3 Object Lock, 7-year immutable retention) |
| FAST onboarding for Automated Testing | 10-scenario attack battery + benchmark script |
| Silo User Sessions | Scope enforcement + environment isolation + per-agent evidence partitions |
| HITL for High-Risk Operations | ESCALATE verdict + approval_workflow + SNS notifications |
