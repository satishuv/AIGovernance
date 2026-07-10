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
- Latency: ~200ms for ALLOW, <50ms for DENY (short-circuits early)

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

## GenAI Security Threat Coverage

This architecture addresses the known GenAI security threat landscape. Every threat category, vulnerability class, and attack technique maps to a deployed governance module.

### Threats Covered

| Threat Category | Specific Threat | Governance Module |
|-----------------|----------------|-------------------|
| Guardrail Evasion | Encoding, unicode, delimiter bypass | input_sanitizer + behavioral_invariants (physical limits) |
| Guardrail Evasion | Overreliance on system instructions | behavioral_invariants (hard limits no model output can override) |
| Guardrail Evasion | Output filter bypass | output_guardrails + per-tool output sanitization |
| Data Exfiltration | PII, credentials, prompt history leakage | output_guardrails + cache_governance (PII detection and redaction) |
| Data Exfiltration | System info disclosure (runtime, errors) | output_guardrails (infrastructure pattern stripping) |
| Data Exfiltration | System context/prompt exposure | output_guardrails (system prompt leak detection) |
| Data Exfiltration | RAG-based data extraction | retrieval_validator + exfiltration_detector |
| Model Integrity | Behavioral drift | runtime_drift_detection + continuous_monitoring |
| System Integrity | Knowledge base poisoning | retrieval_validator (validates all retrieved content before context injection) |
| System Integrity | Retrieval flooding | tool_execution_auth (rate limiting per tool per agent) |
| System Integrity | Insecure deserialization of outputs | output_guardrails (XSS, script tag detection) |
| System Integrity | Session hijacking | Scope enforcement + per-agent session attributes |
| Unauthorized Access | Missing authentication/authorization | agent_identity + agent_registry + IAM permission boundaries |
| Unauthorized Access | Cross-agent privilege escalation | privilege_escalation + multi_agent (cross-agent rules) |
| Trust and Safety | Hallucinations | Evidence grounding + output guardrails (coherence check) |
| Trust and Safety | Out of band response | Scope enforcement (agent limited to permitted action groups) |
| Agent Threats | Autonomous tool-misuse loop | tool_execution_auth (rate limiting + chain detection) |
| Agent Threats | Unbounded invocations | tool_execution_auth (rate_limit_per_minute) |
| Agent Threats | Decision drifts | runtime_drift_detection (behavioral baseline comparison) |
| Agent Threats | Context manipulation | input_sanitizer (context stuffing >5000 chars = DENY) |
| Agent Threats | Multi-agent collaborative compromise | multi_agent (cross-agent rules prevent one agent modifying another) |
| Agent Threats | Improper lifecycle management | agent_registry (formal registration required, status tracked) |
| Agent Threats | Agent self-modification | privilege_escalation (blocks self-modification, auto-reduces scope) |

### Attack Techniques Covered

| Technique | Description | Governance Module |
|-----------|-------------|-------------------|
| Character manipulation | Homoglyphs, invisible characters, unicode tricks | input_sanitizer (NFKD normalization, homoglyph map) |
| Encoding attacks | Base64, hex, URL encoding to hide payloads | input_sanitizer (decodes and scans all encoded payloads) |
| Mixed-language evasion | Multiple languages to bypass filters | input_sanitizer (instruction patterns detected post-normalization) |
| Jailbreak | Prompt crafting to bypass safety | input_sanitizer + behavioral_invariants (physical limits survive jailbreak) |
| Multiturn attacks | Splitting adversarial prompts across turns | continuous_monitoring (tracks patterns across requests) |
| Denial of service | Resource exhaustion, infinite loops | tool_execution_auth (rate limiting) + behavioral_invariants (output caps) |
| Context overflow | Stuffing context window to push out instructions | input_sanitizer (context stuffing detection at 5000 chars) |
| Confused deputy | Coercing privileged entity to act | Scope enforcement + per-tool auth (agent cannot act above its scope) |
| Retrieval source poisoning | Injecting malicious content into data sources | retrieval_validator (scans all retrieved content for injection) |
| Indirect prompt injection | Injection via agent-retrieved data | retrieval_validator + output_guardrails |
| Capability forging | Agent hallucinating unauthorized capabilities | Scope-action-group enforcement (physical check in Action Group Lambda) |
| Session isolation bypass | Accessing other users/agents data | Per-agent scope table + environment isolation |
| Knowledge base attacks | Discovery, poisoning, spoofing of KB | retrieval_validator (validates content from all data sources) |

### Vulnerabilities Covered

| Vulnerability Class | Description | Governance Module |
|--------------------|-------------|-------------------|
| Insufficient guardrails | Lack of input/output filtering | 8 security modules + OPA + per-tool checks (defense-in-depth) |
| Function call validation gaps | No validation on tool invocations | tool_execution_auth (per-tool parameter validation on every call) |
| RAG content filtering bypass | Unfiltered retrieved content | retrieval_validator (validates before context injection) |
| Least privilege violation | Overly permissive access | IAM permission boundaries (scope 1-4, enforced by AWS) |
| Insecure logging | Sensitive data in unprotected logs | evidence_pipeline (S3 Object Lock, encrypted, configurable retention (default 1 year, 7 years in production)) |
| Orchestration logic flaws | Policy contradictions, dead rules | proactive_engine (validates policy integrity before deploy) |
| Credential exposure | API keys in responses | output_guardrails (credential pattern detection + redaction) |
| Agent privilege boundaries | Weak isolation between agent scopes | Scope enforcement + IAM boundaries (two independent layers) |
| Retrieval system vulnerabilities | Embedding, integrity, query control | retrieval_validator + cache_governance + rate limiting |
| Uncontrolled recursion | No safeguard against loops | tool_execution_auth (rate limiting prevents loops) |
| Inter-agent trust | Implicit trust between agents | multi_agent (cross-agent rules, no implicit trust) |
| Memory manipulation | Poisoning agent context/memory | retrieval_validator (validates all content entering agent context) |

### Enterprise Security Review Readiness

This architecture satisfies standard GenAI security review requirements:

| Security Review Task | Implementation |
|---------------------|---------------|
| Protect against data leakage | output_guardrails + cache_governance + exfiltration_detector |
| Input validation and sanitization | input_sanitizer (6 validation checks including encoding, delimiters, injection) |
| Response data usage audit | evidence_pipeline (every response logged with SHA-256 hash) |
| Emergency shutdown mechanism | kill_switch + behavioral_invariants (auto-trigger on canary leak) |
| Authentication and authorization | agent_identity + agent_registry + tool_execution_auth |
| Prompt and response logging | evidence_pipeline (S3 Object Lock, configurable immutable retention) |
| Automated security testing | 10-scenario attack battery + benchmark script |
| Session isolation | Scope enforcement + environment isolation + per-agent evidence partitions |
| Human-in-the-loop for high-risk | ESCALATE verdict + approval_workflow + SNS notifications |
