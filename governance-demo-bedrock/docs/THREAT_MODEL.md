# Threat Model and Security Assumptions

## System Boundary

The governance framework wraps an AI agent (Amazon Bedrock Agent running Nova Micro) that manages a software deployment pipeline. The agent has graduated autonomy (scope 0-4) and interacts with S3, DynamoDB, and external APIs through governed action groups.

## Trust Boundaries

```
UNTRUSTED                         TRUST BOUNDARY                    TRUSTED
-----------                       ---------------                   --------
User input         -->  [ Input Sanitizer + Guardrails ]  -->  Governance Pipeline
Tool responses     -->  [ Tool Response Validator ]        -->  Agent reasoning
External data      -->  [ RAG Validation ]                 -->  Knowledge base
Agent output       -->  [ Output Guardrails ]              -->  End user
```

## Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| External attacker | Crafted prompts via user interface | Data exfiltration, unauthorized deployment |
| Compromised data source | Poisoned S3 objects, DynamoDB records | Indirect prompt injection, agent hijacking |
| Malicious insider | Direct API access, knowledge of system prompts | Privilege escalation, audit evasion |
| Compromised peer agent | Inter-agent messaging | Lateral movement, collusion |
| Supply chain attacker | Poisoned model weights, tool metadata | Persistent backdoor, long-term exfiltration |

## Security Assumptions

### What We Assume Is Secure

1. **AWS IAM** - AWS IAM correctly enforces permission boundaries and role assumptions
2. **AWS KMS / S3 encryption** - Data at rest is protected by AWS-managed encryption
3. **Bedrock foundation model** - The model itself has not been tampered with (we use managed `amazon.nova-micro-v1:0`)
4. **Network** - VPC and TLS protect data in transit between Lambda functions
5. **DynamoDB** - Table-level encryption and IAM policies prevent unauthorized access to governance state
6. **S3 Object Lock** - COMPLIANCE mode cannot be bypassed (AWS guarantees WORM)
7. **CloudTrail** - AWS CloudTrail logs cannot be forged or deleted by non-root accounts

### What We Do NOT Assume

1. **User input is safe** - All input is treated as potentially adversarial
2. **Tool responses are safe** - Data returned from S3/DynamoDB/APIs may be poisoned
3. **Agent reasoning is reliable** - The model may follow injected instructions; governance operates externally
4. **Single defense is sufficient** - Any individual layer may be bypassed; defense-in-depth required
5. **Model alignment is permanent** - Safety training may be circumvented; behavioral invariants enforce hard limits
6. **Evidence is voluntarily generated** - Evidence pipeline is mandatory, not optional; async but verified

## Attack Surfaces and Mitigations

### 1. Direct Prompt Injection
**Threat:** Attacker crafts input to override agent instructions.
**Mitigations:**
- Input sanitizer (regex: base64, ChatML, leet-speak, multilingual)
- Bedrock Guardrails (AI classifier: semantic attacks, harmful content)
- Behavioral invariants (hard limits no model output can override)

### 2. Indirect Prompt Injection (Tool Response Poisoning)
**Threat:** Attacker poisons data in S3/DynamoDB; agent reads it and follows embedded instructions.
**Mitigations:**
- Tool response validator (injection patterns, action directives, entropy)
- Sensitive data stripping before agent processing
- Response size enforcement per tool type

### 3. Privilege Escalation
**Threat:** Agent attempts to increase its own scope or invoke unauthorized tools.
**Mitigations:**
- IAM permission boundaries per scope level (enforced by AWS, not model)
- Enum-based action group allowlisting
- Scope enforcement via DynamoDB (external state, not model memory)
- Privilege escalation detector (self-modification and policy-modification blocked)

### 4. Data Exfiltration
**Threat:** Agent leaks sensitive data in its responses or via tool calls.
**Mitigations:**
- Output guardrails (ARN/credential/JWT stripping)
- PII detection and redaction (HIPAA: SSN, MRN, NPI)
- Exfiltration detector (endpoint allowlisting, output size limits)
- Canary token tripwire (detects if agent context is leaked)

### 5. Denial of Service / Resource Exhaustion
**Threat:** Attacker triggers infinite tool loops or massive evidence generation.
**Mitigations:**
- Per-invocation tool call cap (max 25)
- Recursion depth prevention (max 1)
- Per-tool rate limiting
- Lambda timeout (30s governance, 60s action group)
- Step Functions Express timeout

### 6. Evidence Tampering
**Threat:** Attacker modifies or deletes governance records to cover tracks.
**Mitigations:**
- S3 Object Lock COMPLIANCE mode (cannot be deleted, even by root)
- SHA-256 hash chains (tampering detectable via hash verification)
- Async evidence writing (non-blocking, but mandatory)
- Fail-safe: evidence write failure does NOT block deny decisions

### 7. Kill Switch Bypass
**Threat:** Attacker disables the kill switch to prevent emergency shutdown.
**Mitigations:**
- Kill switch is a DynamoDB native SDK call (no Lambda cold start)
- Kill switch check is first in pipeline (runs before any other logic)
- Kill switch activation triggers CloudWatch alarm + SNS notification
- IAM restricts kill switch write to authorized operators only

## Application Security of Our Own Surface (Plane 3)

The threats above govern agent *actions* (Plane 1). This section covers classic
application security of the control plane's own attack surface: the CDK stack,
Lambda handlers (scope enforcer entry, api_router, action-group endpoints), their
authorization, input handling, dependencies, and secrets. Recent incidents
(ChatGPT AgentForger CSRF, LiteLLM/Ollama exposed endpoints, the OpenAI sandbox
escape) are Plane-3 failures: no amount of Plane-1 action-governance fixes a
request-forgery or an unauthenticated endpoint in the surface that fronts it.

Scope boundary: this covers OUR surface only. App-sec of a customer's model
platform (e.g. ChatGPT Agent Builder) is that vendor's responsibility; we do not
claim to secure it.

### 8. Request Forgery / Unauthenticated Invocation (AgentForger class)
**Threat:** An attacker forges a request to a governance or action endpoint, or
auto-executes an instruction via a crafted link/parameter, standing up or
driving an agent without genuine operator intent.
**Mitigations:**
- Approval / STEP_UP is governance-enforced and NOT agent- or request-configurable: an agent cannot set its own connectors to "never ask" or disable its approval requirement (the decisive AgentForger step).
- Agent registry: unregistered/forged agents are denied (`agent_not_registered`), so a stood-up rogue agent cannot act through the control plane.
- Scope-enforcer entry authenticates the caller and fails closed on unknown verdicts; approvals are cryptographically bound to the exact request (TOCTOU/replay defense) and single-use.
**Residual:** CSRF/authz of any web UI that fronts the API is the deploying
customer's responsibility; we document the requirement (authenticated,
CSRF-protected front door) rather than provide the UI.

### 9. Dependency / Supply-Chain Vulnerabilities
**Threat:** A CVE in a runtime dependency (cf. LiteLLM CVE-2024-6587,
CVE-2026-40217/35029) or a compromised package grants code execution.
**Mitigations:**
- `bandit` static scan in CI (high-severity gate).
- `pip-audit` dependency-CVE scan in CI (added with this section).
- `detect-secrets` scan in CI to block committed credentials.
- Flat, minimal Lambda dependency surface (boto3 + stdlib).

### 10. Secrets Handling
**Threat:** Credentials leaked via source, logs, or environment.
**Mitigations:**
- No secrets in source (enforced by `.gitignore` + `detect-secrets` CI scan).
- KMS asymmetric key for evidence signing: the private key never leaves KMS.
- Structured logging avoids emitting secret material; deploy logs (which carry
  request tokens) are gitignored.

### 11. AI-Accelerated Vulnerability Discovery (collapsing exploit window)
**Threat:** Frontier AI models find exploitable logic bugs, design flaws, and
misconfigurations in our own code faster than they can be patched, shrinking the
window between discovery and exploitation (cf. CrowdStrike Project QuiltWorks,
April 2026).
**Mitigations (in-repo, lightweight tier):**
- `bandit` (static), `pip-audit` (dependency CVEs), `detect-secrets` in CI.
- Minimal Lambda dependency surface.
**External tool class (consume, do not build):** enterprise frontier-model SAST
+ exploit-path prioritization services (e.g. Project QuiltWorks, and the broader
"frontier-AI vulnerability discovery" category) are the heavy tier for scanning
OUR surface. They are a service we would be a *customer* of, not a capability
this framework provides. Running one against this repo is the Plane-3 escalation
path beyond the CI scanners above.
**Compensating control (Plane 1):** when the exploit window collapses and a bug
is unpatched, runtime action governance still denies or escalates the malicious
*action* that tries to reach it. We do not discover the vulnerability; we govern
the action. This is a compensating control, not a substitute for remediation.

## Fail-Safe Guarantees

| Component Failure | Result | Rationale |
|-------------------|--------|-----------|
| DynamoDB unavailable | DENY ALL | Cannot verify agent identity or scope |
| Policy engine crash | DENY | `safe_evaluate_policy()` returns fail-safe deny |
| Risk scoring crash | Score 100, ESCALATE | `safe_compute_risk()` assumes worst case |
| Evidence write failure | Decision proceeds (deny/allow/escalate unaffected) | Evidence is audit, not authorization |
| Bedrock Guardrails timeout | Input passes to next layer | Defense-in-depth; other layers still check |
| Kill switch table read failure | DENY ALL | Fail-closed on kill switch check |

## Residual Risks (Accepted)

| Risk | Severity | Acceptance Rationale |
|------|----------|---------------------|
| Novel prompt injection bypassing all regex + AI classifier | Medium | Mitigated by behavioral invariants (hard limits) and output guardrails |
| DynamoDB eventually-consistent reads on scope table | Low | Scope changes propagate within milliseconds; risk window is negligible |
| `cloudwatch:PutMetricData` uses `Resource: "*"` | Low | Restricted to namespace `AGCP/Governance` via IAM condition; AWS limitation |
| Model-level hallucination affecting action selection | Medium | Governance validates the ACTION, not the model's reasoning; wrong action still gets governed |
| Latency overhead (1.2-2s per decision in Lambda mode) | Low | Step Functions mode reduces to ~200ms; acceptable for governed workloads |
