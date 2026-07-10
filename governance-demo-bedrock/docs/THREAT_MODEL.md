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
