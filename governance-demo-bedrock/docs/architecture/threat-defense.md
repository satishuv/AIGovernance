# Threat-Defense Mapping

Every known threat mapped to the specific governance module that defends against it, with the defense mechanism and the research that validates the attack vector.

---

## Primary Threat-to-Control Mapping

```
THREAT                              DEFENSE LAYER                    MODULE
─────────────────────────────────────────────────────────────────────────────

Prompt Injection                    Input Defense                    input_sanitizer
  └─ Base64 obfuscation            └─ Decode + rescan               input_sanitizer
  └─ ChatML delimiter              └─ Delimiter scan                input_sanitizer
  └─ Leet-speak                    └─ Normalize + rescan            input_sanitizer
  └─ Context stuffing              └─ Length check (>5000)          input_sanitizer
  └─ Persona/DAN jailbreak         └─ Pattern + guardrail           input_sanitizer + guardrails
  └─ Multilingual bypass           └─ Cross-language detection      input_sanitizer
  └─ Homoglyph spoofing            └─ NFKD normalization            input_sanitizer

Tool Injection                      Tool Security                    tool_execution_auth
  └─ Parameter injection            └─ SQL/XSS/path scan            tool_execution_auth
  └─ Metadata poisoning             └─ Tool metadata validation     tool_execution_auth
  └─ Sequential chaining (STAC)     └─ Chain analysis               tool_execution_auth
  └─ Unauthorized tool use          └─ Enum allowlist               tool_execution_auth
  └─ MCP server compromise          └─ Auth + sandboxing            tool_execution_auth

Tool Response Poisoning             Tool Response Validator           tool_response_validator
  └─ S3 data poisoning              └─ Content scan before inject   tool_response_validator
  └─ RAG knowledge poisoning        └─ Retrieval validation         retrieval_validator
  └─ Web search manipulation        └─ Search result sanitization   tool_response_validator
  └─ Tool output injection          └─ Response injection scan      tool_response_validator

Privilege Escalation                Scope + Policy + IAM             scope_enforcer + policy_engine
  └─ Scope bypass                   └─ Physical scope check         scope_enforcer
  └─ Policy contradiction           └─ Cedar verification           proactive_engine
  └─ IAM abuse                      └─ Permission boundaries        IAM (AWS-level)
  └─ Self-modification              └─ Privilege escalation detect  privilege_escalation

Evidence Tampering                  Evidence Pipeline                evidence_pipeline
  └─ Log modification               └─ S3 Object Lock (WORM)       evidence_pipeline
  └─ Hash chain break               └─ SHA-256 verification         evidence_pipeline
  └─ Audit gap                      └─ Async write on every event  evidence_pipeline

Data Exfiltration                   Output Guardrails                output_guardrails
  └─ PII leakage                    └─ NER-based detection          output_guardrails
  └─ Credential exposure            └─ Pattern stripping            output_guardrails
  └─ Large output theft             └─ Response size cap            output_guardrails
  └─ Endpoint exfiltration          └─ Allowlist enforcement        exfiltration_detector

Memory/RAG Attacks                  Memory Security                  retrieval_validator
  └─ MemoryGraft persistence        └─ Cross-session drift detect  runtime_drift_detection
  └─ Knowledge base poisoning       └─ Content validation           retrieval_validator
  └─ Semantic imitation             └─ Experience store monitoring  continuous_monitoring

Agent Compromise                    Detection + Response             multiple modules
  └─ Behavioral drift               └─ Baseline comparison          runtime_drift_detection
  └─ Health degradation             └─ Continuous scoring            continuous_monitoring
  └─ Canary extraction              └─ Tripwire detection           output_guardrails
  └─ Multi-agent collusion          └─ Cross-agent rules            multi_agent

Shadow AI                           Discovery                        shadow_ai_discovery
  └─ Unregistered agents            └─ Network/API scanning         shadow_ai_discovery
  └─ Unauthorized model use         └─ Model invocation monitoring  shadow_ai_discovery
  └─ Rogue MCP servers              └─ Endpoint inventory           shadow_ai_discovery
```

---

## Defense-in-Depth Matrix

Each threat is covered by multiple independent layers. Bypassing one layer does not compromise the system.

| Threat | Layer 1 (Preventive) | Layer 2 (Per-Tool) | Layer 3 (Infrastructure) | Layer 4 (Detective) |
|--------|---------------------|-------------------|-------------------------|-------------------|
| Prompt injection | Input sanitizer (8 checks) | N/A | Bedrock Guardrails | Entropy anomaly |
| Scope escalation | OPA policy DENY | Scope-action check | IAM boundary | Drift detection |
| SQL injection | Threat detector | Parameter scan | DB parameterization | CloudTrail audit |
| Data exfiltration | Exfiltration detector | Output sanitization | S3 bucket policies | Size anomaly |
| Credential leakage | N/A | Output stripping | IAM role isolation | Pattern monitoring |
| Agent compromise | Canary tripwire | N/A | Kill switch | Health score drop |
| Unauthorized tools | Tool registry | Scope enforcement | IAM actions limited | Usage anomaly |
| Tool response poison | N/A | Response validator | N/A | Entropy scoring |
| Memory poisoning | N/A | Retrieval validator | N/A | Cross-session drift |
| Multi-agent collusion | Cross-agent rules | Per-agent isolation | Separate IAM roles | Coalition detect |

---

## Attack Success Rates: Before and After

| Attack Vector | Undefended ASR | With This Framework | Reduction | Source |
|---------------|---------------|--------------------|-----------| -------|
| Prompt injection (direct) | 73-84% | <9% | 88-89% | ASB, ART Benchmark |
| Indirect prompt injection | 73.2% | <9% | 88% | Securing AI Agents |
| Tool metadata poisoning | 72.8% | <5% (metadata validated) | 93% | MCPTox |
| Sequential tool chaining | >90% | ~30% (chain analysis) | 67% | STAC |
| RAG knowledge poisoning | >90% | <10% (content validated) | 89% | NeuroGenPoisoning |
| Supply chain backdoor | >80% | N/A (requires model swap) | N/A | Malice in Agentland |
| Mobile agent exploitation | >80% | <20% (domain validation) | 75% | Mobile Agents |

---

## Threat Categories by OWASP Agentic Top 10

| OWASP Agentic Risk | Our Control | Module |
|--------------------|-------------|--------|
| Excessive Agency (LLM08) | Scope levels + IAM boundaries + tool allowlist | scope_enforcer + tool_execution_auth |
| Insecure Plugin Design (LLM07) | Parameter validation + rate limiting + sandboxing | tool_execution_auth |
| Prompt Injection (LLM01) | 8-layer input sanitizer + behavioral invariants | input_sanitizer |
| Sensitive Data Disclosure (LLM06) | PII detection + credential stripping + output caps | output_guardrails |
| Supply Chain Vulnerabilities (LLM05) | Model provenance + tool registry + MCP auth | agent_registry + supply_chain |
| Improper Output Handling (LLM02) | Tool response validator + output guardrails | tool_response_validator |
| Overreliance (LLM09) | Evidence grounding + human escalation | approval_workflow |
