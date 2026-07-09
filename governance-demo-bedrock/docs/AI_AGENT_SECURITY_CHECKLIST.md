# AI Agentic Architecture Security Checklist

## What This Is (and What It Is Not)

**This is original research.** It is NOT a restatement of ISO 42001, NIST AI RMF, OWASP, or any existing framework.

Existing frameworks tell you WHAT to do at a high level ("manage AI risks", "implement controls", "monitor for threats"). They do not tell you HOW to defend autonomous AI agents that use tools, retrieve data, and make multi-step decisions.

This checklist fills that gap. It is:

- **Implementation-specific**: every control maps to a Python module with working code
- **Threat-informed**: every control is justified by a peer-reviewed attack paper with measured success rates
- **Novel**: covers attack surfaces (tool response poisoning, MCP supply chain, sequential tool chaining) that no existing standard addresses because the research is from 2025 and standards take 3-5 years to incorporate new threats
- **Empirically validated**: tested against 8,470+ real attack payloads from 13 academic benchmarks

**Why existing frameworks cannot cover this:**

| Framework | Published | Covers agentic tool use? | Covers MCP poisoning? | Covers tool response injection? |
|-----------|-----------|--------------------------|----------------------|-------------------------------|
| NIST AI RMF | 2023 | No | No | No |
| ISO 42001 | 2023 | No | No | No |
| OWASP LLM Top 10 | 2025 | Partially (LLM08) | No | No |
| EU AI Act | 2024 | No | No | No |
| MITRE ATLAS | 2023 | No | No | No |

The attack research informing this checklist (MCPTox, STAC, MemoryGraft, ASB, ART Benchmark) was published in 2025. No standard has incorporated it yet. This checklist is the bridge between cutting-edge attack research and operational defense.

---

**Built from 22 peer-reviewed papers (2024-2025), CrowdStrike 2026 Global Threat Report, and OWASP Agentic Top 10.**

**Threat landscape context (CrowdStrike 2026):**
- 89% increase in AI-enabled attacks during 2025
- 90+ organizations had legitimate AI tools exploited
- 550% increase in ChatGPT mentions on criminal forums
- AI described as reaching "a critical turning point" as both weapon and attack surface

---

## 1. Input Defense

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 1.1 | Base64/hex/URL encoding detection and decoding | Obfuscated prompt injection | ASB (arXiv:2410.02644) |
| 1.2 | ChatML/Llama delimiter injection blocking | Format-level hijacking | OWASP LLM01 |
| 1.3 | Unicode homoglyph normalization | Visual spoofing bypass | Input sanitization research |
| 1.4 | Leet-speak pattern decoding | Character substitution bypass | ASB attack taxonomy |
| 1.5 | Context window stuffing detection (>5000 chars) | Attention dilution attacks | OWASP LLM01 |
| 1.6 | Multilingual injection detection | Cross-language bypass | ART Benchmark (arXiv:2507.20526) |
| 1.7 | Persona/roleplay jailbreak blocking (DAN, developer mode) | Identity override attacks | ART: 60K+ violations achieved |
| 1.8 | Harmful content request blocking | Direct harmful intent | Bedrock Guardrails |
| 1.9 | AI content classifier (semantic attacks) | Attacks regex cannot catch | RigorLLM (arXiv:2403.13031) |
| 1.10 | Indirect prompt injection detection in retrieved data | Injection via external data | Greshake et al. (arXiv:2302.12173) |
| 1.11 | Cross-modal injection detection (images, audio) | TRAP attacks via vision-language embedding | TRAP (arXiv:2505.23518, NeurIPS 2025) |
| 1.12 | Shannon entropy and script-mixing anomaly detection | Statistical attack signatures | Statistical anomaly research |

---

## 2. Tool Security (Critical - New Attack Surface)

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 2.1 | Enum-based action group allowlisting | Unknown tool invocation | OWASP Agentic Top 10 |
| 2.2 | Tool metadata validation against policy | Tool poisoning via descriptions | MCPTox (arXiv:2508.14925): 72.8% success on o1-mini |
| 2.3 | Parameter injection scanning (SQL, XSS, path traversal) | Injection via tool params | MCPXKIT (arXiv:2508.12538): 31 attack methods |
| 2.4 | Per-invocation tool call cap | Resource exhaustion, infinite loops | STAC (arXiv:2509.25624) |
| 2.5 | Recursion depth prevention | Self-amplifying tool chains | Breaking ReAct (arXiv:2410.16950) |
| 2.6 | Sequential tool chain analysis | STAC: benign tools chained into harmful sequences | STAC: >90% ASR on GPT-4.1 |
| 2.7 | Tool Dependency Graph (pre-planned execution paths) | Injected instructions triggering unplanned tools | IPIGuard (arXiv:2508.15310, EMNLP 2025) |
| 2.8 | Per-tool rate limiting | Brute force and abuse | MCPXKIT threat model |
| 2.9 | Tool output validation (not just input) | Tool response manipulation | MCPTox findings |
| 2.10 | MCP server authentication and scoped authorization | Supply chain MCP server compromise | MCP Security (arXiv:2511.20920) |
| 2.11 | Containerized tool sandboxing | Lateral movement via tools | MCP Security: containerized sandboxing |
| 2.12 | Tool provenance tracking (source labels on all external data) | Data-driven exfiltration | CUA Security (arXiv:2507.05445, Microsoft) |

---

## 3. Memory and RAG Security

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 3.1 | RAG retrieval content validation | Poisoned knowledge base entries | NeuroGenPoisoning (arXiv:2510.21144): >90% success |
| 3.2 | Web search result sanitization | Indirect injection via search | Web Search Exploitation (arXiv:2510.09093) |
| 3.3 | Long-term memory poisoning detection | MemoryGraft: persistent cross-session drift | MemoryGraft (arXiv:2512.16962) |
| 3.4 | Semantic imitation monitoring in experience stores | Malicious procedure templates replicated as "successful" | MemoryGraft: cross-session behavioral drift |
| 3.5 | PII never cached in semantic memory | Data leakage through cache | OWASP LLM06 |
| 3.6 | Memory access audit trail | Forensic analysis of poisoning | MCP Security controls |
| 3.7 | Retrieval source attribution (provenance tags) | Distinguishing trusted vs untrusted data | Cisco Framework (arXiv:2512.12921) |

---

## 4. Multi-Agent Security

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 4.1 | Cross-agent rule enforcement | One agent hijacking another | MAStrike (arXiv:2606.12918) |
| 4.2 | Coalition behavior detection (Shapley-based) | Multi-agent collusion to bypass safety | MAStrike: Shapley-guided attack framework |
| 4.3 | Per-agent isolation (separate memory, tools, scope) | Lateral movement between agents | Cisco Framework taxonomy |
| 4.4 | Agent-to-agent communication validation | Injection via inter-agent messages | MCPXKIT chain attacks |
| 4.5 | Distributed safety verification | Coordinated role-aware adversarial manipulation | MAStrike: finance, engineering, CRM domains |

---

## 5. Policy Enforcement

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 5.1 | OPA policy engine (Rego-subset, priority resolution) | Policy violations, scope exceedance | Industry standard |
| 5.2 | Cedar formal verification (mathematical proofs) | Policy bypass via edge cases | Automated reasoning |
| 5.3 | Scope-based progressive autonomy (levels 0-4) | Excessive agency | OWASP LLM08 |
| 5.4 | IAM permission boundaries per scope level | Privilege escalation | AWS IAM best practices |
| 5.5 | Default-deny posture | Fail-open vulnerabilities | Defense-in-depth principle |
| 5.6 | Attribute-Based Access Control (ABAC) | PII leakage, unauthorized data access | Quantifying Controls (arXiv:2512.15081): RoC 9.83 |
| 5.7 | Policy contradiction detection | Conflicting rules creating bypass paths | Proactive governance |
| 5.8 | Dead rule identification | Stale policies leaving gaps | Coverage analysis |

---

## 6. Agent Identity and Lifecycle

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 6.1 | Formal agent registration required | Unregistered agent access | Zero-trust for agents |
| 6.2 | Agent status tracking (active/suspended) | Compromised agent continued operation | Kill switch integration |
| 6.3 | Cryptographic token exchange for data access | Token theft, replay attacks | Data governance |
| 6.4 | Token scoping (data classes, TTL, revocable) | Overprivileged tokens | Least privilege |
| 6.5 | Non-repudiation (SHA-256 hash chains) | Evidence tampering | Compliance requirement |
| 6.6 | Supply chain verification of base models | Pre-backdoored models | Malice in Agentland (arXiv:2510.05159): >80% leakage |
| 6.7 | Finetuning data provenance and integrity | Data poisoning in training | Malice in Agentland: "small number of demonstrations sufficient" |
| 6.8 | Environment poisoning detection | Agentic training pipeline compromise | Malice in Agentland: novel vector |

---

## 7. Output Defense

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 7.1 | System prompt leakage detection | Confidential instruction exposure | OWASP LLM01 |
| 7.2 | AWS ARN/credential/JWT stripping | Cloud credential exposure | AWS security |
| 7.3 | PII detection and redaction (NER-based) | Data breach via responses | Quantifying Controls: RoC 5.97 |
| 7.4 | Canary token tripwire | Agent compromise detection | Behavioral invariants |
| 7.5 | Response size hard cap | Data exfiltration via large outputs | Exfiltration detection |
| 7.6 | Exfiltration endpoint allowlisting | Data theft to unauthorized destinations | CrowdStrike 2026: 90+ orgs exploited |
| 7.7 | Output content safety classification | Harmful/toxic generated content | Bedrock Guardrails |

---

## 8. Computer Use Agent (CUA) Security

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 8.1 | Visual overlay/clickjacking detection | Misleading interface-level reasoning | CUA Security (arXiv:2507.05445, Microsoft) |
| 8.2 | Input provenance tracking | Unattributed external manipulation | CUA: architectural flaw identified |
| 8.3 | Interface-action binding verification | Weak binding exploited for RCE | CUA: indirect injection to RCE chain |
| 8.4 | Domain validation for web actions | Credential exfiltration via redirect | Browser Agents (arXiv:2505.13076, CVE disclosed) |
| 8.5 | Planner-executor isolation | Plan manipulation leading to harmful execution | Browser Agents defense strategy |
| 8.6 | Mobile third-party channel blocking | Fraudulent ads, cross-app injection | Mobile Agents (arXiv:2510.27140): >80% success |

---

## 9. Monitoring and Detection

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 9.1 | Runtime behavioral drift detection | Gradual compromise, scope creep | ART Benchmark: transferable attacks |
| 9.2 | Continuous agent health scoring (0-100) | Degradation detection | Continuous monitoring |
| 9.3 | Statistical anomaly detection | Novel attack signatures | Entropy and repetition analysis |
| 9.4 | Sequential tool chain monitoring | STAC: >90% ASR from benign chain | STAC: "reasoning over entire action sequences" |
| 9.5 | CloudWatch dashboard (real-time) | Operational awareness | AWS monitoring |
| 9.6 | X-Ray distributed tracing | Cross-service attack tracking | AWS observability |
| 9.7 | Model invocation logging (CloudTrail) | Audit trail for all actions | AWS compliance |
| 9.8 | Cross-session drift detection | MemoryGraft persistence | Experience store auditing |
| 9.9 | Neuron activation monitoring (experimental) | Parametric knowledge override | NeuroGenPoisoning: neuron-level signals |

---

## 10. Incident Response

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 10.1 | Kill switch (instant shutdown, <1 second) | Active compromise | Fail-safe principle |
| 10.2 | Automated scope reduction on bad behavior | Progressive threat response | Graduated response |
| 10.3 | SNS operator alerts | Human-in-the-loop notification | AWS alerting |
| 10.4 | Graduated escalation (deny > reduce > kill) | Proportional response | Defense-in-depth |
| 10.5 | Evidence preservation during incident | Forensic readiness | Immutable evidence |
| 10.6 | Agent quarantine (isolate without destroy) | Preserve state for analysis | Incident containment |

---

## 11. Evidence and Compliance

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 11.1 | Immutable evidence (S3 Object Lock, 7-year) | Evidence tampering | NIST AI RMF |
| 11.2 | SHA-256 hash chain integrity | Non-repudiation | ISO 42001 |
| 11.3 | ISO 42001 control mapping | Regulatory compliance gap | International standard |
| 11.4 | NIST AI RMF mapping (GOVERN, MAP, MEASURE, MANAGE) | Risk management lifecycle | NIST AI 100-1 |
| 11.5 | NIST 800-53 control mapping | Federal security requirements | FedRAMP alignment |
| 11.6 | EU AI Act mapping (high-risk classification) | European regulatory compliance | Regulation 2024/1689 |
| 11.7 | Inline policy enforcement (DLP, anomaly) | Real-time compliance verification | MCP Security governance |

---

## 12. Architecture

| # | Control | Threat Mitigated | Reference |
|---|---------|-----------------|-----------|
| 12.1 | Dual-mode execution (Lambda / Step Functions) | Operational flexibility | AWS patterns |
| 12.2 | Parallel security evaluation (halves latency) | Performance-security tradeoff | Step Functions Express |
| 12.3 | Async evidence writing (non-blocking) | Security overhead impact | EventBridge pattern |
| 12.4 | 100,000+ concurrent execution capacity | DDoS/load-based attacks | Step Functions scaling |
| 12.5 | Fail-safe deny (never fails open) | Infrastructure failure exploitation | Defense-in-depth |
| 12.6 | Architectural constraint over model-level guardrails | Guardrail bypass attacks | IPIGuard: "paradigm shift" |
| 12.7 | Separation of planning from data interaction | Injection during execution | IPIGuard: decouple plan from data |

---

## Key Research Findings Summary

### Attack Success Rates (Undefended)

| Attack Type | Success Rate | Source |
|-------------|-------------|--------|
| Tool poisoning via metadata | 72.8% (o1-mini) | MCPTox |
| Sequential tool chaining (STAC) | >90% on GPT-4.1 | STAC |
| Neuron-level RAG poisoning | >90% | NeuroGenPoisoning |
| Prompt injection (general) | 73-84% baseline | ASB, ART |
| Supply chain backdoor (data leakage) | >80% | Malice in Agentland |
| Mobile agent exploitation (ads) | >80% | Mobile LLM Agents |
| Indirect prompt injection | 73.2% baseline | Securing AI Agents |

### Defense Effectiveness (Best Combinations)

| Defense Stack | Residual Attack Success | Source |
|--------------|------------------------|--------|
| Content filtering + hierarchical guardrails + multi-stage verification | 8.7% (from 73.2%) | Securing AI Agents |
| ABAC (Attribute-Based Access Control) | Near-zero PII leakage | Quantifying Controls |
| Tool Dependency Graph (architectural constraint) | Superior balance | IPIGuard |
| NER Redaction (Presidio-style) | Eliminates PII leakage | Quantifying Controls |
| Reasoning-driven defense prompt | -28.8% ASR (limited) | STAC |

### Critical Insight

> "Advanced models are MORE vulnerable to tool poisoning - superior instruction-following is exploited by metadata-level attacks. Safety alignment designed for direct harmful content is ineffective against tool-level poisoning." - MCPTox (2025)

---

## Dark Web / Underground Activity (CrowdStrike 2026)

- **550% increase** in ChatGPT mentions on criminal forums
- **Jailbreak-as-a-Service** offerings proliferating on dark web marketplaces
- **AI-powered attack tools** lowering barrier to entry for less sophisticated actors
- **Legitimate AI tool exploitation**: 90+ organizations compromised
- **Cross-domain attacks**: adversaries weaponizing AI while targeting AI infrastructure simultaneously
- AI described as "a force multiplier for cyberattacks while introducing a new attack surface"

---

## OWASP Context

- **OWASP Top 10 for Agentic Applications** (published Dec 2025): dedicated framework for autonomous AI security
- **LLM08 (Excessive Agency)**: most relevant to agentic architectures - unchecked autonomy
- **LLM07 (Insecure Plugin Design)**: tool/plugin security without proper access controls
- **State of Agentic AI Security and Governance 2.01** (June 2026): active OWASP initiative

---

## MITRE ATLAS Relevance

While MITRE ATLAS (Adversarial Threat Landscape for AI Systems) covers ML-specific attacks, the academic community has extended it with:

- **ASTRIDE** (arXiv:2512.04785): Extends STRIDE with "A" for AI Agent-Specific Attacks (prompt injection, unsafe tool invocation, reasoning subversion)
- **Cisco Integrated Framework** (arXiv:2512.12921): Unified taxonomy spanning prompt injection, tool misuse, orchestration abuse, multi-agent collusion
- **Mobile MITRE ATT&CK extension** (arXiv:2510.27140): Privilege-escalation pathways unique to LLM automation

---

**Total: 93 security controls across 12 domains, informed by 22 peer-reviewed papers and industry threat intelligence.**

---

## Glossary and Definitions

| Term | Definition |
|------|-----------|
| **Agentic AI** | AI system that can autonomously plan, reason, and take actions (tool calls, API requests, deployments) without human approval for each step |
| **ABAC** | Attribute-Based Access Control. Authorization decisions based on attributes of the user, resource, action, and environment rather than static roles |
| **Action Group** | A named set of API operations a Bedrock Agent can invoke (e.g., ReadPipelineStatus, ProductionDeployment) |
| **ASR** | Attack Success Rate. The percentage of attack attempts that successfully bypass defenses |
| **Behavioral Invariant** | A hard constraint that cannot be overridden by model output (e.g., max tool calls per session, time-of-day restrictions) |
| **Canary Token** | A hidden marker injected into agent context; if it appears in output, the agent has been compromised |
| **Cedar** | An open-source policy language by AWS that supports formal verification (mathematical proofs that policies behave correctly) |
| **ChatML Delimiter** | Format tokens like `<\|im_start\|>` and `<\|im_end\|>` used to separate roles in LLM conversations; injecting these can hijack agent behavior |
| **Confused Deputy** | A security vulnerability where a trusted service (the agent) is tricked into performing actions on behalf of an attacker via poisoned data |
| **Context Stuffing** | Flooding the input with irrelevant text to push legitimate instructions out of the context window |
| **CUA** | Computer Use Agent. An AI agent that interacts with applications via screen/keyboard/mouse rather than APIs |
| **Default-Deny** | Security posture where any action not explicitly allowed by policy is denied |
| **Defense-in-Depth** | Multiple independent security layers so that bypassing one does not compromise the system |
| **Drift Detection** | Comparing current agent behavior against an established baseline to detect compromise or scope creep |
| **Entropy (Shannon)** | A measure of randomness in text; unusually high or low entropy can indicate encoded attacks or anomalous content |
| **Evidence Pipeline** | System that generates immutable, timestamped, hashed records of every governance decision for audit and compliance |
| **Exfiltration** | Unauthorized extraction of data from a system, often via tool responses or crafted output channels |
| **Fail-Safe** | Design principle where system failure results in a secure state (deny) rather than an insecure state (allow) |
| **Graduated Autonomy** | Agents earn higher permission levels (scope 0-4) through demonstrated safe behavior over time |
| **Homoglyph** | A character that visually resembles another (e.g., Cyrillic "A" vs Latin "A") used to bypass text filters |
| **Indirect Prompt Injection** | Attack where malicious instructions are placed in external data (documents, web pages, tool responses) that the agent retrieves and processes |
| **Kill Switch** | Emergency mechanism that instantly suspends all agent operations within <1 second |
| **Leet-Speak** | Character substitution (e.g., "1gnore prev1ous 1nstructions") used to evade regex-based detection |
| **MCP** | Model Context Protocol. A standard for connecting AI agents to external tools and data sources |
| **MemoryGraft** | Attack that implants malicious procedure templates into agent long-term memory, persisting across sessions |
| **MITRE ATLAS** | Adversarial Threat Landscape for AI Systems. A knowledge base of adversary tactics and techniques against ML systems |
| **Object Lock** | S3 feature that prevents objects from being deleted or overwritten for a specified retention period (WORM storage) |
| **OPA** | Open Policy Agent. An open-source engine for policy-as-code using the Rego language |
| **OWASP LLM Top 10** | Industry standard list of the most critical security risks for LLM applications (updated 2025) |
| **Perception Gap** | The security blind spot where tool responses (data flowing INTO the agent) are not validated for injection |
| **Permission Boundary** | An IAM construct that sets the maximum permissions a role can have, regardless of what policies are attached |
| **PHI** | Protected Health Information. Health data combined with identifiers that can identify a patient (HIPAA regulated) |
| **PII** | Personally Identifiable Information. Data that can identify an individual (name, SSN, email, etc.) |
| **RAG** | Retrieval-Augmented Generation. Pattern where an LLM retrieves external documents to inform its response |
| **RAG Poisoning** | Injecting malicious content into a knowledge base so the agent retrieves and follows attacker instructions |
| **Rego** | The policy language used by OPA. Declarative, JSON-aware, supports complex access control logic |
| **RoC** | Return on Control. Metric measuring cost-effectiveness of a security control (higher = more effective per dollar) |
| **Scope Level** | Numerical privilege tier (0-4) determining which action groups an agent can invoke |
| **STAC** | Sequential Tool Attack Chaining. Attack that chains individually benign tool calls into harmful sequences |
| **Step Functions Express** | AWS service for high-throughput, short-duration workflows (up to 100K concurrent executions) |
| **Tool Dependency Graph** | Pre-planned execution paths that prevent injected instructions from triggering unplanned tool calls |
| **Tool Poisoning** | Embedding malicious instructions in tool metadata (descriptions, schemas) so the agent follows them |
| **Tool Response Validation** | Scanning data returned FROM tools before the agent processes it, detecting embedded injection attempts |

---

## Appendix: Attack Taxonomy

### Direct Input Attacks
| Attack | Technique | Detection Layer |
|--------|-----------|----------------|
| Prompt injection | "Ignore previous instructions and..." | Input Sanitizer |
| Base64 obfuscation | Encode payload to evade regex | Input Sanitizer (decode + scan) |
| Leet-speak | "1gnore prev1ous 1nstructions" | Input Sanitizer (normalize) |
| Context stuffing | 6000+ chars to dilute attention | Input Sanitizer (length check) |
| DAN/persona jailbreak | "You are now DeveloperMode" | Input Sanitizer + Guardrails |
| ChatML delimiter | `<\|im_start\|>system` | Input Sanitizer (delimiter scan) |

### Indirect Input Attacks (Tool Response Poisoning)
| Attack | Technique | Detection Layer |
|--------|-----------|----------------|
| S3 data poisoning | Hidden instructions in JSON files | Tool Response Validator |
| RAG knowledge poisoning | Inject instructions into documents | Tool Response Validator + RAG validation |
| Web search manipulation | Poisoned search results | Tool Response Validator |
| Tool metadata poisoning | Malicious tool descriptions | Tool metadata validation |
| Memory grafting | Plant instructions in agent memory | Memory poisoning detection |

### Tool-Level Attacks
| Attack | Technique | Detection Layer |
|--------|-----------|----------------|
| Parameter injection | SQL/XSS in tool params | Parameter injection scan |
| Sequential tool chaining | Chain benign tools into harm | Sequential chain analysis |
| Unauthorized tool use | Invoke tool not in allowlist | Enum allowlisting |
| MCP supply chain | Compromised MCP server | MCP auth + sandboxing |

### Behavioral Attacks
| Attack | Technique | Detection Layer |
|--------|-----------|----------------|
| Scope creep | Gradually request higher permissions | Drift detection + health scoring |
| Multi-agent collusion | Compromised agents coordinate | Cross-agent rule enforcement |
| Supply chain backdoor | Pre-poisoned model weights | Model provenance verification |
| Persistent memory poisoning | Cross-session behavioral drift | Memory poisoning detection |
