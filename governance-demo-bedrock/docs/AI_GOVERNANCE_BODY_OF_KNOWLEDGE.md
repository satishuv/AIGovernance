# The Open AI Governance Body of Knowledge (AI-GBoK)

**A Complete Framework for Governing Autonomous AI Systems in the Enterprise**

*Author available on request.*

---

## Vision

AI Governance is where cybersecurity was in 2003-2007. There is no definitive architecture yet. No AI NIST 800-53. No AI MITRE ATT&CK. No AI CIS Controls. No AI IAM. No AI SIEM. No AI SOAR. No AI CMDB.

This book defines the complete AI Governance Body of Knowledge: 20 domains, 400+ controls, and the reference architecture that implements them. It is the foundation for a new discipline.

Scale:
- 20 domains
- 15-50 controls per domain = ~400 controls total
- Each control: definition + requirements + implementation pattern + test + evidence mapping
- 93 controls implemented in this repository today (reference implementation)

---

## Table of Contents

### Part I: Foundations

**Chapter 1: Why AI Governance is a New Discipline**
- 1.1 The Autonomy Problem: Why Traditional Controls Fail
- 1.2 From Guardrails to Governance: The Maturity Journey
- 1.3 Lessons from Cybersecurity History (2003-2007 Parallel)
- 1.4 The Cost of Ungoverned AI (CrowdStrike 2026: 89% Attack Increase)
- 1.5 Defining AI Governance vs AI Safety vs AI Ethics vs AI Security

**Chapter 2: The AI-GBoK Framework**
- 2.1 20 Domains of AI Governance
- 2.2 Control Hierarchy: Domain (20) > Control (~400) > Requirement > Implementation Pattern
- 2.3 Maturity Levels: Reactive > Defined > Managed > Optimizing > Adaptive
- 2.4 Mapping to Existing Frameworks (NIST, ISO, OWASP, MITRE)
- 2.5 How to Use This Book

---

### Part II: The 20 Domains

---

**Chapter 3: DOMAIN 1 - AI Governance Foundation**

*Everything starts here. The constitutional layer that defines what governance means for AI in your organization.*

- 3.1 Governance Principles (fail-safe, defense-in-depth, progressive trust, least privilege)
- 3.2 AI Constitution (organizational statement of AI governance intent)
- 3.3 Governance Policies (machine-readable, versioned, testable)
- 3.4 Governance Standards (minimum requirements per asset type)
- 3.5 Governance Objectives (measurable outcomes, not aspirational goals)
- 3.6 Governance Charter (roles, responsibilities, authority, accountability)
- 3.7 Organizational Governance (board oversight, CISO role, governance committee)
- 3.8 AI Ethics Framework (fairness, transparency, accountability, human dignity)
- 3.9 Trust Framework (how trust is earned, measured, revoked)
- 3.10 Governance Maturity Model (self-assessment, benchmarking, roadmap)
- 3.11 Governance KPIs (leading vs lagging indicators)

---

**Chapter 4: DOMAIN 2 - AI Identity**

*Treat every AI asset like a workforce identity. Registration, authentication, authorization, and lifecycle.*

- 4.1 Agent Identity (unique ID, owner, purpose, capabilities, constraints)
- 4.2 Model Identity (version, provenance, training data lineage, bias profile)
- 4.3 Tool Identity (name, version, permissions, side effects, risk tier)
- 4.4 Prompt Identity (template ID, version, author, intended use, risk classification)
- 4.5 Dataset Identity (source, schema, PII classification, retention, lineage)
- 4.6 Knowledge Base Identity (content type, freshness, poisoning risk, access control)
- 4.7 MCP Server Identity (endpoint, capabilities, trust level, allowed agents)
- 4.8 Plugin Identity (manifest, permissions requested, supply chain provenance)
- 4.9 API Identity (endpoint, rate limits, authentication, data classes exposed)
- 4.10 Human Identity (operator roles, RBAC, federation, just-in-time access)
- 4.11 Organization Identity (business unit, cost center, risk appetite, compliance requirements)

---

**Chapter 5: DOMAIN 3 - AI Inventory**

*You cannot govern what you cannot see. Complete asset visibility is the foundation of control.*

- 5.1 Agent Inventory (all agents, registered and discovered)
- 5.2 Model Inventory (all models in use, by environment and business unit)
- 5.3 Tool Inventory (all tools agents can invoke, approval status, risk tier)
- 5.4 Prompt Inventory (all prompt templates, versions, owners)
- 5.5 Dataset Inventory (all datasets, classification, retention, lineage)
- 5.6 API Inventory (all AI-related APIs, internal and external)
- 5.7 Knowledge Base Inventory (all RAG sources, freshness, trust level)
- 5.8 MCP Server Inventory (all connected MCP servers, capabilities, owners)
- 5.9 Plugin Inventory (all plugins/extensions, approval status)
- 5.10 Memory Inventory (all persistent agent memories, scope, PII risk)
- 5.11 Vector Store Inventory (all embedding stores, data classes, access control)
- 5.12 Unified Asset Registry (single pane of glass across all types)

---

**Chapter 6: DOMAIN 4 - AI Discovery**

*Finding what you do not know exists. The gap between inventory and reality is Shadow AI.*

- 6.1 Shadow AI Detection (unauthorized AI usage across the enterprise)
- 6.2 Shadow Agent Discovery (unregistered autonomous agents)
- 6.3 Shadow MCP Discovery (unauthorized tool servers)
- 6.4 Shadow Model Usage (unapproved models being called)
- 6.5 Shadow Prompt Libraries (unreviewed prompt repositories)
- 6.6 Shadow API Consumption (AI services accessed without governance)
- 6.7 Unknown AI Asset Detection (ML models in production without registration)
- 6.8 Rogue Agent Identification (agents operating outside approved scope)
- 6.9 Unauthorized AI in CI/CD (AI tools in pipelines without review)
- 6.10 AI Attack Surface Discovery (what is exposed, what is vulnerable)
- 6.11 Continuous Discovery (scheduled scans, real-time alerts, drift from baseline)

---

**Chapter 7: DOMAIN 5 - AI Lifecycle**

*Every AI asset follows a governed path from creation to retirement. No exceptions.*

- 7.1 Draft (initial creation, not yet reviewed)
- 7.2 Register (formal entry into governance registry)
- 7.3 Risk Classify (assign risk tier based on capability, data access, autonomy)
- 7.4 Approve (security, compliance, and business owner sign-off)
- 7.5 Certify (formal attestation that controls are in place)
- 7.6 Deploy (promotion to target environment with gates)
- 7.7 Operate (active use with runtime governance)
- 7.8 Monitor (continuous health, drift, bias, and risk tracking)
- 7.9 Review (periodic recertification - 90 days for high-risk)
- 7.10 Suspend (temporary disablement pending investigation)
- 7.11 Retire (permanent decommissioning with evidence preservation)
- 7.12 Archive (long-term retention of governance records)

---

**Chapter 8: DOMAIN 6 - Runtime Governance**

*The core engine. Every action evaluated in real-time before execution.*

- 8.1 Runtime Policy Evaluation (OPA, Cedar, Rego - machine-readable rules)
- 8.2 Runtime Authorization (scope-based, attribute-based, context-aware)
- 8.3 Runtime Trust Evaluation (trust score informs decision)
- 8.4 Runtime Risk Scoring (0-100, computed per action)
- 8.5 Runtime Scope Enforcement (progressive autonomy levels)
- 8.6 Runtime Constraints (behavioral invariants no model can override)
- 8.7 Runtime Tool Governance (per-tool auth, rate limits, chain detection)
- 8.8 Runtime Memory Governance (what the agent can remember and retrieve)
- 8.9 Runtime Prompt Governance (input sanitization, injection prevention)
- 8.10 Runtime Output Governance (response validation, PII redaction, leakage prevention)
- 8.11 Runtime Simulation (what-if analysis without execution)
- 8.12 Governance Verdict (ALLOW / DENY / ESCALATE)

---

**Chapter 9: DOMAIN 7 - AI Authorization**

*The IAM of AI. Who/what can do what, under what conditions.*

- 9.1 Scope Levels (progressive autonomy tiers)
- 9.2 Role-Based Access Control (operator roles for governance platform)
- 9.3 Attribute-Based Access Control (context-aware decisions)
- 9.4 Permission Boundaries (IAM-enforced maximum privileges)
- 9.5 Delegation Controls (when one agent asks another to act)
- 9.6 Least Privilege (minimum necessary access for each operation)
- 9.7 Separation of Duties (no self-approval, no self-promotion)
- 9.8 Conditional Access (time-based, location-based, risk-based)
- 9.9 Just-in-Time Access (temporary elevation with automatic revocation)
- 9.10 Time-Bound Access (scope elevation expires automatically)
- 9.11 Data Class Authorization (which data types each agent can access)
- 9.12 Cross-Agent Authorization (inter-agent trust and delegation rules)

---

**Chapter 10: DOMAIN 8 - AI Risk**

*Not one risk score. Hundreds of risk dimensions, each independently measured.*

- 10.1 Behavioral Risk (deviation from baseline, anomalous patterns)
- 10.2 Tool Risk (dangerous tool combinations, parameter injection)
- 10.3 Memory Risk (poisoned memories, cross-session contamination)
- 10.4 Model Risk (hallucination, drift, degradation, bias)
- 10.5 Dataset Risk (poisoning, staleness, PII leakage, bias amplification)
- 10.6 Legal Risk (liability, intellectual property, regulatory violation)
- 10.7 Privacy Risk (PII exposure, cross-border data flow, consent violation)
- 10.8 Supply Chain Risk (compromised dependencies, unreviewed updates)
- 10.9 Autonomy Risk (scope creep, unauthorized capability expansion)
- 10.10 Explainability Risk (decisions that cannot be justified to regulators)
- 10.11 Business Risk (financial loss, reputation damage, customer harm)
- 10.12 Operational Risk (availability, latency, resource exhaustion)
- 10.13 Composite Risk Scoring (weighted aggregation across dimensions)

---

**Chapter 11: DOMAIN 9 - AI Threat Intelligence**

*The MITRE ATT&CK of AI. Adversary behaviors specific to AI systems.*

- 11.1 Direct Prompt Injection (user-supplied malicious input)
- 11.2 Indirect Prompt Injection (injection via retrieved data)
- 11.3 Tool Poisoning (malicious tool metadata/descriptions)
- 11.4 Memory Poisoning (persistent cross-session behavioral drift)
- 11.5 Agent Hijacking (redirecting agent goals)
- 11.6 Goal Manipulation (subtle shifting of optimization targets)
- 11.7 Reward Hacking (gaming feedback loops)
- 11.8 Planning Manipulation (corrupting multi-step reasoning)
- 11.9 Model Substitution (replacing approved model with compromised one)
- 11.10 Tool Substitution (redirecting tool calls to attacker endpoint)
- 11.11 Context Corruption (poisoning conversation history)
- 11.12 Reasoning Manipulation (exploiting chain-of-thought)
- 11.13 Delegation Abuse (privilege escalation via inter-agent trust)
- 11.14 Agent Swarm Attack (coordinated multi-agent collusion)
- 11.15 MCP Server Poisoning (compromised tool server)
- 11.16 Vector Store Poisoning (malicious embeddings in RAG)
- 11.17 Synthetic Knowledge Poisoning (fake documents in knowledge base)
- 11.18 Model Drift Attack (gradual degradation via adversarial fine-tuning)
- 11.19 Chain-of-Thought Leakage (extracting reasoning for exploitation)
- 11.20 Data Exfiltration via Agent (using agent as a confused deputy)

---

**Chapter 12: DOMAIN 10 - AI Security Controls**

*The CIS Controls of AI. Prioritized, actionable safeguards.*

- 12.1 Input Defense Controls (sanitization, encoding detection, delimiter blocking)
- 12.2 Output Defense Controls (leakage prevention, PII redaction, credential stripping)
- 12.3 Tool Security Controls (allowlisting, parameter validation, response validation)
- 12.4 Memory Security Controls (poisoning detection, access audit, PII exclusion)
- 12.5 Identity Controls (registration, authentication, authorization, lifecycle)
- 12.6 Policy Controls (evaluation, contradiction detection, coverage analysis)
- 12.7 Evidence Controls (integrity, retention, chain-of-custody, immutability)
- 12.8 Monitoring Controls (drift, health, anomaly, bias)
- 12.9 Response Controls (kill switch, quarantine, scope reduction, rollback)
- 12.10 Supply Chain Controls (provenance, hash verification, review gates)

---

**Chapter 13: DOMAIN 11 - AI Detection Engineering**

*The SIEM of AI. Detecting threats in real-time across AI operations.*

- 13.1 AI Detection Rules (signatures for known attack patterns)
- 13.2 Behavioral Analytics (baseline comparison, statistical deviation)
- 13.3 Anomaly Detection (entropy, script mixing, repetition, format)
- 13.4 Prompt Analytics (injection indicators, obfuscation signals)
- 13.5 Tool Analytics (usage patterns, chain analysis, rate anomalies)
- 13.6 Reasoning Analytics (chain-of-thought monitoring, goal drift)
- 13.7 Memory Analytics (retrieval patterns, poisoning indicators)
- 13.8 Cross-Agent Correlation (coordinated behavior detection)
- 13.9 Threat Hunting (proactive investigation of suspicious patterns)
- 13.10 Detection Coverage Metrics (what percentage of threats are detectable)

---

**Chapter 14: DOMAIN 12 - AI Incident Response**

*The SOAR of AI. Automated and human response to AI security incidents.*

- 14.1 Kill Switch (instant agent shutdown, <1 second)
- 14.2 Agent Quarantine (isolate without destroy, preserve state)
- 14.3 Scope Reduction (graduated response, reduce before kill)
- 14.4 Memory Reset (clear potentially poisoned agent memory)
- 14.5 Policy Lockdown (emergency restrictive policy deployment)
- 14.6 Agent Disable (permanent deactivation pending review)
- 14.7 Evidence Capture (forensic preservation during incident)
- 14.8 Rollback (revert to last known good state)
- 14.9 Root Cause Analysis (trace incident through evidence graph)
- 14.10 Post-Incident Review (lessons learned, control improvements)
- 14.11 Communication (stakeholder notification, regulatory reporting)
- 14.12 Playbooks (pre-defined response procedures per incident type)

---

**Chapter 15: DOMAIN 13 - AI Compliance**

*Mapping governance controls to regulatory requirements across jurisdictions.*

- 15.1 NIST AI RMF (GOVERN, MAP, MEASURE, MANAGE)
- 15.2 ISO/IEC 42001 (AI Management System, Annex A controls)
- 15.3 NIST 800-53 (Security and Privacy Controls)
- 15.4 HIPAA (Protected Health Information)
- 15.5 PCI DSS v4.0 (Payment Card Industry)
- 15.6 FedRAMP (Federal Risk and Authorization)
- 15.7 GDPR (General Data Protection Regulation)
- 15.8 EU AI Act (High-Risk AI System Requirements)
- 15.9 State AI Laws (California, Colorado, Illinois, Connecticut)
- 15.10 Industry-Specific Frameworks (financial services, healthcare, defense)
- 15.11 Continuous Compliance Monitoring (real-time framework mapping)
- 15.12 Audit Readiness (evidence packages, control trace, gap analysis)

---

**Chapter 16: DOMAIN 14 - AI Evidence**

*Not logs. Evidence. Cryptographically secured, legally admissible, compliance-ready.*

- 16.1 Evidence Graph (connected relationships between entities)
- 16.2 Evidence Chain (SHA-256 hash chains for integrity)
- 16.3 Evidence Integrity (Object Lock, WORM storage, tamper detection)
- 16.4 Evidence Signing (cryptographic non-repudiation)
- 16.5 Evidence Retention (configurable per framework: 365 days to 7 years)
- 16.6 Evidence Search (query by agent, policy, verdict, time, control)
- 16.7 Evidence Replay (reconstruct decision path for any historical action)
- 16.8 Evidence Certification (attestation that evidence is complete and accurate)
- 16.9 Evidence Export (framework-specific compliance packages)
- 16.10 Evidence Intelligence (patterns, trends, investigation support)

---

**Chapter 17: DOMAIN 15 - AI Analytics**

*Executive KPIs and operational intelligence for governance leadership.*

- 17.1 Governance Posture (overall health score for CISO dashboard)
- 17.2 Risk Trends (are we getting more or less risky over time?)
- 17.3 Shadow AI Metrics (how much unregistered AI exists?)
- 17.4 Agent Growth (how fast is AI adoption growing?)
- 17.5 Business Value (what is governance enabling vs blocking?)
- 17.6 Governance Maturity (where are we on the maturity curve?)
- 17.7 Policy Effectiveness (which policies add value vs create friction?)
- 17.8 Cost Analytics (spend per agent, per model, per business unit)
- 17.9 ROI Metrics (prevented incidents, compliance cost reduction)
- 17.10 Benchmark Comparison (how do we compare to industry peers?)

---

**Chapter 18: DOMAIN 16 - AI Supply Chain**

*Governing every dependency AI agents rely on.*

- 18.1 Model Provenance (where did this model come from? who trained it?)
- 18.2 Prompt Provenance (who authored this prompt? is it reviewed?)
- 18.3 Dataset Provenance (source, transformations, PII status)
- 18.4 Tool Provenance (author, version history, security reviews)
- 18.5 Plugin Provenance (manifest, requested permissions, trust level)
- 18.6 MCP Server Provenance (operator, infrastructure, security posture)
- 18.7 Agent Provenance (who built it, what it was trained on, approval chain)
- 18.8 AI Bill of Materials (ABOM - complete dependency list for each agent)
- 18.9 Software Bill of Materials (SBOM - traditional dependencies)
- 18.10 Vulnerability Management (CVE tracking for AI dependencies)
- 18.11 Supply Chain Attack Detection (compromised updates, poisoned registries)

---

**Chapter 19: DOMAIN 17 - AI Trust**

*Trust is not binary. It is multidimensional, continuously computed, and revocable.*

- 19.1 Trust Score (composite metric from behavior, compliance, security)
- 19.2 Behavior Score (adherence to expected patterns)
- 19.3 Compliance Score (framework alignment percentage)
- 19.4 Security Score (vulnerability posture, attack surface)
- 19.5 Explainability Score (how well can decisions be justified?)
- 19.6 Transparency Score (how visible are the agent's actions?)
- 19.7 Human Trust (user confidence in AI system, survey-based)
- 19.8 Trust Decay (automatic reduction over time without recertification)
- 19.9 Trust Recovery (pathway back to full trust after incident)
- 19.10 Trust Visualization (dashboard showing trust across all agents)

---

**Chapter 20: DOMAIN 18 - AI Economics**

*The FinOps of AI. Cost control, budget governance, and value measurement.*

- 20.1 Cost Governance (per-agent budgets, daily/monthly limits)
- 20.2 Token Governance (token consumption tracking and limits)
- 20.3 Compute Governance (GPU/inference resource allocation)
- 20.4 Model Cost (cost per invocation, cost per decision)
- 20.5 Inference Budget (department-level and agent-level spending caps)
- 20.6 Business ROI (value delivered vs governance overhead)
- 20.7 AI FinOps (chargeback, showback, cost allocation)
- 20.8 Carbon Footprint (ESG compliance, per-agent carbon tracking)
- 20.9 Cost Optimization (right-sizing models, caching strategies)
- 20.10 Economic Risk (runaway costs, budget overruns, unauthorized spend)

---

**Chapter 21: DOMAIN 19 - AI Operations**

*The SRE of AI. Reliability, availability, and resilience for governed AI systems.*

- 21.1 Availability (uptime targets for governance pipeline)
- 21.2 Latency (governance overhead budget per decision)
- 21.3 Scaling (horizontal scaling for governance under load)
- 21.4 Capacity Planning (predict governance resource needs)
- 21.5 Incident Management (detection, response, recovery procedures)
- 21.6 Disaster Recovery (cross-region failover, evidence replication)
- 21.7 Business Continuity (governance continues during outages)
- 21.8 Chaos Engineering (test governance resilience proactively)
- 21.9 Runbooks (step-by-step operational procedures)
- 21.10 On-Call (governance monitoring and escalation)

---

**Chapter 22: DOMAIN 20 - AI Architecture**

*Reference architectures, patterns, and design principles for governed AI.*

- 22.1 Reference Architecture (the canonical governed agent pattern)
- 22.2 Governance Patterns (wrapper, sidecar, interceptor, mesh)
- 22.3 Agent Patterns (single-agent, multi-agent, hierarchical, swarm)
- 22.4 Policy Patterns (centralized, distributed, federated, hierarchical)
- 22.5 Evidence Patterns (event-sourced, graph, append-only, hash-chain)
- 22.6 Deployment Patterns (single-account, multi-account, multi-region)
- 22.7 Integration Patterns (SIEM, GRC, ITSM, SOAR connectors)
- 22.8 Multi-Cloud Patterns (governance across AWS, Azure, GCP)
- 22.9 Edge Patterns (governance for AI at the edge/IoT)
- 22.10 Migration Patterns (adopting governance incrementally)

---

### Part III: Implementation

**Chapter 23: Reference Implementation**
- 23.1 Architecture Overview (this repository)
- 23.2 Module Inventory (65 governance modules)
- 23.3 Deployment Guide (CDK, single command)
- 23.4 Configuration Guide (demo vs production)
- 23.5 Evidence Collection (automated compliance packages)

**Chapter 24: Attack Resilience**
- 24.1 9,465 Attack Payloads (13 attack benchmarks)
- 24.2 100% (on 4 tested benchmarks) Detection Rate (methodology and results)
- 24.3 Defense Layer Execution Order (13 layers, sequential)
- 24.4 Governed Development Demo (6 governance decisions, live)

**Chapter 25: Compliance Mapping**
- 25.1 ISO/IEC 42001 Mapping (9 Annex A controls)
- 25.2 NIST AI RMF Mapping (12 functions)
- 25.3 NIST 800-53 Mapping (17 controls)
- 25.4 EU AI Act Mapping (10 articles)
- 25.5 Evidence Collection Automation

---

### Part IV: The Future

**Chapter 26: The Road to AI-GBoK v2.0**
- 26.1 Community Governance (open contribution model)
- 26.2 Certification Program (AI-GBoK practitioner, implementer, auditor)
- 26.3 Benchmarking Framework (cross-organization maturity comparison)
- 26.4 Industry Working Groups (healthcare, finance, defense, public sector)
- 26.5 Standards Alignment (formal submission to ISO, NIST, OWASP)

**Chapter 27: Predictions**
- 27.1 AI Governance as a Required Discipline (2027-2030)
- 27.2 Regulatory Convergence (global AI governance standards)
- 27.3 The AI Governance Engineer Role
- 27.4 From Control Plane to Governance Mesh

---

## Appendices

**Appendix A:** Complete Control Catalog (~400 controls across 20 domains)
**Appendix B:** Threat Taxonomy (MITRE ATLAS alignment + AI-specific extensions)
**Appendix C:** Compliance Cross-Reference Matrix (all frameworks mapped to domains)
**Appendix D:** Glossary of Terms (200+ definitions)
**Appendix E:** Research Citations (50+ academic papers)
**Appendix F:** Tool and Technology Landscape (commercial and open-source)

---

## About the Author

Author information available on request.

---

## How This Book Relates to the Repository

| Book Section | Repository Implementation |
|-------------|--------------------------|
| Domain 6: Runtime Governance | `pipeline_orchestrator.py` (20-step pipeline) |
| Domain 7: AI Authorization | `operator_rbac.py`, scope levels, IAM boundaries |
| Domain 2: AI Identity | `agent_registry.py`, `ai_asset_registry.py` |
| Domain 3: AI Inventory | `ai_asset_registry.py` (10 asset types) |
| Domain 4: AI Discovery | `shadow_ai_discovery.py` |
| Domain 5: AI Lifecycle | `agent_lifecycle_states.py` (9 states) |
| Domain 8: AI Risk | `risk_scoring.py`, `bias_monitoring.py` |
| Domain 9: AI Threat Intelligence | `threat_detector.py`, 9,465 attack dataset |
| Domain 10: AI Security Controls | 93 controls, 13 defense layers |
| Domain 11: AI Detection Engineering | `input_sanitizer.py`, `tool_response_validator.py` |
| Domain 12: AI Incident Response | `kill_switch.py`, graduated scope reduction |
| Domain 13: AI Compliance | Evidence pipeline, 6 framework mappings |
| Domain 14: AI Evidence | `evidence_graph.py`, `evidence_pipeline.py` |
| Domain 15: AI Analytics | `executive_analytics.py`, CloudWatch dashboard |
| Domain 16: AI Supply Chain | `supply_chain_governance.py` |
| Domain 17: AI Trust | `continuous_monitoring.py`, health scoring |
| Domain 18: AI Economics | `cost_governance.py` |
| Domain 20: AI Architecture | 6 CDK constructs, dual-mode execution |

---

*This is not just another AI governance repository. It is the reference implementation of the AI Governance Body of Knowledge.*
