# Building Trustworthy Agentic AI: A Governance Framework for Public Sector and Regulated Organizations

**Publication type:** AWS Whitepaper / Compliance Guide

**Authors:**
- Paul Keastead, Assurance Consultant, [Affiliation]
- Author (CISA, CISM, PCI QSA, ISO 27001 LA), Associate Assurance Consultant, [Affiliation]

---

## Abstract

Agentic AI systems can reason, plan, and act with varying degrees of autonomy. For public sector and regulated organizations, this creates governance challenges that traditional AI control models do not address. This whitepaper introduces a scope-based classification model for agent autonomy, defines six security dimensions for governance, and provides a phased implementation approach. It is intended for security leaders, compliance officers, and architects responsible for deploying AI systems in environments where accountability, auditability, and regulatory alignment are required.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Understanding Agentic AI](#understanding-agentic-ai-from-assistants-to-autonomous-systems)
3. [Why Traditional Governance Breaks Down](#why-traditional-governance-breaks-down-for-agentic-ai)
4. [A Scope-Based Approach to Agentic AI Security](#a-scope-based-approach-to-agentic-ai-security)
5. [Dynamic Scope Elevation and De-Escalation](#dynamic-scope-elevation-and-de-escalation)
6. [Six Security Dimensions for Governance](#six-security-dimensions-for-agentic-ai-governance)
7. [Auditing Agentic AI Systems](#auditing-agentic-ai-systems-across-the-six-security-dimensions)
8. [Aligning with ISO/IEC 42001](#aligning-agentic-ai-governance-with-isoiec-42001)
9. [Phased Implementation](#a-phased-approach-to-implementation)
10. [Operationalizing Governance](#how-organizations-should-operationalize-agentic-ai-governance)
11. [Incident Response](#incident-response-for-agentic-ai-systems)
12. [Considerations for Regulated Environments](#practical-considerations-for-regulated-environments)
13. [Conclusion and Next Steps](#conclusion-and-next-steps)

---

## Introduction

Public sector organizations face a growing challenge as they adopt agentic AI systems: how to gain the benefits of increased autonomy while meeting security, compliance, and accountability requirements.

Traditional AI systems respond to prompts or run narrowly defined tasks. Agentic AI systems go further. They understand context, make decisions, plan multi-step workflows, and take autonomous actions. These capabilities introduce governance and risk considerations that existing AI control models do not fully address.

As agentic AI systems gain the ability to act across systems, data, and services, the consequences of design gaps, misconfiguration, or unintended behavior grow. For organizations in regulated environments, governance, auditability, and operational control become foundational requirements, not optional enhancements.

This whitepaper outlines a practical governance framework for agentic AI systems, with a focus on public sector and other highly regulated environments. It introduces:

- A scope-based model for classifying agent autonomy and authority
- Six security dimensions that support trustworthy agentic AI systems
- Guidance on aligning agentic AI governance with existing compliance and audit programs

---

## Understanding Agentic AI: From Assistants to Autonomous Systems

Agentic AI systems represent an evolution from reactive assistants to systems capable of reasoning, planning, and acting with varying levels of independence. These systems select tools dynamically, maintain memory across interactions, and adapt behavior based on changing conditions. In advanced implementations, agents collaborate to accomplish complex objectives.

Two characteristics matter most for governance:

- **Autonomy:** The degree to which the system makes decisions without human intervention.
- **Agency:** The scope of actions the system is authorized to take within its environment.

Understanding where an AI system falls along these dimensions is a prerequisite for applying appropriate controls. Treating all AI systems as equivalent leads to one of two outcomes: over-constraining low-risk use cases or under-governing highly autonomous systems.

---

## Why Traditional Governance Breaks Down for Agentic AI

Traditional AI governance models target systems that operate at human decision speed, where actions are discrete, reviewable, and directly attributable to a person or process. These models assume that organizations can manage risk through periodic reviews, static approvals, and policy-based controls enforced outside the system.

Agentic AI systems break these assumptions.

Agentic systems reason across steps, select tools dynamically, maintain persistent state, and act at machine speed. Risk no longer stays confined to a single inference or output. It emerges from sequences of decisions, interactions between agents and tools, and accumulated context over time.

In this environment, governance failures do not occur because policies are missing. They occur because controls are not technically enforced at the point of action. Observed failure patterns include:

- **Authority escalation through tool chaining:** Agents combine permitted actions to achieve outcomes beyond their intended scope.
- **Privilege amplification through delegated identities:** Agents inherit or accumulate permissions that exceed their authorization.
- **State-influenced decision drift:** Memory or context from prior interactions shapes subsequent decisions in unintended ways.
- **Silent autonomy escalation:** Agents gradually operate at higher scope levels without formal approval or detection.

Documentation and human review alone cannot mitigate these risks. Organizations must embed governance into system architecture through enforceable boundaries, continuous monitoring, and auditable evidence of behavior. Without this shift, organizations deploy systems that appear compliant on paper but operate outside acceptable risk thresholds in practice.

---

## A Scope-Based Approach to Agentic AI Security

Not all agentic AI systems require the same level of governance. Applying a single control model across all implementations leads to unnecessary friction or unaddressed risk. A scope-based classification approach helps organizations match governance controls to actual system capability and impact.

**Figure 1: Agentic AI Autonomy Scopes and Human Oversight**

> *[DIAGRAM SUGGESTION: A horizontal progression showing Scope 1 through Scope 4 as distinct lanes. Each lane shows the agent's capability expanding (wider lane) while human oversight decreases (thinner oversight bar above). Use color coding: green (Scope 1) → yellow (Scope 2) → orange (Scope 3) → red (Scope 4). Include icons for key characteristics in each scope. Add a "governance intensity" arrow increasing left to right along the bottom.]*

This framework defines four scope levels based on the degree of agency and autonomy.

### Scope 1: No Agency

Scope 1 systems operate in read-only or advisory mode. They are human-initiated, follow fixed paths, and cannot modify systems or data.

These systems analyze information, summarize content, or provide recommendations. Governance is still required, but risk is limited because the system cannot take direct action.

**Examples:** Document summarization, compliance gap analysis, log review assistants.

### Scope 2: Prescribed Agency

Scope 2 systems propose or prepare changes but require explicit human approval before taking action. They access tools and systems, but a human authorizes each consequential action.

**Examples:** Systems that draft policy updates, generate configuration recommendations, or prepare remediation steps for human review.

### Scope 3: Supervised Agency

Scope 3 systems run end-to-end workflows after human initiation. They select tools dynamically and complete tasks autonomously within predefined boundaries. Human oversight remains available through monitoring, intervention points, or escalation paths.

**Examples:** Automated security event response systems that handle defined incidents while escalating higher-risk situations for review.

### Scope 4: Full Agency

Scope 4 systems operate with continuous autonomy and initiate actions without direct human prompting. They adapt behavior over time and operate independently for extended periods. Humans provide strategic oversight rather than task-level control.

This scope requires the most rigorous governance and is appropriate only where organizations have mature controls, monitoring, and assurance mechanisms in place.

**Examples:** Autonomous infrastructure optimization, continuous compliance monitoring with auto-remediation.

---

## Dynamic Scope Elevation and De-Escalation

**Figure 2: Dynamic Scope Elevation and De-Escalation for Agentic AI Systems**

> *[DIAGRAM SUGGESTION: A vertical state diagram with Scope 1 at the bottom and Scope 4 at the top. Upward arrows (green, labeled "Elevation") show requirements: "Evidence of control effectiveness", "Formal approval", "Additional controls validated". Downward arrows (red, labeled "De-escalation") show triggers: "Anomalous behavior detected", "Boundary violation", "Control failure", "Security incident". Include a side panel showing "Continuous Reassessment Loop" with monitoring feeding back into scope decisions.]*

In practice, the scope of an agentic AI system is not static. As systems evolve, they gain access to new tools, data sources, or workflows that materially change their effective level of autonomy. Treating scope as a one-time classification decision creates blind spots that undermine governance over time.

Organizations should treat scope as a dynamic property that is continuously enforced and reassessed.

**Scope elevation** (moving from prescribed agency to supervised or full agency) should require:

- Explicit approval supported by evidence that additional controls are in place and functioning
- Triggers such as expanded tool access, reduced human oversight, or deployment into higher-impact environments

**Scope de-escalation** should occur automatically when risk conditions change:

- Anomalous behavior, boundary violations, control failures, or security incidents should result in immediate restriction of agent capabilities
- Human review must be completed before autonomy is restored

This approach ensures that autonomy is earned and retained based on demonstrated control effectiveness, not assumed indefinitely.

---

## Six Security Dimensions for Agentic AI Governance

**Figure 3: Six Security Dimensions for Agentic AI Governance**

> *[DIAGRAM SUGGESTION: A hexagonal diagram with six nodes, one for each dimension. Place "Agentic AI System" in the center. Connect each dimension to the center and to its adjacent dimensions to show interdependency. Use consistent iconography: shield (Identity), lock (Data/Memory/State), clipboard (Audit), guardrail (Agent Controls), fence (Boundaries), gears (Orchestration). Add a note: "Governance effectiveness depends on consistent enforcement across all six dimensions."]*

Regardless of scope, governance of agentic AI systems requires controls across six security dimensions. These are not new security concepts, but agentic systems combine them in ways that amplify the impact of gaps or misconfiguration.

### 1. Identity Context

Agentic systems must operate under clearly defined identities with explicit authorization boundaries. This includes the ability to act on behalf of users or services while maintaining traceability and accountability. Strong identity controls enable auditability and prevent unintended privilege escalation.

Every agent action must be attributable to a defined human or organizational authority responsible for approving the agent's scope, permissions, and operating context.

### 2. Data, Memory, and State Protection

Agentic AI systems often maintain persistent memory and state across interactions. Protecting this information requires access controls, encryption, and safeguards against unauthorized modification. Memory integrity is especially important when system decisions depend on prior context.

### 3. Audit and Logging

When AI systems act autonomously, comprehensive logging becomes essential. Governance requires visibility into what actions the system took, when they occurred, and the context that led to those decisions. This supports operational oversight, incident investigation, and compliance assessments.

### 4. Agent and Model Controls

Guardrails prevent agents from producing harmful outputs or running unsafe actions. These controls include input validation, output filtering, behavioral constraints, and isolation mechanisms to limit blast radius if a system behaves unexpectedly.

Agentic AI systems intended for regulated environments should prioritize deterministic and evidence-based behavior over unconstrained autonomy. Free-form decision making and opaque actions undermine auditability and make post-incident analysis difficult.

Structured outputs (explicit plans, configuration diffs, or step-by-step remediation actions) enable human review, risk scoring, and regulatory mapping. Storing these outputs in protected, immutable systems supports accountability and compliance without slowing operations.

### 5. Agency Boundaries and Policies

Clear, enforceable boundaries define what an agent can and cannot do. These boundaries must be implemented through technical controls rather than relying solely on policy documentation. Explicit limits reduce the risk of unintended behavior as system autonomy increases.

### 6. Orchestration

Agentic systems often rely on orchestration layers to coordinate tools, services, and other agents. Structured workflows, approval gates, and state management help maintain control over complex interactions and support consistent governance across implementations.

---

## Auditing Agentic AI Systems Across the Six Security Dimensions

**Figure 4: Agentic AI Audit Evidence Pack Architecture**

> *[DIAGRAM SUGGESTION: A three-layer architecture diagram. Bottom layer: "Evidence Collection" (agent logs, identity records, state snapshots, boundary enforcement logs, orchestration traces). Middle layer: "Evidence Protection" (immutable storage, integrity verification, access controls, retention policies). Top layer: "Audit Delivery" (end-to-end reconstruction, control effectiveness reports, compliance mapping, incident investigation packs). Show data flowing upward through the layers. Add a note: "The evidence pack must support end-to-end reconstruction of an agent run, prove control enforcement at the point of action, and preserve integrity for audit and incident response."]*

Auditing agentic AI systems requires evidence that controls are technically enforced and operationally effective. Policy statements alone are insufficient. For each security dimension, organizations should demonstrate control effectiveness through logs, configurations, and observable system behavior.

| Security Dimension | Audit Focus | Evidence of Control Failure |
|---|---|---|
| **Identity Context** | Each agent operates under a unique, least-privilege identity. All actions are traceable to that identity. | Shared credentials, undocumented delegation |
| **Data, Memory, and State** | Persistent memory is protected by access controls and encryption. Integrity is preserved. Lifecycle management is defined. | Prior context modified or injected without authorization |
| **Audit and Logging** | Complete, immutable records of agent decisions, actions, and triggering context. End-to-end behavior reconstruction is possible. | Gaps in logs, mutable records, missing context |
| **Agent and Model Controls** | Enforced guardrails that prevent unsafe actions (not merely detect them). Structured, explainable outputs. | Unstructured outputs, unenforced guardrails |
| **Agency Boundaries** | Agents cannot exceed authorized actions, even if prompted or misconfigured. | Boundary bypass through prompt injection or tool chaining |
| **Orchestration** | Workflows are explicit, state-managed, and subject to approval gates. Ability to pause, terminate, or roll back agent activity. | Implicit workflows, no kill switch capability |

---

## Aligning Agentic AI Governance with ISO/IEC 42001

ISO/IEC 42001 provides a management system framework for responsible AI use. Organizations can align agentic AI governance with this standard by mapping technical controls to management system requirements and Annex A controls.

| Governance Dimension | ISO/IEC 42001 Alignment |
|---|---|
| Identity and authorization controls | Responsible AI use requirements |
| Data, memory, and state protection | Data governance objectives |
| Audit and logging | Accountability and continuous improvement |
| Agent and model controls | Risk management and impact assessment |
| Agency boundaries | Operational controls and constraints |
| Orchestration | Process management and oversight |

Aligning governance models this way allows organizations to support both operational security and formal compliance or certification efforts without creating parallel control structures.

---

## A Phased Approach to Implementation

**Figure 5: Agentic AI Governance Implementation Lifecycle**

> *[DIAGRAM SUGGESTION: A circular lifecycle diagram with six phases arranged clockwise. Each phase is a distinct segment with an icon and brief label. Add gate checkpoints between phases (especially between Phase 3 and Phase 4) with a note: "Organizations should not move to higher autonomy scopes until Phase 3 validation succeeds and evidence artifacts are audit-ready." Use arrows showing the cycle can repeat. Include a center label: "Continuous Governance Maturity."]*

Implementing governance for agentic AI systems works best as an incremental process.

### Phase 1: Discovery and Classification
Inventory AI systems and classify them by scope. Assess current controls across the six security dimensions.

### Phase 2: Controls Mapping
Map required controls to each system based on scope and risk. Identify opportunities to standardize and automate controls.

### Phase 3: Controls Validation
Validate that controls function as intended through testing, evidence review, and demonstrations. Confirm that escalation paths and intervention mechanisms work as designed.

> **Gate checkpoint:** Organizations should not advance to higher autonomy scopes until Phase 3 validation succeeds and evidence artifacts are audit-ready.

### Phase 4: Threat Modeling
Identify threats specific to each scope level, from prompt manipulation in lower-scope systems to goal misalignment or unintended autonomy in higher-scope systems.

### Phase 5: Automation
Automate monitoring, detection, and compliance checks where possible to reduce manual effort and improve consistency.

### Phase 6: Audit Readiness
Organize documentation, evidence, and operational procedures to support internal reviews, external audits, or certification efforts.

---

## How Organizations Should Operationalize Agentic AI Governance

### Step 1: Create an Agent Inventory (Week 1–2)

Begin by creating a centralized inventory of all agentic AI systems in use or under development. Each entry should document the agent's purpose, data accessed, tools used, and current autonomy scope.

**Artifacts to produce:**
- Agent inventory register
- Assigned scope (1–4) per agent
- Named business and security owner for each agent

> **Principle:** If an organization cannot list its agents, it cannot govern them.

### Step 2: Assign Scope and Enforce Boundaries (Week 2–4)

Each agent must be explicitly assigned a scope level. Scope must be enforced technically, not only documented in policy. Agents should be prevented from accessing tools or data outside their authorized scope.

**Artifacts to produce:**
- Scope classification record
- Technical enforcement evidence (IAM policies, tool allow-lists)
- Approval record for Scope 3 or Scope 4 agents

> **Principle:** No agent should operate at higher scope without explicit authorization.

### Step 3: Implement Minimum Required Controls (Week 3–6)

Before enabling autonomy beyond Scope 1, implement baseline controls across all six security dimensions: unique agent identities, protected memory, comprehensive logging, enforced guardrails, and kill-switch capabilities.

**Artifacts to produce:**
- Control-to-agent mapping
- Evidence of logging, identity isolation, and guardrails
- Kill-switch test results

> **Principle:** If controls are not technically enforced, autonomy must be reduced.

### Step 4: Audit Agent Behavior Regularly (Ongoing)

Audit agentic AI systems using observable evidence rather than policy assertions. Audits should verify that agents operate within scope, produce explainable outputs, and generate complete logs.

**Artifacts to produce:**
- Audit checklist aligned to six dimensions
- Sample log reconstructions
- Findings and remediation actions

> **Principle:** Audits should be repeatable and evidence-based.

### Step 5: Prepare for Agent Incidents (Before Production)

Include agentic AI systems in incident response planning. Define what constitutes an agent-related incident and test response actions such as suspension, scope de-escalation, and rollback.

**Artifacts to produce:**
- Agent incident response playbook
- Escalation paths and decision authority
- Evidence from tabletop or live testing

> **Principle:** If an organization cannot stop an agent, it should not deploy it.

### Step 6: Increase Autonomy Only After Proving Control Effectiveness

Grant higher levels of autonomy only after controls have been validated through testing and audit. Treat autonomy as a privilege earned through demonstrated governance maturity.

**Artifacts to produce:**
- Autonomy elevation approval record
- Evidence from prior audits and incidents
- Executive risk acceptance (for Scope 4)

> **Principle:** Autonomy must be earned, not assumed.

---

## Incident Response for Agentic AI Systems

Agentic AI systems require incident response procedures tailored to autonomous behavior. Traditional incident response models assume human-initiated actions and do not account for the speed or complexity of agent-driven incidents.

**Agent-specific incident types include:**
- Unauthorized action execution
- Boundary violations
- Incorrect or harmful remediation
- Memory corruption
- Unintended goal pursuit

Organizations should explicitly classify these scenarios as security or operational incidents.

**Required response capabilities:**
- Immediate suspension of agent activity
- Revocation of agent credentials
- Scope de-escalation
- Preservation of logs and state for investigation

Human review should determine root cause, assess control failures, and approve remediation before restoring autonomy.

Incident response plans should incorporate agentic systems into existing processes, including escalation paths, evidence handling, and post-incident reviews. Regular testing of kill switches and rollback mechanisms is essential to confirm that response actions function under real conditions.

---

## Practical Considerations for Regulated Environments

Organizations operating in regulated environments face additional considerations:

**Data ownership and sovereignty**
Agentic AI systems often access sensitive data. Governance must ensure data remains under organizational control and subject to applicable jurisdictional and regulatory requirements.

**Compliance alignment**
Controls should integrate with existing compliance programs rather than introducing parallel processes. Leveraging existing assurance mechanisms reduces friction and improves adoption.

**Transparency and accountability**
Public sector AI systems require clear traceability and explainability. Logging agent decisions and actions supports oversight, public accountability, and trust.

**Progressive adoption**
Organizations should begin with lower-scope implementations and progress toward higher autonomy as governance maturity increases. Higher-scope systems should not be deployed until lower-scope controls are proven effective.

---

## Conclusion and Next Steps

Agentic AI systems introduce governance challenges because they can reason, decide, and act with varying degrees of autonomy. For public sector and regulated organizations, structured governance, accountability, and auditability are essential.

By classifying agentic AI systems by scope and applying controls across six core security dimensions, organizations can manage risk in a scalable and practical way. Aligning this approach with existing compliance and assurance practices enables agentic AI adoption without weakening trust.

**Recommended next steps:**

1. Assess current AI systems and classify them by scope
2. Define scope boundaries with technical enforcement
3. Implement baseline controls across all six security dimensions
4. Validate controls through testing before increasing autonomy
5. Establish audit and incident response procedures specific to agentic AI

Organizations should approach agentic AI adoption progressively. Lower-scope systems provide an opportunity to validate controls, monitoring, and response mechanisms before introducing higher levels of autonomy. Advancement should be based on demonstrated governance maturity rather than technical capability alone.

---

## Learn More

To explore how AWS can support your organization's agentic AI governance journey, visit [AWS for Government](https://aws.amazon.com/government-education/) or contact your AWS account team.

For more information on securing AI workloads:
- [AWS AI Security and Governance](https://aws.amazon.com/ai/responsible-ai/)
- [[Affiliation]](https://aws.amazon.com/professional-services/security-assurance/)
- [AWS Well-Architected Framework, Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

---

## About the Authors

**Paul Keastead** is an Assurance Consultant with [Affiliation] (SAS). He helps organizations achieve and maintain their compliance objectives in the cloud. Leveraging his experience as a FedRAMP Assessor and over a decade of expertise in National Security and Public Sector technology compliance, Paul works closely with customers, partners, and AWS teams to align security and compliance requirements with business objectives.

**Author** (CISA, CISM, PCI QSA, ISO 27001 LA) is an Associate Assurance Consultant with [Affiliation] (SAS). He helps organizations achieve and maintain their compliance objectives while securing their cloud environments. Leveraging his 8+ years of cybersecurity experience, Satish works closely with customers and AWS teams to conduct comprehensive security assessments and align security controls with customer requirements.

---

*© 2026 Amazon Web Services, Inc. or its affiliates. All rights reserved.*
