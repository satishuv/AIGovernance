Building trustworthy agentic AI: A governance framework for public sector and regulated organizations	3
Introduction	3
What this whitepaper covers	4
Understanding agentic AI: from assistants to autonomous systems	4
Why traditional governance breaks down for agentic AI	4
A scope-based approach to agentic AI security	5
Figure 1: Agentic AI autonomy scopes and human oversight	6
Scope 1: No agency	6
Scope 2: Prescribed agency	6
Scope 3: Supervised agency	7
Scope 4: Full agency	7
Dynamic scope elevation and de-escalation	8
Figure 2: Dynamic scope elevation and de-escalation for agentic AI systems.	8
Six security dimensions for agentic AI governance	10
Figure 3: Six security dimensions for agentic AI governance	10
Identity context	10
Data, memory, and state protection	11
Audit and logging	11
Agent and model controls	11
Agency boundaries and policies	11
Orchestration	12
Auditing agentic AI systems across the six security dimensions	12
Figure 4. Agentic AI audit evidence pack architecture (collection, protection, and audit delivery)	12
Aligning agentic AI governance with ISO/IEC 42001	13
A phased approach to implementation	14
Figure 5. Agentic AI governance implementation lifecycle	14
Phase 1: Discovery and classification	14
Phase 2: Controls mapping	14
Phase 3: Controls validation	14
Phase 4: Threat modeling	14
Phase 5: Automation	15
Phase 6: Audit readiness	15
How organizations should operationalize agentic AI governance	15
Step 1: Create an agent inventory (Week 1–2)	15
Step 2: Assign scope and enforce boundaries (Week 2–4)	15
Step 3: Implement minimum required controls (Week 3–6)	16
Step 4: Audit agent behavior regularly (Ongoing)	16
Incident response for agentic AI systems	17
Practical considerations for regulated environments	17
Conclusion and next steps	18
Learn more	19
About the authors	19

 
Building trustworthy agentic AI: A governance framework for public sector and regulated organizations
Authors:
Paul Keastead, Assurance Consultant, Security Assurance Services
Author, Associate Assurance Consultant, Security Assurance Services
Introduction
Public sector organizations face a growing challenge as they adopt agentic AI systems: how to benefit from increased autonomy while continuing to meet security, compliance, and accountability expectations. Unlike traditional AI systems that respond to prompts or run narrowly defined tasks, agentic AI systems can understand context, make decisions, plan multi-step workflows, and take autonomous actions. These capabilities introduce governance and risk considerations that existing AI control models do not fully address.
As agentic AI systems gain the ability to act across systems, data, and services, the consequences of design gaps, misconfiguration, or unintended behavior increase. For organizations in regulated environments, governance, auditability, and operational control become foundational requirements, not optional enhancements.
This whitepaper outlines a practical governance framework for agentic AI systems, with a focus on public sector and other highly regulated environments. It introduces a scope-based model for classifying agent autonomy and identifies core security dimensions. It also describes how organizations can align agentic AI governance with existing risk, compliance, and assurance programs.



What this whitepaper covers
This whitepaper covers:
•	How agentic AI systems differ from traditional AI from a governance and risk perspective
•	A scope-based model for classifying agent autonomy and authority
•	Six security dimensions that support trustworthy agentic AI systems
•	How agentic AI governance can align with existing compliance and audit expectations
Understanding agentic AI: from assistants to autonomous systems
Agentic AI systems represent an evolution from reactive assistants to systems capable of reasoning, planning, and acting with varying levels of independence. These systems can select tools dynamically, maintain memory across interactions, and adapt behavior based on changing conditions. In advanced implementations, agents collaborate to accomplish complex objectives.
Two characteristics matter most for governance:
•	Autonomy: the degree to which the system can make decisions without human intervention
•	Agency: the scope of actions the system is authorized to take within its environment
Understanding where an AI system falls along these dimensions is a prerequisite for applying appropriate controls. Treating all AI systems as equivalent can result in either over constraining low-risk use cases or under governing highly autonomous systems.
Why traditional governance breaks down for agentic AI
Traditional AI governance models target systems that operate at human decision speed, where actions are discrete, reviewable, and directly attributable to a person or process. These models assume that organizations can manage risk through periodic reviews, static approvals, and policy-based controls enforced outside the system.


Agentic AI systems break these assumptions.
Agentic systems reason across steps, select tools dynamically, maintain persistent state, and act at machine speed. Risk is no longer confined to a single inference or output; it emerges from sequences of decisions, interactions between agents and tools, and accumulated context over time.
In this environment, governance failures occur not because policies are missing, but because controls are not technically enforced at the point of action. Observed failure patterns include:
•	Authority escalation through tool chaining: agents combine permitted actions to achieve outcomes beyond their intended scope
•	Privilege amplification through delegated identities: agents inherit or accumulate permissions that exceed their authorization
•	State-influenced decision drift: memory or context from prior interactions shapes subsequent decisions in unintended ways
•	Silent autonomy escalation: agents gradually operate at higher scope levels without formal approval or detection
Documentation and human review alone cannot mitigate these risks. Organizations must embed governance into system architecture through enforceable boundaries, ongoing monitoring, and auditable evidence of behavior. Without this shift, organizations risk deploying systems that appear compliant on paper but operate outside acceptable risk thresholds in practice.
A scope-based approach to agentic AI security
Not all agentic AI systems require the same level of governance. Applying a single control model across all implementations often leads to unnecessary friction or unaddressed risk. A scope-based classification approach helps organizations match governance controls to actual system capability and impact.
Figure 1: Agentic AI autonomy scopes and human oversight
 
Figure 1 illustrates the progression of agent autonomy and corresponding shifts in human oversight.


This framework defines four scope levels based on the degree of agency and autonomy.
Scope 1: No agency
Scope 1 systems operate in read-only or advisory mode. They are human-initiated, follow fixed execution paths, and cannot modify systems or data.
These systems typically analyze information, summarize content, or provide recommendations. While governance is still required, risk is limited because the system cannot take direct action.
Scope 2: Prescribed agency
Scope 2 systems can propose or prepare changes but require explicit human approval before execution. They may access multiple tools or systems, but a human remains responsible for authorizing each consequential action.
This scope is appropriate for systems that draft policy updates, generate configuration recommendations, or prepare remediation steps for human review.
Scope 3: Supervised agency
Scope 3 systems execute end-to-end workflows after human initiation. They select tools dynamically and can complete tasks autonomously within predefined boundaries. Human oversight remains available through monitoring, intervention points, or escalation paths.
Examples include systems that respond automatically to defined security events while escalating higher risk situations for review.
Scope 4: Full agency
Scope 4 systems operate with continuous autonomy and can initiate actions without direct human prompting. They may adapt behavior over time and operate independently for extended periods, with humans providing strategic oversight rather than task-level control.
This scope requires the most rigorous governance and is appropriate only where organizations have mature controls, monitoring, and assurance mechanisms in place.
Dynamic scope elevation and de-escalation
Figure 2: Dynamic scope elevation and de-escalation for agentic AI systems.
 
Figure 2 illustrates how agent autonomy is treated as a dynamic property, elevated only after control effectiveness is demonstrated, and automatically reduced when risk conditions, control failures, or anomalous behavior are detected.
In practice, the scope of an agentic AI system is not static. As systems evolve, they may gain access to new tools, data sources, or workflows that materially change their effective level of autonomy. Treating scope as a one-time classification decision creates blind spots that undermine governance over time.
Organizations should therefore treat scope as a dynamic property that is continuously enforced and reassessed. Scope elevation, such as moving from prescribed agency to supervised or full agency, should require explicit approval supported by evidence that additional controls are in place and functioning as intended. Triggers for scope elevation include expanded tool access, reduced human oversight, or deployment into higher-impact environments.
Equally important is the ability to automatically de-escalate scope when risk conditions change. Anomalous behavior, boundary violations, control failures, or security incidents should result in immediate restriction of agent capabilities until human review is completed. This ensures that autonomy is earned and retained based on demonstrated control effectiveness, rather than assumed indefinitely.
By implementing technical mechanisms for both scope elevation and de-escalation, organizations can prevent gradual, unapproved increases in autonomy and maintain alignment between system capability and governance maturity.
Six security dimensions for agentic AI governance
Figure 3: Six security dimensions for agentic AI governance
 
As shown in Figure 3, governance effectiveness depends on consistent enforcement across all six dimensions rather than isolated controls.
Regardless of scope, effective governance of agentic AI systems requires controls across six security dimensions. These dimensions are not new security concepts, but agentic systems combine them in ways that amplify the impact of gaps or misconfiguration.
Identity context
Agentic systems must operate under clearly defined identities with explicit authorization boundaries. This includes the ability to act on behalf of users or services while maintaining traceability and accountability. Strong identity controls enable auditability and prevent unintended privilege escalation.
Data, memory, and state protection
Agentic AI systems often maintain persistent memory and state across interactions. Protecting this information requires access controls, encryption, and safeguards against unauthorized modification. Memory integrity is especially important when system decisions depend on prior context.
Every agent action must be attributable to a defined human or organizational authority responsible for approving the agent’s scope, permissions, and operating context.
Audit and logging
When AI systems act autonomously, comprehensive logging becomes essential. Governance requires visibility into what actions the system took, when they occurred, and the context that led to those decisions. This supports operational oversight, incident investigation, and compliance assessments.
Agent and model controls
Guardrails prevent agents from producing harmful outputs or running unsafe actions. These controls include input validation, output filtering, behavioral constraints, and isolation mechanisms to limit blast radius if a system behaves unexpectedly.
Agentic AI systems intended for regulated environments should prioritize deterministic and evidence-based behavior over unconstrained autonomy. Free-form decision making and opaque actions undermine auditability and make post-incident analysis difficult.
Structured outputs (such as explicit plans, configuration diffs, or step-by-step remediation actions) enable human review, risk scoring, and regulatory mapping. Storing these outputs in protected, immutable systems supports accountability and compliance without slowing operations.
By constraining agent behavior to explainable and reviewable actions, organizations can increase trust while maintaining operational efficiency.
Agency boundaries and policies
Clear, enforceable boundaries define what an agent can and cannot do. These boundaries must be implemented through technical controls rather than relying solely on policy documentation. Explicit limits reduce the risk of unintended behavior as system autonomy increases.
Orchestration
Agentic systems often rely on orchestration layers to coordinate tools, services, and other agents. Structured workflows, approval gates, and state management help maintain control over complex interactions and support consistent governance across implementations.
Auditing agentic AI systems across the six security dimensions
Figure 4. Agentic AI audit evidence pack architecture (collection, protection, and audit delivery)
 
Figure 4. The evidence pack must support end-to-end reconstruction of an agent run, prove control enforcement at the point of action, and preserve integrity for audit and incident response.

Auditing agentic AI systems requires evidence that controls are technically enforced and operationally effective. Policy statements alone are insufficient. For each security dimension, organizations should be able to demonstrate control effectiveness through logs, configurations, and observable system behavior.
For identity context, audits should confirm that each agent operates under a unique, least privilege identity and that all actions are traceable to that identity. Shared credentials or undocumented delegation represent control failures.
For data, memory, and state protection, audits should verify that persistent memory is protected by access controls and encryption, that integrity is preserved, and that lifecycle management is defined. Systems should demonstrate that prior context cannot be modified or injected without authorization.
Audit and logging controls should provide complete, immutable records of agent decisions, actions, and triggering context. Auditors should be able to reconstruct an agent’s behavior end-to-end for a given event or time period.
Agent and model controls should demonstrate enforced guardrails that prevent unsafe actions rather than merely detecting them. Outputs should be structured and explainable, enabling human review and regulatory mapping.
Agency boundaries and policies must be enforced through technical mechanisms. Audits should confirm that agents cannot exceed authorized actions, even if prompted or misconfigured.
Finally, orchestration controls should show that workflows are explicit, state-managed, and subject to approval gates where required. Evidence should demonstrate the ability to pause, terminate, or roll back agent activity when necessary.
Aligning agentic AI governance with ISO/IEC 42001
ISO/IEC 42001 provides a management system framework for responsible AI use. Organizations can align agentic AI governance with this standard by mapping technical controls to management system requirements and Annex A controls.
For example, identity and authorization controls align with responsible AI use requirements, while data, memory, and state protection support data governance objectives. Audit and logging capabilities contribute directly to accountability and continuous improvement expectations.
Aligning governance models in this way allows organizations to support both operational security and formal compliance or certification efforts without creating parallel control structures.
A phased approach to implementation
Figure 5. Agentic AI governance implementation lifecycle
 
Figure 5. Organizations should not move to higher autonomy scopes until Phase 3 validation succeeds and evidence artifacts are audit ready.
Implementing governance for agentic AI systems is best approached incrementally.
Phase 1: Discovery and classification
Inventory AI systems and classify them according to scope. Assess current controls across the six security dimensions.
Phase 2: Controls mapping
Map required controls to each system based on scope and risk. Identify opportunities to standardize and automate controls.
Phase 3: Controls validation
Validate that controls function as intended through testing, evidence review, and demonstrations. Confirm that escalation paths and intervention mechanisms work as designed.
Phase 4: Threat modeling
Identify threats specific to each scope level, from prompt manipulation in lower-scope systems to goal misalignment or unintended autonomy in higher-scope systems.
Phase 5: Automation
Automate monitoring, detection, and compliance checks where possible to reduce manual effort and improve consistency.
Phase 6: Audit readiness
Organize documentation, evidence, and operational procedures to support internal reviews, external audits, or certification efforts.
How organizations should operationalize agentic AI governance
Step 1: Create an agent inventory (Week 1–2)
Organizations should begin by creating a centralized inventory of all agentic AI systems in use or under development. Each entry should document the agent’s purpose, data accessed, tools used, and current autonomy scope.
What to produce (artifact):
•	Agent inventory register
•	Assigned scope (1–4)
•	Named business and security owner
If an organization cannot list its agents, it cannot govern them.
Step 2: Assign scope and enforce boundaries (Week 2–4)
Each agent must be explicitly assigned a scope level. Scope must be enforced technically, not only documented in policy. Agents should be prevented from accessing tools or data outside their authorized scope.
What to produce (artifact):
•	Scope classification record
•	Technical enforcement evidence (IAM policies, tool allow lists)
•	Approval record for Scope 3 or Scope 4 agents
No agent should operate at higher-scope without explicit authorization.
Step 3: Implement minimum required controls (Week 3–6)
Before enabling autonomy beyond Scope 1, organizations should implement baseline controls across all six security dimensions, including unique agent identities, protected memory, comprehensive logging, enforced guardrails, and kill-switch capabilities.
What to produce (artifact):
•	Control-to-agent mapping
•	Evidence of logging, identity isolation, and guardrails
•	Kill-switch test results
If controls are not technically enforced, autonomy must be reduced.
Step 4: Audit agent behavior regularly (Ongoing)
Organizations should audit agentic AI systems using observable evidence rather than policy assertions. Audits should verify that agents operate within scope, produce explainable outputs, and generate complete logs.
What to produce (artifact):
•	Audit checklist aligned to six dimensions
•	Sample log reconstructions
•	Findings and remediation actions
Audits should be repeatable and evidence-based.
Step 5: Prepare for agent incidents (Before production)
Agentic AI systems must be included in incident response planning. Organizations should define what constitutes an agent-related incident and test response actions such as suspension, scope de-escalation, and rollback.
What to produce (artifact):
•	Agent incident response playbook
•	Escalation paths and decision authority
•	Evidence from tabletop or live testing
If an organization cannot stop an agent, it should not deploy it.
Step 6: Increase autonomy only after proving control effectiveness
Higher levels of autonomy should be granted only after controls have been validated through testing and audit. Autonomy should be treated as a privilege earned through demonstrated governance maturity.
What to produce (artifact):
•	Autonomy elevation approval record
•	Evidence from prior audits and incidents
•	Executive risk acceptance (for Scope 4)
Autonomy must be earned, not assumed.
Incident response for agentic AI systems
Agentic AI systems require incident response procedures tailored to autonomous behavior. Traditional incident response models assume human-initiated actions and do not account for the speed or complexity of agent-driven incidents.
Agent-specific incidents include unauthorized action execution, boundary violations, incorrect or harmful remediation, memory corruption, or unintended goal pursuit. Organizations should explicitly classify these scenarios as security or operational incidents.
Effective response capabilities include immediate suspension of agent activity, revocation of agent credentials, scope de-escalation, and preservation of logs and state for investigation. Human review should determine root cause, assess control failures, and approve remediation before autonomy is restored.
Incident response plans should incorporate agentic systems into existing processes, including escalation paths, evidence handling, and post-incident reviews. Regular testing of kill switches and rollback mechanisms is essential to ensure response actions function under real conditions.
Practical considerations for regulated environments
Organizations operating in regulated environments face additional considerations.

Data ownership and sovereignty
Agentic AI systems often access sensitive data. Governance must ensure data remains under organizational control and subject to applicable jurisdictional and regulatory requirements. 
Compliance alignment
Controls should integrate with existing compliance programs rather than introducing parallel processes. Leveraging existing assurance mechanisms reduces friction and improves adoption.

Transparency and accountability
 Public sector AI systems require clear traceability and explainability. Logging agent decisions and actions supports oversight, public accountability, and trust. 
Progressive adoption
Organizations should begin with lower-scope implementations and progress toward higher autonomy as governance maturity increases. Higher-scope systems should not be deployed until lower-scope controls are proven effective.
Conclusion and next steps
Agentic AI systems introduce new governance challenges because they can reason, decide, and act with varying degrees of autonomy. For public sector and regulated organizations, this makes structured governance, accountability, and auditability essential.
By classifying agentic AI systems by scope and applying controls across six core security dimensions, organizations can manage risk in a scalable and practical way. Aligning this approach with existing compliance and assurance practices enables agentic AI adoption without weakening trust.
Organizations should start by assessing current AI systems, defining scope boundaries, and incrementally strengthening governance as autonomy increases.
Organizations should approach agentic AI adoption progressively. Lower scope systems provide an opportunity to validate controls, monitoring, and response mechanisms before introducing higher levels of autonomy. Advancement should be based on demonstrated governance maturity rather than technical capability alone.
By aligning autonomy with proven control effectiveness, organizations can adopt agentic AI in a way that maintains trust, accountability, and regulatory confidence.
Learn more
To explore how AWS can support your organization's agentic AI governance journey, visit AWS for Government or contact your AWS account team to discuss your specific requirements.
For more information on securing AI workloads, see:
• AWS AI security and governance
• [Affiliation]
• AWS Well Architected Framework - Security Pillar
About the authors
  
Paul Keastead is an Assurance Consultant with [Affiliation] (SAS). He helps organizations achieve and maintain their compliance objectives in the cloud. Leveraging his experience as a FedRAMP Assessor and over a decade of expertise in National Security and Public Sector technology compliance, Paul works closely with customers, partners, and AWS teams to align security and compliance requirements with business objectives.

 
Author (CISA, CISM, PCI QSA, ISO 27001 LA) is an Associate Assurance Consultant with [Affiliation] (SAS). He helps organizations achieve and maintain their compliance objectives while securing their cloud environments. Leveraging his 8+ years of cybersecurity experience, Satish works closely with customers and AWS teams to conduct comprehensive security assessments and align security controls with customer requirements.