AIGovernance: A Governance Framework for Agentic AI


WHAT IS THIS?

AIGovernance is a reference implementation that demonstrates how to govern AI agents running on AWS. It provides runtime controls, policy enforcement, risk scoring, human oversight, and compliance evidence generation for AI systems built with Amazon Bedrock Agents.

This repository accompanies the AWS whitepaper "Building Trustworthy Agentic AI: A Governance Framework for Public Sector and Regulated Organizations" by the [Affiliation] team.


Key Terms

AI Agent: Software that reasons, plans, and takes actions autonomously using a large language model (LLM).

Governance: Rules, controls, and oversight mechanisms that constrain what an AI agent can do.

Scope Level: A number (0 to 4) representing how much autonomy an agent has, where 0 is fully disabled and 4 is full autonomy.

Policy-as-Code: Governance rules written as machine-readable files (JSON) instead of manual checklists.

Kill Switch: An emergency mechanism that immediately revokes all agent permissions.

Evidence Record: A structured log entry that proves a governance decision was made, stored for audit purposes.


WHO IS THIS FOR?

Security and compliance teams evaluating AI governance patterns for regulated industries.

Solutions architects designing governed AI agent deployments on AWS.

Public sector organizations adopting AI under ISO/IEC 42001 or NIST AI RMF requirements.

Developers building AI agents who need runtime safety controls.

Auditors seeking to understand how AI governance evidence is generated and stored.


WHY DOES THIS EXIST?

AI agents that can reason and act autonomously introduce risks that traditional software controls do not address. An agent with access to production systems could deploy untested code, exfiltrate data, or escalate its own permissions without human awareness.

This project provides a working answer to the question: How do you let AI agents be useful while keeping them safe, auditable, and compliant?

It implements progressive trust (start with minimal permissions, earn more through demonstrated safe behavior), fail-safe defaults (deny on failure, never fail open), and continuous evidence generation (every decision is logged, hashed, and traceable to compliance controls).


THE USE CASE: SOFTWARE DEPLOYMENT PIPELINE

The demo simulates a real-world software delivery lifecycle (SDLC) where an AI agent assists a development team in shipping features from code to production. The agent operates across four action groups, each representing a stage of the pipeline. Think of these as four specialized agents working in parallel, each with different levels of trust and autonomy.

Scope 1, Read-Only Observer: The agent reads the deployment pipeline state, including build artifacts, test results, and current deployment configurations. It can summarize status but cannot modify anything. Example: "Show me the current deployment status and test results for the latest build."

Scope 2, Propose Changes: The agent drafts deployment plans, change requests, and rollback strategies. All proposals go to a pending approval queue for human review before execution. Example: "Draft a deployment plan for build 47 to staging, including a rollback strategy."

Scope 3, Act Within Boundaries: The agent auto-deploys to staging environments, triggers integration tests, and promotes builds to pre-production, all within predefined guardrails such as non-production environments only and only builds that passed all tests. Example: "Deploy the latest green build to staging and run integration tests."

Scope 4, Full Autonomy: The agent manages the full CI/CD pipeline including production deployments, canary analysis, and automatic rollback on failure. Human oversight is strategic, not task-level. Example: "Manage the full release pipeline for this sprint's features."

Kill Switch Scenario: An operator notices the agent is deploying a build that failed a security scan. They invoke the kill switch, which immediately revokes the agent's permissions and halts all in-flight deployments.

Why this use case: Every technical audience understands CI/CD pipelines. The risk gradient from reading build status to deploying to production is intuitive. It demonstrates why you would not give an AI agent production deploy access on day one, and how governance controls let you progressively increase trust based on demonstrated safe behavior.

The data used in the demo is entirely synthetic: mock build manifests, test result reports, deployment configurations, and rollback plans stored in S3.


WHERE DOES IT RUN?

The entire platform runs on AWS using native services:

AI Agent Runtime: Amazon Bedrock Agents (Amazon Nova Micro)
Governance Engine: AWS Lambda (Python)
Policy and Configuration Storage: Amazon DynamoDB
Policy Definitions: Amazon S3 (versioned)
Evidence Storage: Amazon S3 (Object Lock for immutability)
API Endpoints: Amazon API Gateway
Alerts and Notifications: Amazon SNS
Metrics and Alarms: Amazon CloudWatch
Scheduled Reports: Amazon EventBridge
Infrastructure-as-Code: AWS CDK (Python)

Deployment target: A single AWS account in us-east-1. The stack deploys in under 3 minutes using cdk deploy.


WHEN WAS IT BUILT?

Development: January to March 2026. The implementation progressed through five phases:

Phase 1a: Core governance engine including policy evaluation, risk scoring, decision engine, and fail-safe defaults.

Phase 1b: Agent identity, agent registry, tool/model registration, separation of duties, and environment isolation.

Phase 1c: Kill switch, evidence pipeline with hash chains, threat detection, control traces, compliance mapping, and validation suite.

Phase 2: Human-in-the-loop approval workflow, change logging with 7-year retention, queryable decision history, and ISO 42001 and NIST AI RMF compliance documents.

Phase 3: CloudWatch metrics and alarms, privilege escalation hardening, data exfiltration prevention, graduated scope reduction, and multi-agent governance.

All five phases are complete and deployed.


HOW DOES IT WORK?

Every agent action request passes through a governance pipeline before execution:

1. Kill Switch check: deny all requests if the emergency shutdown is active.
2. Threat Detection: block known-bad inputs (SQL injection, prompt injection); flag suspicious patterns.
3. Agent Identity check: deny if the agent is suspended.
4. Agent Registry check: deny if the agent is not registered in the governance registry.
5. Environment Isolation: deny cross-environment actions (dev, staging, prod boundaries).
6. Data Class Access check: deny access to data classes not declared in the agent's registry entry.
7. Tool/Model Registry check: deny use of unapproved tools, models, or data sources.
8. Policy Evaluation: evaluate the request against policy-as-code rules loaded from S3.
9. Risk Scoring: compute a 0 to 100 risk score from weighted factors (scope level, action type, target resource, history).
10. Decision Engine: combine the policy result and risk score into a final verdict.
11. Evidence Write: store the decision as a SHA-256 hashed, immutable record in S3.
12. Control Trace: link the evidence record to ISO 42001 and NIST AI RMF control IDs.
13. Decision History: index the decision for queryable audit.
14. CloudWatch Metrics: publish real-time operational data.

The final verdict is one of three outcomes:

ALLOW: The Bedrock Agent executes the requested action.
DENY: The request is blocked and the user receives an explanation.
ESCALATE: The action requires human approval before execution.


Compliance Coverage

Every governance decision generates evidence records tagged with framework control IDs:

ISO/IEC 42001 Annex A controls: A.2 (AI Policy), A.3 (Internal Organization), A.4 (Resources for AI), A.5 (Assessing AI Impacts), A.6 (AI System Lifecycle), A.7 (AI System Support), A.8 (Data for AI), A.9 (AI System Performance), A.10 (Third-party and Customer Relationships).

NIST AI RMF functions: GOVERN (1 through 6), MAP (1 through 5), MEASURE (1 through 4), MANAGE (1 through 4).

Monthly MEASURE and MANAGE reports are auto-generated via EventBridge scheduling.


Repository Structure

governance-demo/            Lambda-based proof of concept (frozen, read-only)
governance-demo-bedrock/    Full Bedrock Agent governance platform (active)
  lambdas/
    governance_engine/      20+ governance modules
    scope_enforcer/         Request orchestrator
    kill_switch/            Emergency shutdown
    action_group/           Business logic (pipeline operations)
    seed_tables/            DynamoDB initialization
  schemas/                  OpenAPI action group schemas
  sample_data/              Policies, configs, compliance mappings
  tests/                    CDK and governance tests
  governance_bedrock_stack.py   CDK infrastructure (single stack)


Authors

Built by the [Affiliation] team:

Author, Associate Assurance Consultant


This repository is a reference implementation for educational and demonstration purposes. It is not a managed AWS service. Organizations should adapt the patterns to their specific regulatory and operational requirements.
