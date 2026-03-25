# ISO 42001 Compliance Mapping

| Control ID | Control Name | Implementation Component | Evidence Generated | Compliance Status |
|---|---|---|---|---|
| A.2 | AI Policy | Policy_Engine | Policy definition records, policy evaluation logs, policy version history | implemented |
| A.2 | AI Policy | Policy_Lifecycle | Policy version metadata, approval records, rollback audit logs | implemented |
| A.2 | AI Policy | Change_Logger | Policy change records with 7-year retention, change audit trail | implemented |
| A.3 | Internal Organization | Separation_of_Duties | Role assignment records, SoD constraint enforcement logs | implemented |
| A.3 | Internal Organization | Agent_Registry | Agent registration records, ownership assignments, audit logs | implemented |
| A.3 | Internal Organization | Approval_Workflow | Approval/denial records with SoD enforcement, approver identity logs | implemented |
| A.4 | Resources for AI | Agent_Registry | Agent inventory with purpose, owner, tools, data classes | implemented |
| A.4 | Resources for AI | Tool_Model_Registry | Approved model/tool/data source registry entries | implemented |
| A.5 | Assessing AI Impacts | Risk_Scoring_Engine | Risk assessment records with scores, categories, escalation flags | implemented |
| A.5 | Assessing AI Impacts | Decision_Engine | Governance decision records with verdicts and explanations | implemented |
| A.5 | Assessing AI Impacts | Decision_History | Queryable decision history with risk score filtering | implemented |
| A.6 | AI System Lifecycle | Evidence_Pipeline | Structured evidence records with hash chains and framework tags | implemented |
| A.6 | AI System Lifecycle | Policy_Lifecycle | Policy version history, approval workflow records | implemented |
| A.6 | AI System Lifecycle | Change_Logger | Scope and policy change records indexed for audit queries | implemented |
| A.7 | AI System Support | Kill_Switch | Emergency shutdown activation/deactivation audit logs | implemented |
| A.7 | AI System Support | Approval_Workflow | Human-in-the-loop approval records for escalated actions | implemented |
| A.8 | Data for AI | Agent_Registry | Data class declarations per agent, access control enforcement logs | implemented |
| A.8 | Data for AI | Threat_Detector | Input validation logs, threat detection records | implemented |
| A.9 | AI System Performance | Decision_Engine | Decision latency metrics, budget exceedance records | implemented |
| A.9 | AI System Performance | Kill_Switch | Emergency shutdown activation/deactivation audit logs | implemented |
| A.9 | AI System Performance | Decision_History | Historical decision performance data, verdict distribution analytics | implemented |
| A.10 | Third-party and Customer Relationships | Tool_Model_Registry | Third-party model/tool approval records, revocation logs | implemented |
| A.10 | Third-party and Customer Relationships | Separation_of_Duties | Role-based access control records, SoD enforcement logs | implemented |
