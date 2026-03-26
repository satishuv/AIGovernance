# NIST AI RMF Compliance Mapping

| Function | Category | Subcategory | Implementation Component | Evidence Generated | Compliance Status |
|---|---|---|---|---|---|
| GOVERN | GOVERN 1 | Policies, Processes, Procedures, and Practices | Policy_Engine | Policy evaluation logs, policy definition records | implemented |
| GOVERN | GOVERN 1 | Policies, Processes, Procedures, and Practices | Policy_Lifecycle | Policy versioning records, approval workflow audit trail | implemented |
| GOVERN | GOVERN 2 | Accountability | Separation_of_Duties | Role assignment records, SoD constraint enforcement logs | implemented |
| GOVERN | GOVERN 2 | Accountability | Approval_Workflow | Approval/denial records with approver identity and SoD enforcement | implemented |
| GOVERN | GOVERN 3 | Workforce Diversity | Agent_Registry | Agent ownership records, multi-stakeholder registration data | implemented |
| GOVERN | GOVERN 4 | Organizational Practices | Change_Logger | Scope and policy change records with 7-year retention | implemented |
| GOVERN | GOVERN 4 | Organizational Practices | Decision_History | Queryable decision history for organizational review | implemented |
| GOVERN | GOVERN 5 | Processes for Engagement | Approval_Workflow | Human-in-the-loop approval records, stakeholder notification logs | implemented |
| GOVERN | GOVERN 6 | Policies and Procedures for Trustworthy AI | Evidence_Pipeline | Immutable evidence records with hash chains and retention policies | implemented |
| GOVERN | GOVERN 6 | Policies and Procedures for Trustworthy AI | Kill_Switch | Emergency shutdown audit logs, fail-safe activation records | implemented |
| MAP | MAP 1 | Context and Use Cases | Agent_Registry | Agent purpose declarations, data class inventories, tool registrations | implemented |
| MAP | MAP 2 | Categorization | Risk_Scoring_Engine | Risk category assignments, action type classifications | implemented |
| MAP | MAP 3 | Benefits and Costs | Decision_Engine | Decision records with risk-benefit verdicts and explanations | implemented |
| MAP | MAP 4 | Risks and Impacts | Risk_Scoring_Engine | Risk assessment records with weighted factor analysis | implemented |
| MAP | MAP 4 | Risks and Impacts | Threat_Detector | Threat detection records, input validation logs | implemented |
| MAP | MAP 5 | Likelihood and Severity | Risk_Scoring_Engine | Escalation threshold evaluations, severity-based risk scores | implemented |
| MEASURE | MEASURE 1 | Metrics and Methodologies | Decision_Engine | Latency metrics, decision performance measurements | implemented |
| MEASURE | MEASURE 1 | Metrics and Methodologies | MeasureManage_Engine | Aggregate metrics reports, denial/escalation rates, risk score distributions | implemented |
| MEASURE | MEASURE 1 | Metrics and Methodologies | CloudWatch_Metrics_Publisher | Real-time decision count, latency, risk score, kill switch, and evidence failure metrics | implemented |
| MEASURE | MEASURE 2 | Evaluation and Tracking | Decision_History | Decision trend data, verdict distribution over time | implemented |
| MEASURE | MEASURE 3 | Continuous Improvement | Change_Logger | Policy and scope change history for improvement tracking | implemented |
| MEASURE | MEASURE 4 | Feedback and Communication | Approval_Workflow | Approval feedback records, stakeholder communication logs | implemented |
| MANAGE | MANAGE 1 | Risk Response | MeasureManage_Engine | MANAGE reports with incident summaries, policy change summaries, remediation actions | implemented |
| MANAGE | MANAGE 1 | Risk Response | Graduated_Scope_Reduction | Scope reduction events with rolling avg risk, sustained threshold, cooldown tracking | implemented |
| MANAGE | MANAGE 2 | Risk Prioritization | Privilege_Escalation_Detector | Privilege escalation attempt records, denial pattern tracking, auto scope reduction logs | implemented |
| MANAGE | MANAGE 2 | Risk Prioritization | Exfiltration_Detector | Exfiltration detection records, blocked output logs, allowlist enforcement | implemented |
| MANAGE | MANAGE 3 | Risk Monitoring | CloudWatch_Metrics_Publisher | CloudWatch alarms for latency, evidence failures, kill switch activations | implemented |
| MANAGE | MANAGE 3 | Risk Monitoring | MeasureManage_Engine | Threshold comparison reports, automated alerts when metrics exceed thresholds | implemented |
| MANAGE | MANAGE 4 | Risk Communication | Multi_Agent_Manager | Per-agent risk profiles, aggregate cross-agent compliance reports | implemented |
| MANAGE | MANAGE 4 | Risk Communication | Extended_Validation_Suite | Compliance validation reports with gap analysis and remediation recommendations | implemented |
