# Governance Engine Module Map

65 modules in a flat directory (required by Lambda import constraints). This map groups them by function.

---

## Pipeline Core (the request path)

| Module | Purpose |
|--------|---------|
| `index.py` | Lambda entrypoint, routes to pipeline_orchestrator or api_router |
| `pipeline_orchestrator.py` | Runs the 20-step governance pipeline |
| `api_router.py` | Routes API Gateway events: approvals, decisions, reports, risk-profiles, validation |
| `decision_engine.py` | Final ALLOW / DENY / ESCALATE verdict from policy + risk |
| `models.py` | All data models (GovernanceDecision, PolicyResult, RiskAssessment, LatencyMetric, etc.) |
| `latency.py` | Per-component latency tracking with 200ms budget |
| `circuit_breaker.py` | Hard 500ms SLA, trips to fast-DENY on repeated timeouts |

## Input Defense (blocks attacks before they reach the agent)

| Module | Purpose |
|--------|---------|
| `input_sanitizer.py` | Unicode normalization, encoding decode, delimiter scan, stuffing check, instruction pattern detection |
| `threat_detector.py` | Regex pattern matching against DynamoDB-loaded threat signatures |
| `bedrock_guardrails.py` | AWS Bedrock Guardrails API integration (content safety, PII, denied topics) |
| `anomaly_detector.py` | Statistical anomaly: Shannon entropy, character distribution, repetition scoring |

## Policy Evaluation (decides what's allowed)

| Module | Purpose |
|--------|---------|
| `opa_engine.py` | OPA Rego-subset evaluator (embedded or external mode) |
| `policy_engine.py` | Policy loading from S3, caching, evaluation orchestration |
| `cedar_engine.py` | Cedar authorization engine (ABAC, data classification). `authorize_agent_role_boxed()` enforces `HUMAN_ONLY_ACTIONS` boundary before Cedar runs; `verify_agent_subset_of_human()` detects privilege escalations. Available but not in default pipeline. |
| `risk_scoring.py` | Composite risk score (0-100) from 5 weighted factors, capped |
| `behavioral_invariants.py` | Hard physical limits (output size cap, canary tripwire, time-of-day) |
| `formal_assurance.py` | Proves 6 safety invariants hold regardless of input |
| `proactive_engine.py` | Pre-deploy validation: contradictions, dead rules, coverage gaps |
| `policy_lifecycle.py` | Policy versioning, approval workflow, separation-of-duties for policy changes |

## Agent Identity and Authorization

| Module | Purpose |
|--------|---------|
| `agent_identity.py` | Agent identity lifecycle (create, update scope, suspend) |
| `agent_registry.py` | Formal agent registration and status tracking |
| `agent_lifecycle_states.py` | 9-state lifecycle (draft, registered, deployed, suspended, etc.) |
| `agent_token_exchange.py` | Cryptographic token exchange for verified data access |
| `agent_memory.py` | Persistent cross-session governed memory with poisoning detection |
| `ai_asset_registry.py` | Unified registry of all AI assets (10 types) |
| `tool_model_registry.py` | Tool/model/data-source registration with approval workflow |
| `tool_execution_auth.py` | Per-tool authorization, parameter scan, configurable rate limiting, chain detection |
| `operator_rbac.py` | 6 operator roles (admin, author, reviewer, operator, auditor, analyst) |
| `separation_of_duties.py` | Enforces governance role assignments and prevents conflicting role combinations |
| `privilege_escalation.py` | Detects/blocks agents modifying their own scope |
| `environment_isolation.py` | Deployment environment partitioning (dev/staging/prod), cross-environment violation detection |

## Tool Security (governs the tool layer)

| Module | Purpose |
|--------|---------|
| `tool_response_validator.py` | Validates data FROM tools (the Perception Gap defense): injection, entropy, sensitive data |
| `output_guardrails.py` | System prompt leak detection, internal path exposure, canary token leakage, instruction echo |
| `exfiltration_detector.py` | Detects data theft via output channels (size limits, endpoint allowlisting) |
| `retrieval_validator.py` | Validates RAG/retrieved content before agent context injection |
| `cache_governance.py` | Governs what gets cached, PII never cached in semantic memory |

## Information Flow and Provenance

| Module | Purpose |
|--------|---------|
| `information_flow.py` | Cross-session taint tracking: labels inputs by trust origin (trusted: user/operator; untrusted: tool response, retrieved doc, web, MCP), records session taint in DynamoDB, detects untrusted-to-privileged-sink flows. Off by default (`INFORMATION_FLOW_ENABLED`). Fail-open. Integrated into pipeline after probe detection and before the decision engine. |

## Detection and Monitoring

| Module | Purpose |
|--------|---------|
| `runtime_drift_detection.py` | Behavioral baseline comparison (composite drift score) |
| `continuous_monitoring.py` | Agent health scoring (0-100) via EMA, z-score anomaly detection |
| `guardian_monitor.py` | Parallel guardian pattern: independent AI safety evaluator |
| `bias_monitoring.py` | Fairness monitoring (four-fifths rule, sentiment, demographic) |
| `multi_agent.py` | Per-agent configuration, policy binding, cross-agent rules, evidence partitioning |

## Incident Response

| Module | Purpose |
|--------|---------|
| `kill_switch.py` | Emergency shutdown: sets scope=0 via DynamoDB flag. Supports activate, deactivate (requires operator role), query. |
| `graduated_scope_reduction.py` | Automated scope decrease on sustained high risk or repeated denials |
| `approval_workflow.py` | Human approval queue for ESCALATE verdicts (timeout = auto-DENY) |

## Evidence and Compliance

| Module | Purpose |
|--------|---------|
| `evidence_pipeline.py` | Writes evidence to S3 with SHA-256 hashing, hash chain, retry logic, retention class |
| `evidence_integrity.py` | Verification of individual records and hash chain continuity |
| `evidence_graph.py` | Relationship graph between decisions, actions, and agents |
| `control_trace.py` | Links each decision to ISO/NIST/EU AI Act controls |
| `control_mapping.py` | Mapping table linking ISO 42001 and NIST AI RMF controls to implementations |
| `compliance_mapper.py` | Generates compliance mapping documents (JSON + Markdown) |
| `compliance_refresh.py` | Regenerates compliance mappings on deploy |
| `decision_history.py` | Queryable decision index (by agent, verdict, risk, time) |
| `change_logger.py` | Logs all scope/policy changes to S3 + DynamoDB |

## Enterprise Governance

| Module | Purpose |
|--------|---------|
| `ai_asset_registry.py` | Unified registry (10 asset types) |
| `cost_governance.py` | Per-agent budgets, spend tracking, alerts, carbon footprint |
| `shadow_ai_discovery.py` | Discovers unregistered AI via CloudTrail/API scanning |
| `supply_chain_governance.py` | Model/tool/MCP/dataset provenance verification |
| `governance_change_management.py` | Approval workflow for any governance platform mutation |
| `executive_analytics.py` | Posture dashboard, agent risk ranking, ROI metrics |

## Resilience

| Module | Purpose |
|--------|---------|
| `fail_safe.py` | Wraps critical components: policy failure=deny, risk failure=score 100, evidence failure=proceed |
| `governance_failover.py` | Multi-region failover with automatic routing |
| `governance_rollback.py` | Versioned governance state with instant rollback |
| `pipeline_integrity.py` | Self-protection via SHA-256 code hash verification |
| `false_positive_tracker.py` | FP rate tracking with 2% SLA threshold |

## Step Functions Pipeline Handlers

| Module | Purpose |
|--------|---------|
| `handler_input_defense.py` | Step Functions Layer 2: input sanitization + threat detection |
| `handler_authorization.py` | Step Functions Layer 3: identity, registry, tool auth checks |
| `handler_policy_risk.py` | Step Functions Layer 4: policy evaluation, risk scoring, drift, verdict |
| `handler_post_decision.py` | Step Functions Layer 6: async evidence, monitoring, metrics |

## Validation and Reporting

| Module | Purpose |
|--------|---------|
| `validation_suite.py` | Baseline governance validation tests that gate autonomy advancement |
| `extended_validation.py` | Comprehensive compliance validation with gap detection |
| `cloudwatch_metrics.py` | Publishes custom governance metrics to CloudWatch |
| `measure_manage.py` | NIST AI RMF MEASURE/MANAGE: aggregate metrics, trends, remediation |
