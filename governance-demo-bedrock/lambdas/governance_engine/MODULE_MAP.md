# Governance Engine Module Map

72 modules in a flat directory (required by Lambda import constraints). This map groups them by function.

---

## Pipeline Core (the request path)

| Module | Purpose |
|--------|---------|
| `index.py` | Lambda entrypoint, routes to pipeline or API |
| `pipeline_orchestrator.py` | Runs the 20-step governance pipeline |
| `api_router.py` | Handles API requests (status, config, admin) |
| `decision_engine.py` | Final ALLOW / DENY / ESCALATE verdict |
| `models.py` | All data models (GovernanceDecision, PolicyResult, etc.) |
| `latency.py` | Per-component latency tracking with 200ms budget |
| `circuit_breaker.py` | Hard 500ms SLA, trips to fast-DENY on repeated timeouts |

## Input Defense (blocks attacks before they reach the agent)

| Module | Purpose |
|--------|---------|
| `input_sanitizer.py` | 8 checks: Base64, ChatML, homoglyph, leet, stuffing, multilingual, persona, harmful |
| `threat_detector.py` | Pattern matching against known threat signatures (DynamoDB) |
| `bedrock_guardrails.py` | AWS Bedrock Guardrails integration (content safety, PII) |

## Policy Evaluation (decides what's allowed)

| Module | Purpose |
|--------|---------|
| `opa_engine.py` | OPA Rego-subset policy engine with priority resolution |
| `policy_engine.py` | Policy loading, caching, and evaluation orchestration |
| `risk_scoring.py` | Composite risk score (0-100) from multiple signals |
| `behavioral_invariants.py` | Hard limits no model output can override (tool cap, time, size) |
| `formal_assurance.py` | Mathematical proofs that 5 invariants hold |

## Agent Identity and Authorization

| Module | Purpose |
|--------|---------|
| `agent_identity.py` | Agent identity management, scope changes |
| `agent_registry.py` | Agent registration, status tracking |
| `tool_model_registry.py` | Tool/model/data-source registration and approval |
| `tool_execution_auth.py` | Per-tool authorization, rate limiting, chain detection |
| `operator_rbac.py` | 6 operator roles with permission enforcement |
| `agent_token_exchange.py` | Cryptographic token exchange for data access |
| `environment_isolation.py` | Per-agent environment separation |

## Tool Security (governs the tool layer)

| Module | Purpose |
|--------|---------|
| `tool_response_validator.py` | Validates data FROM tools (the Perception Gap defense) |
| `output_guardrails.py` | PII stripping, credential removal, exfiltration blocking |
| `exfiltration_detector.py` | Detects data theft via output channels |
| `retrieval_validator.py` | Validates RAG/retrieved content before agent context |
| `cache_governance.py` | Governs what gets cached and PII in semantic memory |

## Detection and Monitoring

| Module | Purpose |
|--------|---------|
| `runtime_drift_detection.py` | Behavioral baseline comparison |
| `continuous_monitoring.py` | Health scoring (0-100) per agent |
| `anomaly_detector.py` | Statistical anomaly detection (z-score, entropy) |
| `bias_monitoring.py` | Fairness monitoring (four-fifths rule) |
| `privilege_escalation.py` | Detects and blocks self-elevation attempts |
| `multi_agent.py` | Cross-agent rules, collusion detection |

## Incident Response

| Module | Purpose |
|--------|---------|
| `kill_switch.py` | Instant shutdown (<1s), scope to 0, deny-all IAM |
| `graduated_scope_reduction.py` | Automated scope decrease on bad behavior |
| `approval_workflow.py` | Human approval queue for ESCALATE verdicts |

## Evidence and Compliance

| Module | Purpose |
|--------|---------|
| `evidence_pipeline.py` | Writes evidence records (async, non-blocking) |
| `evidence_integrity.py` | SHA-256 hash chain verification |
| `evidence_graph.py` | Relationship graph between decisions and actions |
| `control_trace.py` | Maps each decision to compliance controls |
| `decision_history.py` | Queryable history of all governance decisions |
| `change_logger.py` | Logs scope and policy changes to S3 + DynamoDB |
| `compliance_refresh.py` | Triggers compliance mapping updates |

## Enterprise Governance

| Module | Purpose |
|--------|---------|
| `ai_asset_registry.py` | Unified registry (10 asset types) |
| `agent_lifecycle_states.py` | 9-state agent lifecycle management |
| `supply_chain_governance.py` | Model/tool/MCP/dataset provenance |
| `shadow_ai_discovery.py` | Find unregistered AI in your infrastructure |
| `cost_governance.py` | Per-agent budgets, spend tracking, carbon |
| `governance_change_management.py` | Approval workflow for governance mutations |
| `executive_analytics.py` | Posture dashboard, ROI, risk ranking |

## Resilience

| Module | Purpose |
|--------|---------|
| `fail_safe.py` | Fail-safe wrappers (any exception = DENY) |
| `governance_failover.py` | Multi-region failover with automatic routing |
| `governance_rollback.py` | Versioned governance state with instant rollback |
| `pipeline_integrity.py` | Self-protection via code hash verification |
| `false_positive_tracker.py` | FP rate tracking with SLA enforcement |

## Metrics and Reporting

| Module | Purpose |
|--------|---------|
| `cloudwatch_metrics.py` | Publishes governance metrics to CloudWatch |
| `measure_manage.py` | NIST AI RMF MEASURE/MANAGE function implementation |
