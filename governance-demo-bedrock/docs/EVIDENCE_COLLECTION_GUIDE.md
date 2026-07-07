# Evidence Collection Guide

Evidence requirements for each of the 93 security controls. For each control: what to collect, where it lives, and how to generate it.

---

## 1. Input Defense

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 1.1 | Base64/hex/URL encoding detection | Log entries showing decoded payloads blocked | CloudWatch Logs: filter `"event": "input_sanitization_blocked"` with `decoded_payloads` field |
| 1.2 | ChatML/Llama delimiter blocking | Log entries with `delimiter_injections` detected | CloudWatch Logs: filter `"delimiter_injections"` in governance engine logs |
| 1.3 | Unicode homoglyph normalization | Unit test results showing normalization | `pytest tests/ -k homoglyph` output; code review of `_HOMOGLYPH_MAP` in `input_sanitizer.py` |
| 1.4 | Leet-speak pattern decoding | Test payloads blocked (e.g., "1gnore prev1ous") | Demo validation Section 4 results; `run_demo_validation.py` output |
| 1.5 | Context window stuffing detection | Log entries blocking >5000 char inputs | CloudWatch Logs: filter `"context_stuffing": true` |
| 1.6 | Multilingual injection detection | Test payloads in German, Spanish, etc. blocked | Demo validation `german_injection` scenario PASS; attack dataset results |
| 1.7 | Persona/roleplay jailbreak blocking | DAN, developer mode attacks blocked | Demo validation `dan_persona`, `developer_mode` scenarios; 8,470 attack dataset results |
| 1.8 | Harmful content request blocking | Violence, malware, fraud prompts blocked | Demo validation Section 5; Bedrock Guardrails invocation logs |
| 1.9 | AI content classifier (Bedrock Guardrails) | Guardrail invocation records with BLOCKED status | CloudTrail: `bedrock:ApplyGuardrail` events; Bedrock Guardrails console metrics |
| 1.10 | Indirect prompt injection in retrieved data | Tool response validator blocks with injection patterns | CloudWatch Logs: `"event": "tool_response_injection_detected"` |
| 1.11 | Shannon entropy anomaly detection | Entropy scores logged for flagged inputs | CloudWatch Logs: `entropy_score` field in sanitization results |

---

## 2. Tool Response Validation

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 2.1 | Injection pattern detection in tool responses | Blocked responses with `injections_found` list | CloudWatch Logs: `"audit_event": "tool_response_blocked"` |
| 2.2 | Action directive detection | Directives caught (e.g., "call ProductionDeployment") | Log field `injections_found` containing `specific-tool-directive` |
| 2.3 | ChatML/Llama delimiter in tool data | Delimiter injections caught in response data | Log field `injections_found` containing `chatml-delimiter` or `llama-delimiter` |
| 2.4 | Sensitive data stripping from responses | Count of stripped items (ARNs, keys, JWTs) | Log field `sensitive_data_stripped` with type and count |
| 2.5 | Response format anomaly detection | Anomalies list (e.g., `expected_json_got_prose`) | Log field `anomalies` in validation result |
| 2.6 | Response size enforcement | Oversized responses flagged | Log field `anomalies` containing `response_size_exceeded` |
| 2.7 | Entropy scoring on tool output | Entropy score per response | Log field `entropy_score` in validation output |
| 2.8 | Multi-redaction blocking | Responses with >3 redactions fully blocked | Log: `"blocked": true` with reason `Multiple injections detected` |

---

## 3. Output Defense

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 3.1 | System prompt leakage detection | Leakage indicators caught and redacted | CloudWatch Logs: output guardrails `leakage_detected` events |
| 3.2 | ARN/credential/JWT stripping | Count of stripped patterns per response | Output guardrails log: `sensitive_patterns_removed` |
| 3.3 | PII detection and redaction | PII entities detected (SSN blocked, MRN anonymized) | Bedrock Guardrails PII detection logs; demo HIPAA scenario results |
| 3.4 | Canary token tripwire | Canary token presence in output triggers alert | Log: `"event": "canary_token_leaked"` (indicates compromise) |
| 3.5 | Response size hard cap | Truncated responses logged | Output guardrails: `response_truncated` events |
| 3.6 | Exfiltration endpoint allowlisting | Blocked outbound requests to non-allowlisted endpoints | ExfiltrationDetector logs: `"blocked": true` with `pattern_type` |
| 3.7 | Output content safety | Harmful content caught in agent responses | Bedrock Guardrails output evaluation logs |

---

## 4. Policy Enforcement

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 4.1 | OPA policy engine | Policy evaluation results (matched rules, verdicts) | CloudWatch Logs: `policy_evaluation` with `opa_rules` matched |
| 4.2 | Cedar formal verification | Cedar policy files + verification proof output | `sample_data/policies/cedar/` files; Cedar CLI `cedar authorize` output |
| 4.3 | Scope-based progressive autonomy | Scope table entries showing current levels per agent | DynamoDB ScopeTable scan; `aws dynamodb scan --table-name [ScopeTable]` |
| 4.4 | IAM permission boundaries | Boundary ARNs attached to Lambda roles | `aws iam get-role --role-name [ActionGroupLambdaRole]` showing `PermissionsBoundary` |
| 4.5 | Default-deny posture | Deny decisions when no matching policy | Log: `policy_id: "default-deny"` in governance decisions |
| 4.6 | ABAC for data access | Data class checks logged per request | Log: `"audit_event": "undeclared_data_class_violation"` for denials |
| 4.7 | Policy contradiction detection | Proactive engine scan results | `proactive_policy_analysis.py` output showing contradictions found |
| 4.8 | Dead rule identification | List of rules with zero matches over time period | Policy analytics query on decision history table |
| 4.9 | Coverage gap analysis | Uncovered action/scope combinations identified | Proactive engine coverage report |

---

## 5. Per-Tool Security

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 5.1 | Enum-based allowlisting | Rejected requests for unknown action groups | Log: `"audit_event": "allowlist_rejection"` with action group name |
| 5.2 | Tool metadata validation | Validated tool descriptions against policy | CDK template: action group definitions; schema files in `schemas/` |
| 5.3 | Parameter injection scanning | SQL/XSS/path traversal attempts blocked | Log: `"audit_event": "parameter_injection_blocked"` with pattern type |
| 5.4 | Per-invocation tool call cap (25) | Requests exceeding cap denied | Log: `"error_category": "invocation_cap_exceeded"` |
| 5.5 | Recursion depth prevention (max 1) | Recursive calls blocked | Log: `"error_category": "recursion_limit_exceeded"` |
| 5.6 | Sequential tool chain analysis | Flagged suspicious sequences | Log: `tool_chain_detection` events with sequence details |
| 5.7 | Tool Dependency Graph | Pre-defined execution paths in config | `tool_auth_table` CHAIN# entries; architecture documentation |
| 5.8 | Per-tool rate limiting | Rate limit exceeded rejections | Log: `"denial_reason"` containing `rate_limit` |
| 5.9 | Tool output validation | Validation results on every response | Log: `tool_response_validation` entries with pass/fail |
| 5.10 | MCP server authentication | Scoped auth tokens per MCP connection | MCP server config; IAM role trust policies |
| 5.11 | Containerized tool sandboxing | Lambda execution environment isolation | CDK template showing separate Lambda functions per tool category |

---

## 6. Agent Identity and Lifecycle

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 6.1 | Formal agent registration | Registry table entries per agent | DynamoDB AgentRegistryTable scan: `aws dynamodb scan --table-name [AgentRegistryTable]` |
| 6.2 | Agent status tracking | Status field (active/suspended) with timestamps | ScopeTable entries showing `status` and `updated_at` |
| 6.3 | Cryptographic token exchange | Token issuance and validation logs | Token exchange service logs; `token_exchange.py` audit trail |
| 6.4 | Token scoping | Token metadata (data_classes, TTL, revocable) | Token table entries showing constraints per issued token |
| 6.5 | Non-repudiation (SHA-256) | Hash chain records in evidence bucket | S3 evidence objects with `integrity_hash` field; hash chain verification script output |
| 6.6 | Cross-agent rule enforcement | Cross-agent violations denied | Log: `"error_category": "cross_agent_violation"` |
| 6.7 | Supply chain model verification | Model provenance metadata | Bedrock model ARN in CDK; foundation model version pinned to `amazon.nova-micro-v1:0` |
| 6.8 | Finetuning data provenance | Training data lineage documentation | Data provenance records (for custom models); N/A for foundation models |

---

## 7. Memory and RAG Security

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 7.1 | RAG retrieval content validation | Validation results on retrieved documents | Tool response validator logs on RAG-sourced content |
| 7.2 | Web search result sanitization | Sanitized search results before agent processing | Tool response validator applied to search tool responses |
| 7.3 | Long-term memory poisoning detection | Anomaly flags on memory store writes | Memory audit logs showing rejected/flagged insertions |
| 7.4 | Semantic imitation monitoring | Alerts on pattern replication from retrieved experiences | Drift detection comparing action patterns to baseline |
| 7.5 | PII never cached | Cache policy configuration; absence of PII in cache | Cache governance config; periodic cache audit scan results |
| 7.6 | Memory access audit trail | Read/write logs for agent memory stores | DynamoDB stream logs or CloudTrail data events on memory tables |
| 7.7 | Retrieval source attribution | Source tags on all retrieved content | Provenance metadata in evidence records; source field in RAG responses |

---

## 8. Data Governance

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 8.1 | Data classification enforcement | Cedar authorization decisions for PHI access | Cedar policy evaluation logs; PHI access denied/allowed records |
| 8.2 | Tokenized data-lake access | Token check-in/check-out records | Token exchange audit trail; time-bounded access logs |
| 8.3 | Semantic cache governance | Cache eviction policy; PII scan results | Cache configuration; periodic PII scan output showing zero PII cached |
| 8.4 | Exfiltration detection | Blocked exfiltration attempts with pattern type | ExfiltrationDetector logs: endpoint, size, pattern detected |

---

## 9. Monitoring and Detection

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 9.1 | Runtime behavioral drift detection | Drift scores over time per agent | CloudWatch metric: `AGCP/Governance/DriftScore`; drift table records |
| 9.2 | Continuous agent health scoring | Health score history (0-100) per agent | CloudWatch metric: `AGCP/Governance/AgentHealthScore`; AgentHealthTable records |
| 9.3 | Statistical anomaly detection | Entropy and script-mixing flags | Anomaly detection logs with scores and thresholds |
| 9.4 | Sequential tool chain monitoring | Flagged sequences with timestamps | Tool chain detection logs; CHAIN# entries in ToolAuthTable |
| 9.5 | CloudWatch dashboard | Dashboard screenshot or JSON export | `aws cloudwatch get-dashboard --dashboard-name AIGovernance-Monitoring` |
| 9.6 | PHI attestation dashboard | Dashboard showing PHI detection/redaction stats | PHI attestation dashboard export; compliance officer sign-off |
| 9.7 | X-Ray distributed tracing | Trace segments showing governance pipeline flow | X-Ray console: service map + trace timeline for governance requests |
| 9.8 | Model invocation logging | CloudTrail events for Bedrock API calls | CloudTrail: filter `eventSource=bedrock.amazonaws.com` |
| 9.9 | Cross-session drift detection | Baseline comparison across sessions | RuntimeDriftTable `baseline` vs `activity` record comparison |

---

## 10. Incident Response

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 10.1 | Kill switch (<1 second) | Kill switch activation/deactivation timestamps | ScopeTable `kill_switch` record; SNS notification timestamp; CloudWatch alarm |
| 10.2 | Automated scope reduction | Scope reduction events with trigger reason | Log: `graduated_scope_reduction` events; ScopeReductionHistoryTable records |
| 10.3 | SNS operator alerts | Alert delivery confirmations | SNS delivery logs; operator acknowledgment records |
| 10.4 | Graduated escalation | Escalation chain execution (deny > reduce > kill) | Decision history showing progression; approval queue records |
| 10.5 | Evidence preservation | Immutable evidence written during incident | S3 evidence objects with Object Lock confirmation; no deletions in retention period |
| 10.6 | Agent quarantine | Suspended agent with preserved state | ScopeTable showing `status: suspended` with original state preserved in registry |

---

## 11. Evidence and Compliance

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 11.1 | Immutable evidence (S3 Object Lock) | Object Lock configuration; sample evidence object | `aws s3api get-object-lock-configuration --bucket [ImmutableEvidenceBucket]`; sample object metadata |
| 11.2 | SHA-256 hash chain | Hash values matching across chain; verification script output | `evidence_pipeline.py` hash verification; sample chain showing prev_hash linkage |
| 11.3 | ISO 42001 mapping | Control trace records mapped to Annex A | ControlTraceTable query: `control_id BEGINS_WITH "ISO42001"`; compliance refresh output |
| 11.4 | NIST AI RMF mapping | Evidence records tagged with GOVERN/MAP/MEASURE/MANAGE | ControlTraceTable query by framework; `compliance/` S3 prefix contents |
| 11.5 | NIST 800-53 mapping | Control implementation statements per control family | Compliance mapping JSON files in `sample_data/compliance/` |
| 11.6 | PCI DSS v4.0 mapping | Requirement-to-control mapping documentation | Compliance mapping files; control trace records |
| 11.7 | EU AI Act mapping | Article-to-implementation mapping | Compliance mapping files; risk management documentation |
| 11.8 | Inline policy enforcement | Real-time DLP and anomaly detection results | Governance engine decision logs showing inline checks |

---

## 12. Architecture

| # | Control | Evidence Required | Source / How to Collect |
|---|---------|------------------|------------------------|
| 12.1 | Dual-mode execution | Environment variable showing mode | `aws lambda get-function-configuration` for ScopeEnforcer: `GOVERNANCE_MODE` value |
| 12.2 | Parallel execution | Step Functions execution history showing parallel branches | Step Functions console: execution detail with parallel state timing |
| 12.3 | Async evidence writing | EventBridge rule configuration; non-blocking evidence writes | EventBridge rule: `governance.pipeline/GovernanceDecision`; latency logs showing no evidence-write blocking |
| 12.4 | 100K+ concurrent capacity | Step Functions Express type configuration | CDK template: `state_machine_type: "EXPRESS"`; AWS documentation on Express limits |
| 12.5 | Fail-safe deny | Error scenarios resulting in deny (not allow) | Test: invoke with invalid/missing tables -> verify deny response; code review of catch-all handlers |
| 12.6 | Architectural constraint over guardrails | Tool Dependency Graph preventing unplanned calls | IPIGuard-style architecture in `tool_execution_auth.py`; CHAIN# definitions |
| 12.7 | Planning-data separation | Scope enforcer (planning) separate from action group (data) | Architecture diagram; CDK showing separate Lambda functions with different permissions |
| 12.8 | Zero false positives | Demo validation showing legitimate requests pass | `run_demo_validation.py` output: 21/21 PASS including 3 ALLOW scenarios |

---

## How to Generate a Complete Evidence Package

### For Annual Audit

```bash
# 1. Export governance decisions (last 12 months)
aws dynamodb scan --table-name [DecisionHistoryTable] \
  --filter-expression "#ts BETWEEN :start AND :end" \
  --expression-attribute-names '{"#ts":"timestamp"}' \
  --expression-attribute-values '{":start":{"S":"2025-07-01"},":end":{"S":"2026-07-01"}}' \
  > evidence/decisions_annual.json

# 2. Export evidence hash chain integrity
aws s3 ls s3://[ImmutableEvidenceBucket]/evidence/ --recursive | wc -l
aws s3api get-object-lock-configuration --bucket [ImmutableEvidenceBucket]

# 3. Export CloudWatch metrics (monthly aggregates)
aws cloudwatch get-metric-statistics \
  --namespace AGCP/Governance \
  --metric-name DecisionCount \
  --start-time 2025-07-01T00:00:00Z \
  --end-time 2026-07-01T00:00:00Z \
  --period 2592000 \
  --statistics Sum

# 4. Export control traces
aws dynamodb scan --table-name [ControlTraceTable] \
  > evidence/control_traces.json

# 5. CDK template (infrastructure-as-code evidence)
npx cdk synth -c skip_cloudtrail=true > evidence/cloudformation_template.yaml

# 6. Run demo validation (operational evidence)
python test_datasets/run_demo_validation.py > evidence/demo_validation.txt

# 7. Run attack dataset (security effectiveness evidence)
python test_datasets/run_attack_benchmark.py > evidence/attack_benchmark.txt

# 8. Export IAM boundaries
aws iam list-policies --scope Local --query 'Policies[?contains(PolicyName,`Scope`)]'
```

### For Incident Investigation

```bash
# 1. Pull governance decisions for specific agent + time window
aws dynamodb query --table-name [DecisionHistoryTable] \
  --key-condition-expression "agent_id = :aid AND #ts BETWEEN :start AND :end" \
  --expression-attribute-names '{"#ts":"timestamp"}' \
  --expression-attribute-values '{":aid":{"S":"suspect-agent"},":start":{"S":"2026-07-07T10:00:00Z"},":end":{"S":"2026-07-07T12:00:00Z"}}'

# 2. Pull drift detection history
aws dynamodb query --table-name [RuntimeDriftTable] \
  --key-condition-expression "agent_id = :aid" \
  --expression-attribute-values '{":aid":{"S":"suspect-agent"}}'

# 3. Pull tool response validation logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/[ActionGroupLambda] \
  --filter-pattern '"tool_response_blocked"' \
  --start-time [epoch_ms] --end-time [epoch_ms]

# 4. Pull kill switch activation history
aws logs filter-log-events \
  --log-group-name /aws/lambda/[GovernanceEngineLambda] \
  --filter-pattern '"kill_switch_active_denial"'

# 5. Verify evidence integrity (hash chain)
python scripts/verify_evidence_chain.py --bucket [ImmutableEvidenceBucket] --date 2026-07-07
```

### For Continuous Compliance Monitoring

| Frequency | Action | Output |
|-----------|--------|--------|
| Real-time | CloudWatch dashboard review | Visual metrics (verdicts, risk, latency, health) |
| Daily | Automated drift score check | Alert if drift > 50 for any agent |
| Weekly | Decision history export + trend analysis | Week-over-week denial rate, risk score trends |
| Monthly | MEASURE/MANAGE report generation | EventBridge-triggered Lambda output |
| Quarterly | Full control trace export + framework mapping | Compliance package for auditors |
| Annually | Complete evidence package generation | All artifacts above + CDK template + test results |

---

## Evidence Storage Locations

| Evidence Type | Storage | Retention | Integrity |
|---------------|---------|-----------|-----------|
| Governance decisions | DynamoDB DecisionHistoryTable | Indefinite | Table-level encryption |
| Immutable evidence records | S3 ImmutableEvidenceBucket | 7 years (Object Lock) | SHA-256 hash chain + WORM |
| Control traces | DynamoDB ControlTraceTable | Indefinite | Table-level encryption |
| CloudWatch metrics | CloudWatch | 15 months (standard) | AWS-managed |
| CloudTrail events | S3 TrailBucket | Configurable | Log file integrity validation |
| Lambda execution logs | CloudWatch Logs | 30 days (configurable) | AWS-managed |
| CDK templates | Git repository | Indefinite | Git SHA integrity |
| Test results | Git repository + CI artifacts | Indefinite | Git SHA integrity |
