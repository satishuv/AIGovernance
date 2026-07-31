# AARM Conformance Evidence

Maps this framework's implementation to the **AARM v1.0** specification
(Autonomous Action Runtime Management, Feb 2026,
arXiv:2602.09433). AARM defines the system category for agentic runtime
security: Core = R1-R6 (all MUST), Extended = R1-R9 (adds R7-R9 SHOULD).

Target level: **AARM Extended** (technical requirements R1-R9).

> Scope note: this documents the *technical* requirements. AARM also imposes
> organizational conditions to *publicly* claim conformance (5+ production
> customers running 3+ months, a recognized security certification such as
> SOC 2 Type II / ISO 27001 / FedRAMP, TWG engagement, and a TWG-reviewed
> evidence package). Those are not code and are tracked separately; this
> document does not assert a public conformance claim.

## Requirement mapping

| Req | Level | Requirement | Implementation | Test evidence |
|-----|-------|-------------|----------------|---------------|
| R1 | MUST | Pre-execution interception; no fail-open | `scope_enforcer/index.py` entry gate + `pipeline_orchestrator.run_pipeline` fail-closed pipeline; unknown/failed paths return deny | `test_security_governance.py::TestFailClosed*` (OPA exception -> deny), `pipeline_orchestrator` top-level except -> `_deny_response` |
| R2 | MUST | Context accumulation (intent, prior actions, thread) | `decision_history`, session/chain state, `runtime_drift_detection`; `intent_alignment.IntentStore` captures stated intent per session | `test_governance_engine_units.py` decision-history + drift tests; `test_governance_logic.py::TestIntentAlignment` |
| R3 | MUST | Policy evaluation with **intent alignment** | `intent_alignment.assess_alignment` scores action vs stated intent; feeds `context_sufficient`/divergence into `decision_engine.decide` | `test_governance_logic.py::TestIntentAlignment`; `TestDecisionEngine::test_allow_with_insufficient_context_yields_defer` |
| R4 | MUST | **Five decisions**: ALLOW/DENY/MODIFY/STEP_UP/DEFER | `verdicts.py` (5 tokens + `to_aarm` map, escalate->STEP_UP); `decision_engine._resolve_verdict` emits modify/defer; DEFER timeout->deny reuses `approval_workflow.check_timeout` | `test_governance_logic.py::TestVerdicts`, `TestDecisionEngine` modify/defer + precedence cases |
| R5 | MUST | Tamper-evident receipts (offline-verifiable; schema incl. policy hash, delegation, deferral fields) | `evidence_pipeline.write_evidence` SHA-256 hash chain + KMS ECDSA signature over the digest; `EvidenceRecord` carries policy_version_hash, delegation_chain, deferral fields | `test_governance_engine_units.py::TestEvidenceSigning` (offline verify + tamper-fails), `TestEvidenceIntegrity` (hash chain) |
| R6 | MUST | Identity binding (cryptographic; role/scope; preserved across resolve) | Receipt signed with KMS asymmetric key; `session_id`/`agent_role`/`scope_level` are signed content | `TestEvidenceSigning::test_receipt_is_signed`, `test_tampered_identity_fails_signature` |
| R7 | SHOULD | Semantic distance tracking / drift over horizon | `intent_alignment.semantic_distance` (lexical default, Titan optional); divergence biases escalation; rolling distance via `runtime_drift_detection` | `test_governance_logic.py::TestIntentAlignment::test_divergent_action_flags_divergence` |
| R8 | SHOULD | Telemetry export (OpenTelemetry) incl. DEFER events | `telemetry_export.build_otlp_log_record` emits OTLP-JSON logs; called non-blocking from `pipeline_orchestrator` | `test_governance_logic.py::TestTelemetryExport` (schema, STEP_UP map, DEFER event) |
| R9 | SHOULD | Least-privilege at execution time | Graduated autonomy on per-scope IAM permission boundaries swapped/verified before invocation | `test_security_governance.py::TestBoundaryConcurrencySafety` + scope-boundary least-privilege tests |

## Eleven threat classes (AARM threat model)

| # | Threat | Primary control module |
|---|--------|------------------------|
| T1 | Prompt injection | `input_sanitizer`, `threat_detector`, `bedrock_guardrails` |
| T2 | Confused deputy | `tool_execution_auth`, scope enforcement |
| T3 | Data exfiltration | `exfiltration_detector`, `output_guardrails` |
| T4 | Goal hijacking | `behavioral_invariants`, intent alignment (R3) |
| T5 | Memory poisoning | `agent_memory` (poisoning detection), `cache_governance`, `information_flow` (provenance-taint on memory reads from untrusted sources) |
| T6 | Intent drift | `intent_alignment` + `runtime_drift_detection` (R7) + `CumulativeDriftTracker` (rolling session mean) |
| T7 | Cross-agent propagation | `multi_agent` cross-agent rules |
| T8 | Over-privileged credentials | `privilege_escalation`, graduated scope (R9) |
| T9 | Side-channel leakage | `side_channel_defense`: deny-timing floor (removes stage-of-denial latency oracle) + oracle-probing detection (near-identical repeat-request bursts). Residual: hardware/micro-timing channels not defeated. Plus output size/canary limits |
| T10 | Environmental manipulation | `environment_isolation` |
| T11 | Malicious tool output | `tool_response_validator` (perception-gap + forgery detection) |

## Reference architecture (AARM section 6)

This deployment is a **Vendor Integration** (Bedrock Agent action-group entry)
plus a control-plane pipeline. The decision engine is model- and
runtime-agnostic; the Bedrock-specific bindings (guardrail, action-group entry)
are the integration surface.

## Verification

- Unit/integration: `python -m pytest tests/ -q` (344 tests, 1 skipped for `LIVE_AWS=1`).
- Live demo: `python test_datasets/run_demo_validation.py` (21/21).
- Signed-receipt offline verification: `TestEvidenceSigning` proves a receipt
  signed via KMS verifies with the exported public key and fails on any tamper.
- R9 / role separation: `tests/test_compromised_enforcer.py::TestRoleSeparation`
  proves enforcer role holds `iam:PutRolePermissionsBoundary` and action-group role
  does not, via direct IAM policy inspection against live Isengard infrastructure
  (requires `LIVE_AWS=1`).
