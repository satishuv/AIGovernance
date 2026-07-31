"""Governance decision pipeline orchestrator.

Runs the 20-step governance pipeline: threat detection, identity checks,
policy evaluation, risk scoring, decision, evidence, and post-decision hooks.
"""

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import boto3

from agent_identity import AgentIdentityManager
from agent_registry import AgentRegistry
from approval_workflow import ApprovalWorkflow
from behavioral_invariants import BehavioralInvariantsEnforcer
from cloudwatch_metrics import CloudWatchMetricsPublisher
from continuous_monitoring import ContinuousMonitoringManager
from control_trace import ControlTraceManager
from decision_engine import DecisionEngine
from decision_history import DecisionHistory
from environment_isolation import EnvironmentIsolation
from evidence_pipeline import EvidencePipeline
from exfiltration_detector import ExfiltrationDetector
from fail_safe import safe_compute_risk, safe_evaluate_opa, safe_evaluate_policy, safe_write_evidence
from graduated_scope_reduction import GraduatedScopeReduction
from input_sanitizer import InputSanitizer
from kill_switch import KillSwitchManager
from latency import LatencyTracker
from models import GovernanceDecision, PolicyEvaluationResult
from multi_agent import MultiAgentManager
from opa_engine import OPAEngine
from policy_engine import PolicyEngine
from privilege_escalation import PrivilegeEscalationDetector
from risk_scoring import RiskScoringEngine
from runtime_drift_detection import RuntimeDriftDetector
from threat_detector import ThreatDetector
from tool_execution_auth import ToolExecutionAuthManager
from tool_model_registry import ToolModelRegistry
from verdicts import to_aarm as _to_aarm
from intent_alignment import IntentStore, assess_alignment
from telemetry_export import export_decision
from side_channel_defense import ProbeDetector, normalize_deny_timing
from information_flow import FlowTracker, INFORMATION_FLOW_ENABLED, INFORMATION_FLOW_STRICT
from decision_trace import DecisionTraceBuilder, DecisionTraceManager, RESULT_BLOCK

logger = logging.getLogger()

POLICY_BUCKET_NAME = os.environ.get("POLICY_BUCKET_NAME", "")
POLICY_PREFIX = os.environ.get("POLICY_PREFIX", "policies/")
EVIDENCE_BUCKET_NAME = os.environ.get("EVIDENCE_BUCKET_NAME", "")
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
AGENT_REGISTRY_TABLE_NAME = os.environ.get("AGENT_REGISTRY_TABLE_NAME", "")
TOOL_MODEL_REGISTRY_TABLE_NAME = os.environ.get("TOOL_MODEL_REGISTRY_TABLE_NAME", "")
CONTROL_TRACE_TABLE_NAME = os.environ.get("CONTROL_TRACE_TABLE_NAME", "")
THREAT_PATTERNS_TABLE_NAME = os.environ.get("THREAT_PATTERNS_TABLE_NAME", "")
IMMUTABLE_EVIDENCE_BUCKET_NAME = os.environ.get("IMMUTABLE_EVIDENCE_BUCKET_NAME", "")
PENDING_APPROVAL_TABLE_NAME = os.environ.get("PENDING_APPROVAL_TABLE_NAME", "")
CHANGE_LOG_TABLE_NAME = os.environ.get("CHANGE_LOG_TABLE_NAME", "")
DECISION_HISTORY_TABLE_NAME = os.environ.get("DECISION_HISTORY_TABLE_NAME", "")
DENIAL_PATTERN_TABLE_NAME = os.environ.get("DENIAL_PATTERN_TABLE_NAME", "")
EXFILTRATION_ALLOWLIST_TABLE_NAME = os.environ.get("EXFILTRATION_ALLOWLIST_TABLE_NAME", "")
SCOPE_REDUCTION_HISTORY_TABLE_NAME = os.environ.get("SCOPE_REDUCTION_HISTORY_TABLE_NAME", "")
MULTI_AGENT_CONFIG_TABLE_NAME = os.environ.get("MULTI_AGENT_CONFIG_TABLE_NAME", "")
RUNTIME_DRIFT_TABLE_NAME = os.environ.get("RUNTIME_DRIFT_TABLE_NAME", "")
AGENT_HEALTH_TABLE_NAME = os.environ.get("AGENT_HEALTH_TABLE_NAME", "")
TOOL_AUTH_TABLE_NAME = os.environ.get("TOOL_AUTH_TABLE_NAME", "")
DECISION_TRACE_TABLE_NAME = os.environ.get("DECISION_TRACE_TABLE_NAME", "")
# When "true", single-Lambda mode emits a durable EventBridge event and lets the
# PostDecision Lambda write evidence asynchronously, removing the ~1.4s inline
# WORM write from the hot path. Durable (EventBridge retries), so evidence is
# NOT dropped (unlike a naive background thread). Default false = inline write
# (unchanged, fully synchronous, safest).
EVIDENCE_ASYNC = os.environ.get("EVIDENCE_ASYNC", "false").lower() == "true"
EVIDENCE_EVENT_BUS = os.environ.get("EVIDENCE_EVENT_BUS", "default")

_ACTION_GROUP_DATA_CLASS_MAP: Dict[str, str] = {
    "ReadPipelineStatus": "pipeline_status",
    "ProposeChanges": "deployment_config",
    "ReadDeploymentConfig": "deployment_config",
    "WriteDeploymentConfig": "deployment_config",
    "ReadBuildResults": "build_results",
    "ReadTestResults": "test_results",
}

_INPUT_TEXT_DATA_CLASS_HINTS: Dict[str, str] = {
    "pipeline": "pipeline_status",
    "deploy": "deployment_config",
    "build": "build_results",
    "test": "test_results",
    "config": "deployment_config",
}


def _derive_data_class(action_group: str, input_text: str) -> str:
    if action_group in _ACTION_GROUP_DATA_CLASS_MAP:
        return _ACTION_GROUP_DATA_CLASS_MAP[action_group]
    lower_text = (input_text or "").lower()
    for keyword, data_class in _INPUT_TEXT_DATA_CLASS_HINTS.items():
        if keyword in lower_text:
            return data_class
    return ""


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Warm-container OPA policy cache. Loading policies from S3 on every invocation
# costs ~0.5s (measured); policies change rarely, so cache per container with a
# short TTL. Honors the 60s policy-refresh requirement: a warm container picks
# up policy changes within TTL_SECONDS. Safe (no correctness risk): on any load
# error we fall back to a fresh engine, and OPA evaluation itself is fail-closed.
_OPA_CACHE = {"engine": None, "loaded_monotonic": 0.0}
_OPA_CACHE_TTL_SECONDS = 60.0


def _get_cached_opa_engine() -> "OPAEngine":
    now = time.monotonic()
    cached = _OPA_CACHE["engine"]
    if cached is not None and (now - _OPA_CACHE["loaded_monotonic"]) < _OPA_CACHE_TTL_SECONDS:
        return cached
    engine = OPAEngine()
    try:
        engine.load_policies_from_s3(boto3.client("s3"), POLICY_BUCKET_NAME, POLICY_PREFIX)
        _OPA_CACHE["engine"] = engine
        _OPA_CACHE["loaded_monotonic"] = now
    except Exception:
        # Do not cache a failed load; return the (empty) engine so the caller's
        # fail-closed path (safe_evaluate_opa / default-deny) still applies.
        pass
    return engine


# Request-start monotonic time, set per invocation in run_pipeline. Used to
# apply the AARM T9 deny-timing floor so denials do not leak the stage of denial
# via response latency. One request per Lambda container at a time makes a module
# global safe here.
_REQUEST_START_MONOTONIC = None

# Per-request decision-trace builder, set in run_pipeline. _deny_response records
# the decisive blocking stage here so every deny path is captured in one place.
# One request per Lambda container makes a module global safe.
_TRACE_BUILDER = None
# Set per request so _deny_response knows the agent/session/simulation context
# needed to persist a signed trace on early-deny paths (which return before the
# side-effects block).
_TRACE_CONTEXT = {"agent_id": "", "session_id": "", "action": "", "simulation": False}

# Maps an error_category (passed to _deny_response) to a human stage name for the
# auditor trace. Covers the pipeline's blocking stages.
_ERROR_CATEGORY_STAGE = {
    "infrastructure_unavailable": "governance_init",
    "kill_switch_active": "kill_switch",
    "behavioral_invariant_violation": "behavioral_invariants",
    "self_modification": "privilege_escalation",
    "policy_modification": "privilege_escalation",
    "cross_agent_violation": "multi_agent_rules",
    "runtime_drift_critical": "runtime_drift",
    "input_sanitization_blocked": "input_sanitizer",
    "content_safety_blocked": "bedrock_guardrails",
    "threat_detected": "threat_detector",
    "agent_suspended": "agent_identity",
    "agent_not_registered": "agent_registry",
    "cross_environment_violation": "environment_isolation",
    "undeclared_data_class": "data_class_access",
    "unapproved_tool_model": "tool_model_registry",
    "tool_auth_denied": "tool_execution_auth",
    "exfiltration_blocked": "exfiltration_detector",
    "unknown_verdict": "verdict_guard",
    "pipeline_failure": "pipeline",
}


def _deny_response(reason: str, agent_id: str = "", error_category: str = "governance_denial") -> Dict[str, Any]:
    # Record the decisive blocking stage in the auditor trace (single choke point
    # for all deny paths).
    if _TRACE_BUILDER is not None:
        try:
            _TRACE_BUILDER.add(
                stage=_ERROR_CATEGORY_STAGE.get(error_category, error_category),
                result=RESULT_BLOCK, detail=reason, decisive=True,
            )
        except Exception:
            pass
    # AARM T9 timing-oracle defense: hold denials to a minimum time floor so the
    # early-exit stage (kill switch, sanitizer, threat, policy, ...) is not
    # distinguishable by latency. Skipped when no start time is set (e.g. unit
    # tests calling _deny_response directly).
    if _REQUEST_START_MONOTONIC is not None:
        try:
            normalize_deny_timing(_REQUEST_START_MONOTONIC)
        except Exception:
            pass
    decision = GovernanceDecision(
        decision_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action_requested="unknown",
        verdict="deny",
        explanation=reason,
        timestamp=_iso_now(),
    )
    # Persist a signed auditor trace for this deny (early-return paths never reach
    # the side-effects block). Best-effort: never blocks or alters the denial.
    if _TRACE_BUILDER is not None and DECISION_TRACE_TABLE_NAME and not _TRACE_CONTEXT.get("simulation"):
        try:
            trace = _TRACE_BUILDER.build(
                decision_id=decision.decision_id,
                agent_id=agent_id or _TRACE_CONTEXT.get("agent_id", ""),
                action_requested=_TRACE_CONTEXT.get("action", "") or "unknown",
                verdict="deny", session_id=_TRACE_CONTEXT.get("session_id", ""),
            )
            _kms = boto3.client("kms") if os.environ.get("EVIDENCE_SIGNING_KEY_ID") else None
            DecisionTraceManager.sign_and_store(
                trace, boto3.resource("dynamodb").Table(DECISION_TRACE_TABLE_NAME), _kms,
            )
        except Exception:
            pass
    result = decision.to_dict()
    result["error_category"] = error_category
    return result


def _write_evidence_to_s3(decision: GovernanceDecision) -> None:
    if not EVIDENCE_BUCKET_NAME:
        return
    now = datetime.now(timezone.utc)
    key = (
        f"evidence/decisions/{now.year:04d}/{now.month:02d}/"
        f"{now.day:02d}/{decision.decision_id}.json"
    )
    s3_client = boto3.client("s3")
    from index import DecimalEncoder
    s3_client.put_object(
        Bucket=EVIDENCE_BUCKET_NAME,
        Key=key,
        Body=json.dumps(decision.to_dict(), cls=DecimalEncoder),
        ContentType="application/json",
    )


def run_pipeline(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Execute the full governance decision pipeline.

    Supports simulation_mode: when event contains "simulation_mode": true,
    the pipeline evaluates the request fully but skips all side effects
    (evidence writes, CloudWatch metrics, approval notifications, health
    updates, drift recording). Returns enriched response with simulation
    metadata for what-if analysis.
    """
    from index import DecimalEncoder

    # AARM T9: mark request start so denials can be held to a timing floor,
    # removing the stage-of-denial latency oracle.
    global _REQUEST_START_MONOTONIC, _TRACE_BUILDER, _TRACE_CONTEXT
    _REQUEST_START_MONOTONIC = time.monotonic()
    # Auditor decision trace: accumulate stage reasoning across the pipeline.
    _TRACE_BUILDER = DecisionTraceBuilder()

    simulation_mode = event.get("simulation_mode", False)
    agent_id = event.get("agent_id", "")
    _TRACE_CONTEXT = {
        "agent_id": agent_id,
        "session_id": event.get("session_id", "") or event.get("sessionId", ""),
        "action": event.get("action_group", ""),
        "simulation": bool(simulation_mode),
    }
    action_request = {
        "agent_id": agent_id,
        "action_group": event.get("action_group", ""),
        "target_resource": event.get("target_resource", ""),
        "input_text": event.get("input_text", ""),
        "scope_level": int(event.get("scope_level", 1)),
    }
    scope_level = action_request["scope_level"]
    action_group = action_request["action_group"]
    target_resource = action_request["target_resource"]
    input_text = action_request["input_text"]
    session_id = event.get("session_id", "") or event.get("sessionId", "")

    tracker = LatencyTracker()

    try:
        # Initialize engines
        try:
            dynamodb = boto3.resource("dynamodb")
            policy_engine = PolicyEngine()
            risk_engine = RiskScoringEngine()
            risk_engine.load_config()
            decision_engine = DecisionEngine(escalation_threshold=risk_engine.escalation_threshold)

            identity_manager = AgentIdentityManager(dynamodb.Table(SCOPE_TABLE_NAME)) if SCOPE_TABLE_NAME else None
            agent_registry = AgentRegistry(dynamodb.Table(AGENT_REGISTRY_TABLE_NAME)) if AGENT_REGISTRY_TABLE_NAME else None
            tool_model_registry = ToolModelRegistry(dynamodb.Table(TOOL_MODEL_REGISTRY_TABLE_NAME)) if TOOL_MODEL_REGISTRY_TABLE_NAME else None
            env_isolation = EnvironmentIsolation()
            kill_switch_manager = KillSwitchManager()
            scope_table_resource = dynamodb.Table(SCOPE_TABLE_NAME) if SCOPE_TABLE_NAME else None

            threat_detector = ThreatDetector()
            if THREAT_PATTERNS_TABLE_NAME:
                threat_detector.load_patterns(dynamodb.Table(THREAT_PATTERNS_TABLE_NAME))

            evidence_pipeline = EvidencePipeline()
            control_trace_table = dynamodb.Table(CONTROL_TRACE_TABLE_NAME) if CONTROL_TRACE_TABLE_NAME else None

            approval_workflow = ApprovalWorkflow(dynamodb.Table(PENDING_APPROVAL_TABLE_NAME)) if PENDING_APPROVAL_TABLE_NAME else None
            decision_history = DecisionHistory(dynamodb.Table(DECISION_HISTORY_TABLE_NAME)) if DECISION_HISTORY_TABLE_NAME else None

            privilege_escalation_detector = PrivilegeEscalationDetector()
            cw_metrics_publisher = CloudWatchMetricsPublisher()
            cloudwatch_client = boto3.client("cloudwatch")

            exfiltration_detector = ExfiltrationDetector()
            exfiltration_allowlist_table = dynamodb.Table(EXFILTRATION_ALLOWLIST_TABLE_NAME) if EXFILTRATION_ALLOWLIST_TABLE_NAME else None

            graduated_scope_reduction = GraduatedScopeReduction()
            scope_reduction_history_table = dynamodb.Table(SCOPE_REDUCTION_HISTORY_TABLE_NAME) if SCOPE_REDUCTION_HISTORY_TABLE_NAME else None
            denial_pattern_table = dynamodb.Table(DENIAL_PATTERN_TABLE_NAME) if DENIAL_PATTERN_TABLE_NAME else None
            multi_agent_manager = MultiAgentManager()
            multi_agent_config_table = dynamodb.Table(MULTI_AGENT_CONFIG_TABLE_NAME) if MULTI_AGENT_CONFIG_TABLE_NAME else None

        except Exception as init_exc:
            logger.error(json.dumps({
                "event": "governance_tables_unavailable",
                "component_name": "GovernanceEngineInit",
                "failure_type": type(init_exc).__name__,
                "fallback_action_taken": "deny_all",
                "error": str(init_exc),
                "agent_id": agent_id,
                "timestamp": _iso_now(),
            }))
            return _deny_response(
                reason="Governance tables are unavailable. All requests are denied as a fail-safe measure.",
                agent_id=agent_id,
                error_category="infrastructure_unavailable",
            )

        # Kill switch check
        if scope_table_resource is not None:
            kill_result = kill_switch_manager.check_kill_switch(scope_table_resource)
            if kill_result:
                return _deny_response(
                    reason="Kill switch is active. All requests are denied.",
                    agent_id=agent_id,
                    error_category="kill_switch_active",
                )

        # Behavioral invariants
        invariants_enforcer = BehavioralInvariantsEnforcer()
        canary_tokens = []
        pre_invariants = invariants_enforcer.enforce_pre_request(action_request)
        if not pre_invariants.passed:
            return _deny_response(
                reason=f"Behavioral invariant violated: {pre_invariants.block_reason}",
                agent_id=agent_id,
                error_category="behavioral_invariant_violation",
            )
        canary_tokens = pre_invariants.canary_tokens

        # Threat detection
        risk_score_adjustment = 0

        # Privilege escalation hardening
        if privilege_escalation_detector.is_self_modification(agent_id, action_request):
            deny_result = privilege_escalation_detector.deny_and_log(agent_id, action_request, "self_modification")
            if denial_pattern_table is not None:
                exceeded, count = privilege_escalation_detector.track_denial_pattern(agent_id, denial_pattern_table)
                if exceeded and scope_table_resource is not None:
                    sns_client = boto3.client("sns")
                    topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                    privilege_escalation_detector.auto_reduce_scope(agent_id, scope_table_resource, sns_client, topic_arn)
            return deny_result

        if privilege_escalation_detector.is_policy_modification(action_request):
            deny_result = privilege_escalation_detector.deny_and_log(agent_id, action_request, "policy_modification")
            if denial_pattern_table is not None:
                exceeded, count = privilege_escalation_detector.track_denial_pattern(agent_id, denial_pattern_table)
                if exceeded and scope_table_resource is not None:
                    sns_client = boto3.client("sns")
                    topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                    privilege_escalation_detector.auto_reduce_scope(agent_id, scope_table_resource, sns_client, topic_arn)
            return deny_result

        # Multi-agent cross-agent rules
        target_agent_id = action_request.get("target_resource", "")
        if multi_agent_config_table is not None and target_agent_id:
            allowed, violation_reason = multi_agent_manager.enforce_cross_agent_rules(agent_id, target_agent_id, action_request)
            if not allowed:
                return _deny_response(reason=violation_reason, agent_id=agent_id, error_category="cross_agent_violation")

        # Runtime drift detection
        runtime_drift_table = None
        if RUNTIME_DRIFT_TABLE_NAME:
            runtime_drift_table = dynamodb.Table(RUNTIME_DRIFT_TABLE_NAME)
            drift_detector = RuntimeDriftDetector()
            drift_result = drift_detector.compute_drift_score(
                agent_id, action_request.get("action_group", ""),
                action_request.get("target_resource", ""),
                action_request.get("scope_level", 1), runtime_drift_table,
            )
            if drift_result.baseline_present:
                if drift_result.drift_score > 80:
                    return _deny_response(
                        reason=f"Agent behavior drift critical: score {drift_result.drift_score:.0f}/100. {drift_result.factors}",
                        agent_id=agent_id, error_category="runtime_drift_critical",
                    )
                elif drift_result.drift_score > 50:
                    risk_score_adjustment += int(drift_result.drift_score * 0.3)

        # Input sanitization
        input_sanitizer = InputSanitizer()
        modification_applied = False
        if input_text:
            sanitization = input_sanitizer.sanitize(input_text)
            if sanitization.blocked:
                return _deny_response(
                    reason=f"Input blocked by advanced sanitization: {sanitization.block_reason}",
                    agent_id=agent_id, error_category="input_sanitization_blocked",
                )
            # AARM R4 MODIFY: a non-blocking transform occurred (sanitized text
            # differs from the original). Surfaced as the MODIFY verdict so the
            # transformed request executes explicitly rather than silently.
            if sanitization.sanitized_text != input_text:
                modification_applied = True
            input_text = sanitization.sanitized_text

        # Bedrock Guardrails
        from bedrock_guardrails import BedrockGuardrailsEvaluator
        guardrail_evaluator = BedrockGuardrailsEvaluator()
        if guardrail_evaluator.configured and input_text:
            guardrail_result = guardrail_evaluator.evaluate_input(input_text)
            if guardrail_result.blocked:
                return _deny_response(
                    reason=f"Input blocked by content safety guardrail: {guardrail_result.explanation}",
                    agent_id=agent_id, error_category="content_safety_blocked",
                )

        # Threat detector patterns
        if input_text and threat_detector._patterns:
            threat_result = threat_detector.evaluate(input_text, agent_id)
            if threat_result["classification"] == "denied":
                matched_categories = list({p["category"] for p in threat_result["matched_patterns"]})
                return _deny_response(
                    reason=f"Input denied by threat detection: matched {', '.join(matched_categories)} pattern.",
                    agent_id=agent_id, error_category="threat_detected",
                )
            elif threat_result["classification"] == "suspicious":
                risk_score_adjustment = threat_result.get("risk_score_adjustment", 0)

        # Agent identity check + freshness/revocation validation (AARM R6).
        # Consolidated gate: no verifiable identity, a revoked/suspended
        # principal, or a stale/revoked token all deny; transient trusted-source
        # errors are flagged onto the decision rather than silently trusted.
        from identity_validation import validate_identity
        identity_token = event.get("identity_token")
        identity_result = validate_identity(agent_id, identity_manager, token=identity_token)
        if identity_result.deny:
            return _deny_response(
                reason=identity_result.reason, agent_id=agent_id,
                error_category="identity_unverified",
            )

        # Agent registry check
        registry_entry = None
        if agent_registry is not None:
            registry_entry = agent_registry.get_agent(agent_id)
            if registry_entry is None:
                return _deny_response(
                    reason="Agent not registered in governance registry",
                    agent_id=agent_id, error_category="agent_not_registered",
                )

        # Environment isolation check
        agent_environment = ""
        if registry_entry is not None:
            agent_environment = registry_entry.environment
            target_env = target_resource if target_resource in {"dev", "staging", "prod"} else agent_environment
            if agent_environment not in ("all", "") and not env_isolation.check_cross_environment(agent_environment, target_env):
                return _deny_response(
                    reason=f"Cross-environment action denied: agent environment '{agent_environment}' does not match target environment '{target_env}'",
                    agent_id=agent_id, error_category="cross_environment_violation",
                )

        # Data class access check + sensitivity classification (AARM R2).
        # Derive the data class; when classification is unavailable, fail safe to
        # the HIGHEST sensitivity level rather than treating data as unclassified.
        derived_data_class = _derive_data_class(action_group, input_text)
        from data_sensitivity import classify_sensitivity, is_classification_available
        action_request["data_class"] = derived_data_class
        action_request["data_sensitivity"] = classify_sensitivity(derived_data_class)
        action_request["classification_available"] = is_classification_available(derived_data_class)
        if agent_registry is not None and registry_entry is not None:
            if derived_data_class:
                if not agent_registry.check_data_class_access(agent_id, derived_data_class):
                    return _deny_response(
                        reason=f"Agent '{agent_id}' attempted to access data class '{derived_data_class}' which is not declared in its registry entry. Declared: {registry_entry.data_classes}",
                        agent_id=agent_id, error_category="undeclared_data_class",
                    )

        # Tool/Model usage check
        if tool_model_registry is not None and action_group:
            if not tool_model_registry.check_usage_allowed(category="tool_connector", name=action_group, version="*"):
                return _deny_response(
                    reason=f"Action group '{action_group}' is not approved in the Tool/Model Registry",
                    agent_id=agent_id, error_category="unapproved_tool_model",
                )

        # Tool execution authorization
        tool_auth_table = None
        if TOOL_AUTH_TABLE_NAME:
            tool_auth_table = dynamodb.Table(TOOL_AUTH_TABLE_NAME)
            tool_exec_auth = ToolExecutionAuthManager()
            tool_name = event.get("tool_name", "") or action_request.get("action_group", "")
            tool_parameters = event.get("tool_parameters", {})
            if tool_name:
                tool_auth_result = tool_exec_auth.authorize_tool(agent_id, tool_name, tool_parameters, tool_auth_table)
                if not tool_auth_result.authorized:
                    return _deny_response(
                        reason=f"Tool execution denied: {tool_auth_result.denial_reason}",
                        agent_id=agent_id, error_category="tool_auth_denied",
                    )

        # Policy evaluation
        if agent_environment:
            env_policy_filter = env_isolation.get_environment_policy_filter(agent_environment)
            action_request["environment_filter"] = env_policy_filter

        with tracker.track("policy_evaluation"):
            opa_engine = _get_cached_opa_engine()

            if opa_engine.rule_count > 0:
                now_utc = datetime.now(timezone.utc)
                opa_input = {**action_request, "hour": now_utc.hour, "day_of_week": now_utc.strftime("%A").lower()}
                opa_decision = safe_evaluate_opa(opa_engine, opa_input)
                policy_result = PolicyEvaluationResult(
                    policy_id=opa_decision.matched_rules[0] if opa_decision.matched_rules else "default-deny",
                    outcome=opa_decision.verdict,
                    matching_conditions={"opa_rules": opa_decision.matched_rules},
                    evaluation_timestamp=opa_decision.timestamp,
                )
            else:
                policy_result = safe_evaluate_policy(policy_engine, action_request)

        # Risk scoring
        with tracker.track("risk_scoring"):
            risk_assessment = safe_compute_risk(risk_engine, action_request, scope_level)

        if risk_score_adjustment > 0:
            adjusted = min(100, risk_assessment.risk_score + risk_score_adjustment)
            risk_assessment.risk_score = adjusted
            if adjusted >= risk_engine.escalation_threshold:
                risk_assessment.escalation_flagged = True

        # Record policy + risk reasoning for the auditor trace.
        try:
            _TRACE_BUILDER.add(
                stage="policy_evaluation", result="pass",
                detail=f"policy outcome '{policy_result.outcome}' (policy {policy_result.policy_id})",
                extra={"policy_id": policy_result.policy_id, "outcome": policy_result.outcome},
            )
            _TRACE_BUILDER.add(
                stage="risk_scoring", result="pass",
                detail=f"risk score {risk_assessment.risk_score:.1f} / threshold {risk_engine.escalation_threshold:.0f}",
                extra={"risk_factors": dict(getattr(risk_assessment, "factors_applied", {}) or {})},
            )
        except Exception:
            pass

        # Intent alignment (AARM R3) + drift accumulation (AARM R7).
        # Capture the stated intent on the first request of a session, then
        # score the current action's alignment. Ambiguous alignment yields
        # insufficient context (-> DEFER); strong divergence biases to escalate.
        # Never fails the pipeline: any error leaves context_sufficient=True.
        context_sufficient = True
        if runtime_drift_table is not None and input_text:
            try:
                intent_store = IntentStore(runtime_drift_table)
                intent_store.capture_intent(agent_id, session_id, input_text)
                stated_intent = intent_store.get_intent(agent_id, session_id)
                action_descriptor = f"{action_group} {target_resource} {input_text}".strip()
                alignment = assess_alignment(stated_intent, action_descriptor)
                context_sufficient = alignment.context_sufficient
                if alignment.divergent and risk_assessment is not None:
                    # Strong divergence from stated intent escalates for review.
                    risk_assessment.risk_score = min(100, risk_assessment.risk_score + 30)
                    if risk_assessment.risk_score >= risk_engine.escalation_threshold:
                        risk_assessment.escalation_flagged = True
                # AARM R7: accumulate cumulative drift across the session (not
                # just per-action). Slow drift that stays under the per-action
                # bar still escalates once the session running-mean crosses the
                # calibrated threshold.
                if stated_intent:
                    from intent_alignment import CumulativeDriftTracker
                    cdrift = CumulativeDriftTracker(runtime_drift_table).record_distance(
                        session_id or agent_id, alignment.distance)
                    if cdrift.drift_exceeded and risk_assessment is not None:
                        risk_assessment.risk_score = min(100, risk_assessment.risk_score + 25)
                        if risk_assessment.risk_score >= risk_engine.escalation_threshold:
                            risk_assessment.escalation_flagged = True
                        logger.info(json.dumps({
                            "event": "cumulative_drift_exceeded",
                            "agent_id": agent_id, "session_id": session_id,
                            "mean_distance": cdrift.mean_distance,
                            "action_count": cdrift.action_count,
                            "timestamp": _iso_now(),
                        }))
            except Exception:
                context_sufficient = True

        # Side-channel oracle-probing detection (AARM T9). A burst of
        # near-identical requests within a session is the signature of bit-by-bit
        # side-channel extraction; flag it to escalate rather than answer the
        # oracle. Never fails the pipeline.
        if runtime_drift_table is not None and input_text and session_id:
            try:
                probe = ProbeDetector(runtime_drift_table).record_and_check(session_id, input_text)
                if probe.is_probing and risk_assessment is not None:
                    risk_assessment.risk_score = min(100, risk_assessment.risk_score + 40)
                    if risk_assessment.risk_score >= risk_engine.escalation_threshold:
                        risk_assessment.escalation_flagged = True
                    logger.info(json.dumps({
                        "event": "side_channel_probe_detected",
                        "agent_id": agent_id, "session_id": session_id,
                        "similar_count": probe.similar_count,
                        "timestamp": _iso_now(),
                    }))
            except Exception:
                pass

        # Information-flow taint tracking (cross-turn, provenance-based).
        # Records the source trust for the current request; if the session has
        # seen untrusted data (tool response, retrieved doc, web, MCP) AND this
        # action is a privileged sink, flags the flow. Never blocks on its own:
        # a tainted flow adds to the risk score so the decision engine decides,
        # and any exception leaves the pipeline unchanged (fail-open).
        if INFORMATION_FLOW_ENABLED:
            try:
                ifc_table = dynamodb.Table(RUNTIME_DRIFT_TABLE_NAME) if RUNTIME_DRIFT_TABLE_NAME else None
                ifc_tracker = FlowTracker(ifc_table)
                current_source = event.get("source_type", "") or event.get("input_source", "")
                data_sensitivity = action_request.get("data_sensitivity", "")
                has_external_output = action_group in {
                    "SendEmail", "TransferFunds", "DeleteResource", "WriteDeploymentConfig",
                }
                ifc_verdict = ifc_tracker.check_flow(
                    session_id=session_id,
                    current_source=current_source,
                    action_group=action_group,
                    data_sensitivity=data_sensitivity,
                    has_external_output=has_external_output,
                )
                if ifc_verdict.tainted_sink:
                    logger.info(json.dumps({
                        "event": "information_flow_tainted_sink",
                        "agent_id": agent_id, "session_id": session_id,
                        "action_group": action_group,
                        "signal": ifc_verdict.signal,
                        "reason": ifc_verdict.reason,
                        "timestamp": _iso_now(),
                    }))
                    if ifc_verdict.signal == "deny" and INFORMATION_FLOW_STRICT:
                        return _deny_response(
                            reason=f"Information-flow control: {ifc_verdict.reason}",
                            agent_id=agent_id,
                            error_category="information_flow_tainted",
                        )
                    if risk_assessment is not None:
                        risk_assessment.risk_score = min(100, risk_assessment.risk_score + 25)
                        if risk_assessment.risk_score >= risk_engine.escalation_threshold:
                            risk_assessment.escalation_flagged = True
                try:
                    _TRACE_BUILDER.add(
                        stage="information_flow",
                        result="block" if (ifc_verdict.tainted_sink and INFORMATION_FLOW_STRICT) else (
                            "flag" if ifc_verdict.tainted_sink else "pass"
                        ),
                        detail=ifc_verdict.reason or f"source_trust={ifc_verdict.source_trust} privileged_sink={ifc_verdict.privileged_sink}",
                        extra=ifc_verdict.to_trace_extra(),
                    )
                except Exception:
                    pass
            except Exception as ifc_exc:
                logger.warning(json.dumps({
                    "event": "information_flow_check_error",
                    "error": str(ifc_exc)[:120],
                    "timestamp": _iso_now(),
                }))

        # Decision
        with tracker.track("decision_engine"):
            decision = decision_engine.decide(
                policy_result, risk_assessment, action_request, agent_id,
                modification_applied=modification_applied,
                context_sufficient=context_sufficient,
            )

        # DEFER dependent-action cascade bound (AARM R4). A deferred action
        # cascades into the session's suspended set; if the cascade exceeds the
        # configured limit, convert DEFER -> DENY so unresolved defers cannot
        # accumulate unbounded.
        if decision.verdict == "defer" and runtime_drift_table is not None and session_id:
            try:
                from defer_cascade import DeferCascadeTracker
                cascade = DeferCascadeTracker(runtime_drift_table).register_defer(session_id)
                if cascade.verdict == "deny":
                    decision.verdict = "deny"
                    decision.explanation = cascade.reason
            except Exception:
                pass

        decision_engine.log_decision(decision)

        # Record the final decision stage in the auditor trace. If no earlier
        # stage was marked decisive (e.g. a clean allow), the decision engine is.
        try:
            already_decisive = any(s.get("decisive") for s in _TRACE_BUILDER.stages)
            _TRACE_BUILDER.add(
                stage="decision_engine", result="pass",
                detail=decision.explanation, decisive=not already_decisive,
            )
        except Exception:
            pass

        # --- Side effects (skipped in simulation mode) ---
        if not simulation_mode:
            # Auditor decision trace (AARM auditability): assemble the per-stage
            # rationale, sign it, and store it. Best-effort like evidence write:
            # a trace failure must never change the verdict.
            if DECISION_TRACE_TABLE_NAME:
                try:
                    trace_builder = _TRACE_BUILDER
                    trace = trace_builder.build(
                        decision_id=decision.decision_id, agent_id=agent_id,
                        action_requested=decision.action_requested, verdict=decision.verdict,
                        session_id=session_id,
                        risk_factors=dict(getattr(risk_assessment, "factors_applied", {}) or {}),
                        policy_id=getattr(policy_result, "policy_id", ""),
                    )
                    trace_kms = boto3.client("kms") if os.environ.get("EVIDENCE_SIGNING_KEY_ID") else None
                    DecisionTraceManager.sign_and_store(
                        trace, dynamodb.Table(DECISION_TRACE_TABLE_NAME), trace_kms,
                    )
                except Exception as tr_exc:
                    logger.error(json.dumps({
                        "event": "decision_trace_pipeline_failed",
                        "error": str(tr_exc), "decision_id": decision.decision_id,
                        "timestamp": _iso_now(),
                    }))
            # Evidence write
            evidence_record = None
            evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
            with tracker.track("evidence_write_initiation"):
                if EVIDENCE_ASYNC:
                    # Durable async path: emit the decision to EventBridge; the
                    # PostDecision Lambda performs the WORM write off the hot path.
                    # EventBridge retries on failure, so evidence is not lost.
                    # Removes ~1.4s from ALLOW latency. Control trace below is
                    # skipped here (PostDecision owns downstream side effects).
                    try:
                        boto3.client("events").put_events(Entries=[{
                            "Source": "governance.pipeline",
                            "DetailType": "GovernanceDecision",
                            "Detail": json.dumps(decision.to_dict(), cls=DecimalEncoder),
                            "EventBusName": EVIDENCE_EVENT_BUS,
                        }])
                    except Exception as ev_exc:
                        # If the event emit fails, fall back to a synchronous
                        # inline write so evidence is never silently dropped.
                        logger.error(json.dumps({
                            "event": "evidence_async_emit_failed_falling_back_inline",
                            "error": str(ev_exc), "decision_id": decision.decision_id, "timestamp": _iso_now(),
                        }))
                        if evidence_bucket:
                            try:
                                ev_kms = boto3.client("kms") if os.environ.get("EVIDENCE_SIGNING_KEY_ID") else None
                                evidence_record = evidence_pipeline.write_evidence(
                                    decision=decision, s3_client=boto3.client("s3"), bucket=evidence_bucket,
                                    environment=agent_environment or "dev", agent_id=agent_id, kms_client=ev_kms,
                                    session_id=session_id, agent_role=agent_environment or "", scope_level=scope_level)
                            except Exception:
                                try:
                                    cw_metrics_publisher.publish_evidence_failure_metric(cloudwatch_client)
                                except Exception:
                                    pass
                elif evidence_bucket:
                    try:
                        ev_s3 = boto3.client("s3")
                        # AARM R5/R6: sign the receipt when a signing key is
                        # configured. KMS client init is cheap and skipped-signing
                        # is safe when EVIDENCE_SIGNING_KEY_ID is unset.
                        ev_kms = boto3.client("kms") if os.environ.get("EVIDENCE_SIGNING_KEY_ID") else None
                        policy_version_hash = ""
                        try:
                            policy_version_hash = hashlib.sha256(
                                json.dumps(policy_result.to_dict(), sort_keys=True, default=str).encode("utf-8")
                            ).hexdigest()
                        except Exception:
                            policy_version_hash = ""
                        evidence_record = evidence_pipeline.write_evidence(
                            decision=decision, s3_client=ev_s3, bucket=evidence_bucket,
                            environment=agent_environment or "dev", agent_id=agent_id,
                            kms_client=ev_kms,
                            session_id=session_id,
                            agent_role=agent_environment or "",
                            scope_level=scope_level,
                            policy_version_hash=policy_version_hash,
                        )
                    except Exception as ev_exc:
                        logger.error(json.dumps({
                            "event": "evidence_pipeline_write_failed",
                            "error": str(ev_exc), "decision_id": decision.decision_id, "timestamp": _iso_now(),
                        }))
                        try:
                            cw_metrics_publisher.publish_evidence_failure_metric(cloudwatch_client)
                        except Exception:
                            pass
                else:
                    safe_write_evidence(_write_evidence_to_s3, decision)

            # Control trace
            if evidence_record is not None and control_trace_table is not None:
                try:
                    traces = evidence_pipeline.generate_control_traces(evidence_record, evidence_record.framework_mapping or [])
                    if traces:
                        ControlTraceManager.store_traces(traces, control_trace_table)
                except Exception as ct_exc:
                    logger.error(json.dumps({
                        "event": "control_trace_storage_failed",
                        "error": str(ct_exc), "decision_id": decision.decision_id, "timestamp": _iso_now(),
                    }))

            # Approval workflow for escalated (STEP_UP) and deferred decisions.
            # DEFER suspends pending more context with a shorter timeout; both
            # reuse the pending-approval record + auto-timeout-to-deny path.
            if decision.verdict in ("escalate", "defer") and approval_workflow is not None:
                try:
                    _timeout = 300 if decision.verdict == "defer" else 3600
                    approval_id = approval_workflow.create_pending_approval(decision, timeout_seconds=_timeout)
                    approval_record = approval_workflow._get_approval(approval_id)
                    if approval_record is not None:
                        try:
                            sns_client = boto3.client("sns")
                            topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                            if topic_arn:
                                approval_workflow.notify_approvers(approval_record, sns_client, topic_arn)
                        except Exception:
                            pass
                except Exception as aw_exc:
                    logger.error(json.dumps({
                        "event": "approval_workflow_failed",
                        "error": str(aw_exc), "decision_id": decision.decision_id, "timestamp": _iso_now(),
                    }))

            # Decision history
            if decision_history is not None:
                try:
                    decision_history.index_decision(decision)
                except Exception as dh_exc:
                    logger.error(json.dumps({
                        "event": "decision_history_indexing_failed",
                        "error": str(dh_exc), "decision_id": decision.decision_id, "timestamp": _iso_now(),
                    }))

            # CloudWatch metrics
            try:
                cw_metrics_publisher.publish_decision_metric(decision.verdict, cloudwatch_client)
                cw_metrics_publisher.publish_risk_score_metric(risk_assessment.risk_score, cloudwatch_client)
            except Exception:
                pass

            # AARM R8: OpenTelemetry export (OTLP-JSON) for SIEM/observability.
            # Non-blocking; DEFER/STEP_UP/MODIFY all exported with AARM decision names.
            export_decision(decision.to_dict())

            # Continuous monitoring + drift recording
            if AGENT_HEALTH_TABLE_NAME:
                try:
                    health_table = dynamodb.Table(AGENT_HEALTH_TABLE_NAME)
                    health_monitor = ContinuousMonitoringManager()
                    health_monitor.update_health(agent_id, decision.verdict, risk_assessment.risk_score if risk_assessment else 0, health_table)
                except Exception:
                    pass

            if runtime_drift_table is not None:
                try:
                    drift_detector = RuntimeDriftDetector()
                    drift_detector.record_activity(agent_id, action_request.get("action_group", ""), action_request.get("target_resource", ""), action_request.get("scope_level", 1), runtime_drift_table)
                except Exception:
                    pass

            # allow and modify both execute the action (modify runs the
            # sanitized/transformed version), so both record the tool call.
            if tool_auth_table is not None and decision.verdict in ("allow", "modify"):
                try:
                    tool_name = event.get("tool_name", "") or action_request.get("action_group", "")
                    if tool_name:
                        tool_exec_auth = ToolExecutionAuthManager()
                        tool_exec_auth.record_tool_call(agent_id, tool_name, tool_auth_table)
                except Exception:
                    pass

            # Output exfiltration check
            output_text = event.get("output_text", "")
            if output_text:
                try:
                    exfil_config = {}
                    if exfiltration_allowlist_table is not None:
                        allowlist = exfiltration_detector.load_allowlist(exfiltration_allowlist_table)
                        exfil_config["allowlist"] = allowlist
                    exfil_result = exfiltration_detector.evaluate_output(agent_id, output_text, scope_level, exfil_config)
                    if exfil_result.blocked:
                        exfiltration_detector.block_and_log(agent_id, exfil_result)
                        return _deny_response(
                            reason=f"Output blocked: {exfil_result.pattern_type} detected",
                            agent_id=agent_id, error_category="exfiltration_blocked",
                        )
                except Exception:
                    pass

            # Graduated scope reduction
            if (decision_history is not None and scope_reduction_history_table is not None and scope_table_resource is not None):
                try:
                    rolling_avg, dec_count = graduated_scope_reduction.compute_rolling_avg_risk(agent_id, dynamodb.Table(DECISION_HISTORY_TABLE_NAME))
                    if rolling_avg > 0:
                        threshold = 70.0
                        exceeded, duration = graduated_scope_reduction.check_sustained_threshold(agent_id, rolling_avg, threshold, 1800, scope_reduction_history_table)
                        if exceeded:
                            cooldown_active, remaining = graduated_scope_reduction.check_cooldown(agent_id, scope_reduction_history_table)
                            if not cooldown_active:
                                mode = graduated_scope_reduction.get_reduction_mode(dynamodb.Table(os.environ.get("RISK_CONFIG_TABLE_NAME", "")))
                                sns_client = boto3.client("sns")
                                topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                                graduated_scope_reduction.execute_reduction(
                                    agent_id, mode, scope_table_resource,
                                    dynamodb.Table(PENDING_APPROVAL_TABLE_NAME) if PENDING_APPROVAL_TABLE_NAME else None,
                                    sns_client, topic_arn,
                                    {"rolling_avg": rolling_avg, "threshold": threshold, "sustained_seconds": duration},
                                )
                except Exception:
                    pass

        # Latency metric
        latency_metric = tracker.record_latency(decision.decision_id)
        decision.latency_breakdown = latency_metric.component_latencies

        if not simulation_mode:
            try:
                cw_metrics_publisher.publish_latency_metric(latency_metric.total_elapsed_ms, cloudwatch_client)
            except Exception:
                pass

        # Return decision
        response_body = decision.to_dict()
        if canary_tokens:
            response_body["_canary_tokens"] = canary_tokens
        if simulation_mode:
            response_body["simulation"] = True
            # allow and modify both execute (modify runs the transformed action).
            response_body["would_execute"] = decision.verdict in ("allow", "modify")
            response_body["aarm_decision"] = _to_aarm(decision.verdict)
            response_body["side_effects_skipped"] = [
                "evidence_write", "control_trace", "approval_workflow",
                "decision_history", "cloudwatch_metrics", "health_update",
                "drift_recording", "scope_reduction",
            ]
            response_body["risk_factors"] = {
                "scope_level": scope_level,
                "action_group": action_group,
                "target_resource": target_resource,
                "risk_score": risk_assessment.risk_score if risk_assessment else 0,
                "escalation_threshold": risk_engine.escalation_threshold,
                "exceeds_threshold": (risk_assessment.risk_score if risk_assessment else 0) >= risk_engine.escalation_threshold,
            }
            if decision.verdict == "escalate":
                response_body["remediation"] = "Request human approval via the approval API, or reduce risk by using a lower scope level"
            elif decision.verdict == "defer":
                response_body["remediation"] = "Provide the missing session context (stated intent / disambiguation); unresolved defers time out to deny"
            elif decision.verdict == "modify":
                response_body["remediation"] = "The request will execute in sanitized/transformed form; no action needed"
            elif decision.verdict == "deny":
                response_body["remediation"] = f"Action requires appropriate scope and policy. Current scope: {scope_level}"
        return json.loads(json.dumps(response_body, cls=DecimalEncoder))

    except Exception as exc:
        logger.error(json.dumps({
            "event": "governance_pipeline_failure",
            "component_name": "GovernanceEnginePipeline",
            "failure_type": type(exc).__name__,
            "fallback_action_taken": "deny",
            "error": str(exc),
            "agent_id": agent_id,
            "timestamp": _iso_now(),
        }))
        return _deny_response(
            reason=f"Governance pipeline failure: {type(exc).__name__}. Request denied as fail-safe.",
            agent_id=agent_id, error_category="pipeline_failure",
        )
