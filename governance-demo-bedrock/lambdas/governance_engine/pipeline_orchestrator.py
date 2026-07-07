"""Governance decision pipeline orchestrator.

Runs the 20-step governance pipeline: threat detection, identity checks,
policy evaluation, risk scoring, decision, evidence, and post-decision hooks.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict

import boto3

from agent_identity import AgentIdentityManager
from agent_registry import AgentRegistry
from approval_workflow import ApprovalWorkflow
from behavioral_invariants import BehavioralInvariantsEnforcer
from change_logger import ChangeLogger
from cloudwatch_metrics import CloudWatchMetricsPublisher
from continuous_monitoring import ContinuousMonitoringManager
from control_trace import ControlTraceManager
from decision_engine import DecisionEngine
from decision_history import DecisionHistory
from environment_isolation import EnvironmentIsolation
from evidence_pipeline import EvidencePipeline
from exfiltration_detector import ExfiltrationDetector
from fail_safe import safe_compute_risk, safe_evaluate_policy, safe_write_evidence
from graduated_scope_reduction import GraduatedScopeReduction
from input_sanitizer import InputSanitizer
from kill_switch import KillSwitchManager
from latency import LatencyTracker
from models import GovernanceDecision, PolicyEvaluationResult, RiskAssessment
from multi_agent import MultiAgentManager
from opa_engine import OPAEngine
from policy_engine import PolicyEngine
from privilege_escalation import PrivilegeEscalationDetector
from risk_scoring import RiskScoringEngine
from runtime_drift_detection import RuntimeDriftDetector
from threat_detector import ThreatDetector
from tool_execution_auth import ToolExecutionAuthManager
from tool_model_registry import ToolModelRegistry

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


def _deny_response(reason: str, agent_id: str = "", error_category: str = "governance_denial") -> Dict[str, Any]:
    decision = GovernanceDecision(
        decision_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action_requested="unknown",
        verdict="deny",
        explanation=reason,
        timestamp=_iso_now(),
    )
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
    """Execute the full governance decision pipeline."""
    from index import DecimalEncoder

    agent_id = event.get("agent_id", "")
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
            change_logger = ChangeLogger(dynamodb.Table(CHANGE_LOG_TABLE_NAME)) if CHANGE_LOG_TABLE_NAME else None
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
        if input_text:
            sanitization = input_sanitizer.sanitize(input_text)
            if sanitization.blocked:
                return _deny_response(
                    reason=f"Input blocked by advanced sanitization: {sanitization.block_reason}",
                    agent_id=agent_id, error_category="input_sanitization_blocked",
                )
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

        # Agent identity check
        if identity_manager is not None:
            if identity_manager.is_suspended(agent_id):
                return _deny_response(reason="Agent is suspended", agent_id=agent_id, error_category="agent_suspended")

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

        # Data class access check
        if agent_registry is not None and registry_entry is not None:
            data_class = _derive_data_class(action_group, input_text)
            if data_class:
                if not agent_registry.check_data_class_access(agent_id, data_class):
                    return _deny_response(
                        reason=f"Agent '{agent_id}' attempted to access data class '{data_class}' which is not declared in its registry entry. Declared: {registry_entry.data_classes}",
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
            opa_engine = OPAEngine()
            opa_engine.load_policies_from_s3(boto3.client("s3"), POLICY_BUCKET_NAME, POLICY_PREFIX)

            if opa_engine.rule_count > 0:
                now_utc = datetime.now(timezone.utc)
                opa_input = {**action_request, "hour": now_utc.hour, "day_of_week": now_utc.strftime("%A").lower()}
                opa_decision = opa_engine.evaluate(opa_input)
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

        # Decision
        with tracker.track("decision_engine"):
            decision = decision_engine.decide(policy_result, risk_assessment, action_request, agent_id)

        decision_engine.log_decision(decision)

        # Evidence write
        evidence_record = None
        evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
        with tracker.track("evidence_write_initiation"):
            if evidence_bucket:
                try:
                    ev_s3 = boto3.client("s3")
                    evidence_record = evidence_pipeline.write_evidence(
                        decision=decision, s3_client=ev_s3, bucket=evidence_bucket,
                        environment=agent_environment or "dev", agent_id=agent_id,
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

        # Approval workflow for escalated decisions
        if decision.verdict == "escalate" and approval_workflow is not None:
            try:
                approval_id = approval_workflow.create_pending_approval(decision, timeout_seconds=3600)
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

        if tool_auth_table is not None and decision.verdict == "allow":
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

        try:
            cw_metrics_publisher.publish_latency_metric(latency_metric.total_elapsed_ms, cloudwatch_client)
        except Exception:
            pass

        # Return decision
        response_body = decision.to_dict()
        if canary_tokens:
            response_body["_canary_tokens"] = canary_tokens
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
