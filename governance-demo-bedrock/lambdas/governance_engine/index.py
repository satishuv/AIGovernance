"""Governance Engine Lambda handler — orchestrates the full governance decision pipeline.

Entry point for the Governance Engine Lambda. Invoked synchronously by the
Scope Enforcer to evaluate agent action requests against policies, compute
risk scores, produce governance decisions, write evidence, and track latency.

Pipeline steps (Phase 1a + Phase 1b + Phase 1c):
1.  Parse incoming event (agent_id, action_group, target_resource, input_text, scope_level)
2.  Initialize LatencyTracker
3.  Kill switch check — deny all if active (Req 8.3)
4.  Threat detection — deny if known_bad, adjust risk if suspicious (Req 12.1, 12.2, 12.3)
5.  Agent Identity check — deny if agent is suspended (Req 5.4)
6.  Agent Registry check — deny if agent has no registry entry (Req 6.2)
7.  Environment Isolation check — deny if cross-environment action (Req 19.2, 19.5)
8.  Data class access check — deny if undeclared data class (Req 6.4)
9.  Tool/Model usage check — deny if unapproved tool/model/data_source (Req 7.3, 7.4, 7.5)
10. Pass environment to policy engine for scoped evaluation (Req 19.2)
11. Policy evaluation via safe_evaluate_policy() (Req 2.1, 18.1)
12. Risk scoring via safe_compute_risk() (Req 3.1, 18.3)
13. Decision engine verdict (Req 4.1)
14. Log structured decision record (Req 4.6, 4.9)
15. Evidence write via EvidencePipeline (Req 9.1, 9.4)
16. Control trace generation and storage (Req 13.1, 13.2)
17. Record latency metric (Req 17.1, 17.2)
18. Return GovernanceDecision as JSON response

DynamoDB unavailability: if governance tables are unreachable, deny all
requests and log a structured failure record (Req 18.2).

Requirements: 1.1, 2.1, 3.1, 4.1, 5.4, 6.2, 6.4, 7.3, 7.4, 7.5, 8.3, 9.1, 9.4, 12.1, 12.2, 12.3, 13.1, 13.2, 17.1, 18.1, 18.2, 18.4, 18.5, 19.2, 19.5
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import boto3

from .agent_identity import AgentIdentityManager
from .agent_registry import AgentRegistry
from .control_trace import ControlTraceManager
from .decision_engine import DecisionEngine
from .environment_isolation import EnvironmentIsolation
from .evidence_pipeline import EvidencePipeline
from .fail_safe import safe_compute_risk, safe_evaluate_policy, safe_write_evidence
from .kill_switch import KillSwitchManager
from .latency import LatencyTracker
from .models import GovernanceDecision, PolicyEvaluationResult, RiskAssessment
from .policy_engine import PolicyEngine
from .risk_scoring import RiskScoringEngine
from .threat_detector import ThreatDetector
from .tool_model_registry import ToolModelRegistry

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
POLICY_BUCKET_NAME = os.environ.get("POLICY_BUCKET_NAME", "")
POLICY_PREFIX = os.environ.get("POLICY_PREFIX", "policies/")
EVIDENCE_BUCKET_NAME = os.environ.get("EVIDENCE_BUCKET_NAME", "")
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
AGENT_REGISTRY_TABLE_NAME = os.environ.get("AGENT_REGISTRY_TABLE_NAME", "")
TOOL_MODEL_REGISTRY_TABLE_NAME = os.environ.get("TOOL_MODEL_REGISTRY_TABLE_NAME", "")
CONTROL_TRACE_TABLE_NAME = os.environ.get("CONTROL_TRACE_TABLE_NAME", "")
THREAT_PATTERNS_TABLE_NAME = os.environ.get("THREAT_PATTERNS_TABLE_NAME", "")
CONTROL_MAPPING_TABLE_NAME = os.environ.get("CONTROL_MAPPING_TABLE_NAME", "")
IMMUTABLE_EVIDENCE_BUCKET_NAME = os.environ.get("IMMUTABLE_EVIDENCE_BUCKET_NAME", "")


# ---------------------------------------------------------------------------
# Data class derivation heuristics
# ---------------------------------------------------------------------------
# Maps action_group names to their associated data classes.
_ACTION_GROUP_DATA_CLASS_MAP: Dict[str, str] = {
    "ReadPipelineStatus": "pipeline_status",
    "ProposeChanges": "deployment_config",
    "ReadDeploymentConfig": "deployment_config",
    "WriteDeploymentConfig": "deployment_config",
    "ReadBuildResults": "build_results",
    "ReadTestResults": "test_results",
}

# Keywords in input_text that hint at a data class.
_INPUT_TEXT_DATA_CLASS_HINTS: Dict[str, str] = {
    "pipeline": "pipeline_status",
    "deploy": "deployment_config",
    "build": "build_results",
    "test": "test_results",
    "config": "deployment_config",
}


def _derive_data_class(action_group: str, input_text: str) -> str:
    """Derive the data class from the action_group or input_text.

    Checks the action_group map first; falls back to keyword matching
    in input_text. Returns empty string if no data class can be derived.
    """
    if action_group in _ACTION_GROUP_DATA_CLASS_MAP:
        return _ACTION_GROUP_DATA_CLASS_MAP[action_group]

    lower_text = (input_text or "").lower()
    for keyword, data_class in _INPUT_TEXT_DATA_CLASS_HINTS.items():
        if keyword in lower_text:
            return data_class

    return ""


def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _build_action_request(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalise the action request from the incoming event."""
    return {
        "agent_id": event.get("agent_id", ""),
        "action_group": event.get("action_group", ""),
        "target_resource": event.get("target_resource", ""),
        "input_text": event.get("input_text", ""),
        "scope_level": int(event.get("scope_level", 1)),
    }


def _write_evidence_to_s3(decision: GovernanceDecision) -> None:
    """Write a governance decision as an evidence record to S3."""
    if not EVIDENCE_BUCKET_NAME:
        logger.warning(
            json.dumps({
                "event": "evidence_write_skipped",
                "reason": "EVIDENCE_BUCKET_NAME not set",
                "decision_id": decision.decision_id,
                "timestamp": _iso_now(),
            })
        )
        return

    now = datetime.now(timezone.utc)
    key = (
        f"evidence/decisions/{now.year:04d}/{now.month:02d}/"
        f"{now.day:02d}/{decision.decision_id}.json"
    )

    s3_client = boto3.client("s3")
    s3_client.put_object(
        Bucket=EVIDENCE_BUCKET_NAME,
        Key=key,
        Body=json.dumps(decision.to_dict()),
        ContentType="application/json",
    )

    logger.info(
        json.dumps({
            "event": "evidence_written",
            "bucket": EVIDENCE_BUCKET_NAME,
            "key": key,
            "decision_id": decision.decision_id,
            "timestamp": _iso_now(),
        })
    )


def _deny_response(
    reason: str,
    agent_id: str = "",
    error_category: str = "governance_denial",
) -> Dict[str, Any]:
    """Build a deny response dict with structured error information."""
    import uuid

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



def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point — orchestrate the governance decision pipeline.

    Input event format::

        {
            "agent_id": "demo-agent",
            "action_group": "ReadPipelineStatus",
            "target_resource": "production",
            "input_text": "Show me the build status",
            "scope_level": 2
        }

    Returns:
        A JSON-serialisable dict representing the GovernanceDecision.
        On unrecoverable failure the verdict is always "deny" (Req 18.2, 18.5).
    """
    agent_id = event.get("agent_id", "")

    # ------------------------------------------------------------------
    # 1. Parse incoming event
    # ------------------------------------------------------------------
    action_request = _build_action_request(event)
    scope_level = action_request["scope_level"]
    action_group = action_request["action_group"]
    target_resource = action_request["target_resource"]
    input_text = action_request["input_text"]

    # ------------------------------------------------------------------
    # 2. Initialize LatencyTracker (Req 17.1)
    # ------------------------------------------------------------------
    tracker = LatencyTracker()

    try:
        # --------------------------------------------------------------
        # Initialise engines — DynamoDB unavailability check (Req 18.2)
        # --------------------------------------------------------------
        try:
            dynamodb = boto3.resource("dynamodb")

            # Phase 1a engines
            policy_engine = PolicyEngine()
            s3_client = boto3.client("s3")
            policy_engine.load_policies(s3_client, POLICY_BUCKET_NAME, POLICY_PREFIX)

            risk_engine = RiskScoringEngine()
            risk_engine.load_config()

            decision_engine = DecisionEngine(
                escalation_threshold=risk_engine.escalation_threshold,
            )

            # Phase 1b managers
            identity_manager = AgentIdentityManager(
                dynamodb.Table(SCOPE_TABLE_NAME)
            ) if SCOPE_TABLE_NAME else None

            agent_registry = AgentRegistry(
                dynamodb.Table(AGENT_REGISTRY_TABLE_NAME)
            ) if AGENT_REGISTRY_TABLE_NAME else None

            tool_model_registry = ToolModelRegistry(
                dynamodb.Table(TOOL_MODEL_REGISTRY_TABLE_NAME)
            ) if TOOL_MODEL_REGISTRY_TABLE_NAME else None

            env_isolation = EnvironmentIsolation()

            # Phase 1c managers
            kill_switch_manager = KillSwitchManager()
            scope_table_resource = (
                dynamodb.Table(SCOPE_TABLE_NAME) if SCOPE_TABLE_NAME else None
            )

            threat_detector = ThreatDetector()
            if THREAT_PATTERNS_TABLE_NAME:
                threat_detector.load_patterns(
                    dynamodb.Table(THREAT_PATTERNS_TABLE_NAME)
                )

            evidence_pipeline = EvidencePipeline()

            control_trace_table = (
                dynamodb.Table(CONTROL_TRACE_TABLE_NAME)
                if CONTROL_TRACE_TABLE_NAME else None
            )

        except Exception as init_exc:
            # DynamoDB / S3 tables unreachable — deny all (Req 18.2)
            logger.error(
                json.dumps({
                    "event": "governance_tables_unavailable",
                    "component_name": "GovernanceEngineInit",
                    "failure_type": type(init_exc).__name__,
                    "fallback_action_taken": "deny_all",
                    "error": str(init_exc),
                    "agent_id": agent_id,
                    "timestamp": _iso_now(),
                })
            )
            return _deny_response(
                reason=(
                    "Governance tables are unavailable. All requests are "
                    "denied as a fail-safe measure."
                ),
                agent_id=agent_id,
                error_category="infrastructure_unavailable",
            )

        # ==============================================================
        # Phase 1c pre-checks — kill switch and threat detection
        # ==============================================================

        # --------------------------------------------------------------
        # 3. Kill switch check — deny all if active (Req 8.3)
        # --------------------------------------------------------------
        if scope_table_resource is not None:
            kill_result = kill_switch_manager.check_kill_switch(scope_table_resource)
            if kill_result:
                logger.warning(
                    json.dumps({
                        "audit_event": "kill_switch_active_denial",
                        "agent_id": agent_id,
                        "timestamp": _iso_now(),
                    })
                )
                return _deny_response(
                    reason="Kill switch is active. All requests are denied.",
                    agent_id=agent_id,
                    error_category="kill_switch_active",
                )

        # --------------------------------------------------------------
        # 4. Threat detection (Req 12.1, 12.2, 12.3)
        # --------------------------------------------------------------
        risk_score_adjustment = 0
        if input_text and threat_detector._patterns:
            threat_result = threat_detector.evaluate(input_text, agent_id)
            if threat_result["classification"] == "denied":
                matched_categories = list({
                    p["category"] for p in threat_result["matched_patterns"]
                })
                logger.warning(
                    json.dumps({
                        "audit_event": "threat_detection_denial",
                        "agent_id": agent_id,
                        "classification": "denied",
                        "matched_patterns": threat_result["matched_patterns"],
                        "timestamp": _iso_now(),
                    })
                )
                return _deny_response(
                    reason=(
                        f"Input denied by threat detection: matched "
                        f"{', '.join(matched_categories)} pattern."
                    ),
                    agent_id=agent_id,
                    error_category="threat_detected",
                )
            elif threat_result["classification"] == "suspicious":
                risk_score_adjustment = threat_result.get("risk_score_adjustment", 0)

        # ==============================================================
        # Phase 1b pre-checks — run BEFORE policy evaluation
        # ==============================================================

        # --------------------------------------------------------------
        # 3. Agent Identity check — deny if suspended (Req 5.4)
        # --------------------------------------------------------------
        if identity_manager is not None:
            if identity_manager.is_suspended(agent_id):
                logger.warning(
                    json.dumps({
                        "audit_event": "agent_suspended_denial",
                        "agent_id": agent_id,
                        "timestamp": _iso_now(),
                    })
                )
                return _deny_response(
                    reason="Agent is suspended",
                    agent_id=agent_id,
                    error_category="agent_suspended",
                )

        # --------------------------------------------------------------
        # 4. Agent Registry check — deny if not registered (Req 6.2)
        # --------------------------------------------------------------
        registry_entry = None
        if agent_registry is not None:
            registry_entry = agent_registry.get_agent(agent_id)
            if registry_entry is None:
                logger.warning(
                    json.dumps({
                        "audit_event": "agent_not_registered_denial",
                        "agent_id": agent_id,
                        "timestamp": _iso_now(),
                    })
                )
                return _deny_response(
                    reason="Agent not registered in governance registry",
                    agent_id=agent_id,
                    error_category="agent_not_registered",
                )

        # --------------------------------------------------------------
        # 5. Environment Isolation check (Req 19.2, 19.5)
        # --------------------------------------------------------------
        agent_environment = ""
        if registry_entry is not None:
            agent_environment = registry_entry.environment

            # Derive target environment from target_resource when it is
            # itself an environment name; otherwise the agent stays in
            # its own environment.
            target_env = (
                target_resource
                if target_resource in {"dev", "staging", "prod"}
                else agent_environment
            )

            if not env_isolation.check_cross_environment(
                agent_environment, target_env
            ):
                logger.warning(
                    json.dumps({
                        "audit_event": "cross_environment_denial",
                        "agent_id": agent_id,
                        "agent_environment": agent_environment,
                        "target_environment": target_env,
                        "timestamp": _iso_now(),
                    })
                )
                return _deny_response(
                    reason=(
                        f"Cross-environment action denied: agent environment "
                        f"'{agent_environment}' does not match target "
                        f"environment '{target_env}'"
                    ),
                    agent_id=agent_id,
                    error_category="cross_environment_violation",
                )

        # --------------------------------------------------------------
        # 6. Data class access check (Req 6.4)
        # --------------------------------------------------------------
        if agent_registry is not None and registry_entry is not None:
            data_class = _derive_data_class(action_group, input_text)
            if data_class:
                if not agent_registry.check_data_class_access(
                    agent_id, data_class
                ):
                    logger.warning(
                        json.dumps({
                            "audit_event": "undeclared_data_class_violation",
                            "agent_id": agent_id,
                            "data_class": data_class,
                            "declared_data_classes": registry_entry.data_classes,
                            "action_group": action_group,
                            "timestamp": _iso_now(),
                        })
                    )
                    return _deny_response(
                        reason=(
                            f"Agent '{agent_id}' attempted to access data "
                            f"class '{data_class}' which is not declared in "
                            f"its registry entry. Declared: "
                            f"{registry_entry.data_classes}"
                        ),
                        agent_id=agent_id,
                        error_category="undeclared_data_class",
                    )

        # --------------------------------------------------------------
        # 7. Tool/Model usage check (Req 7.3, 7.4, 7.5)
        # --------------------------------------------------------------
        if tool_model_registry is not None and action_group:
            if not tool_model_registry.check_usage_allowed(
                category="tool_connector",
                name=action_group,
                version="*",
            ):
                logger.warning(
                    json.dumps({
                        "audit_event": "unapproved_tool_usage_violation",
                        "agent_id": agent_id,
                        "action_group": action_group,
                        "category": "tool_connector",
                        "timestamp": _iso_now(),
                    })
                )
                return _deny_response(
                    reason=(
                        f"Action group '{action_group}' is not approved in "
                        f"the Tool/Model Registry"
                    ),
                    agent_id=agent_id,
                    error_category="unapproved_tool_model",
                )

        # ==============================================================
        # Phase 1a pipeline — policy evaluation -> risk -> decision
        # ==============================================================

        # --------------------------------------------------------------
        # 8. Pass environment to policy engine (Req 19.2)
        # --------------------------------------------------------------
        if agent_environment:
            env_policy_filter = env_isolation.get_environment_policy_filter(
                agent_environment
            )
            action_request["environment_filter"] = env_policy_filter

        # --------------------------------------------------------------
        # 9. Policy evaluation (Req 2.1) — fail-safe wrapper (Req 18.1)
        # --------------------------------------------------------------
        with tracker.track("policy_evaluation"):
            policy_result = safe_evaluate_policy(
                policy_engine, action_request,
            )

        # --------------------------------------------------------------
        # 12. Risk scoring (Req 3.1) — fail-safe wrapper (Req 18.3)
        # --------------------------------------------------------------
        with tracker.track("risk_scoring"):
            risk_assessment = safe_compute_risk(
                risk_engine, action_request, scope_level,
            )

        # Apply threat detection risk_score_adjustment (Req 12.3)
        if risk_score_adjustment > 0:
            adjusted = min(100, risk_assessment.risk_score + risk_score_adjustment)
            risk_assessment.risk_score = adjusted
            if adjusted >= risk_engine.escalation_threshold:
                risk_assessment.escalation_flagged = True

        # --------------------------------------------------------------
        # 13. Decision engine (Req 4.1)
        # --------------------------------------------------------------
        with tracker.track("decision_engine"):
            decision = decision_engine.decide(
                policy_result, risk_assessment, action_request, agent_id,
            )

        # --------------------------------------------------------------
        # 14. Log structured decision record (Req 4.6, 4.9)
        # --------------------------------------------------------------
        decision_engine.log_decision(decision)

        # --------------------------------------------------------------
        # 15. Evidence write via EvidencePipeline (Req 9.1, 9.4)
        # --------------------------------------------------------------
        evidence_record = None
        evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
        with tracker.track("evidence_write_initiation"):
            if evidence_bucket:
                try:
                    ev_s3 = boto3.client("s3")
                    evidence_record = evidence_pipeline.write_evidence(
                        decision=decision,
                        s3_client=ev_s3,
                        bucket=evidence_bucket,
                        environment=agent_environment or "dev",
                        agent_id=agent_id,
                    )
                except Exception as ev_exc:
                    logger.error(
                        json.dumps({
                            "event": "evidence_pipeline_write_failed",
                            "error": str(ev_exc),
                            "decision_id": decision.decision_id,
                            "timestamp": _iso_now(),
                        })
                    )
            else:
                safe_write_evidence(_write_evidence_to_s3, decision)

        # --------------------------------------------------------------
        # 16. Control trace generation and storage (Req 13.1, 13.2)
        # --------------------------------------------------------------
        if evidence_record is not None and control_trace_table is not None:
            try:
                traces = evidence_pipeline.generate_control_traces(
                    evidence_record,
                    evidence_record.framework_mapping or [],
                )
                if traces:
                    ControlTraceManager.store_traces(traces, control_trace_table)
            except Exception as ct_exc:
                logger.error(
                    json.dumps({
                        "event": "control_trace_storage_failed",
                        "error": str(ct_exc),
                        "decision_id": decision.decision_id,
                        "timestamp": _iso_now(),
                    })
                )

        # --------------------------------------------------------------
        # 17. Record latency metric (Req 17.1, 17.2)
        # --------------------------------------------------------------
        latency_metric = tracker.record_latency(decision.decision_id)
        decision.latency_breakdown = latency_metric.component_latencies

        # --------------------------------------------------------------
        # 18. Return GovernanceDecision as JSON
        # --------------------------------------------------------------
        return decision.to_dict()

    except Exception as exc:
        # Catch-all: deny on any unexpected failure (Req 18.5)
        logger.error(
            json.dumps({
                "event": "governance_pipeline_failure",
                "component_name": "GovernanceEnginePipeline",
                "failure_type": type(exc).__name__,
                "fallback_action_taken": "deny",
                "error": str(exc),
                "agent_id": agent_id,
                "timestamp": _iso_now(),
            })
        )
        return _deny_response(
            reason=f"Governance pipeline failure: {type(exc).__name__}. "
                   f"Request denied as fail-safe.",
            agent_id=agent_id,
            error_category="pipeline_failure",
        )
