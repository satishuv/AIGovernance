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
from decimal import Decimal
from typing import Any, Dict

import boto3


class DecimalEncoder(json.JSONEncoder):
    """Handle Decimal types from DynamoDB in JSON serialization."""
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o) if o % 1 else int(o)
        return super().default(o)

from agent_identity import AgentIdentityManager
from agent_registry import AgentRegistry
from control_trace import ControlTraceManager
from decision_engine import DecisionEngine
from environment_isolation import EnvironmentIsolation
from evidence_pipeline import EvidencePipeline
from fail_safe import safe_compute_risk, safe_evaluate_policy, safe_write_evidence
from kill_switch import KillSwitchManager
from latency import LatencyTracker
from models import GovernanceDecision, PolicyEvaluationResult, RiskAssessment
from policy_engine import PolicyEngine
from risk_scoring import RiskScoringEngine
from threat_detector import ThreatDetector
from tool_model_registry import ToolModelRegistry

# Phase 2 imports
from approval_workflow import ApprovalWorkflow
from change_logger import ChangeLogger
from decision_history import DecisionHistory

# Phase 3 imports
from cloudwatch_metrics import CloudWatchMetricsPublisher
from exfiltration_detector import ExfiltrationDetector
from graduated_scope_reduction import GraduatedScopeReduction
from multi_agent import MultiAgentManager
from privilege_escalation import PrivilegeEscalationDetector

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

# Phase 2 environment variables
PENDING_APPROVAL_TABLE_NAME = os.environ.get("PENDING_APPROVAL_TABLE_NAME", "")
CHANGE_LOG_TABLE_NAME = os.environ.get("CHANGE_LOG_TABLE_NAME", "")
DECISION_HISTORY_TABLE_NAME = os.environ.get("DECISION_HISTORY_TABLE_NAME", "")

# Phase 3 environment variables
DENIAL_PATTERN_TABLE_NAME = os.environ.get("DENIAL_PATTERN_TABLE_NAME", "")
EXFILTRATION_ALLOWLIST_TABLE_NAME = os.environ.get("EXFILTRATION_ALLOWLIST_TABLE_NAME", "")
SCOPE_REDUCTION_HISTORY_TABLE_NAME = os.environ.get("SCOPE_REDUCTION_HISTORY_TABLE_NAME", "")
MULTI_AGENT_CONFIG_TABLE_NAME = os.environ.get("MULTI_AGENT_CONFIG_TABLE_NAME", "")
METRICS_THRESHOLD_TABLE_NAME = os.environ.get("METRICS_THRESHOLD_TABLE_NAME", "")


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
        Body=json.dumps(decision.to_dict(), cls=DecimalEncoder),
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



def _api_response(status_code: int, body: Any) -> Dict[str, Any]:
    """Build an API Gateway proxy response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _handle_api_gateway_event(
    event: Dict[str, Any], context: Any
) -> Dict[str, Any]:
    """Handle API Gateway proxy events for Phase 2 endpoints.

    Routes:
        POST /approvals/{approval_id}/approve
        POST /approvals/{approval_id}/deny
        GET  /approvals/pending
        GET  /decisions/{agent_id}

    Requirements: 20.3, 20.4, 20.5, 22.2, 22.3
    """
    http_method = event.get("httpMethod", "")
    resource = event.get("resource", "")
    path_params = event.get("pathParameters") or {}
    query_params = event.get("queryStringParameters") or {}

    try:
        body = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        body = {}

    try:
        dynamodb = boto3.resource("dynamodb")

        # --- Approval endpoints ---
        if "/approvals/" in resource:
            if not PENDING_APPROVAL_TABLE_NAME:
                return _api_response(503, {"error": "Approval table not configured"})

            aw = ApprovalWorkflow(dynamodb.Table(PENDING_APPROVAL_TABLE_NAME))

            # GET /approvals/pending
            if resource.endswith("/pending") and http_method == "GET":
                from boto3.dynamodb.conditions import Attr

                table = dynamodb.Table(PENDING_APPROVAL_TABLE_NAME)
                response = table.scan(
                    FilterExpression=Attr("status").eq("pending"),
                )
                items = response.get("Items", [])

                # Check timeouts on each pending approval
                active_pending = []
                for item in items:
                    aid = item.get("approval_id", "")
                    timed_out = aw.check_timeout(aid)
                    if timed_out is None:
                        active_pending.append(item)

                return _api_response(200, {"pending_approvals": active_pending})

            approval_id = path_params.get("approval_id", "")

            # POST /approvals/{approval_id}/approve
            if resource.endswith("/approve") and http_method == "POST":
                approver_id = body.get("approver_id", "")
                conditions = body.get("conditions", "")

                # Look up agent owner from registry
                agent_owner_id = ""
                if AGENT_REGISTRY_TABLE_NAME:
                    approval_record = aw._get_approval(approval_id)
                    if approval_record:
                        ar = AgentRegistry(dynamodb.Table(AGENT_REGISTRY_TABLE_NAME))
                        reg_entry = ar.get_agent(approval_record.agent_id)
                        if reg_entry:
                            agent_owner_id = reg_entry.owner

                result = aw.approve(approval_id, approver_id, agent_owner_id, conditions)

                # Write approval evidence
                evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
                if evidence_bucket and result:
                    try:
                        s3_client = boto3.client("s3")
                        aw.write_approval_evidence(
                            result, s3_client, evidence_bucket, "prod",
                        )
                    except Exception:
                        pass

                return _api_response(200, result.to_dict() if result else {})

            # POST /approvals/{approval_id}/deny
            if resource.endswith("/deny") and http_method == "POST":
                approver_id = body.get("approver_id", "")
                denial_reason = body.get("denial_reason", "")

                result = aw.deny(approval_id, approver_id, denial_reason)

                # Write denial evidence
                evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
                if evidence_bucket and result:
                    try:
                        s3_client = boto3.client("s3")
                        aw.write_approval_evidence(
                            result, s3_client, evidence_bucket, "prod",
                        )
                    except Exception:
                        pass

                return _api_response(200, result.to_dict() if result else {})

        # --- Decision history endpoints ---
        if "/decisions/" in resource and http_method == "GET":
            if not DECISION_HISTORY_TABLE_NAME:
                return _api_response(503, {"error": "Decision history table not configured"})

            dh = DecisionHistory(dynamodb.Table(DECISION_HISTORY_TABLE_NAME))
            agent_id = path_params.get("agent_id", "")

            start_date = query_params.get("start_date")
            end_date = query_params.get("end_date")
            verdict = query_params.get("verdict")
            min_score = query_params.get("min_score")
            max_score = query_params.get("max_score")
            control_id = query_params.get("control_id")
            limit = int(query_params.get("limit", "100"))
            last_key_str = query_params.get("last_evaluated_key")
            last_key = json.loads(last_key_str) if last_key_str else None

            if control_id:
                entries, next_key = dh.query_by_control_id(
                    control_id, limit=limit, last_evaluated_key=last_key,
                )
            elif verdict:
                entries, next_key = dh.query_by_verdict(
                    agent_id, verdict, start_date, end_date,
                    limit=limit, last_evaluated_key=last_key,
                )
            elif min_score is not None and max_score is not None:
                entries, next_key = dh.query_by_risk_score_range(
                    agent_id, float(min_score), float(max_score),
                    limit=limit, last_evaluated_key=last_key,
                )
            else:
                entries, next_key = dh.query_by_agent(
                    agent_id, start_date, end_date,
                    limit=limit, last_evaluated_key=last_key,
                )

            result = {
                "decisions": [e.to_dict() for e in entries],
                "last_evaluated_key": next_key,
            }
            return _api_response(200, result)

        # --- Phase 3 report endpoints ---
        if "/reports/" in resource and http_method == "GET":
            from measure_manage import MeasureManageEngine

            mm_engine = MeasureManageEngine()
            period = path_params.get("period", "monthly")

            dh_table_name = os.environ.get("DECISION_HISTORY_TABLE_NAME", "")
            cl_table_name = os.environ.get("CHANGE_LOG_TABLE_NAME", "")

            if not dh_table_name:
                return _api_response(503, {"error": "Decision history table not configured"})

            from datetime import datetime as dt, timedelta
            now = dt.utcnow()
            end_date = now.isoformat()
            start_date = (now - timedelta(days=30)).isoformat()

            if "/reports/measure" in resource:
                metrics = mm_engine.compute_aggregate_metrics(
                    dynamodb.Table(dh_table_name), start_date, end_date,
                )
                threshold_config = {}
                mt_table_name = os.environ.get("METRICS_THRESHOLD_TABLE_NAME", "")
                if mt_table_name:
                    mt_table = dynamodb.Table(mt_table_name)
                    resp = mt_table.scan()
                    for item in resp.get("Items", []):
                        threshold_config[item["metric_name"]] = float(item.get("threshold", 0))
                report = mm_engine.generate_measure_report(metrics, threshold_config)
                return _api_response(200, report.to_dict())

            if "/reports/manage" in resource:
                cl_table = dynamodb.Table(cl_table_name) if cl_table_name else None
                dh_table = dynamodb.Table(dh_table_name)
                report = mm_engine.generate_manage_report(
                    cl_table, dh_table, start_date, end_date,
                )
                return _api_response(200, report.to_dict())

        # --- Phase 3 agent risk profile endpoint ---
        if "/agents/" in resource and "/risk-profile" in resource and http_method == "GET":
            agent_id = path_params.get("agent_id", "")
            mac_table_name = os.environ.get("MULTI_AGENT_CONFIG_TABLE_NAME", "")
            if not mac_table_name:
                return _api_response(503, {"error": "Multi-agent config table not configured"})
            from multi_agent import MultiAgentManager as MAM
            mam = MAM()
            config = mam.get_agent_config(agent_id, dynamodb.Table(mac_table_name))
            if config is None:
                return _api_response(404, {"error": f"Agent config not found: {agent_id}"})
            return _api_response(200, config.to_dict())

        # --- Phase 3 extended validation endpoint ---
        if "/validation/extended" in resource and http_method == "POST":
            from extended_validation import ExtendedValidationSuite
            suite = ExtendedValidationSuite()
            results = []

            cm_table_name = os.environ.get("CONTROL_MAPPING_TABLE_NAME", "")
            if cm_table_name:
                r = suite.test_control_mapping_completeness(dynamodb.Table(cm_table_name))
                results.append(r)

            report = suite.generate_compliance_report(results, "json")
            return _api_response(200, report)

        return _api_response(404, {"error": "Route not found"})

    except ValueError as ve:
        return _api_response(400, {"error": str(ve)})
    except Exception as exc:
        logger.error(
            json.dumps({
                "event": "api_handler_error",
                "error": str(exc),
                "resource": resource,
                "timestamp": _iso_now(),
            })
        )
        return _api_response(500, {"error": f"Internal error: {type(exc).__name__}"})


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point — orchestrate the governance decision pipeline.

    Handles both direct invocation (from Scope Enforcer) and API Gateway
    proxy events (for approval workflow and decision history endpoints).

    Input event format (direct invocation)::

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
    # ------------------------------------------------------------------
    # Phase 2: Route API Gateway proxy events to appropriate handlers
    # ------------------------------------------------------------------
    if "httpMethod" in event and "resource" in event:
        return _handle_api_gateway_event(event, context)

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

            # Phase 2 managers
            approval_workflow = ApprovalWorkflow(
                dynamodb.Table(PENDING_APPROVAL_TABLE_NAME)
            ) if PENDING_APPROVAL_TABLE_NAME else None

            change_logger = ChangeLogger(
                dynamodb.Table(CHANGE_LOG_TABLE_NAME)
            ) if CHANGE_LOG_TABLE_NAME else None

            decision_history = DecisionHistory(
                dynamodb.Table(DECISION_HISTORY_TABLE_NAME)
            ) if DECISION_HISTORY_TABLE_NAME else None

            # Phase 3 managers
            privilege_escalation_detector = PrivilegeEscalationDetector()
            cw_metrics_publisher = CloudWatchMetricsPublisher()
            cloudwatch_client = boto3.client("cloudwatch")

            exfiltration_detector = ExfiltrationDetector()
            exfiltration_allowlist_table = (
                dynamodb.Table(EXFILTRATION_ALLOWLIST_TABLE_NAME)
                if EXFILTRATION_ALLOWLIST_TABLE_NAME else None
            )

            graduated_scope_reduction = GraduatedScopeReduction()
            scope_reduction_history_table = (
                dynamodb.Table(SCOPE_REDUCTION_HISTORY_TABLE_NAME)
                if SCOPE_REDUCTION_HISTORY_TABLE_NAME else None
            )

            denial_pattern_table = (
                dynamodb.Table(DENIAL_PATTERN_TABLE_NAME)
                if DENIAL_PATTERN_TABLE_NAME else None
            )

            multi_agent_manager = MultiAgentManager()
            multi_agent_config_table = (
                dynamodb.Table(MULTI_AGENT_CONFIG_TABLE_NAME)
                if MULTI_AGENT_CONFIG_TABLE_NAME else None
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

        # ==============================================================
        # Phase 3 pre-check — privilege escalation hardening (Req 27.1, 27.2)
        # ==============================================================
        if privilege_escalation_detector.is_self_modification(agent_id, action_request):
            deny_result = privilege_escalation_detector.deny_and_log(
                agent_id, action_request, "self_modification",
            )
            if denial_pattern_table is not None:
                exceeded, count = privilege_escalation_detector.track_denial_pattern(
                    agent_id, denial_pattern_table,
                )
                if exceeded and scope_table_resource is not None:
                    sns_client = boto3.client("sns")
                    topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                    privilege_escalation_detector.auto_reduce_scope(
                        agent_id, scope_table_resource, sns_client, topic_arn,
                    )
            return deny_result

        if privilege_escalation_detector.is_policy_modification(action_request):
            deny_result = privilege_escalation_detector.deny_and_log(
                agent_id, action_request, "policy_modification",
            )
            if denial_pattern_table is not None:
                exceeded, count = privilege_escalation_detector.track_denial_pattern(
                    agent_id, denial_pattern_table,
                )
                if exceeded and scope_table_resource is not None:
                    sns_client = boto3.client("sns")
                    topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                    privilege_escalation_detector.auto_reduce_scope(
                        agent_id, scope_table_resource, sns_client, topic_arn,
                    )
            return deny_result

        # ==============================================================
        # Phase 3 pre-check — multi-agent cross-agent rules (Req 30.2, 30.3)
        # ==============================================================
        target_agent_id = action_request.get("target_resource", "")
        if multi_agent_config_table is not None and target_agent_id:
            allowed, violation_reason = multi_agent_manager.enforce_cross_agent_rules(
                agent_id, target_agent_id, action_request,
            )
            if not allowed:
                return _deny_response(
                    reason=violation_reason,
                    agent_id=agent_id,
                    error_category="cross_agent_violation",
                )

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
                    # Phase 3: publish evidence failure metric (Req 25.1)
                    try:
                        cw_metrics_publisher.publish_evidence_failure_metric(cloudwatch_client)
                    except Exception:
                        pass
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

        # ==============================================================
        # Phase 2 post-decision — approval workflow + decision history
        # ==============================================================

        # --------------------------------------------------------------
        # 16a. Approval workflow for escalated decisions (Req 20.1, 20.2)
        # --------------------------------------------------------------
        if decision.verdict == "escalate" and approval_workflow is not None:
            try:
                approval_id = approval_workflow.create_pending_approval(
                    decision, timeout_seconds=3600,
                )
                # Retrieve the approval record for notification
                approval_record = approval_workflow._get_approval(approval_id)
                if approval_record is not None:
                    try:
                        sns_client = boto3.client("sns")
                        topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                        if topic_arn:
                            approval_workflow.notify_approvers(
                                approval_record, sns_client, topic_arn,
                            )
                    except Exception as notify_exc:
                        logger.error(
                            json.dumps({
                                "event": "approval_notification_failed",
                                "error": str(notify_exc),
                                "approval_id": approval_id,
                                "timestamp": _iso_now(),
                            })
                        )
            except Exception as aw_exc:
                logger.error(
                    json.dumps({
                        "event": "approval_workflow_failed",
                        "error": str(aw_exc),
                        "decision_id": decision.decision_id,
                        "timestamp": _iso_now(),
                    })
                )

        # --------------------------------------------------------------
        # 16b. Index decision in history (Req 22.1)
        # --------------------------------------------------------------
        if decision_history is not None:
            try:
                decision_history.index_decision(decision)
            except Exception as dh_exc:
                logger.error(
                    json.dumps({
                        "event": "decision_history_indexing_failed",
                        "error": str(dh_exc),
                        "decision_id": decision.decision_id,
                        "timestamp": _iso_now(),
                    })
                )

        # ==============================================================
        # Phase 3 post-decision — CloudWatch metrics (Req 25.1)
        # ==============================================================
        try:
            cw_metrics_publisher.publish_decision_metric(
                decision.verdict, cloudwatch_client,
            )
            cw_metrics_publisher.publish_risk_score_metric(
                risk_assessment.risk_score, cloudwatch_client,
            )
        except Exception as cw_exc:
            logger.error(
                json.dumps({
                    "event": "cloudwatch_metrics_publish_failed",
                    "error": str(cw_exc),
                    "decision_id": decision.decision_id,
                    "timestamp": _iso_now(),
                })
            )

        # ==============================================================
        # Phase 3 post-decision — output exfiltration check (Req 28.1, 28.2)
        # ==============================================================
        output_text = event.get("output_text", "")
        if output_text:
            try:
                exfil_config = {}
                if exfiltration_allowlist_table is not None:
                    allowlist = exfiltration_detector.load_allowlist(
                        exfiltration_allowlist_table,
                    )
                    exfil_config["allowlist"] = allowlist
                exfil_result = exfiltration_detector.evaluate_output(
                    agent_id, output_text, scope_level, exfil_config,
                )
                if exfil_result.blocked:
                    exfiltration_detector.block_and_log(
                        agent_id, exfil_result,
                    )
                    return _deny_response(
                        reason=f"Output blocked: {exfil_result.pattern_type} detected",
                        agent_id=agent_id,
                        error_category="exfiltration_blocked",
                    )
            except Exception as exfil_exc:
                logger.error(
                    json.dumps({
                        "event": "exfiltration_check_failed",
                        "error": str(exfil_exc),
                        "agent_id": agent_id,
                        "timestamp": _iso_now(),
                    })
                )

        # ==============================================================
        # Phase 3 post-decision — graduated scope reduction (Req 29.1, 29.2)
        # ==============================================================
        if (decision_history is not None
                and scope_reduction_history_table is not None
                and scope_table_resource is not None):
            try:
                rolling_avg, dec_count = graduated_scope_reduction.compute_rolling_avg_risk(
                    agent_id, dynamodb.Table(DECISION_HISTORY_TABLE_NAME),
                )
                if rolling_avg > 0:
                    threshold = 70.0
                    exceeded, duration = graduated_scope_reduction.check_sustained_threshold(
                        agent_id, rolling_avg, threshold, 1800,
                        scope_reduction_history_table,
                    )
                    if exceeded:
                        cooldown_active, remaining = graduated_scope_reduction.check_cooldown(
                            agent_id, scope_reduction_history_table,
                        )
                        if not cooldown_active:
                            mode = graduated_scope_reduction.get_reduction_mode(
                                dynamodb.Table(os.environ.get("RISK_CONFIG_TABLE_NAME", "")),
                            )
                            sns_client = boto3.client("sns")
                            topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
                            graduated_scope_reduction.execute_reduction(
                                agent_id, mode, scope_table_resource,
                                dynamodb.Table(PENDING_APPROVAL_TABLE_NAME) if PENDING_APPROVAL_TABLE_NAME else None,
                                sns_client, topic_arn,
                                {"rolling_avg": rolling_avg, "threshold": threshold,
                                 "sustained_seconds": duration},
                            )
            except Exception as gsr_exc:
                logger.error(
                    json.dumps({
                        "event": "graduated_scope_reduction_failed",
                        "error": str(gsr_exc),
                        "agent_id": agent_id,
                        "timestamp": _iso_now(),
                    })
                )

        # --------------------------------------------------------------
        # 17. Record latency metric (Req 17.1, 17.2)
        # --------------------------------------------------------------
        latency_metric = tracker.record_latency(decision.decision_id)
        decision.latency_breakdown = latency_metric.component_latencies

        # Phase 3: publish latency metric to CloudWatch (Req 25.1)
        try:
            cw_metrics_publisher.publish_latency_metric(
                latency_metric.total_elapsed_ms, cloudwatch_client,
            )
        except Exception:
            pass

        # --------------------------------------------------------------
        # 18. Return GovernanceDecision as JSON
        # --------------------------------------------------------------
        return json.loads(json.dumps(decision.to_dict(), cls=DecimalEncoder))

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
