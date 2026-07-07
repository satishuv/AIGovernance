"""API Gateway event router for governance engine endpoints.

Routes:
    POST /approvals/{approval_id}/approve
    POST /approvals/{approval_id}/deny
    GET  /approvals/pending
    GET  /decisions/{agent_id}
    GET  /reports/measure
    GET  /reports/manage
    GET  /agents/{agent_id}/risk-profile
    POST /validation/extended

Requirements: 20.3, 20.4, 20.5, 22.2, 22.3
"""

import json
import logging
import os
from typing import Any, Dict

import boto3

from agent_registry import AgentRegistry
from approval_workflow import ApprovalWorkflow
from decision_history import DecisionHistory

logger = logging.getLogger()

PENDING_APPROVAL_TABLE_NAME = os.environ.get("PENDING_APPROVAL_TABLE_NAME", "")
DECISION_HISTORY_TABLE_NAME = os.environ.get("DECISION_HISTORY_TABLE_NAME", "")
AGENT_REGISTRY_TABLE_NAME = os.environ.get("AGENT_REGISTRY_TABLE_NAME", "")
IMMUTABLE_EVIDENCE_BUCKET_NAME = os.environ.get("IMMUTABLE_EVIDENCE_BUCKET_NAME", "")
EVIDENCE_BUCKET_NAME = os.environ.get("EVIDENCE_BUCKET_NAME", "")


def _api_response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def handle_api_gateway_event(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Route API Gateway proxy events to the appropriate handler."""
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

        if "/approvals/" in resource:
            return _handle_approvals(dynamodb, resource, http_method, path_params, body)

        if "/decisions/" in resource and http_method == "GET":
            return _handle_decisions(dynamodb, path_params, query_params)

        if "/reports/" in resource and http_method == "GET":
            return _handle_reports(dynamodb, resource, path_params)

        if "/agents/" in resource and "/risk-profile" in resource and http_method == "GET":
            return _handle_risk_profile(dynamodb, path_params)

        if "/validation/extended" in resource and http_method == "POST":
            return _handle_extended_validation(dynamodb)

        return _api_response(404, {"error": "Route not found"})

    except ValueError as ve:
        return _api_response(400, {"error": str(ve)})
    except Exception as exc:
        logger.error(json.dumps({
            "event": "api_handler_error",
            "error": str(exc),
            "resource": resource,
            "timestamp": _iso_now(),
        }))
        return _api_response(500, {"error": f"Internal error: {type(exc).__name__}"})


def _handle_approvals(dynamodb, resource, http_method, path_params, body):
    if not PENDING_APPROVAL_TABLE_NAME:
        return _api_response(503, {"error": "Approval table not configured"})

    aw = ApprovalWorkflow(dynamodb.Table(PENDING_APPROVAL_TABLE_NAME))

    if resource.endswith("/pending") and http_method == "GET":
        from boto3.dynamodb.conditions import Attr

        table = dynamodb.Table(PENDING_APPROVAL_TABLE_NAME)
        response = table.scan(
            FilterExpression=Attr("status").eq("pending"),
        )
        items = response.get("Items", [])

        active_pending = []
        for item in items:
            aid = item.get("approval_id", "")
            timed_out = aw.check_timeout(aid)
            if timed_out is None:
                active_pending.append(item)

        return _api_response(200, {"pending_approvals": active_pending})

    approval_id = path_params.get("approval_id", "")

    if resource.endswith("/approve") and http_method == "POST":
        approver_id = body.get("approver_id", "")
        conditions = body.get("conditions", "")

        agent_owner_id = ""
        if AGENT_REGISTRY_TABLE_NAME:
            approval_record = aw._get_approval(approval_id)
            if approval_record:
                ar = AgentRegistry(dynamodb.Table(AGENT_REGISTRY_TABLE_NAME))
                reg_entry = ar.get_agent(approval_record.agent_id)
                if reg_entry:
                    agent_owner_id = reg_entry.owner

        result = aw.approve(approval_id, approver_id, agent_owner_id, conditions)

        evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
        if evidence_bucket and result:
            try:
                s3_client = boto3.client("s3")
                aw.write_approval_evidence(result, s3_client, evidence_bucket, "prod")
            except Exception:
                pass

        return _api_response(200, result.to_dict() if result else {})

    if resource.endswith("/deny") and http_method == "POST":
        approver_id = body.get("approver_id", "")
        denial_reason = body.get("denial_reason", "")

        result = aw.deny(approval_id, approver_id, denial_reason)

        evidence_bucket = IMMUTABLE_EVIDENCE_BUCKET_NAME or EVIDENCE_BUCKET_NAME
        if evidence_bucket and result:
            try:
                s3_client = boto3.client("s3")
                aw.write_approval_evidence(result, s3_client, evidence_bucket, "prod")
            except Exception:
                pass

        return _api_response(200, result.to_dict() if result else {})

    return _api_response(404, {"error": "Route not found"})


def _handle_decisions(dynamodb, path_params, query_params):
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


def _handle_reports(dynamodb, resource, path_params):
    from measure_manage import MeasureManageEngine
    from datetime import datetime as dt, timedelta, timezone as tz

    dh_table_name = os.environ.get("DECISION_HISTORY_TABLE_NAME", "")
    cl_table_name = os.environ.get("CHANGE_LOG_TABLE_NAME", "")

    if not dh_table_name:
        return _api_response(503, {"error": "Decision history table not configured"})

    mm_engine = MeasureManageEngine()
    now = dt.now(tz.utc)
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

    return _api_response(404, {"error": "Route not found"})


def _handle_risk_profile(dynamodb, path_params):
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


def _handle_extended_validation(dynamodb):
    from extended_validation import ExtendedValidationSuite
    suite = ExtendedValidationSuite()
    results = []

    cm_table_name = os.environ.get("CONTROL_MAPPING_TABLE_NAME", "")
    if cm_table_name:
        r = suite.test_control_mapping_completeness(dynamodb.Table(cm_table_name))
        results.append(r)

    report = suite.generate_compliance_report(results, "json")
    return _api_response(200, report)
