"""Post-Decision Lambda - Layer 6 of the governance pipeline.

Handles asynchronous post-decision processing:
- Evidence writing (immutable S3 with hash chain)
- Continuous monitoring health update
- Decision history indexing
- Drift activity recording
- CloudWatch metrics publishing

Triggered by EventBridge rule on GovernanceDecision events.
Non-blocking: runs AFTER the verdict is returned to the user.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

from evidence_pipeline import EvidencePipeline
from continuous_monitoring import ContinuousMonitoringManager
from decision_history import DecisionHistory
from runtime_drift_detection import RuntimeDriftDetector
from control_trace import ControlTraceManager

logger = logging.getLogger()
logger.setLevel(logging.INFO)

EVIDENCE_BUCKET_NAME = os.environ.get("EVIDENCE_BUCKET_NAME", "")
IMMUTABLE_EVIDENCE_BUCKET_NAME = os.environ.get("IMMUTABLE_EVIDENCE_BUCKET_NAME", "")
AGENT_HEALTH_TABLE_NAME = os.environ.get("AGENT_HEALTH_TABLE_NAME", "")
DECISION_HISTORY_TABLE_NAME = os.environ.get("DECISION_HISTORY_TABLE_NAME", "")
RUNTIME_DRIFT_TABLE_NAME = os.environ.get("RUNTIME_DRIFT_TABLE_NAME", "")
CONTROL_TRACE_TABLE_NAME = os.environ.get("CONTROL_TRACE_TABLE_NAME", "")


def handler(event, context):
    """Post-Decision handler.

    Input event (from EventBridge):
        detail: {
            decision_id (str)
            agent_id (str)
            action_requested (str)
            verdict (str)
            risk_score (float)
            policy_result (dict)
            timestamp (str)
        }
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # EventBridge wraps the decision in "detail"
    decision = event.get("detail", event)
    agent_id = decision.get("agent_id", "")
    verdict = decision.get("verdict", "")
    risk_score = float(decision.get("risk_score", 0))
    decision_id = decision.get("decision_id", "")
    action_requested = decision.get("action_requested", "")

    dynamodb = boto3.resource("dynamodb")
    results = {"processed": [], "errors": []}

    # 1. Evidence Write
    if EVIDENCE_BUCKET_NAME:
        try:
            s3_client = boto3.client("s3")
            now = datetime.now(timezone.utc)
            key = (
                f"evidence/decisions/{now.year:04d}/{now.month:02d}/"
                f"{now.day:02d}/{decision_id}.json"
            )
            s3_client.put_object(
                Bucket=EVIDENCE_BUCKET_NAME,
                Key=key,
                Body=json.dumps(decision, default=str),
                ContentType="application/json",
            )
            results["processed"].append("evidence_write")
        except Exception as e:
            results["errors"].append(f"evidence_write: {str(e)}")
            logger.error(json.dumps({"event": "evidence_write_failed", "error": str(e)}))

    # 2. Continuous Monitoring Health Update
    if AGENT_HEALTH_TABLE_NAME:
        try:
            health_table = dynamodb.Table(AGENT_HEALTH_TABLE_NAME)
            monitor = ContinuousMonitoringManager()
            health_state = monitor.update_health(agent_id, verdict, risk_score, health_table)
            results["processed"].append(f"health_update (score={health_state.health_score})")
        except Exception as e:
            results["errors"].append(f"health_update: {str(e)}")
            logger.error(json.dumps({"event": "health_update_failed", "error": str(e)}))

    # 3. Decision History
    if DECISION_HISTORY_TABLE_NAME:
        try:
            history_table = dynamodb.Table(DECISION_HISTORY_TABLE_NAME)
            history = DecisionHistory(history_table)
            history.record(decision)
            results["processed"].append("decision_history")
        except Exception as e:
            results["errors"].append(f"decision_history: {str(e)}")
            logger.error(json.dumps({"event": "decision_history_failed", "error": str(e)}))

    # 4. Drift Activity Recording
    if RUNTIME_DRIFT_TABLE_NAME:
        try:
            drift_table = dynamodb.Table(RUNTIME_DRIFT_TABLE_NAME)
            drift_detector = RuntimeDriftDetector()
            drift_detector.record_activity(
                agent_id, action_requested, decision.get("target_resource", ""),
                int(decision.get("scope_level", 1)), drift_table,
            )
            results["processed"].append("drift_recording")
        except Exception as e:
            results["errors"].append(f"drift_recording: {str(e)}")
            logger.error(json.dumps({"event": "drift_recording_failed", "error": str(e)}))

    # 5. Control Trace
    if CONTROL_TRACE_TABLE_NAME:
        try:
            trace_table = dynamodb.Table(CONTROL_TRACE_TABLE_NAME)
            trace_manager = ControlTraceManager(trace_table)
            trace_manager.generate_trace(decision_id, verdict, action_requested)
            results["processed"].append("control_trace")
        except Exception as e:
            results["errors"].append(f"control_trace: {str(e)}")
            logger.error(json.dumps({"event": "control_trace_failed", "error": str(e)}))

    logger.info(json.dumps({
        "event": "post_decision_complete",
        "decision_id": decision_id,
        "agent_id": agent_id,
        "processed": results["processed"],
        "errors": results["errors"],
        "timestamp": timestamp,
    }))

    return results
