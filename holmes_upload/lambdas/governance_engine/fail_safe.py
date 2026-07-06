"""Fail-safe wrapper functions for critical governance components.

Wraps PolicyEngine, RiskScoringEngine, and evidence write operations
in try/except blocks to ensure safe defaults on failure:
  - Policy evaluation failure -> deny decision
  - Risk scoring failure -> max risk score (100) to trigger escalation
  - Evidence write failure -> decision proceeds, alert published to SNS

All failure records contain: component_name, failure_type,
fallback_action_taken, affected_decision_id (if applicable), timestamp.

Requirements: 18.1, 18.3, 18.4, 18.5, 18.6
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import boto3

from models import PolicyEvaluationResult, RiskAssessment

logger = logging.getLogger(__name__)


def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _log_failure_record(
    component_name: str,
    failure_type: str,
    fallback_action_taken: str,
    affected_decision_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and log a structured failure record.

    Args:
        component_name: Name of the failed component.
        failure_type: Description of the failure (e.g. exception type).
        fallback_action_taken: What the system did in response.
        affected_decision_id: Decision ID affected, if applicable.

    Returns:
        The failure record dict (for testing / further use).
    """
    record: Dict[str, Any] = {
        "event": "component_failure",
        "component_name": component_name,
        "failure_type": failure_type,
        "fallback_action_taken": fallback_action_taken,
        "timestamp": _iso_now(),
    }
    if affected_decision_id is not None:
        record["affected_decision_id"] = affected_decision_id

    logger.error(json.dumps(record))
    return record


# ------------------------------------------------------------------
# safe_evaluate_policy  (Req 18.1, 18.5, 18.6)
# ------------------------------------------------------------------

def safe_evaluate_policy(
    policy_engine: Any,
    action_request: Dict[str, Any],
) -> PolicyEvaluationResult:
    """Wrap PolicyEngine.evaluate() with fail-safe deny on error.

    If the policy engine raises any exception, returns a deny
    PolicyEvaluationResult and logs a structured failure record.

    Args:
        policy_engine: A PolicyEngine instance.
        action_request: The action request dict to evaluate.

    Returns:
        A PolicyEvaluationResult -- either the real result or a
        fail-safe deny result.
    """
    try:
        return policy_engine.evaluate(action_request)
    except Exception as exc:
        _log_failure_record(
            component_name="PolicyEngine",
            failure_type=type(exc).__name__,
            fallback_action_taken="deny",
        )
        return PolicyEvaluationResult(
            policy_id="fail-safe-deny",
            outcome="deny",
            matching_conditions={},
            evaluation_timestamp=_iso_now(),
        )


# ------------------------------------------------------------------
# safe_compute_risk  (Req 18.3, 18.5, 18.6)
# ------------------------------------------------------------------

def safe_compute_risk(
    risk_engine: Any,
    action_request: Dict[str, Any],
    scope_level: int,
    history: Optional[List[Dict[str, Any]]] = None,
) -> RiskAssessment:
    """Wrap RiskScoringEngine.compute_risk() with fail-safe max risk.

    If the risk engine raises any exception, returns a RiskAssessment
    with score=100 (maximum) to trigger escalation, and logs a
    structured failure record.

    Args:
        risk_engine: A RiskScoringEngine instance.
        action_request: The action request dict.
        scope_level: The agent's current scope level.
        history: Optional action history list.

    Returns:
        A RiskAssessment -- either the real result or a fail-safe
        max-risk result.
    """
    try:
        return risk_engine.compute_risk(action_request, scope_level, history)
    except Exception as exc:
        _log_failure_record(
            component_name="RiskScoringEngine",
            failure_type=type(exc).__name__,
            fallback_action_taken="max_risk_score",
        )
        return RiskAssessment(
            risk_score=100.0,
            risk_category="emergency_action",
            factors_applied={"fail_safe": 100.0},
            escalation_flagged=True,
            assessment_timestamp=_iso_now(),
        )


# ------------------------------------------------------------------
# safe_write_evidence  (Req 18.4, 18.5, 18.6)
# ------------------------------------------------------------------

def safe_write_evidence(
    evidence_fn: Callable[..., Any],
    decision: Any,
    sns_client: Optional[Any] = None,
) -> bool:
    """Wrap an evidence write function with fail-safe pass-through.

    If the evidence write raises any exception, the governance decision
    is NOT blocked. Instead, a structured failure record is logged and
    an alert is published to the operator SNS topic.

    Args:
        evidence_fn: A callable that writes evidence (e.g. to S3).
            Called as ``evidence_fn(decision)``.
        decision: The GovernanceDecision to write as evidence.
        sns_client: Optional boto3 SNS client. If None, one is created
            from the default session.

    Returns:
        True if evidence was written successfully, False if the
        write failed (decision still proceeds).
    """
    try:
        evidence_fn(decision)
        return True
    except Exception as exc:
        decision_id = getattr(decision, "decision_id", None)

        _log_failure_record(
            component_name="EvidencePipeline",
            failure_type=type(exc).__name__,
            fallback_action_taken="decision_proceeds_without_evidence",
            affected_decision_id=decision_id,
        )

        # Publish alert to operator SNS topic (Req 18.4)
        _publish_evidence_failure_alert(
            decision_id=decision_id,
            error=str(exc),
            sns_client=sns_client,
        )

        return False


def _publish_evidence_failure_alert(
    decision_id: Optional[str],
    error: str,
    sns_client: Optional[Any] = None,
) -> None:
    """Publish an evidence write failure alert to the operator SNS topic.

    Args:
        decision_id: The affected decision ID, if available.
        error: The error message string.
        sns_client: Optional boto3 SNS client.
    """
    topic_arn = os.environ.get("OPERATOR_SNS_TOPIC_ARN", "")
    if not topic_arn:
        logger.warning(
            json.dumps(
                {
                    "event": "sns_alert_skipped",
                    "reason": "OPERATOR_SNS_TOPIC_ARN not set",
                    "timestamp": _iso_now(),
                }
            )
        )
        return

    try:
        if sns_client is None:
            sns_client = boto3.client("sns")

        message = {
            "event": "evidence_write_failure",
            "affected_decision_id": decision_id,
            "error": error,
            "timestamp": _iso_now(),
        }

        sns_client.publish(
            TopicArn=topic_arn,
            Subject="Governance Evidence Write Failure",
            Message=json.dumps(message),
        )

        logger.info(
            json.dumps(
                {
                    "event": "evidence_failure_alert_published",
                    "topic_arn": topic_arn,
                    "affected_decision_id": decision_id,
                    "timestamp": _iso_now(),
                }
            )
        )
    except Exception as sns_exc:
        logger.error(
            json.dumps(
                {
                    "event": "sns_publish_failure",
                    "topic_arn": topic_arn,
                    "error": str(sns_exc),
                    "timestamp": _iso_now(),
                }
            )
        )
