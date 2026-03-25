"""Governance Engine Lambda handler — orchestrates the full governance decision pipeline.

Entry point for the Governance Engine Lambda. Invoked synchronously by the
Scope Enforcer to evaluate agent action requests against policies, compute
risk scores, produce governance decisions, write evidence, and track latency.

Pipeline steps:
1. Parse incoming event (agent_id, action_group, target_resource, input_text, scope_level)
2. Initialize LatencyTracker
3. Call safe_evaluate_policy() (fail-safe wrapper around PolicyEngine)
4. Call safe_compute_risk() (fail-safe wrapper around RiskScoringEngine)
5. Call DecisionEngine.decide() to produce GovernanceDecision
6. Call DecisionEngine.log_decision() to write structured decision log
7. Call safe_write_evidence() to initiate evidence write to S3 (non-blocking on failure)
8. Record latency metric via LatencyTracker.record_latency()
9. Return GovernanceDecision as JSON response

DynamoDB unavailability: if governance tables are unreachable, deny all
requests and log a structured failure record (Req 18.2).

Requirements: 1.1, 2.1, 3.1, 4.1, 17.1, 18.1, 18.2, 18.4, 18.5
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import boto3

from .decision_engine import DecisionEngine
from .fail_safe import safe_compute_risk, safe_evaluate_policy, safe_write_evidence
from .latency import LatencyTracker
from .models import GovernanceDecision, PolicyEvaluationResult, RiskAssessment
from .policy_engine import PolicyEngine
from .risk_scoring import RiskScoringEngine

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
POLICY_BUCKET_NAME = os.environ.get("POLICY_BUCKET_NAME", "")
POLICY_PREFIX = os.environ.get("POLICY_PREFIX", "policies/")
EVIDENCE_BUCKET_NAME = os.environ.get("EVIDENCE_BUCKET_NAME", "")


def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _build_action_request(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalise the action request from the incoming event.

    Args:
        event: The raw Lambda event dict.

    Returns:
        A dict suitable for passing to PolicyEngine.evaluate() and
        RiskScoringEngine.compute_risk().
    """
    return {
        "agent_id": event.get("agent_id", ""),
        "action_group": event.get("action_group", ""),
        "target_resource": event.get("target_resource", ""),
        "input_text": event.get("input_text", ""),
        "scope_level": int(event.get("scope_level", 1)),
    }


def _write_evidence_to_s3(decision: GovernanceDecision) -> None:
    """Write a governance decision as an evidence record to S3.

    Evidence is partitioned under:
        evidence/decisions/YYYY/MM/DD/{decision_id}.json

    Args:
        decision: The GovernanceDecision to persist.

    Raises:
        Any exception from the S3 put_object call — callers should
        wrap this with safe_write_evidence().
    """
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


def _deny_response(reason: str, agent_id: str = "") -> Dict[str, Any]:
    """Build a fail-safe deny response dict.

    Args:
        reason: Human-readable reason for the denial.
        agent_id: The agent identifier, if available.

    Returns:
        A dict representing a denied GovernanceDecision payload.
    """
    import uuid

    decision = GovernanceDecision(
        decision_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action_requested="unknown",
        verdict="deny",
        explanation=reason,
        timestamp=_iso_now(),
    )
    return decision.to_dict()


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

    # ------------------------------------------------------------------
    # 2. Initialize LatencyTracker (Req 17.1)
    # ------------------------------------------------------------------
    tracker = LatencyTracker()

    try:
        # --------------------------------------------------------------
        # 3. Initialise engines — DynamoDB unavailability check (Req 18.2)
        # --------------------------------------------------------------
        try:
            policy_engine = PolicyEngine()
            s3_client = boto3.client("s3")
            policy_engine.load_policies(s3_client, POLICY_BUCKET_NAME, POLICY_PREFIX)

            risk_engine = RiskScoringEngine()
            risk_engine.load_config()

            decision_engine = DecisionEngine(
                escalation_threshold=risk_engine.escalation_threshold,
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
            )

        # --------------------------------------------------------------
        # 4. Policy evaluation (Req 2.1) — fail-safe wrapper (Req 18.1)
        # --------------------------------------------------------------
        with tracker.track("policy_evaluation"):
            policy_result = safe_evaluate_policy(policy_engine, action_request)

        # --------------------------------------------------------------
        # 5. Risk scoring (Req 3.1) — fail-safe wrapper (Req 18.3)
        # --------------------------------------------------------------
        with tracker.track("risk_scoring"):
            risk_assessment = safe_compute_risk(
                risk_engine, action_request, scope_level,
            )

        # --------------------------------------------------------------
        # 6. Decision engine (Req 4.1)
        # --------------------------------------------------------------
        with tracker.track("decision_engine"):
            decision = decision_engine.decide(
                policy_result, risk_assessment, action_request, agent_id,
            )

        # --------------------------------------------------------------
        # 7. Log structured decision record (Req 4.6, 4.9)
        # --------------------------------------------------------------
        decision_engine.log_decision(decision)

        # --------------------------------------------------------------
        # 8. Evidence write — non-blocking on failure (Req 18.4)
        # --------------------------------------------------------------
        with tracker.track("evidence_write_initiation"):
            safe_write_evidence(_write_evidence_to_s3, decision)

        # --------------------------------------------------------------
        # 9. Record latency metric (Req 17.1, 17.2)
        # --------------------------------------------------------------
        latency_metric = tracker.record_latency(decision.decision_id)
        decision.latency_breakdown = latency_metric.component_latencies

        # --------------------------------------------------------------
        # 10. Return GovernanceDecision as JSON
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
        )
