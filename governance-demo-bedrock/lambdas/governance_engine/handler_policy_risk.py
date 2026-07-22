"""Policy and Risk Lambda - Layer 4 of the governance pipeline.

Performs policy evaluation, risk scoring, drift detection, and decision:
- Load and evaluate policies from S3
- Compute risk score (0-100)
- Apply drift detection adjustments
- Produce final verdict (allow/deny/escalate)

Invoked by Step Functions. Returns governance decision.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3

from policy_engine import PolicyEngine
from opa_engine import OPAEngine
from risk_scoring import RiskScoringEngine
from decision_engine import DecisionEngine
from runtime_drift_detection import RuntimeDriftDetector
from models import GovernanceDecision, PolicyEvaluationResult
from fail_safe import safe_evaluate_opa, safe_evaluate_policy, safe_compute_risk

logger = logging.getLogger()
logger.setLevel(logging.INFO)

POLICY_BUCKET_NAME = os.environ.get("POLICY_BUCKET_NAME", "")
POLICY_PREFIX = os.environ.get("POLICY_PREFIX", "policies/")
RISK_CONFIG_TABLE_NAME = os.environ.get("RISK_CONFIG_TABLE_NAME", "")
FRAMEWORK_MAPPING_TABLE_NAME = os.environ.get("FRAMEWORK_MAPPING_TABLE_NAME", "")
RUNTIME_DRIFT_TABLE_NAME = os.environ.get("RUNTIME_DRIFT_TABLE_NAME", "")

# In-Lambda cache
_CACHE = {}
_CACHE_TTL = 60


def _cached_policy_engine():
    """Return a PolicyEngine with cached policies."""
    now = time.time()
    cache_key = "policy_engine"
    if cache_key in _CACHE and (now - _CACHE[cache_key]["ts"]) < _CACHE_TTL:
        return _CACHE[cache_key]["data"]

    engine = PolicyEngine()
    if POLICY_BUCKET_NAME:
        s3_client = boto3.client("s3")
        engine.load_policies(s3_client, POLICY_BUCKET_NAME, POLICY_PREFIX)

    _CACHE[cache_key] = {"data": engine, "ts": now}
    return engine


def handler(event, context):
    """Policy and Risk handler.

    Input event (merged from parallel branches):
        agent_id (str)
        action_group (str)
        target_resource (str)
        input_text (str)
        scope_level (int)
        sanitized_text (str): From input defense
        risk_score_adjustment (int): From input defense (threat suspicion)
        agent_environment (str): From authorization

    Returns:
        {
            "decision_id": str,
            "agent_id": str,
            "action_requested": str,
            "verdict": "allow" | "deny" | "escalate",
            "risk_score": float,
            "explanation": str,
            "policy_result": dict,
            "framework_mapping": list,
            "timestamp": str
        }
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    agent_id = event.get("agent_id", "")
    action_group = event.get("action_group", "")
    target_resource = event.get("target_resource", "")
    scope_level = int(event.get("scope_level", 1))
    risk_score_adjustment = int(event.get("risk_score_adjustment", 0))

    action_request = {
        "agent_id": agent_id,
        "action_group": action_group,
        "target_resource": target_resource,
        "scope_level": scope_level,
    }

    # 1. Runtime Drift Detection
    if RUNTIME_DRIFT_TABLE_NAME:
        try:
            drift_table = boto3.resource("dynamodb").Table(RUNTIME_DRIFT_TABLE_NAME)
            drift_detector = RuntimeDriftDetector()
            drift_result = drift_detector.compute_drift_score(
                agent_id, action_group, target_resource, scope_level, drift_table,
            )
            if drift_result.baseline_present and drift_result.drift_score > 50:
                risk_score_adjustment += int(drift_result.drift_score * 0.3)
        except Exception as e:
            logger.error(json.dumps({"event": "drift_check_failed", "error": str(e)}))

    # 2. Policy Evaluation (OPA with legacy fallback)
    opa_engine = OPAEngine()
    if POLICY_BUCKET_NAME:
        s3_client = boto3.client("s3")
        opa_engine.load_policies_from_s3(s3_client, POLICY_BUCKET_NAME, POLICY_PREFIX)

    if opa_engine.rule_count > 0:
        now_utc = datetime.now(timezone.utc)
        opa_input = {
            **action_request,
            "hour": now_utc.hour,
            "day_of_week": now_utc.strftime("%A").lower(),
        }
        opa_decision = safe_evaluate_opa(opa_engine, opa_input)
        policy_result = PolicyEvaluationResult(
            policy_id=opa_decision.matched_rules[0] if opa_decision.matched_rules else "default-deny",
            outcome=opa_decision.verdict,
            matching_conditions={"opa_rules": opa_decision.matched_rules},
            evaluation_timestamp=opa_decision.timestamp,
        )
    else:
        policy_engine = _cached_policy_engine()
        policy_result = safe_evaluate_policy(policy_engine, action_request)

    # 3. Risk Scoring
    risk_engine = RiskScoringEngine()
    risk_assessment = safe_compute_risk(risk_engine, action_request, scope_level)
    risk_assessment.risk_score = min(100, risk_assessment.risk_score + risk_score_adjustment)

    # 4. Decision
    decision_engine = DecisionEngine()
    governance_decision = decision_engine.decide(
        policy_result, risk_assessment, action_request, agent_id
    )

    decision = {
        "decision_id": governance_decision.decision_id,
        "agent_id": governance_decision.agent_id,
        "action_requested": governance_decision.action_requested,
        "verdict": governance_decision.verdict,
        "risk_score": float(governance_decision.risk_score),
        "explanation": governance_decision.explanation,
        "policy_result": {
            "policy_id": policy_result.policy_id,
            "outcome": policy_result.outcome,
            "matching_conditions": policy_result.matching_conditions,
        },
        "framework_mapping": governance_decision.framework_mapping,
        "timestamp": governance_decision.timestamp,
    }

    logger.info(json.dumps({
        "audit_event": "governance_decision",
        "decision_id": governance_decision.decision_id,
        "agent_id": agent_id,
        "verdict": governance_decision.verdict,
        "risk_score": float(governance_decision.risk_score),
        "policy_id": policy_result.policy_id,
        "timestamp": timestamp,
    }))

    return decision
