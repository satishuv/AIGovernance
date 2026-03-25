"""Context-Aware Decision Engine — combines policy evaluation and risk scoring.

Produces a final GovernanceDecision by combining the PolicyEvaluationResult
and RiskAssessment, applying escalation threshold logic, populating
framework mappings from DynamoDB, and logging structured decision records.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

from .models import GovernanceDecision, PolicyEvaluationResult, RiskAssessment

logger = logging.getLogger(__name__)


def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


class DecisionEngine:
    """Combines policy evaluation and risk scoring into a governance decision.

    The decision logic follows these rules (Requirements 4.1-4.5):
      - policy outcome "deny"     -> verdict "deny"  (regardless of risk)
      - policy outcome "escalate" -> verdict "escalate" (regardless of risk)
      - policy outcome "allow" and risk_score >= threshold -> verdict "escalate"
      - policy outcome "allow" and risk_score <  threshold -> verdict "allow"

    Each decision includes a human-readable explanation (Req 4.7) and a
    framework_mapping array populated from the FrameworkMappingTable in
    DynamoDB (Req 4.8).
    """

    def __init__(
        self,
        escalation_threshold: float = 70.0,
        dynamodb_resource: Optional[Any] = None,
    ) -> None:
        self._escalation_threshold = escalation_threshold
        self._dynamodb = dynamodb_resource
        self._framework_table_name: str = os.environ.get(
            "FRAMEWORK_MAPPING_TABLE_NAME", ""
        )
        self._framework_cache: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------
    # Core decision logic
    # ------------------------------------------------------------------

    def decide(
        self,
        policy_result: PolicyEvaluationResult,
        risk_assessment: RiskAssessment,
        action_request: Dict[str, Any],
        agent_id: str,
    ) -> GovernanceDecision:
        """Produce a GovernanceDecision from policy and risk inputs.

        Args:
            policy_result: The outcome of policy evaluation.
            risk_assessment: The computed risk assessment.
            action_request: Dict describing the agent's requested action.
            agent_id: Identifier of the agent whose action is evaluated.

        Returns:
            A fully populated GovernanceDecision.
        """
        risk_score = risk_assessment.risk_score
        action_requested = action_request.get("action_group", "unknown")

        # --- Determine verdict (Reqs 4.2-4.5) ---
        verdict, explanation = self._resolve_verdict(
            policy_result, risk_score, action_requested
        )

        # --- Framework mapping (Req 4.8) ---
        framework_mapping = self._lookup_framework_mapping(action_requested)

        decision = GovernanceDecision(
            decision_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action_requested=action_requested,
            policy_result=policy_result.to_dict(),
            risk_score=risk_score,
            verdict=verdict,
            explanation=explanation,
            framework_mapping=framework_mapping,
            timestamp=_iso_now(),
        )

        return decision

    # ------------------------------------------------------------------
    # Verdict resolution
    # ------------------------------------------------------------------

    def _resolve_verdict(
        self,
        policy_result: PolicyEvaluationResult,
        risk_score: float,
        action_requested: str,
    ) -> tuple:
        """Apply the decision matrix and return (verdict, explanation).

        Returns:
            A tuple of (verdict_str, explanation_str).
        """
        outcome = policy_result.outcome

        if outcome == "deny":
            verdict = "deny"
            explanation = (
                f"Action '{action_requested}' denied by policy "
                f"'{policy_result.policy_id}'. "
                f"Policy outcome is 'deny'; risk score ({risk_score:.1f}) "
                f"is not considered when policy explicitly denies."
            )
        elif outcome == "escalate":
            verdict = "escalate"
            explanation = (
                f"Action '{action_requested}' escalated by policy "
                f"'{policy_result.policy_id}'. "
                f"Policy outcome is 'escalate'; risk score ({risk_score:.1f}) "
                f"is not considered when policy explicitly escalates."
            )
        elif outcome == "allow" and risk_score >= self._escalation_threshold:
            verdict = "escalate"
            explanation = (
                f"Action '{action_requested}' allowed by policy "
                f"'{policy_result.policy_id}', but risk score "
                f"({risk_score:.1f}) meets or exceeds the escalation "
                f"threshold ({self._escalation_threshold:.1f}). "
                f"Escalating for human review."
            )
        else:
            # outcome == "allow" and risk_score < threshold
            verdict = "allow"
            explanation = (
                f"Action '{action_requested}' allowed by policy "
                f"'{policy_result.policy_id}'. "
                f"Risk score ({risk_score:.1f}) is below the escalation "
                f"threshold ({self._escalation_threshold:.1f})."
            )

        return verdict, explanation

    # ------------------------------------------------------------------
    # Framework mapping lookup
    # ------------------------------------------------------------------

    def _lookup_framework_mapping(self, action_type: str) -> List[str]:
        """Look up ISO 42001 and NIST AI RMF control IDs for an action type.

        Reads from the FrameworkMappingTable in DynamoDB. Results are
        cached in-memory to avoid repeated lookups for the same action
        type within a single Lambda invocation.

        Args:
            action_type: The action type key (e.g. "data_access").

        Returns:
            A list of control ID strings, or an empty list on failure.
        """
        if action_type in self._framework_cache:
            return list(self._framework_cache[action_type])

        if not self._framework_table_name:
            logger.warning(
                json.dumps(
                    {
                        "event": "framework_mapping_skipped",
                        "reason": "FRAMEWORK_MAPPING_TABLE_NAME not set",
                        "action_type": action_type,
                        "timestamp": _iso_now(),
                    }
                )
            )
            return []

        try:
            if self._dynamodb is None:
                self._dynamodb = boto3.resource("dynamodb")

            table = self._dynamodb.Table(self._framework_table_name)
            response = table.get_item(Key={"action_type": action_type})
            item = response.get("Item", {})

            iso_controls = item.get("iso_42001_controls", [])
            nist_functions = item.get("nist_ai_rmf_functions", [])
            mapping = list(iso_controls) + list(nist_functions)

            self._framework_cache[action_type] = mapping

            logger.info(
                json.dumps(
                    {
                        "event": "framework_mapping_loaded",
                        "action_type": action_type,
                        "control_count": len(mapping),
                        "timestamp": _iso_now(),
                    }
                )
            )
            return list(mapping)

        except Exception as exc:
            logger.error(
                json.dumps(
                    {
                        "event": "framework_mapping_lookup_failure",
                        "action_type": action_type,
                        "error": str(exc),
                        "timestamp": _iso_now(),
                    }
                )
            )
            return []

    # ------------------------------------------------------------------
    # Decision logging (Req 4.6, 4.9)
    # ------------------------------------------------------------------

    def log_decision(self, decision: GovernanceDecision) -> None:
        """Write a structured log entry for a governance decision.

        Serializes the GovernanceDecision to JSON and emits a structured
        log record containing agent_id, action_requested, policy_result,
        risk_score, verdict, timestamp, and framework_mapping.

        Args:
            decision: The GovernanceDecision to log.
        """
        log_entry = {
            "event": "governance_decision",
            "decision_id": decision.decision_id,
            "agent_id": decision.agent_id,
            "action_requested": decision.action_requested,
            "policy_result": decision.policy_result,
            "risk_score": decision.risk_score,
            "verdict": decision.verdict,
            "explanation": decision.explanation,
            "framework_mapping": decision.framework_mapping,
            "timestamp": decision.timestamp,
            "latency_breakdown": decision.latency_breakdown,
        }
        logger.info(json.dumps(log_entry))

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def escalation_threshold(self) -> float:
        """Return the current escalation threshold."""
        return self._escalation_threshold
