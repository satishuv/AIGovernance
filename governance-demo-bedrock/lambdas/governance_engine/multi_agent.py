"""Multi-Agent Governance Support module.

Provides per-agent configuration, policy binding resolution, cross-agent rule
enforcement, per-agent evidence partitioning, and aggregate reporting across
multiple agents.

Requirements: 30.1, 30.2, 30.3, 30.4, 30.5
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models import MultiAgentConfig

logger = logging.getLogger(__name__)


class MultiAgentManager:
    """Manages multi-agent governance configuration and enforcement."""

    def get_agent_config(
        self, agent_id: str, dynamodb_table
    ) -> Optional[MultiAgentConfig]:
        """Retrieve MultiAgentConfig for an agent."""
        try:
            response = dynamodb_table.get_item(Key={"agent_id": agent_id})
            item = response.get("Item")
            if not item:
                logger.warning(json.dumps({
                    "event": "agent_config_not_found",
                    "agent_id": agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                return None
            return MultiAgentConfig.from_dict(item)
        except Exception as exc:
            logger.error(json.dumps({
                "event": "get_agent_config_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

    def get_agent_policy_bindings(
        self, agent_id: str, agent_registry_table,
        policy_metadata_table,
    ) -> List[str]:
        """Resolve agent-specific policy bindings from registry attributes."""
        try:
            reg_response = agent_registry_table.get_item(
                Key={"agent_id": agent_id}
            )
            registry = reg_response.get("Item")
            if not registry:
                return []

            pol_response = policy_metadata_table.scan()
            policies = pol_response.get("Items", [])
            while "LastEvaluatedKey" in pol_response:
                pol_response = policy_metadata_table.scan(
                    ExclusiveStartKey=pol_response["LastEvaluatedKey"]
                )
                policies.extend(pol_response.get("Items", []))

            return [
                p.get("policy_id", "")
                for p in policies
                if p.get("approval_status") == "approved" and p.get("policy_id")
            ]
        except Exception as exc:
            logger.error(json.dumps({
                "event": "get_agent_policy_bindings_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return []

    def enforce_cross_agent_rules(
        self, requesting_agent_id: str, target_agent_id: str,
        action_request: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Prevent one agent from modifying another agent's scope or config.

        Returns:
            Tuple of (allowed, violation_reason). allowed=True if OK.
        """
        if requesting_agent_id == target_agent_id:
            return True, ""

        action_group = action_request.get("action_group", "").lower()
        target_resource = action_request.get("target_resource", "")

        protected = {
            "update_scope", "modify_registry", "modify_tool_registry",
            "suspend_agent", "modify_config",
        }
        if action_group in protected:
            reason = (
                f"Agent '{requesting_agent_id}' cannot modify agent "
                f"'{target_agent_id}' via '{action_group}'."
            )
            logger.warning(json.dumps({
                "audit_event": "cross_agent_violation",
                "requesting_agent": requesting_agent_id,
                "target_agent": target_agent_id,
                "action_group": action_group,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return False, reason

        if target_agent_id in target_resource:
            if any(kw in action_group for kw in ("scope", "config", "registry")):
                reason = (
                    f"Agent '{requesting_agent_id}' cannot target agent "
                    f"'{target_agent_id}' resource '{target_resource}'."
                )
                logger.warning(json.dumps({
                    "audit_event": "cross_agent_resource_violation",
                    "requesting_agent": requesting_agent_id,
                    "target_agent": target_agent_id,
                    "target_resource": target_resource,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                return False, reason

        return True, ""

    @staticmethod
    def get_evidence_partition(agent_id: str) -> str:
        """Return per-agent evidence S3 key prefix."""
        return f"evidence/{agent_id}/"

    def generate_aggregate_report(
        self, agent_ids: List[str], decision_history_table,
        measure_manage_engine, start_date: str, end_date: str,
    ) -> Dict[str, Any]:
        """Produce aggregate metrics across all specified agents.

        Returns:
            Combined report with per-agent breakdowns and cross-agent totals.
        """
        now = datetime.now(timezone.utc).isoformat()
        per_agent: Dict[str, Any] = {}
        total_decisions = 0
        total_denials = 0
        total_escalations = 0
        all_risk: List[float] = []

        for agent_id in agent_ids:
            try:
                metrics = measure_manage_engine.compute_aggregate_metrics(
                    decision_history_table, start_date, end_date
                )
                per_agent[agent_id] = metrics.to_dict()
                total_decisions += metrics.total_decisions
                total_denials += int(metrics.denial_rate * metrics.total_decisions)
                total_escalations += int(
                    metrics.escalation_rate * metrics.total_decisions
                )
                all_risk.append(metrics.avg_risk_score)
            except Exception as exc:
                logger.error(json.dumps({
                    "event": "aggregate_report_agent_failed",
                    "agent_id": agent_id, "error": str(exc),
                    "timestamp": now,
                }))
                per_agent[agent_id] = {"error": str(exc)}

        avg_risk = (
            round(sum(all_risk) / len(all_risk), 2) if all_risk else 0.0
        )
        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": now,
            "start_date": start_date,
            "end_date": end_date,
            "agent_count": len(agent_ids),
            "totals": {
                "total_decisions": total_decisions,
                "total_denials": total_denials,
                "total_escalations": total_escalations,
                "avg_risk_score": avg_risk,
            },
            "per_agent": per_agent,
        }
