"""Continuous Monitoring module.

Tracks agent health scores using exponential moving averages, denial rate penalties,
escalation penalties, and risk penalties. Detects statistical anomalies using z-score
analysis over a rolling window of recent risk scores.

DynamoDB table schema:
    PK: agent_id (String)
    SK: record_type (String) - values: "health_state", "score_window#<timestamp>"
"""

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Health formula parameters
EMA_ALPHA = 0.3
DENIAL_PENALTY_PER_INCIDENT = 8
DENIAL_PENALTY_CAP = 40
RISK_PENALTY_MAX = 30
ESCALATION_PENALTY_PER_INCIDENT = 5
ESCALATION_PENALTY_CAP = 30

# Score history window size
SCORE_HISTORY_MAX = 20

# Anomaly detection threshold (z-score)
ANOMALY_Z_THRESHOLD = 2.0

# Health status thresholds
HEALTHY_THRESHOLD = 70
DEGRADED_THRESHOLD = 40


@dataclass
class AgentHealthState:
    """Health state for a governed agent, updated after each governance decision.

    Attributes:
        agent_id: Identifier of the agent.
        health_score: Composite health score between 0 and 100.
        status: Health status - "healthy", "degraded", or "critical".
        denial_count_1h: Number of denials in the last hour.
        escalation_count_24h: Number of escalations in the last 24 hours.
        avg_risk: Exponential moving average of risk scores.
        score_history: Rolling window of the last 20 risk scores.
        last_updated: ISO 8601 timestamp of the last update.
    """

    agent_id: str
    health_score: int = 100
    status: str = "healthy"
    denial_count_1h: int = 0
    escalation_count_24h: int = 0
    avg_risk: float = 0.0
    score_history: List[float] = field(default_factory=list)
    last_updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "health_score": self.health_score,
            "status": self.status,
            "denial_count_1h": self.denial_count_1h,
            "escalation_count_24h": self.escalation_count_24h,
            "avg_risk": Decimal(str(self.avg_risk)),
            "score_history": [Decimal(str(s)) for s in self.score_history],
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentHealthState":
        return cls(
            agent_id=data["agent_id"],
            health_score=int(data.get("health_score", 100)),
            status=data.get("status", "healthy"),
            denial_count_1h=int(data.get("denial_count_1h", 0)),
            escalation_count_24h=int(data.get("escalation_count_24h", 0)),
            avg_risk=float(data.get("avg_risk", 0.0)),
            score_history=[float(s) for s in data.get("score_history", [])],
            last_updated=data.get("last_updated", ""),
        )


class ContinuousMonitoringManager:
    """Manages agent health tracking and anomaly detection."""

    def update_health(
        self,
        agent_id: str,
        verdict: str,
        risk_score: float,
        health_table,
    ) -> AgentHealthState:
        """Update agent health metrics after a governance decision.

        Recomputes health score from denial rate, risk penalty, and escalation
        penalty components. Health formula:
            health = 100 - (denial_rate_penalty + risk_penalty + escalation_penalty)

        Args:
            agent_id: Identifier of the agent.
            verdict: Governance verdict - "allow", "deny", or "escalate".
            risk_score: Risk score from the current decision (0-100).
            health_table: DynamoDB Table resource for health data.

        Returns:
            Updated AgentHealthState.
        """
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()

        # Load current state
        current_state = self.get_health(agent_id, health_table)

        # Update denial count
        denial_count = current_state.denial_count_1h
        if verdict == "deny":
            denial_count += 1

        # Update escalation count. AARM DEFER is a suspended decision like
        # STEP_UP (escalate), so it counts toward escalations for health.
        escalation_count = current_state.escalation_count_24h
        if verdict in ("escalate", "defer"):
            escalation_count += 1

        # Update exponential moving average of risk
        prev_avg = current_state.avg_risk
        new_avg = (EMA_ALPHA * risk_score) + ((1 - EMA_ALPHA) * prev_avg)
        new_avg = round(new_avg, 2)

        # Update score history (rolling window)
        score_history = list(current_state.score_history)
        score_history.append(risk_score)
        if len(score_history) > SCORE_HISTORY_MAX:
            score_history = score_history[-SCORE_HISTORY_MAX:]

        # Compute health score
        denial_rate_penalty = min(
            denial_count * DENIAL_PENALTY_PER_INCIDENT, DENIAL_PENALTY_CAP
        )
        risk_penalty = (new_avg / 100.0) * RISK_PENALTY_MAX
        escalation_penalty = min(
            escalation_count * ESCALATION_PENALTY_PER_INCIDENT, ESCALATION_PENALTY_CAP
        )

        health_score = int(
            max(0, 100 - (denial_rate_penalty + risk_penalty + escalation_penalty))
        )
        health_score = min(health_score, 100)

        # Determine status
        if health_score >= HEALTHY_THRESHOLD:
            status = "healthy"
        elif health_score >= DEGRADED_THRESHOLD:
            status = "degraded"
        else:
            status = "critical"

        # Build updated state
        updated_state = AgentHealthState(
            agent_id=agent_id,
            health_score=health_score,
            status=status,
            denial_count_1h=denial_count,
            escalation_count_24h=escalation_count,
            avg_risk=new_avg,
            score_history=score_history,
            last_updated=timestamp,
        )

        # Persist to DynamoDB
        self._persist_health_state(updated_state, health_table)

        logger.info(json.dumps({
            "event": "health_updated",
            "agent_id": agent_id,
            "health_score": health_score,
            "status": status,
            "verdict": verdict,
            "risk_score": str(risk_score),
            "denial_count_1h": denial_count,
            "escalation_count_24h": escalation_count,
            "avg_risk": str(new_avg),
            "timestamp": timestamp,
        }))

        return updated_state

    def get_health(self, agent_id: str, health_table) -> AgentHealthState:
        """Read the current health state for an agent.

        Returns a default healthy state (score=100) if no record exists.

        Args:
            agent_id: Identifier of the agent.
            health_table: DynamoDB Table resource for health data.

        Returns:
            Current AgentHealthState.
        """
        try:
            response = health_table.get_item(
                Key={"agent_id": agent_id, "record_type": "health_state"}
            )
            item = response.get("Item")
            if item:
                return AgentHealthState.from_dict(item)
        except Exception as exc:
            logger.error(json.dumps({
                "event": "get_health_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        # Return default healthy state
        return AgentHealthState(
            agent_id=agent_id,
            health_score=100,
            status="healthy",
            denial_count_1h=0,
            escalation_count_24h=0,
            avg_risk=0.0,
            score_history=[],
            last_updated=datetime.now(timezone.utc).isoformat(),
        )

    def detect_anomaly(
        self,
        agent_id: str,
        risk_score: float,
        health_table,
    ) -> Optional[str]:
        """Detect statistical anomalies using z-score analysis.

        Computes z-score of the current risk_score against the stored score
        history. If the score is more than 2 standard deviations above the mean,
        returns an anomaly description.

        Args:
            agent_id: Identifier of the agent.
            risk_score: Current risk score to evaluate.
            health_table: DynamoDB Table resource for health data.

        Returns:
            Anomaly description string if anomaly detected, None otherwise.
        """
        current_state = self.get_health(agent_id, health_table)
        score_history = current_state.score_history

        # Need at least 3 data points for meaningful z-score
        if len(score_history) < 3:
            logger.info(json.dumps({
                "event": "anomaly_check_skipped",
                "reason": "insufficient_history",
                "agent_id": agent_id,
                "history_size": len(score_history),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

        # Compute mean and standard deviation
        mean = sum(score_history) / len(score_history)
        variance = sum((s - mean) ** 2 for s in score_history) / len(score_history)
        std_dev = math.sqrt(variance)

        # Avoid division by zero for constant histories
        if std_dev < 0.01:
            # If all scores are the same and current differs significantly
            if abs(risk_score - mean) > 10:
                anomaly_msg = (
                    f"Risk score {risk_score} deviates significantly from "
                    f"constant baseline of {mean:.1f} for agent {agent_id}"
                )
                logger.warning(json.dumps({
                    "event": "anomaly_detected",
                    "agent_id": agent_id,
                    "risk_score": str(risk_score),
                    "mean": str(round(mean, 2)),
                    "std_dev": "0.0",
                    "reason": "constant_baseline_deviation",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                return anomaly_msg
            return None

        z_score = (risk_score - mean) / std_dev

        if z_score > ANOMALY_Z_THRESHOLD:
            anomaly_msg = (
                f"Risk score {risk_score} is {z_score:.2f} standard deviations "
                f"above mean {mean:.1f} (std_dev={std_dev:.2f}) for agent {agent_id}"
            )
            logger.warning(json.dumps({
                "event": "anomaly_detected",
                "agent_id": agent_id,
                "risk_score": str(risk_score),
                "z_score": str(round(z_score, 2)),
                "mean": str(round(mean, 2)),
                "std_dev": str(round(std_dev, 2)),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return anomaly_msg

        logger.info(json.dumps({
            "event": "anomaly_check_passed",
            "agent_id": agent_id,
            "risk_score": str(risk_score),
            "z_score": str(round(z_score, 2)),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        return None

    def _persist_health_state(
        self, state: AgentHealthState, health_table
    ) -> None:
        """Persist the health state to DynamoDB."""
        item = state.to_dict()
        item["record_type"] = "health_state"

        try:
            health_table.put_item(Item=item)
        except Exception as exc:
            logger.error(json.dumps({
                "event": "persist_health_state_failed",
                "agent_id": state.agent_id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
