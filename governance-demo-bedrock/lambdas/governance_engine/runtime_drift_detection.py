"""Runtime Drift Detection module.

Detects when agent behavior deviates from its registered baseline by comparing
current action requests against historical activity patterns. Computes a composite
drift score (0-100) from four weighted factors: action group novelty, target novelty,
scope deviation, and frequency spike.

DynamoDB table schema:
    PK: agent_id (String)
    SK: record_type (String) - values: "baseline", "drift_tracker", "activity#<timestamp>"
"""

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Drift factor weights (must sum to 100)
WEIGHT_ACTION_GROUP_NOVELTY = 40
WEIGHT_TARGET_NOVELTY = 25
WEIGHT_SCOPE_DEVIATION = 20
WEIGHT_FREQUENCY_SPIKE = 15

# Activity TTL: 7 days in seconds
ACTIVITY_TTL_SECONDS = 7 * 24 * 60 * 60

# Frequency spike threshold: requests per 5-minute window
FREQUENCY_WINDOW_SECONDS = 300
FREQUENCY_SPIKE_THRESHOLD = 10


@dataclass
class DriftResult:
    """Result of a drift score computation for an agent action request.

    Attributes:
        agent_id: Identifier of the agent evaluated.
        drift_score: Composite drift score between 0 and 100.
        factors: Mapping of factor names to their individual contribution values.
        baseline_present: False if no baseline exists (drift check is skipped).
        timestamp: ISO 8601 timestamp of the drift evaluation.
    """

    agent_id: str
    drift_score: float
    factors: Dict[str, float] = field(default_factory=dict)
    baseline_present: bool = True
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "drift_score": Decimal(str(self.drift_score)),
            "factors": {k: Decimal(str(v)) for k, v in self.factors.items()},
            "baseline_present": self.baseline_present,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DriftResult":
        return cls(
            agent_id=data["agent_id"],
            drift_score=float(data["drift_score"]),
            factors={k: float(v) for k, v in data.get("factors", {}).items()},
            baseline_present=data.get("baseline_present", True),
            timestamp=data.get("timestamp", ""),
        )


class RuntimeDriftDetector:
    """Detects behavioral drift by comparing agent requests to stored baselines."""

    def compute_drift_score(
        self,
        agent_id: str,
        action_group: str,
        target_resource: str,
        scope_level: int,
        drift_table,
    ) -> DriftResult:
        """Compute composite drift score for an agent action request.

        Compares the request against the agent's stored baseline. Drift factors:
            - action_group_novelty: action not in baseline frequencies (weight 40)
            - target_novelty: target_resource not in known targets (weight 25)
            - scope_deviation: scope_level much higher than baseline avg (weight 20)
            - frequency_spike: too many requests in short window (weight 15)

        Args:
            agent_id: Identifier of the agent making the request.
            action_group: The action group being invoked.
            target_resource: The resource being targeted.
            scope_level: Current scope level of the request.
            drift_table: DynamoDB Table resource for drift data.

        Returns:
            DriftResult with composite score and per-factor breakdown.
        """
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()

        # Load baseline
        baseline = self._load_baseline(agent_id, drift_table)
        if baseline is None:
            logger.info(json.dumps({
                "event": "drift_check_skipped",
                "reason": "no_baseline",
                "agent_id": agent_id,
                "timestamp": timestamp,
            }))
            return DriftResult(
                agent_id=agent_id,
                drift_score=0.0,
                factors={},
                baseline_present=False,
                timestamp=timestamp,
            )

        factors: Dict[str, float] = {}

        # Factor 1: Action group novelty
        known_actions = baseline.get("action_group_frequencies", {})
        if action_group not in known_actions:
            factors["action_group_novelty"] = float(WEIGHT_ACTION_GROUP_NOVELTY)
        else:
            factors["action_group_novelty"] = 0.0

        # Factor 2: Target novelty
        known_targets = baseline.get("known_targets", [])
        if target_resource not in known_targets:
            factors["target_novelty"] = float(WEIGHT_TARGET_NOVELTY)
        else:
            factors["target_novelty"] = 0.0

        # Factor 3: Scope deviation
        avg_scope = float(baseline.get("avg_scope_level", scope_level))
        if avg_scope > 0:
            deviation_ratio = (scope_level - avg_scope) / max(avg_scope, 1.0)
            # Only penalize upward deviation
            if deviation_ratio > 0:
                scope_contribution = min(
                    deviation_ratio * WEIGHT_SCOPE_DEVIATION,
                    float(WEIGHT_SCOPE_DEVIATION),
                )
            else:
                scope_contribution = 0.0
        else:
            scope_contribution = 0.0
        factors["scope_deviation"] = round(scope_contribution, 2)

        # Factor 4: Frequency spike
        frequency_contribution = self._compute_frequency_factor(
            agent_id, drift_table, now
        )
        factors["frequency_spike"] = round(frequency_contribution, 2)

        # Composite score (capped at 100)
        drift_score = min(sum(factors.values()), 100.0)
        drift_score = round(drift_score, 2)

        # Update drift tracker
        self._update_drift_tracker(agent_id, drift_score, drift_table, timestamp)

        logger.info(json.dumps({
            "event": "drift_score_computed",
            "agent_id": agent_id,
            "drift_score": drift_score,
            "factors": {k: str(v) for k, v in factors.items()},
            "timestamp": timestamp,
        }))

        return DriftResult(
            agent_id=agent_id,
            drift_score=drift_score,
            factors=factors,
            baseline_present=True,
            timestamp=timestamp,
        )

    def record_activity(
        self,
        agent_id: str,
        action_group: str,
        target_resource: str,
        scope_level: int,
        drift_table,
    ) -> None:
        """Record an agent activity for future baseline computation.

        Writes an activity record with a 7-day TTL for automatic cleanup.

        Args:
            agent_id: Identifier of the agent.
            action_group: The action group invoked.
            target_resource: The resource targeted.
            scope_level: Scope level of the request.
            drift_table: DynamoDB Table resource for drift data.
        """
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        ttl_epoch = int((now + timedelta(seconds=ACTIVITY_TTL_SECONDS)).timestamp())

        item = {
            "agent_id": agent_id,
            "record_type": f"activity#{timestamp}",
            "action_group": action_group,
            "target_resource": target_resource,
            "scope_level": scope_level,
            "timestamp": timestamp,
            "ttl": ttl_epoch,
        }

        try:
            drift_table.put_item(Item=item)
            logger.info(json.dumps({
                "event": "activity_recorded",
                "agent_id": agent_id,
                "action_group": action_group,
                "target_resource": target_resource,
                "scope_level": scope_level,
                "timestamp": timestamp,
            }))
        except Exception as exc:
            logger.error(json.dumps({
                "event": "activity_record_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": timestamp,
            }))

    def get_drift_score(self, agent_id: str, drift_table) -> float:
        """Read the current drift score from the tracker record.

        Args:
            agent_id: Identifier of the agent.
            drift_table: DynamoDB Table resource for drift data.

        Returns:
            Current drift score (0-100), or 0.0 if no tracker exists.
        """
        try:
            response = drift_table.get_item(
                Key={"agent_id": agent_id, "record_type": "drift_tracker"}
            )
            item = response.get("Item")
            if item:
                return float(item.get("drift_score", 0.0))
            return 0.0
        except Exception as exc:
            logger.error(json.dumps({
                "event": "get_drift_score_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return 0.0

    def _load_baseline(
        self, agent_id: str, drift_table
    ) -> Optional[Dict[str, Any]]:
        """Load the baseline record for an agent.

        Returns:
            Baseline dict or None if no baseline exists.
        """
        try:
            response = drift_table.get_item(
                Key={"agent_id": agent_id, "record_type": "baseline"}
            )
            return response.get("Item")
        except Exception as exc:
            logger.error(json.dumps({
                "event": "load_baseline_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

    def _compute_frequency_factor(
        self, agent_id: str, drift_table, now: datetime
    ) -> float:
        """Compute frequency spike contribution.

        Counts activity records in the last FREQUENCY_WINDOW_SECONDS and compares
        against the spike threshold.

        Returns:
            Frequency contribution (0 to WEIGHT_FREQUENCY_SPIKE).
        """
        from boto3.dynamodb.conditions import Key

        window_start = (now - timedelta(seconds=FREQUENCY_WINDOW_SECONDS)).isoformat()
        try:
            response = drift_table.query(
                KeyConditionExpression=(
                    Key("agent_id").eq(agent_id)
                    & Key("record_type").between(
                        f"activity#{window_start}",
                        f"activity#{now.isoformat()}",
                    )
                ),
                Select="COUNT",
            )
            count = response.get("Count", 0)
        except Exception as exc:
            logger.error(json.dumps({
                "event": "frequency_query_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return 0.0

        if count <= FREQUENCY_SPIKE_THRESHOLD:
            return 0.0

        # Scale linearly from threshold to 2x threshold
        excess_ratio = min(
            (count - FREQUENCY_SPIKE_THRESHOLD) / max(FREQUENCY_SPIKE_THRESHOLD, 1),
            1.0,
        )
        return excess_ratio * WEIGHT_FREQUENCY_SPIKE

    def _update_drift_tracker(
        self,
        agent_id: str,
        drift_score: float,
        drift_table,
        timestamp: str,
    ) -> None:
        """Update the drift tracker record with the latest score."""
        try:
            drift_table.update_item(
                Key={"agent_id": agent_id, "record_type": "drift_tracker"},
                UpdateExpression=(
                    "SET drift_score = :score, last_updated = :ts"
                ),
                ExpressionAttributeValues={
                    ":score": Decimal(str(drift_score)),
                    ":ts": timestamp,
                },
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "update_drift_tracker_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": timestamp,
            }))
