"""Multi-Region Governance Failover.

Provides governance continuity when the primary region is unavailable.
Uses DynamoDB Global Tables for scope/registry replication and S3
Cross-Region Replication for evidence and policies.

Architecture:
- Primary region: Full governance pipeline (20 steps)
- Secondary region: Hot standby with replicated state
- Failover: Automatic via Route 53 health checks, or manual via operator

State replication:
- Scope table: DynamoDB Global Tables (ms-level replication)
- Agent registry: DynamoDB Global Tables
- Evidence: S3 Cross-Region Replication (eventual, seconds)
- Policies: S3 CRR + cache invalidation on write

Failover does NOT fail open. If both regions are down, all requests DENY.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RegionHealth:
    region: str
    healthy: bool = True
    last_check: float = 0.0
    consecutive_failures: int = 0
    latency_ms: float = 0.0
    last_error: str = ""


@dataclass
class FailoverState:
    primary_region: str = "us-east-1"
    secondary_region: str = "us-west-2"
    active_region: str = "us-east-1"
    mode: str = "primary"
    failover_count: int = 0
    last_failover_time: str = ""
    regions: Dict[str, RegionHealth] = field(default_factory=dict)


class GovernanceFailover:
    """Manages multi-region failover for the governance pipeline.

    Monitors health of the primary governance deployment and
    automatically routes to secondary if primary becomes unhealthy.
    """

    def __init__(
        self,
        primary_region: str = "us-east-1",
        secondary_region: str = "us-west-2",
        health_check_interval_s: float = 10.0,
        failure_threshold: int = 3,
    ):
        self._state = FailoverState(
            primary_region=primary_region,
            secondary_region=secondary_region,
            active_region=primary_region,
        )
        self._state.regions = {
            primary_region: RegionHealth(region=primary_region),
            secondary_region: RegionHealth(region=secondary_region),
        }
        self._health_check_interval_s = health_check_interval_s
        self._failure_threshold = failure_threshold

    @property
    def active_region(self) -> str:
        return self._state.active_region

    @property
    def mode(self) -> str:
        return self._state.mode

    def record_health_check(
        self, region: str, healthy: bool, latency_ms: float = 0.0, error: str = ""
    ) -> None:
        """Record a health check result for a region."""
        if region not in self._state.regions:
            self._state.regions[region] = RegionHealth(region=region)

        health = self._state.regions[region]
        health.last_check = time.monotonic()
        health.latency_ms = latency_ms
        health.last_error = error

        if healthy:
            health.healthy = True
            health.consecutive_failures = 0
        else:
            health.consecutive_failures += 1
            if health.consecutive_failures >= self._failure_threshold:
                health.healthy = False
                self._evaluate_failover()

    def _evaluate_failover(self) -> None:
        """Evaluate whether failover is needed based on region health."""
        primary = self._state.regions.get(self._state.primary_region)
        secondary = self._state.regions.get(self._state.secondary_region)

        if primary and not primary.healthy and self._state.active_region == self._state.primary_region:
            if secondary and secondary.healthy:
                self._failover_to(self._state.secondary_region)
            else:
                logger.error(json.dumps({
                    "event": "all_regions_unhealthy",
                    "action": "deny_all",
                    "primary_failures": primary.consecutive_failures if primary else 0,
                    "secondary_failures": secondary.consecutive_failures if secondary else 0,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))

        elif primary and primary.healthy and self._state.active_region != self._state.primary_region:
            self._failback_to_primary()

    def _failover_to(self, region: str) -> None:
        """Execute failover to the specified region."""
        previous = self._state.active_region
        self._state.active_region = region
        self._state.mode = "failover"
        self._state.failover_count += 1
        self._state.last_failover_time = datetime.now(timezone.utc).isoformat()

        logger.error(json.dumps({
            "event": "governance_failover",
            "from_region": previous,
            "to_region": region,
            "failover_count": self._state.failover_count,
            "reason": "primary_unhealthy",
            "timestamp": self._state.last_failover_time,
        }))

    def _failback_to_primary(self) -> None:
        """Fail back to primary region after recovery."""
        previous = self._state.active_region
        self._state.active_region = self._state.primary_region
        self._state.mode = "primary"

        logger.info(json.dumps({
            "event": "governance_failback",
            "from_region": previous,
            "to_region": self._state.primary_region,
            "reason": "primary_recovered",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

    def manual_failover(self, target_region: str, operator_id: str) -> Dict[str, Any]:
        """Operator-triggered manual failover."""
        if target_region not in self._state.regions:
            return {
                "success": False,
                "error": f"Unknown region '{target_region}'",
            }

        previous = self._state.active_region
        self._state.active_region = target_region
        self._state.mode = "manual_failover"
        self._state.failover_count += 1
        self._state.last_failover_time = datetime.now(timezone.utc).isoformat()

        logger.warning(json.dumps({
            "event": "manual_governance_failover",
            "from_region": previous,
            "to_region": target_region,
            "operator_id": operator_id,
            "timestamp": self._state.last_failover_time,
        }))

        return {
            "success": True,
            "previous_region": previous,
            "active_region": target_region,
            "mode": "manual_failover",
        }

    def get_routing_decision(self) -> Dict[str, Any]:
        """Get the current routing decision for governance requests.

        Used by the Scope Enforcer to know which region's governance
        pipeline to invoke.
        """
        return {
            "active_region": self._state.active_region,
            "mode": self._state.mode,
            "primary_healthy": self._state.regions.get(
                self._state.primary_region, RegionHealth(region="")
            ).healthy,
            "secondary_healthy": self._state.regions.get(
                self._state.secondary_region, RegionHealth(region="")
            ).healthy,
        }

    def get_status(self) -> Dict[str, Any]:
        """Full failover status for dashboards and monitoring."""
        return {
            "active_region": self._state.active_region,
            "mode": self._state.mode,
            "failover_count": self._state.failover_count,
            "last_failover_time": self._state.last_failover_time,
            "regions": {
                name: {
                    "healthy": h.healthy,
                    "consecutive_failures": h.consecutive_failures,
                    "latency_ms": round(h.latency_ms, 2),
                    "last_error": h.last_error,
                }
                for name, h in self._state.regions.items()
            },
        }
