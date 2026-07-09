"""Governance Pipeline Circuit Breaker.

Enforces a hard SLA on governance latency. If the pipeline exceeds the
configured timeout (default 500ms), the circuit breaker trips and returns
an immediate DENY. This prevents slow DynamoDB calls or downstream latency
from hanging user requests indefinitely.

Modes:
- CLOSED: Normal operation, pipeline runs fully.
- OPEN: Pipeline exceeded timeout N times in window, all requests fast-DENY.
- HALF_OPEN: After cooldown, allow one request through to test recovery.

The circuit breaker protects users from governance infrastructure failures
while maintaining fail-safe (never fails open).
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

PIPELINE_TIMEOUT_MS = 500.0
FAILURE_THRESHOLD = 3
RECOVERY_COOLDOWN_S = 30.0
WINDOW_S = 60.0


@dataclass
class CircuitState:
    mode: str = "closed"
    failure_count: int = 0
    last_failure_time: float = 0.0
    last_trip_time: float = 0.0
    total_trips: int = 0
    total_timeouts: int = 0


class GovernanceCircuitBreaker:
    """Circuit breaker for the governance decision pipeline.

    If governance evaluation exceeds PIPELINE_TIMEOUT_MS, the request is
    immediately denied (fail-safe). After FAILURE_THRESHOLD consecutive
    timeouts within WINDOW_S, the circuit opens and all requests are
    fast-denied until RECOVERY_COOLDOWN_S elapses.
    """

    def __init__(
        self,
        timeout_ms: float = PIPELINE_TIMEOUT_MS,
        failure_threshold: int = FAILURE_THRESHOLD,
        recovery_cooldown_s: float = RECOVERY_COOLDOWN_S,
        window_s: float = WINDOW_S,
    ):
        self._timeout_ms = timeout_ms
        self._failure_threshold = failure_threshold
        self._recovery_cooldown_s = recovery_cooldown_s
        self._window_s = window_s
        self._state = CircuitState()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_open(self) -> bool:
        if self._state.mode == "open":
            elapsed = time.monotonic() - self._state.last_trip_time
            if elapsed >= self._recovery_cooldown_s:
                self._state.mode = "half_open"
                logger.info(json.dumps({
                    "event": "circuit_breaker_half_open",
                    "cooldown_elapsed_s": round(elapsed, 2),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                return False
            return True
        return False

    def check_timeout(self, elapsed_ms: float, decision_id: str = "") -> Optional[Dict[str, Any]]:
        """Check if the pipeline has exceeded the timeout SLA.

        Args:
            elapsed_ms: Time spent so far in the pipeline.
            decision_id: The current decision ID for logging.

        Returns:
            A DENY response dict if timeout exceeded, None otherwise.
        """
        if elapsed_ms <= self._timeout_ms:
            return None

        self._state.total_timeouts += 1
        now = time.monotonic()

        if now - self._state.last_failure_time > self._window_s:
            self._state.failure_count = 0

        self._state.failure_count += 1
        self._state.last_failure_time = now

        if self._state.failure_count >= self._failure_threshold:
            self._trip(decision_id)

        logger.warning(json.dumps({
            "event": "governance_pipeline_timeout",
            "decision_id": decision_id,
            "elapsed_ms": round(elapsed_ms, 2),
            "timeout_ms": self._timeout_ms,
            "failure_count": self._state.failure_count,
            "circuit_mode": self._state.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        return {
            "verdict": "deny",
            "reason": (
                f"Governance pipeline exceeded SLA ({elapsed_ms:.0f}ms > "
                f"{self._timeout_ms:.0f}ms). Request denied as fail-safe."
            ),
            "error_category": "governance_timeout",
            "circuit_breaker": {
                "triggered": True,
                "elapsed_ms": round(elapsed_ms, 2),
                "timeout_ms": self._timeout_ms,
                "mode": self._state.mode,
            },
        }

    def pre_check(self, decision_id: str = "") -> Optional[Dict[str, Any]]:
        """Fast pre-check: if circuit is OPEN, deny immediately without running pipeline.

        Returns:
            A DENY response if circuit is open, None if pipeline should proceed.
        """
        if not self.is_open:
            return None

        logger.warning(json.dumps({
            "event": "circuit_breaker_fast_deny",
            "decision_id": decision_id,
            "mode": "open",
            "recovery_in_s": round(
                self._recovery_cooldown_s - (time.monotonic() - self._state.last_trip_time), 1
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        return {
            "verdict": "deny",
            "reason": (
                "Governance circuit breaker is OPEN due to repeated timeouts. "
                "All requests denied until recovery. This is a fail-safe measure."
            ),
            "error_category": "circuit_breaker_open",
            "circuit_breaker": {
                "triggered": True,
                "mode": "open",
                "total_trips": self._state.total_trips,
                "recovery_cooldown_s": self._recovery_cooldown_s,
            },
        }

    def record_success(self) -> None:
        """Record a successful pipeline completion (within SLA)."""
        if self._state.mode == "half_open":
            self._state.mode = "closed"
            self._state.failure_count = 0
            logger.info(json.dumps({
                "event": "circuit_breaker_closed",
                "reason": "successful_request_in_half_open",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
        elif self._state.mode == "closed":
            if self._state.failure_count > 0:
                now = time.monotonic()
                if now - self._state.last_failure_time > self._window_s:
                    self._state.failure_count = 0

    def _trip(self, decision_id: str) -> None:
        """Trip the circuit breaker to OPEN state."""
        self._state.mode = "open"
        self._state.last_trip_time = time.monotonic()
        self._state.total_trips += 1

        logger.error(json.dumps({
            "event": "circuit_breaker_tripped",
            "decision_id": decision_id,
            "failure_count": self._state.failure_count,
            "threshold": self._failure_threshold,
            "total_trips": self._state.total_trips,
            "recovery_cooldown_s": self._recovery_cooldown_s,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

    def get_status(self) -> Dict[str, Any]:
        """Return current circuit breaker status for dashboards."""
        return {
            "mode": self._state.mode,
            "failure_count": self._state.failure_count,
            "failure_threshold": self._failure_threshold,
            "total_trips": self._state.total_trips,
            "total_timeouts": self._state.total_timeouts,
            "timeout_ms": self._timeout_ms,
            "recovery_cooldown_s": self._recovery_cooldown_s,
        }
