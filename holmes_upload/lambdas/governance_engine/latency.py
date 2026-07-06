"""Latency tracking for the governance decision pipeline.

Provides a LatencyTracker class with context-manager-based per-component
timing for: policy_evaluation, risk_scoring, decision_engine, and
evidence_write_initiation. Produces a LatencyMetric record with total
elapsed time, per-component breakdown, and a budget_exceeded flag
(budget = 200ms).

Requirements: 17.1, 17.2, 17.3
"""

import json
import logging
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator

from models import LatencyMetric

logger = logging.getLogger(__name__)

# Latency budget in milliseconds (Req 17.1)
LATENCY_BUDGET_MS = 200.0


def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# Valid component names that can be tracked (Req 17.2)
TRACKED_COMPONENTS = frozenset(
    {
        "policy_evaluation",
        "risk_scoring",
        "decision_engine",
        "evidence_write_initiation",
    }
)


class LatencyTracker:
    """Track per-component latency for a governance decision pipeline run.

    Usage::

        tracker = LatencyTracker()

        with tracker.track("policy_evaluation"):
            # ... policy evaluation work ...

        with tracker.track("risk_scoring"):
            # ... risk scoring work ...

        metric = tracker.record_latency("decision-123")

    The tracker records wall-clock time for each component and produces
    a ``LatencyMetric`` via ``record_latency``.  If the total elapsed
    time exceeds ``LATENCY_BUDGET_MS`` (200 ms), a structured latency
    violation record is logged.

    Requirements: 17.1, 17.2, 17.3
    """

    def __init__(self) -> None:
        self._component_latencies: Dict[str, float] = {}
        self._start_time: float = time.monotonic()

    # ------------------------------------------------------------------
    # Context-manager for per-component timing
    # ------------------------------------------------------------------

    @contextmanager
    def track(self, component_name: str) -> Generator[None, None, None]:
        """Time a named pipeline component.

        Args:
            component_name: One of the ``TRACKED_COMPONENTS`` names.

        Yields:
            Control to the caller's ``with`` block.

        Raises:
            ValueError: If *component_name* is not a recognised component.
        """
        if component_name not in TRACKED_COMPONENTS:
            raise ValueError(
                f"Unknown component '{component_name}'. "
                f"Must be one of {sorted(TRACKED_COMPONENTS)}"
            )

        start = time.monotonic()
        try:
            yield
        finally:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            self._component_latencies[component_name] = elapsed_ms

    # ------------------------------------------------------------------
    # Record final latency metric
    # ------------------------------------------------------------------

    def record_latency(self, decision_id: str) -> LatencyMetric:
        """Produce a ``LatencyMetric`` for the tracked pipeline run.

        Computes total elapsed time from tracker creation to now,
        attaches the per-component breakdown, and sets
        ``budget_exceeded`` if the total exceeds ``LATENCY_BUDGET_MS``.

        If the budget is exceeded a structured latency violation record
        is logged (Req 17.3).

        Args:
            decision_id: The governance decision identifier.

        Returns:
            A populated ``LatencyMetric`` instance.
        """
        total_elapsed_ms = (time.monotonic() - self._start_time) * 1000.0
        budget_exceeded = total_elapsed_ms > LATENCY_BUDGET_MS

        metric = LatencyMetric(
            decision_id=decision_id,
            total_elapsed_ms=round(total_elapsed_ms, 3),
            component_latencies={
                k: round(v, 3) for k, v in self._component_latencies.items()
            },
            budget_exceeded=budget_exceeded,
            timestamp=_iso_now(),
        )

        # Structured latency metric log (Req 17.2)
        logger.info(
            json.dumps(
                {
                    "event": "latency_metric",
                    "decision_id": decision_id,
                    "total_elapsed_ms": metric.total_elapsed_ms,
                    "component_latencies": metric.component_latencies,
                    "budget_exceeded": budget_exceeded,
                    "timestamp": metric.timestamp,
                }
            )
        )

        # Structured latency violation record (Req 17.3)
        if budget_exceeded:
            logger.warning(
                json.dumps(
                    {
                        "event": "latency_budget_exceeded",
                        "decision_id": decision_id,
                        "total_elapsed_ms": metric.total_elapsed_ms,
                        "budget_ms": LATENCY_BUDGET_MS,
                        "component_latencies": metric.component_latencies,
                        "timestamp": metric.timestamp,
                    }
                )
            )

        return metric
