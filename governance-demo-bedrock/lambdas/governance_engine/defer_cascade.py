"""DEFER dependent-action cascade tracking (AARM R4).

AARM R4 requires DEFER semantics to cover:
  - dependent-action cascading: when an action is deferred, actions that depend
    on it (later actions in the same session) also cannot proceed and cascade
    into the deferred state;
  - a configurable cascade limit: when the number of cascaded/deferred actions
    behind unresolved defers exceeds the limit, the system DENIES rather than
    accumulating unbounded suspended work;
  - follow-up receipts on resolution or timeout (handled by approval_workflow
    check_timeout, which DENY-on-timeout for the pending record).

This module tracks, per session, how many actions are currently suspended
behind unresolved DEFER decisions and decides whether a new DEFER may cascade
or must convert to DENY. State reuses the runtime drift table under
record_type "defer_cascade#<session_id>", so no new table is needed.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

# Maximum number of actions that may be simultaneously suspended behind
# unresolved defers in one session. Exceeding it converts DEFER -> DENY.
DEFER_CASCADE_LIMIT = int(os.environ.get("DEFER_CASCADE_LIMIT", "5"))


@dataclass
class CascadeResult:
    """Result of a defer-cascade check.

    Attributes:
        verdict: "defer" if the action may cascade into the deferred state, or
            "deny" if the cascade limit is exceeded.
        depth: The cascade depth after accounting for this action.
        limit: The configured cascade limit.
        reason: Human-readable explanation.
    """
    verdict: str
    depth: int
    limit: int
    reason: str = ""


class DeferCascadeTracker:
    """Tracks and bounds the DEFER dependent-action cascade per session."""

    def __init__(self, drift_table: Any = None, limit: int = None) -> None:
        self._table = drift_table
        self._limit = DEFER_CASCADE_LIMIT if limit is None else limit

    @staticmethod
    def _sk(session_id: str) -> str:
        return f"defer_cascade#{session_id}"

    def _get_depth(self, session_id: str) -> int:
        if self._table is None or not session_id:
            return 0
        try:
            resp = self._table.get_item(Key={"agent_id": self._sk(session_id), "record_type": "state"})
            item = resp.get("Item") or {}
            return int(item.get("cascade_depth", 0))
        except Exception:
            return 0

    def _set_depth(self, session_id: str, depth: int) -> None:
        if self._table is None or not session_id:
            return
        try:
            self._table.put_item(Item={
                "agent_id": self._sk(session_id),
                "record_type": "state",
                "cascade_depth": depth,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass

    def register_defer(self, session_id: str) -> CascadeResult:
        """Register a new deferred action and decide defer-vs-deny (AARM R4).

        Increments the session's cascade depth. If the resulting depth exceeds
        the configured limit, the action must DENY (the cascade is unbounded);
        otherwise it may DEFER.
        """
        current = self._get_depth(session_id)
        new_depth = current + 1
        if new_depth > self._limit:
            # Do not grow past the limit; deny and hold depth at the limit.
            return CascadeResult(
                verdict="deny", depth=current, limit=self._limit,
                reason=(f"DEFER cascade limit exceeded: {new_depth} dependent "
                        f"actions would be suspended (limit {self._limit}); "
                        f"denying to bound unresolved cascades."),
            )
        self._set_depth(session_id, new_depth)
        return CascadeResult(
            verdict="defer", depth=new_depth, limit=self._limit,
            reason=(f"Action deferred; cascade depth {new_depth}/{self._limit}."),
        )

    def resolve_defer(self, session_id: str, count: int = 1) -> int:
        """Decrement cascade depth when deferred actions resolve or time out.

        Returns the new depth. Follow-up receipts for the resolved/timed-out
        actions are produced by the approval workflow; this only maintains the
        cascade counter so future actions are evaluated against the true depth.
        """
        current = self._get_depth(session_id)
        new_depth = max(0, current - max(1, count))
        self._set_depth(session_id, new_depth)
        return new_depth
