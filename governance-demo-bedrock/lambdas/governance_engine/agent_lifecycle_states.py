"""Agent Lifecycle State Machine.

Enforces explicit lifecycle stages for every AI agent with mandatory
gates between transitions. An agent cannot operate outside its approved
lifecycle state.

States:
  DRAFT -> REGISTERED -> RISK_REVIEWED -> APPROVED -> DEPLOYED ->
  MONITORED -> RECERTIFICATION_DUE -> SUSPENDED -> RETIRED

Rules:
- Only DEPLOYED and MONITORED agents can invoke tools
- Expired certification auto-transitions to RECERTIFICATION_DUE
- SUSPENDED agents are denied at the identity check layer
- RETIRED agents are permanently decommissioned
- Transitions require operator RBAC permissions
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from durable_state import conditional_failed, from_item, require_durable, scan_all, to_item

logger = logging.getLogger(__name__)

LIFECYCLE_STATES = [
    "draft",
    "registered",
    "risk_reviewed",
    "approved",
    "deployed",
    "monitored",
    "recertification_due",
    "suspended",
    "retired",
]

VALID_TRANSITIONS = {
    "draft": ["registered"],
    "registered": ["risk_reviewed", "retired"],
    "risk_reviewed": ["approved", "registered"],
    "approved": ["deployed", "suspended"],
    "deployed": ["monitored", "suspended", "retired"],
    "monitored": ["recertification_due", "suspended", "retired"],
    "recertification_due": ["risk_reviewed", "suspended"],
    "suspended": ["risk_reviewed", "retired"],
    "retired": [],
}

OPERATIONAL_STATES = {"deployed", "monitored"}

TRANSITION_PERMISSIONS = {
    "draft->registered": "agent:register",
    "registered->risk_reviewed": "agent:register",
    "risk_reviewed->approved": "approval:approve",
    "approved->deployed": "agent:modify_scope",
    "deployed->monitored": "agent:modify_scope",
    "monitored->recertification_due": "agent:modify_scope",
    "recertification_due->risk_reviewed": "agent:register",
    "suspended->risk_reviewed": "agent:register",
    "suspended->retired": "agent:suspend",
    "deployed->suspended": "agent:suspend",
    "monitored->suspended": "agent:suspend",
    "deployed->retired": "agent:suspend",
    "monitored->retired": "agent:suspend",
}


@dataclass
class LifecycleState:
    """Current lifecycle state of an agent."""
    agent_id: str
    state: str
    entered_at: str
    transitioned_by: str
    certification_expiry: str = ""
    review_due_at: str = ""
    suspension_reason: str = ""
    retirement_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "state": self.state,
            "entered_at": self.entered_at,
            "transitioned_by": self.transitioned_by,
            "certification_expiry": self.certification_expiry,
            "review_due_at": self.review_due_at,
            "is_operational": self.state in OPERATIONAL_STATES,
            "suspension_reason": self.suspension_reason,
            "retirement_reason": self.retirement_reason,
        }


@dataclass
class TransitionResult:
    """Result of a lifecycle state transition."""
    success: bool
    agent_id: str
    from_state: str
    to_state: str
    reason: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "agent_id": self.agent_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


class AgentLifecycleManager:
    """Manages agent lifecycle state transitions with enforcement.

    With a DynamoDB table (partition key agent_id) the table is the source of
    truth and each transition is a conditional write on the state it read,
    so a suspension by one instance cannot be overwritten by another
    instance's stale state. Without a table state lives in memory, which is
    refused inside a deployed Lambda function (P0-12).
    """

    def __init__(self, table=None):
        require_durable("AgentLifecycleManager", table)
        self._table = table
        self._states: Dict[str, LifecycleState] = {}

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _load(self, agent_id: str) -> Optional[LifecycleState]:
        if self._table is None:
            return self._states.get(agent_id)
        item = self._table.get_item(Key={"agent_id": agent_id}, ConsistentRead=True).get("Item")
        if item is None:
            self._states.pop(agent_id, None)
            return None
        known = {f for f in LifecycleState.__dataclass_fields__}
        state = LifecycleState(**{k: v for k, v in from_item(item).items() if k in known})
        self._states[agent_id] = state
        return state

    def _store(self, state: LifecycleState, expected_state: Optional[str]) -> None:
        self._states[state.agent_id] = state
        if self._table is None:
            return
        known = {f for f in LifecycleState.__dataclass_fields__}
        item = to_item({k: getattr(state, k) for k in known})
        if expected_state is None:
            self._table.put_item(Item=item, ConditionExpression="attribute_not_exists(agent_id)")
        else:
            self._table.put_item(Item=item, ConditionExpression="#state = :expected",
                                 ExpressionAttributeNames={"#state": "state"},
                                 ExpressionAttributeValues={":expected": expected_state})

    def initialize_agent(self, agent_id: str, created_by: str) -> LifecycleState:
        """Create a new agent in draft state."""
        state = LifecycleState(
            agent_id=agent_id,
            state="draft",
            entered_at=self._now(),
            transitioned_by=created_by,
        )
        self._store(state, expected_state=None)
        logger.info(json.dumps({
            "event": "agent_lifecycle_initialized",
            "agent_id": agent_id,
            "state": "draft",
            "created_by": created_by,
        }))
        return state

    def transition(self, agent_id: str, target_state: str, transitioned_by: str, reason: str = "") -> TransitionResult:
        """Attempt a lifecycle state transition."""
        now = self._now()
        current = self._load(agent_id)

        if current is None:
            return TransitionResult(
                success=False, agent_id=agent_id, from_state="unknown",
                to_state=target_state, reason="Agent not found in lifecycle manager",
                timestamp=now,
            )

        valid_targets = VALID_TRANSITIONS.get(current.state, [])
        if target_state not in valid_targets:
            return TransitionResult(
                success=False, agent_id=agent_id, from_state=current.state,
                to_state=target_state,
                reason=f"Invalid transition: {current.state} -> {target_state}. Valid: {valid_targets}",
                timestamp=now,
            )

        previous_state = current.state
        current.state = target_state
        current.entered_at = now
        current.transitioned_by = transitioned_by

        if target_state == "approved":
            current.certification_expiry = (
                datetime.now(timezone.utc) + timedelta(days=90)
            ).isoformat()
            current.review_due_at = (
                datetime.now(timezone.utc) + timedelta(days=80)
            ).isoformat()

        if target_state == "suspended":
            current.suspension_reason = reason

        if target_state == "retired":
            current.retirement_reason = reason

        try:
            self._store(current, expected_state=previous_state)
        except Exception as exc:
            if not conditional_failed(exc):
                raise
            self._states.pop(agent_id, None)
            return TransitionResult(
                success=False, agent_id=agent_id, from_state=previous_state, to_state=target_state,
                reason="Lifecycle state changed concurrently; re-read and retry", timestamp=now,
            )

        logger.info(json.dumps({
            "event": "agent_lifecycle_transition",
            "agent_id": agent_id,
            "from_state": previous_state,
            "to_state": target_state,
            "transitioned_by": transitioned_by,
            "reason": reason,
        }))

        return TransitionResult(
            success=True, agent_id=agent_id, from_state=previous_state,
            to_state=target_state, reason=reason, timestamp=now,
        )

    def check_operational(self, agent_id: str) -> bool:
        """Check if agent is in an operational state (can invoke tools). Read errors deny."""
        try:
            state = self._load(agent_id)
        except Exception as exc:
            logger.error(json.dumps({"event": "lifecycle_read_failed", "agent_id": agent_id, "error": str(exc)}))
            return False
        if state is None:
            return False
        return state.state in OPERATIONAL_STATES

    def check_certification_expiry(self, agent_id: str) -> Optional[str]:
        """Check if certification is expired. Returns reason if expired."""
        state = self._load(agent_id)
        if state is None:
            return None
        if not state.certification_expiry:
            return None
        now = self._now()
        if now > state.certification_expiry:
            self.transition(agent_id, "recertification_due", "system",
                          "Certification expired automatically")
            return f"Certification expired at {state.certification_expiry}"
        return None

    def get_state(self, agent_id: str) -> Optional[LifecycleState]:
        return self._load(agent_id)

    def get_all_agents_by_state(self) -> Dict[str, List[str]]:
        """Group all agents by their current lifecycle state (reporting)."""
        if self._table is not None:
            known = {f for f in LifecycleState.__dataclass_fields__}
            self._states = {
                str(i["agent_id"]): LifecycleState(**{k: v for k, v in from_item(i).items() if k in known})
                for i in scan_all(self._table)}
        by_state: Dict[str, List[str]] = {s: [] for s in LIFECYCLE_STATES}
        for agent_id, state in self._states.items():
            by_state[state.state].append(agent_id)
        return by_state

    def get_required_permission(self, from_state: str, to_state: str) -> str:
        """Get the RBAC permission required for a transition."""
        key = f"{from_state}->{to_state}"
        return TRANSITION_PERMISSIONS.get(key, "governance_admin")
