"""Governance Change Management.

Enforces approval workflows for ANY mutation to the governance platform:
- Register/modify/retire an agent
- Add/remove/modify a tool in the allowlist
- Approve/revoke a model
- Add/remove an MCP server
- Modify a prompt template
- Update a dataset or knowledge base
- Change a policy
- Modify risk thresholds or scope levels

No registry change takes effect until a second person approves it
(separation of duties). All changes are logged with full audit trail.

Flow:
  Requester creates ChangeRequest -> Reviewer approves/rejects ->
  If approved: change applied automatically ->
  Evidence record generated

Integrates with:
- operator_rbac.py (who can request/approve changes)
- ai_asset_registry.py (what's being changed)
- evidence_pipeline.py (audit trail)
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

CHANGE_TYPES = [
    "register_agent",
    "modify_agent",
    "retire_agent",
    "register_tool",
    "modify_tool",
    "revoke_tool",
    "register_model",
    "modify_model",
    "revoke_model",
    "register_mcp_server",
    "modify_mcp_server",
    "revoke_mcp_server",
    "register_prompt",
    "modify_prompt",
    "revoke_prompt",
    "register_dataset",
    "modify_dataset",
    "revoke_dataset",
    "register_knowledge_base",
    "modify_knowledge_base",
    "revoke_knowledge_base",
    "register_vector_store",
    "modify_vector_store",
    "revoke_vector_store",
    "modify_policy",
    "modify_risk_threshold",
    "modify_scope_level",
]

CHANGE_STATES = ["pending", "approved", "rejected", "applied", "rolled_back"]


@dataclass
class ChangeRequest:
    """A request to change a governance registry asset."""
    request_id: str
    change_type: str
    target_asset_id: str
    target_asset_type: str
    requester: str
    justification: str
    proposed_changes: Dict[str, Any]
    previous_state: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    reviewer: str = ""
    review_comment: str = ""
    risk_impact: str = "low"
    created_at: str = ""
    reviewed_at: str = ""
    applied_at: str = ""
    rolled_back_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "change_type": self.change_type,
            "target_asset_id": self.target_asset_id,
            "target_asset_type": self.target_asset_type,
            "requester": self.requester,
            "justification": self.justification,
            "proposed_changes": self.proposed_changes,
            "previous_state": self.previous_state,
            "status": self.status,
            "reviewer": self.reviewer,
            "review_comment": self.review_comment,
            "risk_impact": self.risk_impact,
            "created_at": self.created_at,
            "reviewed_at": self.reviewed_at,
            "applied_at": self.applied_at,
        }


def _assess_risk_impact(change_type: str, proposed_changes: Dict[str, Any]) -> str:
    """Assess the risk impact of a proposed change."""
    high_risk_types = {"retire_agent", "revoke_model", "modify_policy", "modify_risk_threshold", "modify_scope_level"}
    if change_type in high_risk_types:
        return "high"

    medium_risk_types = {"modify_agent", "modify_tool", "register_mcp_server", "modify_mcp_server"}
    if change_type in medium_risk_types:
        return "medium"

    if "production" in str(proposed_changes.get("environment", "")):
        return "high"

    return "low"


class GovernanceChangeManagement:
    """Manages approval workflows for all governance registry mutations."""

    def __init__(self):
        self._requests: Dict[str, ChangeRequest] = {}
        self._apply_callbacks: Dict[str, Callable] = {}

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def register_apply_callback(self, change_type: str, callback: Callable) -> None:
        """Register a function to call when a change of this type is approved."""
        self._apply_callbacks[change_type] = callback

    def create_request(
        self,
        change_type: str,
        target_asset_id: str,
        target_asset_type: str,
        requester: str,
        justification: str,
        proposed_changes: Dict[str, Any],
        previous_state: Dict[str, Any] = None,
    ) -> ChangeRequest:
        """Create a new change request (starts in 'pending' status)."""
        if change_type not in CHANGE_TYPES:
            raise ValueError(f"Invalid change_type '{change_type}'. Valid: {CHANGE_TYPES}")
        if not justification:
            raise ValueError("Justification is required for all change requests")

        request = ChangeRequest(
            request_id=str(uuid.uuid4()),
            change_type=change_type,
            target_asset_id=target_asset_id,
            target_asset_type=target_asset_type,
            requester=requester,
            justification=justification,
            proposed_changes=proposed_changes,
            previous_state=previous_state or {},
            status="pending",
            risk_impact=_assess_risk_impact(change_type, proposed_changes),
            created_at=self._now(),
        )

        self._requests[request.request_id] = request

        logger.info(json.dumps({
            "event": "change_request_created",
            "request_id": request.request_id,
            "change_type": change_type,
            "target": target_asset_id,
            "requester": requester,
            "risk_impact": request.risk_impact,
        }))

        return request

    def approve(self, request_id: str, reviewer: str, comment: str = "") -> ChangeRequest:
        """Approve a change request and apply the change."""
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError(f"Change request {request_id} not found")
        if request.status != "pending":
            raise ValueError(f"Request is not pending (current: {request.status})")
        if request.requester == reviewer:
            raise ValueError("Requester cannot approve their own change (separation of duties)")

        request.status = "approved"
        request.reviewer = reviewer
        request.review_comment = comment
        request.reviewed_at = self._now()

        # Apply the change if callback registered
        callback = self._apply_callbacks.get(request.change_type)
        if callback:
            try:
                callback(request.target_asset_id, request.proposed_changes)
                request.status = "applied"
                request.applied_at = self._now()
            except Exception as e:
                request.status = "approved"
                logger.error(json.dumps({
                    "event": "change_apply_failed",
                    "request_id": request_id,
                    "error": str(e),
                }))
        else:
            request.status = "applied"
            request.applied_at = self._now()

        logger.info(json.dumps({
            "event": "change_request_approved",
            "request_id": request_id,
            "change_type": request.change_type,
            "target": request.target_asset_id,
            "reviewer": reviewer,
            "applied": request.status == "applied",
        }))

        return request

    def reject(self, request_id: str, reviewer: str, reason: str) -> ChangeRequest:
        """Reject a change request."""
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError(f"Change request {request_id} not found")
        if request.status != "pending":
            raise ValueError(f"Request is not pending (current: {request.status})")

        request.status = "rejected"
        request.reviewer = reviewer
        request.review_comment = reason
        request.reviewed_at = self._now()

        logger.info(json.dumps({
            "event": "change_request_rejected",
            "request_id": request_id,
            "change_type": request.change_type,
            "target": request.target_asset_id,
            "reviewer": reviewer,
            "reason": reason,
        }))

        return request

    def rollback(self, request_id: str, rolled_back_by: str) -> ChangeRequest:
        """Rollback an applied change to its previous state."""
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError(f"Change request {request_id} not found")
        if request.status != "applied":
            raise ValueError(f"Can only rollback applied changes (current: {request.status})")
        if not request.previous_state:
            raise ValueError("No previous state recorded for rollback")

        callback = self._apply_callbacks.get(request.change_type)
        if callback:
            try:
                callback(request.target_asset_id, request.previous_state)
            except Exception as e:
                logger.error(json.dumps({
                    "event": "change_rollback_failed",
                    "request_id": request_id,
                    "error": str(e),
                }))
                raise

        request.status = "rolled_back"
        request.rolled_back_at = self._now()

        logger.warning(json.dumps({
            "event": "change_rolled_back",
            "request_id": request_id,
            "change_type": request.change_type,
            "target": request.target_asset_id,
            "rolled_back_by": rolled_back_by,
        }))

        return request

    def get_pending(self) -> List[ChangeRequest]:
        """Get all pending change requests."""
        return [r for r in self._requests.values() if r.status == "pending"]

    def get_history(self, target_asset_id: str = None) -> List[Dict[str, Any]]:
        """Get change history, optionally filtered by asset."""
        requests = list(self._requests.values())
        if target_asset_id:
            requests = [r for r in requests if r.target_asset_id == target_asset_id]
        return [r.to_dict() for r in sorted(requests, key=lambda r: r.created_at, reverse=True)]

    def get_summary(self) -> Dict[str, Any]:
        """Get change management summary stats."""
        requests = list(self._requests.values())
        return {
            "total_requests": len(requests),
            "pending": sum(1 for r in requests if r.status == "pending"),
            "approved": sum(1 for r in requests if r.status == "approved"),
            "applied": sum(1 for r in requests if r.status == "applied"),
            "rejected": sum(1 for r in requests if r.status == "rejected"),
            "rolled_back": sum(1 for r in requests if r.status == "rolled_back"),
            "by_type": self._count_by(requests, "change_type"),
            "by_risk": self._count_by(requests, "risk_impact"),
        }

    @staticmethod
    def _count_by(requests: List[ChangeRequest], field: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in requests:
            val = getattr(r, field, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts
