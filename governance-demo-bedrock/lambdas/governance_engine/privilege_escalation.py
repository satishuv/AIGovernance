"""Privilege Escalation Hardening module.

Detects and prevents agents from modifying their own scope, registry entries,
policies, or role assignments. Tracks denial patterns and auto-reduces scope
when repeated escalation attempts exceed configurable thresholds.

Requirements: 27.1, 27.2, 27.3, 27.4
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

SELF_MOD_ACTIONS = {"update_scope", "modify_registry", "modify_tool_registry"}
POLICY_MOD_ACTIONS = {"update_policy", "create_policy", "delete_policy",
                      "assign_role", "revoke_role", "approve_policy"}


class PrivilegeEscalationDetector:
    """Detects privilege escalation attempts and enforces hardening."""

    def is_self_modification(self, agent_id: str, action_request: Dict[str, Any]) -> bool:
        """Return True if the action modifies the agent's own scope/registry/tools."""
        action_group = action_request.get("action_group", "").lower()
        target = action_request.get("target_resource", "")
        if action_group in SELF_MOD_ACTIONS:
            return True
        if target and agent_id and agent_id in target:
            if any(kw in action_group for kw in ("scope", "registry", "config")):
                return True
        return False

    def is_policy_modification(self, action_request: Dict[str, Any]) -> bool:
        """Return True if the action modifies policy definitions or roles."""
        return action_request.get("action_group", "").lower() in POLICY_MOD_ACTIONS

    def deny_and_log(self, agent_id: str, action_request: Dict[str, Any],
                     violation_type: str) -> Dict[str, Any]:
        """Log escalation attempt and return deny decision dict."""
        now = datetime.now(timezone.utc).isoformat()
        record = {
            "event_id": str(uuid.uuid4()),
            "audit_event": "privilege_escalation_attempt",
            "agent_id": agent_id,
            "action_requested": action_request.get("action_group", ""),
            "target_resource": action_request.get("target_resource", ""),
            "violation_type": violation_type,
            "timestamp": now,
        }
        logger.warning(json.dumps(record))
        return {
            "decision_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "action_requested": action_request.get("action_group", ""),
            "verdict": "deny",
            "explanation": (
                f"Privilege escalation denied: {violation_type} attempt "
                f"by agent '{agent_id}'."
            ),
            "timestamp": now,
        }

    def track_denial_pattern(self, agent_id: str, dynamodb_table,
                             time_window_seconds: int = 300,
                             threshold: int = 5) -> Tuple[bool, int]:
        """Increment denial counter; return (exceeded, count)."""
        now = datetime.now(timezone.utc)
        window_key = now.strftime("%Y-%m-%dT%H")
        try:
            response = dynamodb_table.update_item(
                Key={"agent_id": agent_id, "window_start": window_key},
                UpdateExpression=(
                    "SET denial_count = if_not_exists(denial_count, :zero) + :inc, "
                    "last_updated = :ts"
                ),
                ExpressionAttributeValues={
                    ":zero": 0, ":inc": 1, ":ts": now.isoformat(),
                },
                ReturnValues="ALL_NEW",
            )
            count = int(response["Attributes"].get("denial_count", 0))
        except Exception as exc:
            logger.error(json.dumps({
                "event": "track_denial_pattern_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return False, 0

        exceeded = count >= threshold
        if exceeded:
            logger.warning(json.dumps({
                "audit_event": "denial_threshold_exceeded",
                "agent_id": agent_id, "denial_count": count,
                "threshold": threshold, "window": window_key,
                "timestamp": now.isoformat(),
            }))
        return exceeded, count

    def auto_reduce_scope(self, agent_id: str, scope_table,
                          sns_client, topic_arn: str,
                          change_logger=None, s3_client=None,
                          evidence_bucket: str = "") -> Dict[str, Any]:
        """Reduce agent scope by one level and notify operator via SNS."""
        now = datetime.now(timezone.utc).isoformat()
        response = scope_table.get_item(Key={"agent_id": agent_id})
        current_scope = int(response.get("Item", {}).get("scope_level", 1))
        new_scope = max(0, current_scope - 1)

        scope_table.update_item(
            Key={"agent_id": agent_id},
            UpdateExpression="SET scope_level = :s",
            ExpressionAttributeValues={":s": new_scope},
        )
        record = {
            "audit_event": "auto_scope_reduction",
            "agent_id": agent_id,
            "previous_scope": current_scope,
            "new_scope": new_scope,
            "reason": "privilege_escalation_threshold_exceeded",
            "timestamp": now,
        }
        logger.warning(json.dumps(record))
        try:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject="AGCP — Auto Scope Reduction",
                Message=json.dumps(record, default=str),
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "auto_reduce_scope_notification_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": now,
            }))
        # Log scope change via ChangeLogger (Req 21.1, 27.4)
        if change_logger is not None and s3_client is not None and evidence_bucket:
            try:
                change_logger.log_scope_change(
                    agent_id=agent_id,
                    previous_scope=current_scope,
                    new_scope=new_scope,
                    requester_id="system:privilege_escalation_hardening",
                    authorization_method="automatic:privilege_escalation",
                    s3_client=s3_client,
                    bucket=evidence_bucket,
                )
            except Exception as cl_exc:
                logger.error(json.dumps({
                    "event": "change_log_auto_reduce_failed",
                    "agent_id": agent_id, "error": str(cl_exc),
                    "timestamp": now,
                }))
        return record
