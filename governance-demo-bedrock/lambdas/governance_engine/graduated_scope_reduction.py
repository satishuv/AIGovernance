"""Graduated Scope Reduction module.

Computes rolling average risk scores, checks sustained threshold exceedance,
enforces cooldown periods, and executes scope reduction in configurable modes:
automatic, approval-gated, or notify-only.

Requirements: 29.1, 29.2, 29.3, 29.4, 29.5, 29.6
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Tuple

from models import ScopeReductionEvent

logger = logging.getLogger(__name__)

VALID_MODES = {"automatic", "approval-gated", "notify-only"}


class GraduatedScopeReduction:
    """Implements graduated scope reduction based on rolling risk scores."""

    def compute_rolling_avg_risk(
        self, agent_id: str, decision_history_table,
        time_window_seconds: int = 3600,
    ) -> Tuple[float, int]:
        """Compute rolling average risk score over a time window.

        Returns:
            Tuple of (rolling_avg_risk, decision_count).
        """
        from boto3.dynamodb.conditions import Key

        now = datetime.utcnow()
        start = (now - timedelta(seconds=time_window_seconds)).isoformat()
        try:
            response = decision_history_table.query(
                KeyConditionExpression=(
                    Key("agent_id").eq(agent_id)
                    & Key("timestamp").gte(start)
                ),
            )
            items = response.get("Items", [])
        except Exception as exc:
            logger.error(json.dumps({
                "event": "compute_rolling_avg_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return 0.0, 0

        if not items:
            return 0.0, 0
        scores = [float(i.get("risk_score", 0)) for i in items]
        return round(sum(scores) / len(scores), 2), len(scores)

    def check_sustained_threshold(
        self, agent_id: str, rolling_avg: float, threshold: float,
        sustained_period_seconds: int, dynamodb_table,
    ) -> Tuple[bool, int]:
        """Check if rolling avg exceeded threshold for sustained period.

        Returns:
            Tuple of (exceeded, duration_seconds).
        """
        now = datetime.utcnow()
        if rolling_avg < threshold:
            try:
                dynamodb_table.update_item(
                    Key={"agent_id": agent_id, "timestamp": "sustained_tracker"},
                    UpdateExpression="SET exceeded_since = :v",
                    ExpressionAttributeValues={":v": ""},
                )
            except Exception:
                pass
            return False, 0

        try:
            response = dynamodb_table.get_item(
                Key={"agent_id": agent_id, "timestamp": "sustained_tracker"}
            )
            item = response.get("Item", {})
            exceeded_since = item.get("exceeded_since", "")
            if not exceeded_since:
                dynamodb_table.put_item(Item={
                    "agent_id": agent_id,
                    "timestamp": "sustained_tracker",
                    "exceeded_since": now.isoformat(),
                })
                return False, 0
            start_time = datetime.fromisoformat(exceeded_since)
            duration = int((now - start_time).total_seconds())
            return duration >= sustained_period_seconds, duration
        except Exception as exc:
            logger.error(json.dumps({
                "event": "check_sustained_threshold_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return False, 0

    def check_cooldown(
        self, agent_id: str, dynamodb_table,
        min_cooldown_seconds: int = 7200,
    ) -> Tuple[bool, int]:
        """Check if cooldown period has elapsed since last reduction.

        Returns:
            Tuple of (cooldown_active, remaining_seconds).
        """
        from boto3.dynamodb.conditions import Key

        now = datetime.utcnow()
        try:
            response = dynamodb_table.query(
                KeyConditionExpression=Key("agent_id").eq(agent_id),
                ScanIndexForward=False, Limit=5,
            )
            items = [
                i for i in response.get("Items", [])
                if i.get("timestamp") != "sustained_tracker"
            ]
            if not items:
                return False, 0
            last_ts = items[0].get("timestamp", "")
            if not last_ts:
                return False, 0
            elapsed = int((now - datetime.fromisoformat(last_ts)).total_seconds())
            remaining = max(0, min_cooldown_seconds - elapsed)
            return remaining > 0, remaining
        except Exception as exc:
            logger.error(json.dumps({
                "event": "check_cooldown_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return False, 0

    def execute_reduction(
        self, agent_id: str, mode: str, scope_table,
        pending_approval_table, sns_client, topic_arn: str,
        risk_data: Dict[str, Any],
        change_logger=None, s3_client=None, evidence_bucket: str = "",
    ) -> ScopeReductionEvent:
        """Execute scope reduction according to configured mode.

        Modes:
            automatic — reduces scope immediately.
            approval-gated — creates pending approval record.
            notify-only — sends alert without reducing scope.

        Returns:
            ScopeReductionEvent with reduction details.
        """
        now = datetime.utcnow().isoformat()
        event_id = str(uuid.uuid4())

        # Get current scope
        response = scope_table.get_item(Key={"agent_id": agent_id})
        current_scope = int(response.get("Item", {}).get("scope_level", 1))
        new_scope = max(0, current_scope - 1)

        rolling_avg = float(risk_data.get("rolling_avg", 0))
        threshold = float(risk_data.get("threshold", 70))
        sustained = int(risk_data.get("sustained_seconds", 0))

        event = ScopeReductionEvent(
            event_id=event_id,
            agent_id=agent_id,
            previous_scope=current_scope,
            new_scope=new_scope if mode == "automatic" else current_scope,
            rolling_avg_risk_score=rolling_avg,
            threshold=threshold,
            sustained_period_seconds=sustained,
            reduction_mode=mode,
            cooldown_remaining_seconds=0,
            timestamp=now,
        )

        if mode == "automatic":
            scope_table.update_item(
                Key={"agent_id": agent_id},
                UpdateExpression="SET scope_level = :s",
                ExpressionAttributeValues={":s": new_scope},
            )
            event.new_scope = new_scope
            logger.info(json.dumps({
                "audit_event": "graduated_scope_reduction",
                "mode": "automatic", **event.to_dict(),
            }))
            # Log scope change via ChangeLogger (Req 21.1, 29.4)
            if change_logger is not None and s3_client is not None and evidence_bucket:
                try:
                    change_logger.log_scope_change(
                        agent_id=agent_id,
                        previous_scope=current_scope,
                        new_scope=new_scope,
                        requester_id="system:graduated_reduction",
                        authorization_method=f"automatic:{mode}",
                        s3_client=s3_client,
                        bucket=evidence_bucket,
                    )
                except Exception as cl_exc:
                    logger.error(json.dumps({
                        "event": "change_log_scope_reduction_failed",
                        "agent_id": agent_id, "error": str(cl_exc),
                        "timestamp": now,
                    }))

        elif mode == "approval-gated":
            approval_id = str(uuid.uuid4())
            pending_approval_table.put_item(Item={
                "approval_id": approval_id,
                "decision_id": event_id,
                "agent_id": agent_id,
                "action_requested": f"scope_reduction_{current_scope}_to_{new_scope}",
                "risk_score": rolling_avg,
                "escalation_reason": "graduated_scope_reduction",
                "status": "pending",
                "created_at": now,
            })
            logger.info(json.dumps({
                "audit_event": "graduated_scope_reduction_pending",
                "mode": "approval-gated",
                "approval_id": approval_id,
                **event.to_dict(),
            }))

        else:  # notify-only
            logger.info(json.dumps({
                "audit_event": "graduated_scope_reduction_notify",
                "mode": "notify-only", **event.to_dict(),
            }))

        # SNS notification for all modes
        try:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject=f"AGCP — Scope Reduction ({mode})",
                Message=json.dumps(event.to_dict(), default=str),
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "scope_reduction_notification_failed",
                "agent_id": agent_id, "error": str(exc),
                "timestamp": now,
            }))

        return event

    def get_reduction_mode(self, config_table) -> str:
        """Read configured reduction mode from DynamoDB. Defaults to approval-gated."""
        try:
            response = config_table.get_item(
                Key={"config_key": "scope_reduction_mode"}
            )
            mode = response.get("Item", {}).get("value", "approval-gated")
            if mode not in VALID_MODES:
                logger.warning(json.dumps({
                    "event": "invalid_reduction_mode",
                    "configured_mode": mode,
                    "using_default": "approval-gated",
                }))
                return "approval-gated"
            return mode
        except Exception as exc:
            logger.error(json.dumps({
                "event": "get_reduction_mode_failed",
                "error": str(exc),
                "timestamp": datetime.utcnow().isoformat(),
            }))
            return "approval-gated"
