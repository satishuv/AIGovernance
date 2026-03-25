"""Approval Workflow module.

Manages human-in-the-loop approval workflows for escalated governance
decisions. Supports creating pending approvals, notifying approvers,
approving/denying with separation of duties enforcement, timeout handling,
and writing approval evidence to S3.

Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Optional

from governance_engine.models import GovernanceDecision, PendingApproval

logger = logging.getLogger(__name__)


class ApprovalWorkflow:
    """Manages pending approval lifecycle in DynamoDB PendingApprovalTable.

    Args:
        table: A boto3 DynamoDB Table resource for the PendingApprovalTable.
    """

    def __init__(self, table):
        self._table = table

    def create_pending_approval(
        self,
        decision: GovernanceDecision,
        timeout_seconds: int = 3600,
    ) -> str:
        """Create a pending approval record from an escalated decision.

        Args:
            decision: The GovernanceDecision that produced an "escalate" verdict.
            timeout_seconds: Seconds before the approval auto-times-out.

        Returns:
            The generated approval_id.
        """
        now = datetime.utcnow().isoformat()
        approval_id = str(uuid.uuid4())

        approval = PendingApproval(
            approval_id=approval_id,
            decision_id=decision.decision_id,
            agent_id=decision.agent_id,
            action_requested=decision.action_requested,
            risk_score=decision.risk_score,
            escalation_reason=decision.explanation,
            status="pending",
            approver_id="",
            approval_conditions="",
            denial_reason="",
            created_at=now,
            resolved_at="",
            timeout_seconds=timeout_seconds,
        )

        self._table.put_item(Item=approval.to_dict())

        logger.info(
            json.dumps(
                {
                    "audit_event": "pending_approval_created",
                    "approval_id": approval_id,
                    "decision_id": decision.decision_id,
                    "agent_id": decision.agent_id,
                    "risk_score": decision.risk_score,
                    "timeout_seconds": timeout_seconds,
                    "timestamp": now,
                }
            )
        )

        return approval_id

    def notify_approvers(
        self,
        approval: PendingApproval,
        sns_client,
        topic_arn: str,
    ) -> None:
        """Publish structured notification to SNS for approvers.

        Args:
            approval: The PendingApproval record to notify about.
            sns_client: boto3 SNS client.
            topic_arn: ARN of the SNS topic for approver notifications.
        """
        message = {
            "notification_type": "approval_required",
            "approval_id": approval.approval_id,
            "agent_id": approval.agent_id,
            "action_requested": approval.action_requested,
            "risk_score": approval.risk_score,
            "escalation_reason": approval.escalation_reason,
            "timeout_seconds": approval.timeout_seconds,
            "created_at": approval.created_at,
        }

        sns_client.publish(
            TopicArn=topic_arn,
            Subject=f"Approval Required: {approval.approval_id}",
            Message=json.dumps(message, default=str),
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "approvers_notified",
                    "approval_id": approval.approval_id,
                    "topic_arn": topic_arn,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        )

    def approve(
        self,
        approval_id: str,
        approver_id: str,
        agent_owner_id: str,
        conditions: str = "",
    ) -> PendingApproval:
        """Approve a pending approval with separation of duties enforcement.

        The approver must not be the agent owner (separation of duties).

        Args:
            approval_id: The approval to resolve.
            approver_id: Identity of the person approving.
            agent_owner_id: Identity of the agent's owner.
            conditions: Optional conditions attached to the approval.

        Returns:
            The updated PendingApproval record.

        Raises:
            ValueError: If approver_id equals agent_owner_id.
            KeyError: If approval_id is not found.
        """
        if approver_id == agent_owner_id:
            logger.warning(
                json.dumps(
                    {
                        "audit_event": "approval_sod_violation",
                        "approval_id": approval_id,
                        "approver_id": approver_id,
                        "agent_owner_id": agent_owner_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            )
            raise ValueError(
                "Separation of duties violation: approver cannot be the agent owner."
            )

        now = datetime.utcnow().isoformat()

        self._table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression=(
                "SET #s = :status, approver_id = :approver, "
                "approval_conditions = :conditions, resolved_at = :resolved"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "approved",
                ":approver": approver_id,
                ":conditions": conditions,
                ":resolved": now,
            },
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "approval_approved",
                    "approval_id": approval_id,
                    "approver_id": approver_id,
                    "conditions": conditions,
                    "timestamp": now,
                }
            )
        )

        return self._get_approval(approval_id)

    def deny(
        self,
        approval_id: str,
        approver_id: str,
        denial_reason: str,
    ) -> PendingApproval:
        """Deny a pending approval.

        Args:
            approval_id: The approval to deny.
            approver_id: Identity of the person denying.
            denial_reason: Reason for denial.

        Returns:
            The updated PendingApproval record.
        """
        now = datetime.utcnow().isoformat()

        self._table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression=(
                "SET #s = :status, approver_id = :approver, "
                "denial_reason = :reason, resolved_at = :resolved"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "denied",
                ":approver": approver_id,
                ":reason": denial_reason,
                ":resolved": now,
            },
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "approval_denied",
                    "approval_id": approval_id,
                    "approver_id": approver_id,
                    "denial_reason": denial_reason,
                    "timestamp": now,
                }
            )
        )

        return self._get_approval(approval_id)

    def check_timeout(self, approval_id: str) -> Optional[PendingApproval]:
        """Check if a pending approval has exceeded its timeout.

        If the approval is still pending and the elapsed time exceeds
        timeout_seconds, auto-deny with reason "auto-timeout".

        Args:
            approval_id: The approval to check.

        Returns:
            The updated PendingApproval if timed out, None if still within window.
        """
        approval = self._get_approval(approval_id)
        if approval is None or approval.status != "pending":
            return None

        created = datetime.fromisoformat(approval.created_at)
        elapsed = (datetime.utcnow() - created).total_seconds()

        if elapsed >= approval.timeout_seconds:
            now = datetime.utcnow().isoformat()

            self._table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression=(
                    "SET #s = :status, denial_reason = :reason, "
                    "resolved_at = :resolved"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":status": "denied",
                    ":reason": "auto-timeout",
                    ":resolved": now,
                },
            )

            logger.info(
                json.dumps(
                    {
                        "audit_event": "approval_auto_timeout",
                        "approval_id": approval_id,
                        "elapsed_seconds": elapsed,
                        "timeout_seconds": approval.timeout_seconds,
                        "timestamp": now,
                    }
                )
            )

            return self._get_approval(approval_id)

        return None

    def write_approval_evidence(
        self,
        approval: PendingApproval,
        s3_client,
        bucket: str,
        environment: str,
    ) -> str:
        """Write approval/denial decision as evidence to S3.

        Partitions under evidence/{environment}/approvals/YYYY/MM/DD/.

        Args:
            approval: The resolved PendingApproval record.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for evidence storage.
            environment: Deployment environment (dev/staging/prod).

        Returns:
            The S3 key where the evidence was written.
        """
        now = datetime.utcnow()
        s3_key = (
            f"evidence/{environment}/approvals/"
            f"{now.strftime('%Y/%m/%d')}/{approval.approval_id}.json"
        )

        evidence = {
            **approval.to_dict(),
            "evidence_type": "approval_decision",
            "environment": environment,
            "written_at": now.isoformat(),
        }

        s3_client.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=json.dumps(evidence, default=str),
            ContentType="application/json",
            Tagging="framework_mapping=approval_workflow",
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "approval_evidence_written",
                    "approval_id": approval.approval_id,
                    "s3_key": s3_key,
                    "status": approval.status,
                    "timestamp": now.isoformat(),
                }
            )
        )

        return s3_key

    def _get_approval(self, approval_id: str) -> Optional[PendingApproval]:
        """Retrieve a PendingApproval from DynamoDB.

        Args:
            approval_id: The approval's unique identifier.

        Returns:
            PendingApproval if found, None otherwise.
        """
        response = self._table.get_item(Key={"approval_id": approval_id})
        item = response.get("Item")
        if item is None:
            return None
        return PendingApproval.from_dict(item)
