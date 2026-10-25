"""Approval Workflow module.

Manages human-in-the-loop approval workflows for escalated governance
decisions. Supports creating pending approvals, notifying approvers,
approving/denying with separation of duties enforcement, timeout handling,
and writing approval evidence to S3.

Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7
"""

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models import GovernanceDecision, PendingApproval
from request_canonicalization import (
    CanonicalizationError,
    SECURITY_RELEVANT_FIELDS,
    canonical_json,
    canonicalize_action_request,
    compute_action_request_digest,
    to_dynamodb_safe,
)

logger = logging.getLogger(__name__)


def _is_expired(item: Dict[str, Any]) -> bool:
    """True when the approval's absolute expiry has passed (fail closed on bad data)."""
    epoch = item.get("expires_at_epoch")
    if epoch in (None, ""):
        return False  # legacy record without an absolute expiry
    try:
        return int(epoch) <= int(datetime.now(timezone.utc).timestamp())
    except (TypeError, ValueError):
        return True


def _changed_fields(stored: Dict[str, Any], presented: Dict[str, Any]) -> List[str]:
    """Names of security-relevant fields that differ (for audit, never for authz)."""
    changed = []
    for key in SECURITY_RELEVANT_FIELDS:
        try:
            if canonical_json(stored.get(key, "")) != canonical_json(presented.get(key, "")):
                changed.append(key)
        except Exception:
            changed.append(key)
    return changed


def compute_request_digest(agent_id, action, parameters, target,
                           policy_version="", expiry=""):
    """Bind an approval to the exact request it authorizes (TOCTOU defense).

    A human (or system) approves a *specific* request. Without binding, an
    attacker could obtain approval for a benign request and then execute a
    modified one under the same approval (time-of-check/time-of-use), or replay
    a past approval. We hash the security-relevant fields into a digest; the
    executor must present a request that reproduces the same digest, and the
    approval is single-use and expiring.
    """
    canonical = json.dumps(
        {
            "agent_id": agent_id,
            "action": action,
            "parameters": parameters,
            "target": target,
            "policy_version": policy_version,
            "expiry": expiry,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
        now = datetime.now(timezone.utc).isoformat()
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

        item = approval.to_dict()
        # Bind this approval to the exact request (TOCTOU / replay defense).
        # Decisions carry a canonical action_request (operation, target,
        # parameters, environment, data class, financial subject) and the
        # policy version hash; the digest also covers the ABSOLUTE expiry so a
        # stale approval cannot be stretched.
        created_epoch = int(datetime.now(timezone.utc).timestamp())
        expires_epoch = created_epoch + int(timeout_seconds)
        expires_at = datetime.fromtimestamp(expires_epoch, tz=timezone.utc).isoformat()
        req = getattr(decision, "action_request", None) or {}
        policy_version_hash = (getattr(decision, "policy_version_hash", "")
                               or getattr(decision, "policy_version", "") or "")
        if req:
            canonical = canonicalize_action_request(req)
            item["digest_version"] = 2
            item["action_request"] = to_dynamodb_safe(canonical)
            item["policy_version_hash"] = policy_version_hash
            item["request_digest"] = compute_action_request_digest(
                canonical, policy_version_hash, expires_at)
        else:
            # Legacy decisions without a structured request.
            item["digest_version"] = 1
            item["request_digest"] = compute_request_digest(
                agent_id=decision.agent_id,
                action=decision.action_requested,
                parameters={},
                target="",
                policy_version=policy_version_hash,
                expiry=str(timeout_seconds),
            )
        item["expires_at"] = expires_at
        item["expires_at_epoch"] = expires_epoch
        item["consumed"] = False
        self._table.put_item(Item=item)

        logger.info(
            json.dumps(
                {
                    "audit_event": "pending_approval_created",
                    "approval_id": approval_id,
                    "decision_id": decision.decision_id,
                    "agent_id": decision.agent_id,
                    "risk_score": decision.risk_score,
                    "timeout_seconds": timeout_seconds,
                    "request_digest": item["request_digest"],
                    "timestamp": now,
                }
            )
        )

        return approval_id

    def verify_approved_request(self, approval_id, agent_id, action,
                                parameters, target, policy_version=""):
        """Verify at execution time that an approval authorizes THIS request.

        Enforces the TOCTOU / replay guarantees: the approval must exist, be
        status=approved, not previously consumed, and its stored request_digest
        must match a freshly-computed digest of the request being executed. On
        success the approval is atomically marked consumed (single-use).
        Fails closed on any mismatch.

        Returns (ok: bool, reason: str).
        """
        try:
            resp = self._table.get_item(Key={"approval_id": approval_id})
        except Exception as exc:
            return False, f"approval lookup failed ({type(exc).__name__}); failing closed"
        item = resp.get("Item")
        if not item:
            return False, "approval not found"
        if item.get("status") != "approved":
            return False, f"approval status is {item.get('status')!r}, not approved"
        if item.get("consumed"):
            return False, "approval already consumed (replay attempt)"
        if _is_expired(item):
            return False, "approval expired; a new approval is required"

        expected = item.get("request_digest", "")
        actual = compute_request_digest(
            agent_id=agent_id, action=action, parameters=parameters,
            target=target, policy_version=policy_version,
            expiry=str(item.get("timeout_seconds", "")),
        )
        if not expected or not hmac.compare_digest(str(actual), str(expected)):
            logger.error(json.dumps({
                "audit_event": "approval_request_digest_mismatch",
                "approval_id": approval_id,
                "expected": expected, "actual": actual,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return False, ("request does not match the approved request "
                           "(TOCTOU/parameter tampering); failing closed")

        # Atomically consume: single-use, guarded by a condition so a concurrent
        # replay cannot double-consume.
        try:
            self._table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression="SET #c = :t, resolved_at = :r",
                ConditionExpression="#c = :f AND #s = :approved",
                ExpressionAttributeNames={"#s": "status", "#c": "consumed"},
                ExpressionAttributeValues={
                    ":t": True, ":f": False, ":approved": "approved",
                    ":r": datetime.now(timezone.utc).isoformat()},
            )
        except Exception:
            return False, "approval consumed concurrently (replay attempt)"
        return True, "approved request verified and consumed"

    def check_binding(self, approval_id: str, action_request: Dict[str, Any],
                      policy_version_hash: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """Read-only check that a presented request matches an approval.

        Same checks as verify_and_consume except consumption. Callers use it
        to report tampering precisely before running other gates; the atomic
        verify_and_consume still re-checks everything at consumption time.
        """
        try:
            resp = self._table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True)
        except Exception as exc:
            return False, f"approval lookup failed ({type(exc).__name__}); failing closed", {}
        item = resp.get("Item") or {}
        if not item:
            return False, "approval not found", {}
        if int(item.get("digest_version", 1) or 1) != 2:
            return False, "approval is not bound to a structured request; failing closed", item
        status = item.get("status")
        if status != "approved":
            return False, f"approval status is {status!r}, not approved", item
        if item.get("consumed"):
            return False, "approval already consumed (replay attempt)", item
        if _is_expired(item):
            return False, "approval expired; a new approval is required", item
        try:
            canonical = canonicalize_action_request(action_request)
        except CanonicalizationError as exc:
            return False, f"request could not be canonicalized ({exc})", item
        actual = compute_action_request_digest(canonical, policy_version_hash, item.get("expires_at", ""))
        expected = str(item.get("request_digest", ""))
        if not expected or not hmac.compare_digest(actual, expected):
            changed = _changed_fields(item.get("action_request") or {}, canonical)
            if policy_version_hash != item.get("policy_version_hash", ""):
                changed.append("policy_version_hash")
            logger.error(json.dumps({
                "audit_event": "approval_request_digest_mismatch",
                "approval_id": approval_id,
                "changed_fields": changed,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }, default=str))
            detail = f" (changed: {', '.join(changed)})" if changed else ""
            return False, ("approved request digest does not match the presented request"
                           f"{detail}; failing closed"), item
        return True, "presented request matches the approval", item

    def verify_and_consume(self, approval_id: str, action_request: Dict[str, Any],
                           policy_version_hash: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """Verify a structured request against its approval and consume it once.

        The approval must exist, be approved, unexpired and unconsumed, and the
        digest of (canonical request, current policy version hash, the
        approval's absolute expiry) must equal the digest recorded when the
        approval was created. Any difference in agent, session, provider,
        operation, target, parameters, environment, data class, amount or
        currency, or a policy change since approval, fails closed. Consumption
        is a conditional write, so of two concurrent callers only one succeeds.

        Returns (ok, reason, approval_item).
        """
        ok, reason, item = self.check_binding(approval_id, action_request, policy_version_hash)
        if not ok:
            return False, reason, item

        now_epoch = int(datetime.now(timezone.utc).timestamp())
        try:
            self._table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression="SET #c = :t, consumed_at = :r",
                ConditionExpression=("#c = :f AND #s = :approved "
                                     "AND expires_at_epoch > :now"),
                ExpressionAttributeNames={"#s": "status", "#c": "consumed"},
                ExpressionAttributeValues={
                    ":t": True, ":f": False, ":approved": "approved",
                    ":now": now_epoch,
                    ":r": datetime.now(timezone.utc).isoformat()},
            )
        except Exception:
            return False, "approval consumed concurrently (replay attempt)", item
        logger.info(json.dumps({
            "audit_event": "approval_consumed",
            "approval_id": approval_id,
            "decision_id": item.get("decision_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        item["consumed"] = True
        return True, "approved request verified and consumed", item

    def consume_transact_item(self, approval_id: str, grant_id: str = "") -> Dict[str, Any]:
        """Update for a DynamoDB transaction that consumes the approval once.

        Same condition as verify_and_consume: approved, unconsumed, unexpired.
        Put it in the same transaction as the grant write, so the approval is
        consumed exactly when its grant exists. Call check_binding first; this
        item does not re-check the request digest. Values are plain Python
        types: the client of a boto3 DynamoDB resource table converts them.
        """
        now = datetime.now(timezone.utc)
        return {"Update": {
            "TableName": self._table.name,
            "Key": {"approval_id": approval_id},
            "UpdateExpression": "SET #c = :t, consumed_at = :r, grant_id = :g",
            "ConditionExpression": "#c = :f AND #s = :approved AND expires_at_epoch > :now",
            "ExpressionAttributeNames": {"#s": "status", "#c": "consumed"},
            "ExpressionAttributeValues": {":t": True, ":f": False, ":approved": "approved",
                                          ":now": int(now.timestamp()), ":r": now.isoformat(),
                                          ":g": grant_id},
        }}

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
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )

    def approve(
        self,
        approval_id: str,
        approver_id: str,
        agent_owner_id: str,
        conditions: str = "",
        reviewed_digest: Optional[str] = None,
    ) -> PendingApproval:
        """Approve a pending approval with separation of duties enforcement.

        The approver must not be the agent owner (separation of duties). An approval authorizes the
        exact request bound by request_digest and nothing narrower: grants are built from that
        request, so a condition could never be enforced, and a non-empty condition is refused
        instead of being stored beside an unconditional approval. When reviewed_digest is given,
        only the record whose request_digest equals it is approved, so a different pending request
        cannot be approved under that review.

        Args:
            approval_id: The approval to resolve.
            approver_id: Identity of the person approving.
            agent_owner_id: Identity of the agent's owner.
            conditions: Must be empty; kept for API compatibility.
            reviewed_digest: The request_digest the approver reviewed (optional).

        Returns:
            The updated PendingApproval record.

        Raises:
            ValueError: If approver_id equals agent_owner_id, a condition is given, or the record
                is not pending (or does not match reviewed_digest).
        """
        if not approver_id or not str(approver_id).strip():
            raise ValueError("Approver identity is required to approve a request.")
        if str(conditions or "").strip():
            raise ValueError("Conditional approval is not supported: an approval authorizes the exact "
                             "pending request; let it expire and have the agent submit the narrower request.")

        if approver_id == agent_owner_id:
            logger.warning(
                json.dumps(
                    {
                        "audit_event": "approval_sod_violation",
                        "approval_id": approval_id,
                        "approver_id": approver_id,
                        "agent_owner_id": agent_owner_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            )
            raise ValueError(
                "Separation of duties violation: approver cannot be the agent owner."
            )

        now = datetime.now(timezone.utc).isoformat()

        # Only an existing, still-pending approval can be approved. Without the
        # condition, update_item would create a brand-new "approved" record for
        # an unknown id, or re-approve a denied or timed-out one.
        condition = "attribute_exists(approval_id) AND #s = :pending"
        values = {
            ":status": "approved",
            ":approver": approver_id,
            ":conditions": "",
            ":resolved": now,
            ":pending": "pending",
        }
        if reviewed_digest is not None:
            condition += " AND request_digest = :reviewed"
            values[":reviewed"] = str(reviewed_digest)
        try:
            self._table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression=(
                    "SET #s = :status, approver_id = :approver, "
                    "approval_conditions = :conditions, resolved_at = :resolved"
                ),
                ConditionExpression=condition,
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues=values,
            )
        except Exception as exc:
            if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                raise ValueError(
                    f"Approval {approval_id} does not exist, is no longer pending, or is not the "
                    "request that was reviewed."
                ) from exc
            raise

        logger.info(
            json.dumps(
                {
                    "audit_event": "approval_approved",
                    "approval_id": approval_id,
                    "approver_id": approver_id,
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
        now = datetime.now(timezone.utc).isoformat()

        # A pending approval can be denied, and an approved-but-unused one can
        # be withdrawn. A consumed approval already executed and is history.
        try:
            self._table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression=(
                    "SET #s = :status, approver_id = :approver, "
                    "denial_reason = :reason, resolved_at = :resolved"
                ),
                ConditionExpression=(
                    "attribute_exists(approval_id) AND "
                    "(#s = :pending OR (#s = :approved AND #c = :f))"
                ),
                ExpressionAttributeNames={"#s": "status", "#c": "consumed"},
                ExpressionAttributeValues={
                    ":status": "denied",
                    ":approver": approver_id,
                    ":reason": denial_reason,
                    ":resolved": now,
                    ":pending": "pending",
                    ":approved": "approved",
                    ":f": False,
                },
            )
        except Exception as exc:
            if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                raise ValueError(
                    f"Approval {approval_id} does not exist or can no longer be denied."
                ) from exc
            raise

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
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()

        if elapsed >= approval.timeout_seconds:
            now = datetime.now(timezone.utc).isoformat()

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
        now = datetime.now(timezone.utc)
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

    def get_record(self, approval_id: str) -> Dict[str, Any]:
        """Raw approval record (including binding fields), or {} if absent."""
        return self._table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True).get("Item") or {}

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
