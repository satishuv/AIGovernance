"""Policy Lifecycle Management module.

Manages policy versioning, approval workflow with separation-of-duties
enforcement, rollback capability, and version history queries. Policy
content is stored in S3; version metadata lives in DynamoDB.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 21.2
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from models import PolicyVersion

logger = logging.getLogger(__name__)

# Storage layout. Every submitted version is kept under VERSIONS_PREFIX, which
# the policy engines never load. Only approve_policy and rollback_policy copy a
# version to the active key, inside the policies/ prefix the engines read.
VERSIONS_PREFIX = "policy-versions"
ACTIVE_PREFIX = "policies/active"

# Earlier versions of this module wrote archived copies under policies/archive/.
# Copies like these must never take effect, wherever they appear.
_NON_ENFORCEABLE_SEGMENTS = ("/archive/", "/pending/")


def version_key(policy_id: str, version: int) -> str:
    """S3 key that holds one submitted version, outside the loaded prefix."""
    return f"{VERSIONS_PREFIX}/{policy_id}/v{int(version)}.json"


def active_key(policy_id: str) -> str:
    """S3 key of the version currently in force."""
    return f"{ACTIVE_PREFIX}/{policy_id}.json"


def is_enforceable_policy_key(key: str) -> bool:
    """False for archived or pending policy copies, which the engines must skip."""
    return not any(segment in key for segment in _NON_ENFORCEABLE_SEGMENTS)


class PolicyLifecycle:
    """Manages policy definition versioning, approval, and rollback."""

    def update_policy(
        self,
        policy_id: str,
        policy_content: Dict[str, Any],
        author_id: str,
        s3_client,
        bucket: str,
        dynamodb_table,
    ) -> PolicyVersion:
        """Create a new version of a policy definition.

        The version is stored as pending and has no effect until
        approve_policy activates it.

        Args:
            policy_id: Identifier of the policy to update.
            policy_content: The new policy definition content.
            author_id: Identity of the policy author.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for policy storage.
            dynamodb_table: boto3 DynamoDB Table for PolicyMetadataTable.

        Returns:
            The created PolicyVersion record.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Determine next version number (monotonically increasing)
        history = self.get_policy_history(policy_id, dynamodb_table)
        next_version = 1
        if history:
            next_version = max(int(v.version) for v in history) + 1

        # Store the submitted version outside the loaded prefix. It has no
        # effect until approve_policy copies it to the active key.
        key = version_key(policy_id, next_version)
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(policy_content, default=str),
            ContentType="application/json",
        )

        # Record version metadata in DynamoDB
        version_record = PolicyVersion(
            policy_id=policy_id,
            version=next_version,
            author=author_id,
            approval_status="pending",
            approver="",
            timestamp=now,
            s3_key=key,
        )
        dynamodb_table.put_item(Item=version_record.to_dict())

        logger.info(
            json.dumps({
                "audit_event": "policy_updated",
                "policy_id": policy_id,
                "version": next_version,
                "author_id": author_id,
                "timestamp": now,
            })
        )

        # Phase 2: Log policy change via ChangeLogger (Req 21.2)
        change_type_detail = "create" if next_version == 1 else "update"
        self._log_policy_change(
            policy_id=policy_id,
            previous_version=str(next_version - 1) if next_version > 1 else "0",
            new_version=str(next_version),
            author_id=author_id,
            approver_id="",
            change_type_detail=change_type_detail,
            s3_client=s3_client,
            bucket=bucket,
        )

        return version_record

    def approve_policy(
        self,
        policy_id: str,
        version: int,
        approver_id: str,
        approver_roles: List[str],
        author_id: str,
        s3_client=None,
        bucket: str = "",
        dynamodb_table=None,
    ) -> Dict[str, Any]:
        """Approve a pending policy version and make it the active version.

        The approver must have the "policy_approver" role and must not be
        the author, checked against both author_id and the stored record.
        Approval copies the stored version to the active key; other approved
        versions become "superseded".

        Args:
            policy_id: Identifier of the policy.
            version: Version number to approve.
            approver_id: Identity of the approver.
            approver_roles: List of governance roles held by the approver.
            author_id: Identity of the policy author.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for policy storage.
            dynamodb_table: boto3 DynamoDB Table for PolicyMetadataTable.

        Returns:
            Dict with approval details.

        Raises:
            ValueError: If SoD constraints are violated, the role is missing,
                the store is not supplied, or the version is not pending.
        """
        if "policy_approver" not in approver_roles:
            raise ValueError(
                f"User '{approver_id}' does not have the 'policy_approver' "
                "role required to approve policies."
            )

        if approver_id == author_id:
            raise ValueError(
                f"Separation of duties violation: approver '{approver_id}' "
                f"cannot be the same as author '{author_id}'."
            )

        if s3_client is None or not bucket or dynamodb_table is None:
            raise ValueError("Approving a policy needs the policy bucket and metadata table.")

        version = int(version)
        key = {"policy_id": policy_id, "version": version}
        item = dynamodb_table.get_item(Key=key).get("Item")
        if not item:
            raise ValueError(f"Policy '{policy_id}' version {version} does not exist.")
        record = PolicyVersion.from_dict(item)
        if record.approval_status != "pending":
            raise ValueError(
                f"Policy '{policy_id}' version {version} is "
                f"'{record.approval_status}', not pending."
            )
        if approver_id == record.author:
            raise ValueError(
                f"Separation of duties violation: approver '{approver_id}' "
                f"authored version {version}."
            )

        previous = [int(v.version) for v in self.get_policy_history(policy_id, dynamodb_table)
                    if v.approval_status == "approved" and int(v.version) != version]
        now = datetime.now(timezone.utc).isoformat()

        # Conditional write: of two concurrent approvals, only one succeeds.
        dynamodb_table.update_item(
            Key=key,
            UpdateExpression="SET #s = :approved, #a = :approver, #t = :now",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "approval_status", "#a": "approver", "#t": "approved_at"},
            ExpressionAttributeValues={":approved": "approved", ":approver": approver_id,
                                       ":now": now, ":pending": "pending"},
        )
        try:
            s3_client.copy_object(
                Bucket=bucket,
                Key=active_key(policy_id),
                CopySource={"Bucket": bucket, "Key": record.s3_key},
            )
        except Exception:
            # Not active means not approved: return the record to pending.
            dynamodb_table.update_item(
                Key=key,
                UpdateExpression="SET #s = :pending, #a = :empty",
                ExpressionAttributeNames={"#s": "approval_status", "#a": "approver"},
                ExpressionAttributeValues={":pending": "pending", ":empty": ""},
            )
            raise
        self._supersede_others(policy_id, version, dynamodb_table)

        logger.info(
            json.dumps({
                "audit_event": "policy_approved",
                "policy_id": policy_id,
                "version": version,
                "approver_id": approver_id,
                "author_id": record.author,
                "timestamp": now,
            })
        )
        self._log_policy_change(
            policy_id=policy_id,
            previous_version=str(max(previous)) if previous else "0",
            new_version=str(version),
            author_id=record.author,
            approver_id=approver_id,
            change_type_detail="approve",
            s3_client=s3_client,
            bucket=bucket,
        )

        return {
            "policy_id": policy_id,
            "version": version,
            "approval_status": "approved",
            "approver": approver_id,
            "active_key": active_key(policy_id),
            "timestamp": now,
        }

    def _supersede_others(self, policy_id: str, keep_version: int, dynamodb_table) -> None:
        """Mark every other approved version of the policy as superseded."""
        for v in self.get_policy_history(policy_id, dynamodb_table):
            if int(v.version) != int(keep_version) and v.approval_status == "approved":
                dynamodb_table.update_item(
                    Key={"policy_id": policy_id, "version": int(v.version)},
                    UpdateExpression="SET #s = :superseded",
                    ExpressionAttributeNames={"#s": "approval_status"},
                    ExpressionAttributeValues={":superseded": "superseded"},
                )

    def rollback_policy(
        self,
        policy_id: str,
        target_version: int,
        requester_id: str,
        s3_client,
        bucket: str,
        dynamodb_table,
    ) -> PolicyVersion:
        """Rollback a policy to a specified previous version.

        Args:
            policy_id: Identifier of the policy.
            target_version: Version number to restore.
            requester_id: Identity of the person requesting rollback.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name.
            dynamodb_table: boto3 DynamoDB Table for PolicyMetadataTable.

        Returns:
            The new PolicyVersion record created by the rollback.

        Raises:
            ValueError: If the target version was never approved or cannot be restored.
        """
        now = datetime.now(timezone.utc).isoformat()
        history = self.get_policy_history(policy_id, dynamodb_table)
        current_version = max((int(v.version) for v in history), default=0)

        # Only content that was approved before may be restored; otherwise a
        # rollback would activate a version nobody approved.
        target = next((v for v in history if int(v.version) == int(target_version)), None)
        if target is None or target.approval_status not in ("approved", "superseded"):
            raise ValueError(
                f"Policy '{policy_id}' version {target_version} was never approved; "
                "rollback restores only previously approved versions."
            )

        new_version = current_version + 1
        new_key = version_key(policy_id, new_version)
        try:
            for key in (new_key, active_key(policy_id)):
                s3_client.copy_object(
                    Bucket=bucket,
                    Key=key,
                    CopySource={"Bucket": bucket, "Key": target.s3_key},
                )
        except Exception as exc:
            raise ValueError(
                f"Failed to restore policy '{policy_id}' version "
                f"{target_version}: {exc}"
            )

        version_record = PolicyVersion(
            policy_id=policy_id,
            version=new_version,
            author=requester_id,
            approval_status="approved",
            approver=requester_id,
            timestamp=now,
            s3_key=new_key,
        )
        dynamodb_table.put_item(Item=version_record.to_dict())
        self._supersede_others(policy_id, new_version, dynamodb_table)

        logger.info(
            json.dumps({
                "audit_event": "policy_rolled_back",
                "policy_id": policy_id,
                "rolled_back_from_version": current_version,
                "rolled_back_to_version": target_version,
                "new_version": new_version,
                "requester_id": requester_id,
                "timestamp": now,
            })
        )

        # Phase 2: Log rollback via ChangeLogger (Req 21.2)
        self._log_policy_change(
            policy_id=policy_id,
            previous_version=str(current_version),
            new_version=str(new_version),
            author_id=requester_id,
            approver_id=requester_id,
            change_type_detail="rollback",
            s3_client=s3_client,
            bucket=bucket,
        )

        return version_record

    def _log_policy_change(
        self,
        policy_id: str,
        previous_version: str,
        new_version: str,
        author_id: str,
        approver_id: str,
        change_type_detail: str,
        s3_client,
        bucket: str,
    ) -> None:
        """Log a policy change via ChangeLogger if configured.

        Args:
            policy_id: The policy that changed.
            previous_version: Previous version identifier.
            new_version: New version identifier.
            author_id: Identity of the policy author.
            approver_id: Identity of the policy approver.
            change_type_detail: One of "create", "update", or "rollback".
            s3_client: boto3 S3 client.
            bucket: S3 bucket name.
        """
        change_log_table_name = os.environ.get("CHANGE_LOG_TABLE_NAME", "")
        evidence_bucket = os.environ.get(
            "IMMUTABLE_EVIDENCE_BUCKET_NAME",
            os.environ.get("EVIDENCE_BUCKET_NAME", bucket),
        )
        if change_log_table_name and evidence_bucket:
            try:
                import boto3 as _boto3
                from change_logger import ChangeLogger

                dynamodb = _boto3.resource("dynamodb")
                cl = ChangeLogger(dynamodb.Table(change_log_table_name))
                cl.log_policy_change(
                    policy_id=policy_id,
                    previous_version=previous_version,
                    new_version=new_version,
                    author_id=author_id,
                    approver_id=approver_id,
                    change_type_detail=change_type_detail,
                    s3_client=s3_client,
                    bucket=evidence_bucket,
                )
            except Exception as cl_exc:
                logger.error(
                    json.dumps({
                        "event": "policy_change_logging_failed",
                        "error": str(cl_exc),
                        "policy_id": policy_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                )

    @staticmethod
    def get_policy_history(
        policy_id: str, dynamodb_table
    ) -> List[PolicyVersion]:
        """Retrieve version history for a policy, ordered by version desc.

        Args:
            policy_id: Identifier of the policy.
            dynamodb_table: boto3 DynamoDB Table for PolicyMetadataTable.

        Returns:
            List of PolicyVersion records ordered by version descending.
        """
        from boto3.dynamodb.conditions import Key

        response = dynamodb_table.query(
            KeyConditionExpression=Key("policy_id").eq(policy_id),
            ScanIndexForward=False,
        )
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = dynamodb_table.query(
                KeyConditionExpression=Key("policy_id").eq(policy_id),
                ScanIndexForward=False,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        return [PolicyVersion.from_dict(item) for item in items]
