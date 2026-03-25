"""Policy Lifecycle Management module.

Manages policy versioning, approval workflow with separation-of-duties
enforcement, rollback capability, and version history queries. Policy
content is stored in S3; version metadata lives in DynamoDB.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 21.2
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from governance_engine.models import PolicyVersion

logger = logging.getLogger(__name__)


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
        now = datetime.utcnow().isoformat()

        # Determine next version number (monotonically increasing)
        history = self.get_policy_history(policy_id, dynamodb_table)
        next_version = 1
        if history:
            next_version = max(v.version for v in history) + 1

        # Archive current active version if it exists
        if next_version > 1:
            archive_key = f"policies/archive/{policy_id}/v{next_version - 1}.json"
            try:
                active_key = f"policies/active/{policy_id}.json"
                s3_client.copy_object(
                    Bucket=bucket,
                    Key=archive_key,
                    CopySource={"Bucket": bucket, "Key": active_key},
                )
            except Exception as exc:
                logger.warning(
                    json.dumps({
                        "audit_event": "policy_archive_failed",
                        "policy_id": policy_id,
                        "version": next_version - 1,
                        "error": str(exc),
                        "timestamp": now,
                    })
                )

        # Store new version as active
        active_key = f"policies/active/{policy_id}.json"
        s3_client.put_object(
            Bucket=bucket,
            Key=active_key,
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
            s3_key=active_key,
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
    ) -> Dict[str, Any]:
        """Approve a policy version with SoD enforcement.

        The approver must have the "policy_approver" role and must not be
        the same person as the author.

        Args:
            policy_id: Identifier of the policy.
            version: Version number to approve.
            approver_id: Identity of the approver.
            approver_roles: List of governance roles held by the approver.
            author_id: Identity of the policy author.

        Returns:
            Dict with approval details.

        Raises:
            ValueError: If SoD constraints are violated or role is missing.
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

        now = datetime.utcnow().isoformat()

        logger.info(
            json.dumps({
                "audit_event": "policy_approved",
                "policy_id": policy_id,
                "version": version,
                "approver_id": approver_id,
                "author_id": author_id,
                "timestamp": now,
            })
        )

        return {
            "policy_id": policy_id,
            "version": version,
            "approval_status": "approved",
            "approver": approver_id,
            "timestamp": now,
        }

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
            ValueError: If the target version archive is not found.
        """
        now = datetime.utcnow().isoformat()
        history = self.get_policy_history(policy_id, dynamodb_table)
        current_version = max(v.version for v in history) if history else 0

        archive_key = f"policies/archive/{policy_id}/v{target_version}.json"
        active_key = f"policies/active/{policy_id}.json"

        try:
            s3_client.copy_object(
                Bucket=bucket,
                Key=active_key,
                CopySource={"Bucket": bucket, "Key": archive_key},
            )
        except Exception as exc:
            raise ValueError(
                f"Failed to restore policy '{policy_id}' version "
                f"{target_version} from archive: {exc}"
            )

        new_version = current_version + 1
        version_record = PolicyVersion(
            policy_id=policy_id,
            version=new_version,
            author=requester_id,
            approval_status="approved",
            approver=requester_id,
            timestamp=now,
            s3_key=active_key,
        )
        dynamodb_table.put_item(Item=version_record.to_dict())

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
                from governance_engine.change_logger import ChangeLogger

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
                        "timestamp": datetime.utcnow().isoformat(),
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
