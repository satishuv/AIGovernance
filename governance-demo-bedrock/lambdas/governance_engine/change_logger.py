"""Scope and Policy Change Logging module.

Logs all scope and policy changes to both S3 (evidence bucket) and DynamoDB
(ChangeLogTable) for audit, compliance, and queryable history. All records
carry a 2555-day (7-year) retention period.

Requirements: 21.1, 21.2, 21.3, 21.4
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from governance_engine.models import ChangeRecord

logger = logging.getLogger(__name__)


class ChangeLogger:
    """Logs scope and policy changes to S3 and DynamoDB.

    Args:
        table: A boto3 DynamoDB Table resource for the ChangeLogTable.
    """

    def __init__(self, table):
        self._table = table

    def log_scope_change(
        self,
        agent_id: str,
        previous_scope: int,
        new_scope: int,
        requester_id: str,
        authorization_method: str,
        s3_client,
        bucket: str,
    ) -> ChangeRecord:
        """Log a scope level change to S3 and DynamoDB.

        Args:
            agent_id: The agent whose scope changed.
            previous_scope: Previous scope level value.
            new_scope: New scope level value.
            requester_id: Identity of the person who requested the change.
            authorization_method: Method used to authorize the change.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for evidence storage.

        Returns:
            The created ChangeRecord.
        """
        now = datetime.utcnow()
        record_id = str(uuid.uuid4())

        record = ChangeRecord(
            record_id=record_id,
            change_type="scope_change",
            agent_id=agent_id,
            policy_id="",
            previous_value=str(previous_scope),
            new_value=str(new_scope),
            requester_id=requester_id,
            authorization_method=authorization_method,
            timestamp=now.isoformat(),
            retention_days=2555,
        )

        # Write to S3
        s3_key = (
            f"evidence/changes/scope/"
            f"{now.strftime('%Y/%m/%d')}/{record_id}.json"
        )
        s3_client.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=json.dumps(record.to_dict(), default=str),
            ContentType="application/json",
        )

        # Index in DynamoDB
        self._table.put_item(Item=record.to_dict())

        logger.info(
            json.dumps(
                {
                    "audit_event": "scope_change_logged",
                    "record_id": record_id,
                    "agent_id": agent_id,
                    "previous_scope": previous_scope,
                    "new_scope": new_scope,
                    "requester_id": requester_id,
                    "authorization_method": authorization_method,
                    "s3_key": s3_key,
                    "retention_days": 2555,
                    "timestamp": now.isoformat(),
                }
            )
        )

        return record

    def log_policy_change(
        self,
        policy_id: str,
        previous_version: str,
        new_version: str,
        author_id: str,
        approver_id: str,
        change_type_detail: str,
        s3_client,
        bucket: str,
    ) -> ChangeRecord:
        """Log a policy change to S3 and DynamoDB.

        Args:
            policy_id: The policy that changed.
            previous_version: Previous version identifier.
            new_version: New version identifier.
            author_id: Identity of the policy author.
            approver_id: Identity of the policy approver.
            change_type_detail: One of "create", "update", or "rollback".
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for evidence storage.

        Returns:
            The created ChangeRecord.
        """
        now = datetime.utcnow()
        record_id = str(uuid.uuid4())

        record = ChangeRecord(
            record_id=record_id,
            change_type="policy_change",
            agent_id="",
            policy_id=policy_id,
            previous_value=str(previous_version),
            new_value=str(new_version),
            requester_id=author_id,
            authorization_method=f"{change_type_detail}:approver={approver_id}",
            timestamp=now.isoformat(),
            retention_days=2555,
        )

        # Write to S3
        s3_key = (
            f"evidence/changes/policy/"
            f"{now.strftime('%Y/%m/%d')}/{record_id}.json"
        )
        s3_client.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=json.dumps(record.to_dict(), default=str),
            ContentType="application/json",
        )

        # Index in DynamoDB
        self._table.put_item(Item=record.to_dict())

        logger.info(
            json.dumps(
                {
                    "audit_event": "policy_change_logged",
                    "record_id": record_id,
                    "policy_id": policy_id,
                    "change_type_detail": change_type_detail,
                    "previous_version": previous_version,
                    "new_version": new_version,
                    "author_id": author_id,
                    "approver_id": approver_id,
                    "s3_key": s3_key,
                    "retention_days": 2555,
                    "timestamp": now.isoformat(),
                }
            )
        )

        return record

    def query_changes(
        self,
        filters: Dict[str, Any],
    ) -> List[ChangeRecord]:
        """Query change records with filtering support.

        Scans the ChangeLogTable and filters in-memory. Supports filtering
        by agent_id, policy_id, requester_id, and date range (start_date,
        end_date as ISO 8601 strings).

        Args:
            filters: Dictionary of filter criteria. Supported keys:
                - agent_id (str): Match records for this agent.
                - policy_id (str): Match records for this policy.
                - requester_id (str): Match records by this requester.
                - start_date (str): ISO 8601 lower bound (inclusive).
                - end_date (str): ISO 8601 upper bound (inclusive).

        Returns:
            List of matching ChangeRecord objects.
        """
        response = self._table.scan()
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = self._table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))

        records = [ChangeRecord.from_dict(item) for item in items]

        results = []
        for record in records:
            if "agent_id" in filters and record.agent_id != filters["agent_id"]:
                continue
            if "policy_id" in filters and record.policy_id != filters["policy_id"]:
                continue
            if "requester_id" in filters and record.requester_id != filters["requester_id"]:
                continue
            if "start_date" in filters and record.timestamp < filters["start_date"]:
                continue
            if "end_date" in filters and record.timestamp > filters["end_date"]:
                continue
            results.append(record)

        return results
