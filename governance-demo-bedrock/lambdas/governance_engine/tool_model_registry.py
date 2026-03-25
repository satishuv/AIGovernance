"""Tool and Model Registration Governance module.

Manages the registry of approved models, tool connectors, and data sources.
Enforces that new entries require policy_approver role approval before
becoming active. All mutations produce structured audit log entries.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7
"""

import json
import logging
from datetime import datetime
from typing import List, Optional

from governance_engine.models import ToolModelRegistryEntry

logger = logging.getLogger(__name__)

VALID_CATEGORIES = {"model", "tool_connector", "data_source"}


class ToolModelRegistry:
    """Manages tool/model/data-source registry entries in DynamoDB.

    Args:
        table: A boto3 DynamoDB Table resource for the ToolModelRegistryTable.
    """

    def __init__(self, table):
        self._table = table

    def register_entry(
        self,
        entry: ToolModelRegistryEntry,
        requester_id: str,
        requester_roles: List[str],
    ) -> ToolModelRegistryEntry:
        """Register a new tool, model, or data-source entry.

        Validates that the category is valid and the requester holds the
        ``policy_approver`` role. The entry is written with
        ``approval_status="pending"`` regardless of the value on the input.

        Args:
            entry: The ToolModelRegistryEntry to register.
            requester_id: Identity of the person submitting the registration.
            requester_roles: List of governance roles held by the requester.

        Returns:
            The registered ToolModelRegistryEntry (with status "pending").

        Raises:
            ValueError: If the category is invalid.
            PermissionError: If the requester lacks the policy_approver role.
        """
        if entry.category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{entry.category}'. "
                f"Must be one of {sorted(VALID_CATEGORIES)}."
            )

        if "policy_approver" not in requester_roles:
            raise PermissionError(
                "Registering a tool/model entry requires the 'policy_approver' role."
            )

        entry.approval_status = "pending"

        self._table.put_item(Item=entry.to_dict())

        now = datetime.utcnow().isoformat()
        logger.info(
            json.dumps(
                {
                    "audit_event": "tool_model_entry_registered",
                    "entry_id": entry.entry_id,
                    "category": entry.category,
                    "name": entry.name,
                    "version": entry.version,
                    "approval_status": entry.approval_status,
                    "requester_id": requester_id,
                    "timestamp": now,
                }
            )
        )

        return entry

    def approve_entry(
        self,
        entry_id: str,
        approver_id: str,
        approver_roles: List[str],
    ) -> None:
        """Approve a pending registry entry.

        Sets ``approval_status`` to ``"approved"``, records the approver
        identity and an ISO 8601 approval timestamp.

        Args:
            entry_id: Unique identifier of the entry to approve.
            approver_id: Identity of the approver.
            approver_roles: List of governance roles held by the approver.

        Raises:
            PermissionError: If the approver lacks the policy_approver role.
        """
        if "policy_approver" not in approver_roles:
            raise PermissionError(
                "Approving a tool/model entry requires the 'policy_approver' role."
            )

        now = datetime.utcnow().isoformat()

        self._table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression=(
                "SET approval_status = :s, approver = :a, approval_timestamp = :t"
            ),
            ExpressionAttributeValues={
                ":s": "approved",
                ":a": approver_id,
                ":t": now,
            },
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "tool_model_entry_approved",
                    "entry_id": entry_id,
                    "approver_id": approver_id,
                    "timestamp": now,
                }
            )
        )

    def revoke_entry(self, entry_id: str, requester_id: str) -> None:
        """Revoke an existing registry entry.

        Sets ``approval_status`` to ``"revoked"``.

        Args:
            entry_id: Unique identifier of the entry to revoke.
            requester_id: Identity of the person requesting revocation.
        """
        now = datetime.utcnow().isoformat()

        self._table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression="SET approval_status = :s",
            ExpressionAttributeValues={":s": "revoked"},
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "tool_model_entry_revoked",
                    "entry_id": entry_id,
                    "requester_id": requester_id,
                    "timestamp": now,
                }
            )
        )

    def is_approved(self, entry_id: str) -> bool:
        """Check whether a registry entry is approved.

        Args:
            entry_id: Unique identifier of the entry.

        Returns:
            True if the entry exists and its approval_status is "approved",
            False otherwise.
        """
        response = self._table.get_item(Key={"entry_id": entry_id})
        item = response.get("Item")
        if item is None:
            return False
        return item.get("approval_status") == "approved"

    def check_usage_allowed(
        self, category: str, name: str, version: str
    ) -> bool:
        """Check whether a matching approved entry exists.

        Scans the table for an entry matching the given category, name, and
        version with ``approval_status == "approved"``.

        Args:
            category: Entry category ("model", "tool_connector", or "data_source").
            name: Entry name.
            version: Entry version string.

        Returns:
            True if a matching approved entry is found, False otherwise.
        """
        response = self._table.scan()
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = self._table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))

        for item in items:
            if (
                item.get("category") == category
                and item.get("name") == name
                and item.get("version") == version
                and item.get("approval_status") == "approved"
            ):
                return True

        return False
