"""Separation of Duties module.

Enforces governance role assignments and separation-of-duties constraints.
Prevents conflicting role combinations (e.g., policy_author + policy_approver
for the same scope, or operator + auditor). All mutations produce structured
audit log entries.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5
"""

import json
import logging
from datetime import datetime
from typing import List

from governance_engine.models import GovernanceRoleAssignment

logger = logging.getLogger(__name__)

VALID_ROLES = {"policy_author", "policy_approver", "operator", "auditor", "agent_owner"}


class SeparationOfDuties:
    """Manages governance role assignments with SoD constraint enforcement.

    Args:
        table: A boto3 DynamoDB Table resource for the GovernanceRolesTable.
    """

    def __init__(self, table):
        self._table = table

    def assign_role(
        self,
        user_id: str,
        role: str,
        scope: str,
        assigner_id: str,
    ) -> GovernanceRoleAssignment:
        """Assign a governance role to a user.

        Validates the role value and checks separation-of-duties constraints
        before writing the assignment.

        Args:
            user_id: Identifier of the user receiving the role.
            role: Governance role to assign.
            scope: Scope to which the role applies.
            assigner_id: Identity of the person making the assignment.

        Returns:
            The created GovernanceRoleAssignment.

        Raises:
            ValueError: If the role is not valid or violates SoD constraints.
        """
        if role not in VALID_ROLES:
            raise ValueError(
                f"Invalid role '{role}'. Must be one of {sorted(VALID_ROLES)}."
            )

        if not self.check_sod_constraints(user_id, role, scope):
            raise ValueError(
                f"Assigning role '{role}' to user '{user_id}' for scope "
                f"'{scope}' violates separation-of-duties constraints."
            )

        now = datetime.utcnow().isoformat()
        assignment = GovernanceRoleAssignment(
            user_id=user_id,
            role=role,
            scope=scope,
            assigned_by=assigner_id,
            assigned_at=now,
        )

        self._table.put_item(
            Item={
                "user_id": user_id,
                "role": role,
                "scope": scope,
                "assigned_by": assigner_id,
                "assigned_at": now,
            }
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "role_assigned",
                    "user_id": user_id,
                    "role": role,
                    "scope": scope,
                    "assigner_id": assigner_id,
                    "timestamp": now,
                }
            )
        )

        return assignment

    def check_sod_constraints(
        self, user_id: str, role: str, scope: str
    ) -> bool:
        """Check whether a role assignment is allowed under SoD rules.

        Constraints:
        (a) A user cannot hold both ``policy_author`` and ``policy_approver``
            for the same scope.
        (b) A user cannot hold both ``operator`` and ``auditor`` (any scope).

        Args:
            user_id: Identifier of the user.
            role: The role being considered for assignment.
            scope: The scope of the proposed assignment.

        Returns:
            True if the assignment is allowed, False if it violates a
            constraint.
        """
        existing = self.get_user_roles(user_id)
        existing_roles = {(r.role, r.scope) for r in existing}
        existing_role_names = {r.role for r in existing}

        # Constraint (a): policy_author + policy_approver for same scope
        if role == "policy_author" and ("policy_approver", scope) in existing_roles:
            return False
        if role == "policy_approver" and ("policy_author", scope) in existing_roles:
            return False

        # Constraint (b): operator + auditor (any scope)
        if role == "operator" and "auditor" in existing_role_names:
            return False
        if role == "auditor" and "operator" in existing_role_names:
            return False

        return True

    def validate_action(
        self, user_id: str, action: str, scope: str
    ) -> bool:
        """Check if a user's roles allow an action without SoD violation.

        If the action would violate SoD constraints, a structured violation
        record is logged and the method returns False.

        Args:
            user_id: Identifier of the user attempting the action.
            action: The action being attempted.
            scope: The scope in which the action is attempted.

        Returns:
            True if the action is allowed, False if it violates SoD.
        """
        existing = self.get_user_roles(user_id)
        existing_role_names = {r.role for r in existing}
        scoped_roles = {r.role for r in existing if r.scope == scope}

        # Check constraint (a): author + approver for same scope
        if (
            "policy_author" in scoped_roles
            and "policy_approver" in scoped_roles
        ):
            now = datetime.utcnow().isoformat()
            logger.warning(
                json.dumps(
                    {
                        "audit_event": "sod_violation",
                        "user_id": user_id,
                        "attempted_action": action,
                        "violated_constraint": "policy_author + policy_approver for same scope",
                        "scope": scope,
                        "timestamp": now,
                    }
                )
            )
            return False

        # Check constraint (b): operator + auditor
        if "operator" in existing_role_names and "auditor" in existing_role_names:
            now = datetime.utcnow().isoformat()
            logger.warning(
                json.dumps(
                    {
                        "audit_event": "sod_violation",
                        "user_id": user_id,
                        "attempted_action": action,
                        "violated_constraint": "operator + auditor",
                        "scope": scope,
                        "timestamp": now,
                    }
                )
            )
            return False

        return True

    def get_user_roles(self, user_id: str) -> List[GovernanceRoleAssignment]:
        """Retrieve all role assignments for a user.

        Args:
            user_id: Identifier of the user.

        Returns:
            List of GovernanceRoleAssignment objects for the user.
        """
        response = self._table.scan(
            FilterExpression="user_id = :uid",
            ExpressionAttributeValues={":uid": user_id},
        )
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = self._table.scan(
                FilterExpression="user_id = :uid",
                ExpressionAttributeValues={":uid": user_id},
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        return [GovernanceRoleAssignment.from_dict(item) for item in items]
