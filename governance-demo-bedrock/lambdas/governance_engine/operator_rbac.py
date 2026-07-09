"""Enterprise IAM - Role-Based Access Control for Governance Operators.

Controls WHO can perform governance operations:
- Modify policies
- Trigger kill switch
- Approve escalations
- Change agent scope
- View evidence
- Run shadow AI scans
- Deploy policy changes

Roles:
- governance_admin: Full access to all governance operations
- policy_author: Create/modify policies, cannot deploy
- policy_reviewer: Approve/reject policy changes
- operator: Trigger kill switch, change scope, view dashboards
- auditor: Read-only access to evidence, decisions, and reports
- security_analyst: Run scans, view threats, cannot modify policies

This is OPERATOR identity (humans managing the governance system),
not AGENT identity (AI agents being governed).

Addresses LLM Council feedback:
- "RBAC for governance controls"
- "Who can modify policies, view evidence, trigger kill switches"
- "Federated identity for governance operations"
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


ROLES = {
    "governance_admin": {
        "description": "Full access to all governance operations",
        "permissions": [
            "policy:create", "policy:modify", "policy:deploy", "policy:rollback",
            "policy:approve", "policy:reject",
            "agent:register", "agent:suspend", "agent:modify_scope",
            "kill_switch:activate", "kill_switch:deactivate",
            "approval:approve", "approval:deny",
            "evidence:read", "evidence:export",
            "scan:shadow_ai", "scan:supply_chain",
            "dashboard:view", "report:generate",
            "config:modify", "config:view",
        ],
    },
    "policy_author": {
        "description": "Create and modify policies, cannot deploy or approve own changes",
        "permissions": [
            "policy:create", "policy:modify",
            "evidence:read",
            "dashboard:view",
            "config:view",
        ],
    },
    "policy_reviewer": {
        "description": "Approve or reject policy changes, cannot author",
        "permissions": [
            "policy:approve", "policy:reject",
            "policy:deploy", "policy:rollback",
            "evidence:read",
            "dashboard:view",
            "config:view",
        ],
    },
    "operator": {
        "description": "Day-to-day governance operations",
        "permissions": [
            "kill_switch:activate", "kill_switch:deactivate",
            "agent:modify_scope",
            "approval:approve", "approval:deny",
            "evidence:read",
            "dashboard:view", "report:generate",
            "config:view",
        ],
    },
    "auditor": {
        "description": "Read-only access for compliance review",
        "permissions": [
            "evidence:read", "evidence:export",
            "dashboard:view", "report:generate",
            "config:view",
        ],
    },
    "security_analyst": {
        "description": "Security scanning and threat analysis",
        "permissions": [
            "scan:shadow_ai", "scan:supply_chain",
            "evidence:read",
            "dashboard:view", "report:generate",
            "config:view",
        ],
    },
}


@dataclass
class OperatorIdentity:
    """An authenticated governance operator."""
    user_id: str
    roles: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    authenticated_at: str = ""
    session_expiry: str = ""
    federation_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "roles": self.roles,
            "permissions": sorted(self.permissions),
            "authenticated_at": self.authenticated_at,
            "federation_source": self.federation_source,
        }


@dataclass
class AccessDecision:
    """Result of an access control check."""
    allowed: bool
    user_id: str
    operation: str
    required_permission: str
    user_permissions: List[str] = field(default_factory=list)
    denial_reason: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "user_id": self.user_id,
            "operation": self.operation,
            "required_permission": self.required_permission,
            "denial_reason": self.denial_reason,
            "timestamp": self.timestamp,
        }


OPERATION_PERMISSION_MAP = {
    "create_policy": "policy:create",
    "modify_policy": "policy:modify",
    "deploy_policy": "policy:deploy",
    "rollback_policy": "policy:rollback",
    "approve_policy": "policy:approve",
    "reject_policy": "policy:reject",
    "register_agent": "agent:register",
    "suspend_agent": "agent:suspend",
    "modify_agent_scope": "agent:modify_scope",
    "activate_kill_switch": "kill_switch:activate",
    "deactivate_kill_switch": "kill_switch:deactivate",
    "approve_escalation": "approval:approve",
    "deny_escalation": "approval:deny",
    "view_evidence": "evidence:read",
    "export_evidence": "evidence:export",
    "run_shadow_scan": "scan:shadow_ai",
    "run_supply_chain_scan": "scan:supply_chain",
    "view_dashboard": "dashboard:view",
    "generate_report": "report:generate",
    "modify_config": "config:modify",
    "view_config": "config:view",
}


class OperatorRBAC:
    """Role-Based Access Control for governance platform operators."""

    def __init__(self):
        self._operators: Dict[str, OperatorIdentity] = {}

    def register_operator(self, user_id: str, roles: List[str], federation_source: str = "local") -> OperatorIdentity:
        """Register a governance operator with assigned roles."""
        permissions: Set[str] = set()
        for role in roles:
            if role in ROLES:
                permissions.update(ROLES[role]["permissions"])

        operator = OperatorIdentity(
            user_id=user_id,
            roles=roles,
            permissions=permissions,
            authenticated_at=datetime.now(timezone.utc).isoformat(),
            federation_source=federation_source,
        )
        self._operators[user_id] = operator

        logger.info(json.dumps({
            "event": "operator_registered",
            "user_id": user_id,
            "roles": roles,
            "permission_count": len(permissions),
            "federation_source": federation_source,
        }))
        return operator

    def check_access(self, user_id: str, operation: str) -> AccessDecision:
        """Check if an operator has permission to perform an operation."""
        now = datetime.now(timezone.utc).isoformat()

        operator = self._operators.get(user_id)
        if operator is None:
            decision = AccessDecision(
                allowed=False,
                user_id=user_id,
                operation=operation,
                required_permission=OPERATION_PERMISSION_MAP.get(operation, operation),
                denial_reason="Operator not registered in governance RBAC",
                timestamp=now,
            )
            logger.warning(json.dumps({
                "event": "operator_access_denied",
                "user_id": user_id,
                "operation": operation,
                "reason": "not_registered",
            }))
            return decision

        required_permission = OPERATION_PERMISSION_MAP.get(operation, operation)
        allowed = required_permission in operator.permissions

        decision = AccessDecision(
            allowed=allowed,
            user_id=user_id,
            operation=operation,
            required_permission=required_permission,
            user_permissions=sorted(operator.permissions),
            denial_reason="" if allowed else f"Missing permission: {required_permission}. User roles: {operator.roles}",
            timestamp=now,
        )

        if not allowed:
            logger.warning(json.dumps({
                "event": "operator_access_denied",
                "user_id": user_id,
                "operation": operation,
                "required": required_permission,
                "roles": operator.roles,
            }))

        return decision

    def enforce(self, user_id: str, operation: str) -> None:
        """Enforce access - raises ValueError if denied."""
        decision = self.check_access(user_id, operation)
        if not decision.allowed:
            raise ValueError(
                f"Access denied: {user_id} cannot perform '{operation}'. {decision.denial_reason}"
            )

    def load_from_table(self, table) -> None:
        """Load operators from GovernanceRolesTable."""
        try:
            response = table.scan()
            for item in response.get("Items", []):
                user_id = item["user_id"]
                role = item["role"]
                if user_id not in self._operators:
                    self.register_operator(user_id, [role])
                else:
                    if role not in self._operators[user_id].roles:
                        self._operators[user_id].roles.append(role)
                        if role in ROLES:
                            self._operators[user_id].permissions.update(ROLES[role]["permissions"])
        except Exception as e:
            logger.error(json.dumps({
                "event": "operator_rbac_load_failed",
                "error": str(e),
            }))

    def get_all_operators(self) -> List[Dict[str, Any]]:
        """List all registered operators and their roles."""
        return [op.to_dict() for op in self._operators.values()]

    def get_role_definitions(self) -> Dict[str, Any]:
        """Return all role definitions with permissions."""
        return ROLES
