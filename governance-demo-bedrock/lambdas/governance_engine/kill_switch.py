"""Kill Switch — Emergency Shutdown module.

Provides emergency shutdown capability that immediately revokes all agent
permissions by setting scope levels to 0. Supports activation, deactivation
(with operator role check), and active-state queries. All mutations produce
structured audit log entries.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

KILL_SWITCH_CONFIG_KEY = "__kill_switch__"


class KillSwitchManager:
    """Manages emergency kill switch activation and deactivation.

    The kill switch sets all active agent scope levels to 0 and sets a
    persistent flag in the ScopeTable. While active, all agent action
    requests are denied regardless of policy or risk score.
    """

    def activate(
        self,
        operator_id: str,
        scope_table,
        agent_registry_table,
    ) -> Dict[str, Any]:
        """Activate the kill switch — set all active agents to scope 0.

        Args:
            operator_id: Identity of the operator activating the switch.
            scope_table: boto3 DynamoDB Table resource for the ScopeTable.
            agent_registry_table: boto3 DynamoDB Table resource for the
                AgentRegistryTable (used to enumerate active agents).

        Returns:
            Dict with activation details including affected agent IDs.
        """
        now = datetime.utcnow().isoformat()
        affected_agent_ids: List[str] = []

        # Scan agent registry for all agents
        response = agent_registry_table.scan()
        items = response.get("Items", [])
        while "LastEvaluatedKey" in response:
            response = agent_registry_table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        # Set scope_level=0 for each agent in the ScopeTable
        for item in items:
            agent_id = item.get("agent_id", "")
            if not agent_id:
                continue
            try:
                scope_table.update_item(
                    Key={"agent_id": agent_id},
                    UpdateExpression="SET scope_level = :zero",
                    ExpressionAttributeValues={":zero": 0},
                )
                affected_agent_ids.append(agent_id)
            except Exception:
                logger.error(
                    json.dumps(
                        {
                            "audit_event": "kill_switch_agent_update_failed",
                            "agent_id": agent_id,
                            "operator_id": operator_id,
                            "timestamp": now,
                        }
                    )
                )

        # Set kill_switch_active flag
        scope_table.put_item(
            Item={
                "agent_id": KILL_SWITCH_CONFIG_KEY,
                "kill_switch_active": True,
                "activated_by": operator_id,
                "activated_at": now,
            }
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "kill_switch_activated",
                    "operator_id": operator_id,
                    "timestamp": now,
                    "affected_agent_ids": affected_agent_ids,
                }
            )
        )

        return {
            "status": "activated",
            "operator_id": operator_id,
            "timestamp": now,
            "affected_agent_ids": affected_agent_ids,
        }

    def deactivate(
        self,
        operator_id: str,
        operator_roles: List[str],
        scope_table,
    ) -> Dict[str, Any]:
        """Deactivate the kill switch.

        Requires the operator to have the "operator" Governance_Role.
        Does NOT restore scope levels — restoration requires separate
        human authorization per agent.

        Args:
            operator_id: Identity of the operator deactivating the switch.
            operator_roles: List of governance roles held by the operator.
            scope_table: boto3 DynamoDB Table resource for the ScopeTable.

        Returns:
            Dict with deactivation details.

        Raises:
            ValueError: If the operator does not have the "operator" role.
        """
        if "operator" not in operator_roles:
            raise ValueError(
                f"User '{operator_id}' does not have the 'operator' role "
                "required to deactivate the kill switch."
            )

        now = datetime.utcnow().isoformat()

        # Clear kill_switch_active flag
        scope_table.put_item(
            Item={
                "agent_id": KILL_SWITCH_CONFIG_KEY,
                "kill_switch_active": False,
                "deactivated_by": operator_id,
                "deactivated_at": now,
            }
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "kill_switch_deactivated",
                    "operator_id": operator_id,
                    "timestamp": now,
                }
            )
        )

        return {
            "status": "deactivated",
            "operator_id": operator_id,
            "timestamp": now,
        }

    def is_active(self, scope_table) -> bool:
        """Check whether the kill switch is currently active.

        Args:
            scope_table: boto3 DynamoDB Table resource for the ScopeTable.

        Returns:
            True if the kill switch is active, False otherwise.
        """
        response = scope_table.get_item(
            Key={"agent_id": KILL_SWITCH_CONFIG_KEY}
        )
        item = response.get("Item")
        if item is None:
            return False
        return bool(item.get("kill_switch_active", False))

    def check_kill_switch(self, scope_table) -> Dict[str, Any]:
        """Return a deny decision dict if the kill switch is active.

        Args:
            scope_table: boto3 DynamoDB Table resource for the ScopeTable.

        Returns:
            A deny decision dict if active, or an empty dict if inactive.
        """
        if self.is_active(scope_table):
            now = datetime.utcnow().isoformat()
            logger.warning(
                json.dumps(
                    {
                        "audit_event": "kill_switch_deny",
                        "reason": "kill_switch_active",
                        "timestamp": now,
                    }
                )
            )
            return {
                "verdict": "deny",
                "explanation": "Kill switch is active — all agent actions are denied.",
                "timestamp": now,
            }
        return {}


# ---------------------------------------------------------------------------
# Lambda handler for the Phase 1c KillSwitchLambda
# ---------------------------------------------------------------------------

def handler(event, context):
    """Lambda entry point for kill switch activate/deactivate via API Gateway.

    Expects event with:
        - action: "activate" or "deactivate"
        - operator_id: identity of the operator
        - operator_roles: list of governance roles (required for deactivate)

    For API Gateway proxy integration, the body is JSON-encoded in event["body"].
    """
    import os
    import boto3

    # Parse body from API Gateway proxy or direct invocation
    body = event
    if "body" in event and isinstance(event["body"], str):
        body = json.loads(event["body"])
    elif "body" in event and isinstance(event["body"], dict):
        body = event["body"]

    action = body.get("action", "activate")
    operator_id = body.get("operator_id", "unknown")
    operator_roles = body.get("operator_roles", [])

    dynamodb = boto3.resource("dynamodb")
    scope_table = dynamodb.Table(os.environ.get("SCOPE_TABLE_NAME", ""))
    agent_registry_table = dynamodb.Table(
        os.environ.get("AGENT_REGISTRY_TABLE_NAME", "")
    )

    manager = KillSwitchManager()

    try:
        if action == "activate":
            result = manager.activate(operator_id, scope_table, agent_registry_table)
        elif action == "deactivate":
            result = manager.deactivate(operator_id, operator_roles, scope_table)
        else:
            result = {"error": f"Unknown action: {action}"}

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }
    except ValueError as ve:
        return {
            "statusCode": 403,
            "body": json.dumps({"error": str(ve)}),
        }
    except Exception as exc:
        logger.error(json.dumps({
            "event": "kill_switch_handler_error",
            "error": str(exc),
            "action": action,
        }))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(exc)}),
        }
