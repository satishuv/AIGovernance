"""Authorization Lambda - Layer 3 of the governance pipeline.

Performs identity and authorization checks:
- Agent identity verification (suspended check)
- Agent registry validation (registered check)
- Environment isolation enforcement
- Data class access validation
- Tool/model registry check
- Per-tool execution authorization (parameters, rate limits, chains)

Invoked by Step Functions. Returns authorization result.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3

from agent_identity import AgentIdentityManager
from agent_registry import AgentRegistry
from environment_isolation import EnvironmentIsolation
from tool_model_registry import ToolModelRegistry
from tool_execution_auth import ToolExecutionAuthManager

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
AGENT_REGISTRY_TABLE_NAME = os.environ.get("AGENT_REGISTRY_TABLE_NAME", "")
TOOL_MODEL_REGISTRY_TABLE_NAME = os.environ.get("TOOL_MODEL_REGISTRY_TABLE_NAME", "")
TOOL_AUTH_TABLE_NAME = os.environ.get("TOOL_AUTH_TABLE_NAME", "")

# In-Lambda cache (60s TTL)
_CACHE = {}
_CACHE_TTL = 60


def _get_dynamodb_table(table_name):
    """Get DynamoDB table resource, return None if name is empty."""
    if not table_name:
        return None
    return boto3.resource("dynamodb").Table(table_name)


def handler(event, context):
    """Authorization handler.

    Input event:
        agent_id (str): Agent identifier
        action_group (str): Requested action group
        target_resource (str): Target resource
        scope_level (int): Current scope level
        input_text (str): User input (for data class derivation)
        tool_name (str, optional): Specific tool being invoked
        tool_parameters (dict, optional): Tool parameters

    Returns:
        {
            "passed": bool,
            "verdict": "allow" | "deny",
            "error_category": str (if denied),
            "explanation": str (if denied),
            "agent_id": str,
            "agent_environment": str,
            "timestamp": str
        }
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    agent_id = event.get("agent_id", "")
    action_group = event.get("action_group", "")
    target_resource = event.get("target_resource", "")
    scope_level = int(event.get("scope_level", 1))
    input_text = event.get("input_text", "")
    tool_name = event.get("tool_name", "") or action_group
    tool_parameters = event.get("tool_parameters", {})

    result = {
        "passed": True,
        "verdict": "allow",
        "error_category": "",
        "explanation": "",
        "agent_id": agent_id,
        "agent_environment": "",
        "timestamp": timestamp,
    }

    # 1. Agent Identity check
    scope_table = _get_dynamodb_table(SCOPE_TABLE_NAME)
    if scope_table:
        identity_manager = AgentIdentityManager(scope_table)
        if identity_manager.is_suspended(agent_id):
            result["passed"] = False
            result["verdict"] = "deny"
            result["error_category"] = "agent_suspended"
            result["explanation"] = f"Agent '{agent_id}' is suspended."
            return result

    # 2. Agent Registry check
    registry_table = _get_dynamodb_table(AGENT_REGISTRY_TABLE_NAME)
    if registry_table:
        registry = AgentRegistry(registry_table)
        agent_entry = registry.get_agent(agent_id)
        if not agent_entry:
            result["passed"] = False
            result["verdict"] = "deny"
            result["error_category"] = "agent_not_registered"
            result["explanation"] = f"Agent '{agent_id}' is not registered in the governance registry."
            return result
        result["agent_environment"] = getattr(agent_entry, "environment", "") if hasattr(agent_entry, "environment") else agent_entry.get("environment", "") if isinstance(agent_entry, dict) else ""

    # 3. Environment Isolation (skip for generic targets like "default")
    if registry_table and result["agent_environment"] and target_resource not in ("default", "", "any"):
        isolation = EnvironmentIsolation()
        env_allowed = isolation.check_cross_environment(
            result["agent_environment"], target_resource
        )
        if not env_allowed:
            result["passed"] = False
            result["verdict"] = "deny"
            result["error_category"] = "environment_isolation_violation"
            result["explanation"] = (
                f"Agent in environment '{result['agent_environment']}' "
                f"cannot access target '{target_resource}'."
            )
            return result

    # 4. Tool/Model Registry check (skip if entry not found by action_group name)
    tool_model_table = _get_dynamodb_table(TOOL_MODEL_REGISTRY_TABLE_NAME)
    if tool_model_table:
        tool_registry = ToolModelRegistry(tool_model_table)
        entry = tool_registry.get_entry(action_group) if hasattr(tool_registry, 'get_entry') else None
        if entry and not tool_registry.is_approved(action_group):
            result["passed"] = False
            result["verdict"] = "deny"
            result["error_category"] = "unapproved_tool_model"
            result["explanation"] = (
                f"Action group '{action_group}' is not approved for agent '{agent_id}'."
            )
            return result

    # 5. Tool Execution Authorization (per-tool params + rate + chain)
    tool_auth_table = _get_dynamodb_table(TOOL_AUTH_TABLE_NAME)
    if tool_auth_table and tool_name:
        tool_auth = ToolExecutionAuthManager()
        auth_result = tool_auth.authorize_tool(agent_id, tool_name, tool_parameters, tool_auth_table)
        if not auth_result.authorized:
            result["passed"] = False
            result["verdict"] = "deny"
            result["error_category"] = "tool_auth_denied"
            result["explanation"] = f"Tool execution denied: {auth_result.denial_reason}"
            return result

    return result
