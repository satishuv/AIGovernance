"""
Scope Enforcer Lambda for the Bedrock Agent Governance Demo.

Entry point for all user requests. Enforces scope-based governance
before invoking the Bedrock Agent:
1. Optionally updates scope if new_scope is provided (Task 6.4)
2. Reads current scope from Scope Table (Task 6.1)
3. If scope is 0, denies request (kill switch active) (Task 6.1)
4. Swaps IAM permission boundary on Action Group Lambda role (Task 6.2)
5. Calls bedrock-agent-runtime:InvokeAgent with session attributes (Task 6.3)
6. Collects streamed response and returns it (Task 6.3)

Environment variables:
    AGENT_ID: Bedrock Agent ID
    AGENT_ALIAS_ID: Bedrock Agent Alias ID
    SCOPE_TABLE_NAME: DynamoDB table name for scope
    ACTION_GROUP_LAMBDA_ROLE_NAME: IAM role name for the action group lambda
    SCOPE_BOUNDARY_ARNS: JSON-encoded dict mapping scope levels to permission boundary ARNs
"""

import json
import logging
import os
import uuid
from datetime import datetime

import boto3

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AGENT_ID = os.environ.get("AGENT_ID", "")
AGENT_ALIAS_ID = os.environ.get("AGENT_ALIAS_ID", "")
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
ACTION_GROUP_LAMBDA_ROLE_NAME = os.environ.get("ACTION_GROUP_LAMBDA_ROLE_NAME", "")
SCOPE_BOUNDARY_ARNS = json.loads(os.environ.get("SCOPE_BOUNDARY_ARNS", "{}"))

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
bedrock_agent_runtime = boto3.client("bedrock-agent-runtime")

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Scope-to-action-group mapping (Task 6.1 -- Requirements 8.1-8.5)
# ---------------------------------------------------------------------------
SCOPE_ACTION_GROUPS = {
    1: ["ReadPipelineStatus"],
    2: ["ReadPipelineStatus", "ProposeChanges"],
    3: ["ReadPipelineStatus", "ProposeChanges", "StagingDeployment"],
    4: ["ReadPipelineStatus", "ProposeChanges", "StagingDeployment", "ProductionDeployment"],
}


# ---------------------------------------------------------------------------
# Task 6.4 -- Requirement 8.6: Optional scope update from input event
# ---------------------------------------------------------------------------
def update_scope_level(agent_id, new_scope):
    """Update the scope level in the Scope Table for the given agent."""
    table = dynamodb.Table(SCOPE_TABLE_NAME)
    table.update_item(
        Key={"agent_id": agent_id},
        UpdateExpression="SET scope_level = :s, updated_at = :t, updated_by = :u",
        ExpressionAttributeValues={
            ":s": new_scope,
            ":t": datetime.utcnow().isoformat(),
            ":u": "scope_enforcer",
        },
    )
    logger.info(json.dumps({
        "event": "scope_updated",
        "agent_id": agent_id,
        "new_scope": new_scope,
        "timestamp": datetime.utcnow().isoformat(),
    }))


# ---------------------------------------------------------------------------
# Task 6.1 -- Requirements 8.1, 8.7: Read scope and filter action groups
# ---------------------------------------------------------------------------
def get_scope_level(agent_id):
    """Read the current scope level from the Scope Table."""
    table = dynamodb.Table(SCOPE_TABLE_NAME)
    response = table.get_item(Key={"agent_id": agent_id})
    item = response.get("Item")
    if not item:
        return 0
    return int(item.get("scope_level", 0))


def get_permitted_action_groups(scope_level):
    """Return the list of permitted action group names for the given scope level."""
    return SCOPE_ACTION_GROUPS.get(scope_level, [])


# ---------------------------------------------------------------------------
# Task 6.2 -- Requirement 10.6: Permission boundary swapping
# ---------------------------------------------------------------------------
def swap_permission_boundary(scope_level):
    """Swap the IAM permission boundary on the Action Group Lambda role.

    Maps scope levels 1-4 to the corresponding Permission Boundary ARN
    from the SCOPE_BOUNDARY_ARNS environment variable.
    """
    boundary_arn = SCOPE_BOUNDARY_ARNS.get(str(scope_level))
    if not boundary_arn:
        raise ValueError(f"No permission boundary ARN configured for scope level {scope_level}")

    iam.put_role_permissions_boundary(
        RoleName=ACTION_GROUP_LAMBDA_ROLE_NAME,
        PermissionsBoundary=boundary_arn,
    )
    logger.info(json.dumps({
        "event": "permission_boundary_swapped",
        "role_name": ACTION_GROUP_LAMBDA_ROLE_NAME,
        "scope_level": scope_level,
        "boundary_arn": boundary_arn,
        "timestamp": datetime.utcnow().isoformat(),
    }))


# ---------------------------------------------------------------------------
# Task 6.3 -- Requirements 9.1-9.5: Bedrock Agent invocation
# ---------------------------------------------------------------------------
def invoke_bedrock_agent(input_text, session_attributes):
    """Invoke the Bedrock Agent via the InvokeAgent API and collect the streamed response.

    Args:
        input_text: The user's natural language request.
        session_attributes: Dict with scope_level and permitted_action_groups.

    Returns:
        The concatenated text response from the agent.

    Raises:
        Exception with category "agent_invocation_failure" on failure.
    """
    session_id = str(uuid.uuid4())

    try:
        response = bedrock_agent_runtime.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=input_text,
            sessionState={
                "sessionAttributes": session_attributes,
            },
        )

        # Collect streamed response chunks
        completion_text = ""
        for event in response.get("completion", []):
            chunk = event.get("chunk", {})
            if "bytes" in chunk:
                completion_text += chunk["bytes"].decode("utf-8")

        return completion_text

    except Exception as exc:
        raise Exception(
            json.dumps({
                "category": "agent_invocation_failure",
                "reason": str(exc),
            })
        )


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event, context):
    """Orchestrate scope enforcement and Bedrock Agent invocation.

    Input format:
        {
            "agent_id": "demo-agent",
            "input_text": "Show me the build status for build-47",
            "new_scope": 2  // optional
        }
    """
    agent_id = event.get("agent_id", AGENT_ID)
    input_text = event.get("input_text", "")
    new_scope = event.get("new_scope")

    try:
        # Step 1: Optionally update scope (Task 6.4 -- Requirement 8.6)
        if new_scope is not None:
            update_scope_level(agent_id, int(new_scope))

        # Step 2: Read current scope level (Task 6.1)
        scope_level = get_scope_level(agent_id)

        # Step 3: Deny if kill switch is active (Task 6.1 -- Requirement 8.7)
        if scope_level == 0:
            return {
                "status": "denied",
                "error": "agent_disabled",
                "message": "Kill switch is active. All requests are denied.",
            }

        # Step 4: Swap permission boundary (Task 6.2 -- Requirement 10.6)
        swap_permission_boundary(scope_level)

        # Step 5: Build session attributes (Task 6.1 -- Requirement 8.6)
        permitted_groups = get_permitted_action_groups(scope_level)
        session_attributes = {
            "scope_level": str(scope_level),
            "permitted_action_groups": ",".join(permitted_groups),
        }

        # Step 6: Invoke Bedrock Agent (Task 6.3 -- Requirements 9.1-9.4)
        response_text = invoke_bedrock_agent(input_text, session_attributes)

        return {
            "status": "success",
            "scope_level": scope_level,
            "permitted_action_groups": permitted_groups,
            "response": response_text,
        }

    except Exception as exc:
        error_str = str(exc)
        # Try to parse structured error from invoke_bedrock_agent
        try:
            error_data = json.loads(error_str)
            return {
                "status": "error",
                "category": error_data.get("category", "unknown_error"),
                "reason": error_data.get("reason", error_str),
            }
        except (json.JSONDecodeError, TypeError):
            return {
                "status": "error",
                "category": "scope_enforcer_error",
                "reason": error_str,
            }
