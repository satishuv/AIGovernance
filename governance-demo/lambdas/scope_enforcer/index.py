"""Scope Enforcer Lambda handler.

Validates every agent request against the current scope level stored in
DynamoDB before forwarding permitted requests to the Agent Lambda.

Environment variables (set by CDK):
    SCOPE_TABLE_NAME       – DynamoDB scope table name
    PENDING_TABLE_NAME     – DynamoDB pending table name
    AGENT_FUNCTION_NAME    – Agent Lambda function name (for invoking)
    AGENT_ROLE_NAME        – Agent Lambda execution role name (for boundary swaps)
    SCOPE_1_BOUNDARY_ARN   – ARN of the Scope 1 permission boundary policy
    SCOPE_2_BOUNDARY_ARN   – ARN of the Scope 2 permission boundary policy
    SCOPE_3_BOUNDARY_ARN   – ARN of the Scope 3 permission boundary policy
    SCOPE_4_BOUNDARY_ARN   – ARN of the Scope 4 permission boundary policy
"""

import json
import os
import uuid
import datetime
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
PENDING_TABLE_NAME = os.environ.get("PENDING_TABLE_NAME", "")
AGENT_FUNCTION_NAME = os.environ.get("AGENT_FUNCTION_NAME", "")
AGENT_ROLE_NAME = os.environ.get("AGENT_ROLE_NAME", "")

BOUNDARY_ARNS = {
    1: os.environ.get("SCOPE_1_BOUNDARY_ARN", ""),
    2: os.environ.get("SCOPE_2_BOUNDARY_ARN", ""),
    3: os.environ.get("SCOPE_3_BOUNDARY_ARN", ""),
    4: os.environ.get("SCOPE_4_BOUNDARY_ARN", ""),
}

# ---------------------------------------------------------------------------
# AWS clients (created once per container)
# ---------------------------------------------------------------------------
dynamodb_client = boto3.client("dynamodb")
lambda_client = boto3.client("lambda")
iam_client = boto3.client("iam")

# Read actions that are permitted at Scope 1+
READ_ACTIONS = {"s3:GetObject"}

# Write actions that require Scope 2+ or routing
WRITE_ACTIONS = {"s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"}


# ---------------------------------------------------------------------------
# Pure helper functions (module-level for independent testing)
# ---------------------------------------------------------------------------

def validate_scope(level: int) -> bool:
    """Return True iff *level* is a valid operational scope (1-4)."""
    return level in {1, 2, 3, 4}


def classify_action(action: str) -> str:
    """Classify *action* as ``"read"`` or ``"write"``.

    Any action not explicitly in READ_ACTIONS is treated as a write.
    """
    if action in READ_ACTIONS:
        return "read"
    return "write"


def route_request(scope_level: int, action_type: str, event: dict) -> dict:
    """Determine the routing decision for a request.

    Returns a dict describing the decision:
    - ``{"decision": "permit"}`` – forward to Agent Lambda
    - ``{"decision": "deny", "error": ...}`` – reject the request
    - ``{"decision": "pending", ...}`` – queue for human approval (Scope 2 writes)
    """
    # Scope 0: kill-switch state – deny everything
    if scope_level == 0:
        return {
            "decision": "deny",
            "error": "agent_disabled",
            "message": "Agent has been disabled via kill switch (scope 0)",
        }

    # Invalid scope – should not happen if validate_scope passed, but
    # defence-in-depth
    if not validate_scope(scope_level):
        return {
            "decision": "deny",
            "error": "invalid_scope",
            "scope_level": scope_level,
            "message": f"Invalid scope level: {scope_level}. Must be 1-4.",
        }

    # Scope 1: reads only
    if scope_level == 1:
        if action_type == "read":
            return {"decision": "permit"}
        return {
            "decision": "deny",
            "error": "insufficient_scope",
            "message": "Write operations are not permitted at scope level 1",
        }

    # Scope 2: reads permitted, writes routed to Pending Table
    if scope_level == 2:
        if action_type == "read":
            return {"decision": "permit"}
        return {"decision": "pending"}

    # Scope 3: reads and writes within resource boundaries
    if scope_level == 3:
        return {"decision": "permit"}

    # Scope 4: all operations permitted
    if scope_level == 4:
        return {"decision": "permit"}

    # Fallback – deny (fail-closed)
    return {
        "decision": "deny",
        "error": "unknown_scope",
        "message": f"Unhandled scope level: {scope_level}",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_scope_level(agent_id: str) -> int:
    """Read the agent's current scope level from the Scope Table.

    Raises ``ClientError`` if the table is unreachable.
    Returns the integer scope level, or -1 if the agent has no record.
    """
    response = dynamodb_client.get_item(
        TableName=SCOPE_TABLE_NAME,
        Key={"agent_id": {"S": agent_id}},
    )
    item = response.get("Item")
    if not item or "scope_level" not in item:
        return -1
    return int(item["scope_level"]["N"])


def _write_pending_record(event: dict) -> dict:
    """Write a pending-approval record to the Pending Table.

    Returns the record that was written.
    """
    record = {
        "request_id": str(uuid.uuid4()),
        "agent_id": event.get("agent_id", ""),
        "proposed_action": event.get("action", ""),
        "target_resource": event.get("target_resource", ""),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "status": "pending",
    }

    dynamodb_client.put_item(
        TableName=PENDING_TABLE_NAME,
        Item={
            "request_id": {"S": record["request_id"]},
            "agent_id": {"S": record["agent_id"]},
            "proposed_action": {"S": record["proposed_action"]},
            "target_resource": {"S": record["target_resource"]},
            "timestamp": {"S": record["timestamp"]},
            "status": {"S": record["status"]},
        },
    )
    return record


def _invoke_agent(event: dict, scope_level: int) -> dict:
    """Invoke the Agent Lambda synchronously and return its response."""
    agent_payload = {
        "action": event.get("action", ""),
        "target_resource": event.get("target_resource", ""),
        "payload": event.get("payload", {}),
        "scope_level": scope_level,
    }

    response = lambda_client.invoke(
        FunctionName=AGENT_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(agent_payload).encode("utf-8"),
    )

    result = json.loads(response["Payload"].read().decode("utf-8"))
    return result


def _update_permission_boundary(new_scope: int) -> None:
    """Swap the permission boundary on the Agent Lambda's role.

    Uses ``iam:PutRolePolicy`` to attach the boundary matching *new_scope*.
    """
    boundary_arn = BOUNDARY_ARNS.get(new_scope, "")
    if not boundary_arn:
        raise ValueError(f"No boundary ARN configured for scope {new_scope}")

    iam_client.put_role_permissions_boundary(
        RoleName=AGENT_ROLE_NAME,
        PermissionsBoundary=boundary_arn,
    )
    logger.info(
        "Updated permission boundary for role %s to scope %d (%s)",
        AGENT_ROLE_NAME,
        new_scope,
        boundary_arn,
    )


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    """Lambda entry point.

    Expected *event* shape::

        {
            "agent_id": "demo-agent",
            "action": "s3:GetObject",
            "target_resource": "builds/build-47.json",
            "payload": { ... },
            "new_scope": 3          # optional – triggers boundary swap
        }

    Returns::

        { "status": "success", "result": { ... } }
        { "status": "pending", "record": { ... } }
        { "error": "<category>", "message": "<detail>" }
    """
    agent_id = event.get("agent_id", "")
    action = event.get("action", "")
    new_scope = event.get("new_scope")

    # --- Step 0: Handle optional scope change request ---
    if new_scope is not None:
        new_scope = int(new_scope)
        if not validate_scope(new_scope):
            return {
                "error": "invalid_scope",
                "message": f"Invalid scope level: {new_scope}. Must be 1-4.",
            }
        try:
            _update_permission_boundary(new_scope)
        except Exception as exc:
            logger.error("Failed to update permission boundary: %s", exc)
            return {
                "error": "boundary_update_failure",
                "message": str(exc),
            }

    # --- Step 1: Read scope level from Scope Table ---
    try:
        scope_level = _get_scope_level(agent_id)
    except ClientError as exc:
        logger.error(
            "Scope table unreachable for agent_id=%s: %s", agent_id, exc
        )
        return {
            "error": "scope_lookup_failure",
            "message": f"Unable to read scope for agent '{agent_id}': {exc}",
        }

    # --- Step 2: Validate scope level ---
    if scope_level == 0:
        # Kill-switch state – deny immediately
        pass  # handled by route_request below
    elif not validate_scope(scope_level):
        return {
            "error": "invalid_scope",
            "scope_level": scope_level,
            "message": f"Invalid scope level: {scope_level}. Must be 1-4.",
        }

    # --- Step 3: Classify action and route ---
    action_type = classify_action(action)
    decision = route_request(scope_level, action_type, event)

    if decision["decision"] == "deny":
        return {"error": decision.get("error", "denied"), "message": decision.get("message", "")}

    if decision["decision"] == "pending":
        record = _write_pending_record(event)
        return {
            "status": "pending",
            "message": "Write operation queued for human approval",
            "record": record,
        }

    # decision == "permit" – invoke Agent Lambda
    try:
        result = _invoke_agent(event, scope_level)
        return {"status": "success", "result": result}
    except Exception as exc:
        logger.error("Agent invocation failed: %s", exc)
        return {
            "error": "agent_invocation_failure",
            "message": str(exc),
        }
