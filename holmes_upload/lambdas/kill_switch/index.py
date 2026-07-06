"""
Kill Switch Lambda for the Bedrock Agent Governance Demo.

Emergency shutdown mechanism that immediately revokes all agent permissions:
1. Sets scope_level to 0 in the Scope Table for the specified agent_id
2. Attaches a deny-all inline IAM policy to the Action Group Lambda role
   (retries exactly once on failure)
3. Logs a structured JSON activation event

Environment variables:
    SCOPE_TABLE_NAME: DynamoDB table name for scope
    ACTION_GROUP_LAMBDA_ROLE_NAME: IAM role name for the action group lambda
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
ACTION_GROUP_LAMBDA_ROLE_NAME = os.environ.get("ACTION_GROUP_LAMBDA_ROLE_NAME", "")

DENY_ALL_POLICY_NAME = "DenyAllKillSwitch"
DENY_ALL_POLICY_DOCUMENT = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    ],
})

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Task 7.1 -- Requirement 11.1: Set scope to 0
# ---------------------------------------------------------------------------
def set_scope_to_zero(agent_id):
    """Set scope_level to 0 in the Scope Table for the given agent_id."""
    table = dynamodb.Table(SCOPE_TABLE_NAME)
    table.update_item(
        Key={"agent_id": agent_id},
        UpdateExpression="SET scope_level = :s, updated_at = :t, updated_by = :u",
        ExpressionAttributeValues={
            ":s": 0,
            ":t": datetime.now(timezone.utc).isoformat(),
            ":u": "kill_switch",
        },
    )


# ---------------------------------------------------------------------------
# Task 7.1 -- Requirements 11.2, 11.3: Attach deny-all policy with retry
# ---------------------------------------------------------------------------
def attach_deny_all_policy():
    """Attach a deny-all inline IAM policy to the Action Group Lambda role.

    Retries exactly once on failure (Requirement 11.3).

    Returns:
        True if the policy was attached successfully, False otherwise.
    """
    for attempt in range(2):
        try:
            iam.put_role_policy(
                RoleName=ACTION_GROUP_LAMBDA_ROLE_NAME,
                PolicyName=DENY_ALL_POLICY_NAME,
                PolicyDocument=DENY_ALL_POLICY_DOCUMENT,
            )
            return True
        except Exception as exc:
            if attempt == 0:
                logger.warning(json.dumps({
                    "event": "deny_all_policy_retry",
                    "role_name": ACTION_GROUP_LAMBDA_ROLE_NAME,
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            else:
                logger.error(json.dumps({
                    "event": "deny_all_policy_failed",
                    "role_name": ACTION_GROUP_LAMBDA_ROLE_NAME,
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
    return False


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event, context):
    """Activate the kill switch for the specified agent.

    Input format:
        {
            "agent_id": "demo-agent",
            "invoker_identity": "operator@example.com"
        }

    Returns:
        {
            "status": "success" | "partial_success",
            "agent_id": "...",
            "actions_taken": [...]
        }
    """
    agent_id = event.get("agent_id", "")
    invoker_identity = event.get("invoker_identity", "unknown")
    actions_taken = []

    # Step 1: Set scope to 0 (Requirement 11.1)
    set_scope_to_zero(agent_id)
    actions_taken.append("scope_set_to_0")

    # Step 2: Attach deny-all policy (Requirements 11.2, 11.3)
    policy_attached = attach_deny_all_policy()
    if policy_attached:
        actions_taken.append("deny_all_policy_attached")

    # Determine status (Requirement 11.5)
    status = "success" if policy_attached else "partial_success"

    # Step 3: Log structured activation event (Requirement 11.4)
    log_entry = {
        "event": "kill_switch_activated",
        "invoker_identity": invoker_identity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "actions_taken": actions_taken,
    }
    logger.info(json.dumps(log_entry))

    return {
        "status": status,
        "agent_id": agent_id,
        "actions_taken": actions_taken,
    }
