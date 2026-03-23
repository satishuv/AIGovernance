"""Kill Switch Lambda handler.

Immediately revokes all agent permissions by setting scope to 0 in the
Scope Table and attaching a deny-all IAM inline policy to the Agent
Lambda's execution role.

Environment variables (set by CDK):
    SCOPE_TABLE_NAME  – DynamoDB scope table name
    AGENT_ROLE_NAME   – Agent Lambda execution role name
"""

import json
import os
import datetime
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
AGENT_ROLE_NAME = os.environ.get("AGENT_ROLE_NAME", "")

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
    }],
})

DENY_ALL_POLICY_NAME = "kill-switch-deny-all"

# ---------------------------------------------------------------------------
# AWS clients (created once per container)
# ---------------------------------------------------------------------------
dynamodb_client = boto3.client("dynamodb")
iam_client = boto3.client("iam")


def _set_scope_to_zero(agent_id: str) -> None:
    """Set the agent's scope_level to 0 (denied) in the Scope Table."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    dynamodb_client.update_item(
        TableName=SCOPE_TABLE_NAME,
        Key={"agent_id": {"S": agent_id}},
        UpdateExpression="SET scope_level = :zero, updated_at = :ts, updated_by = :by",
        ExpressionAttributeValues={
            ":zero": {"N": "0"},
            ":ts": {"S": now},
            ":by": {"S": "kill-switch"},
        },
    )


def _attach_deny_all_policy() -> None:
    """Attach a deny-all inline policy to the Agent Lambda's execution role.

    Retries exactly once on failure as required by Req 8.6.
    Returns True if the policy was attached, False if both attempts failed.
    """
    try:
        iam_client.put_role_policy(
            RoleName=AGENT_ROLE_NAME,
            PolicyName=DENY_ALL_POLICY_NAME,
            PolicyDocument=DENY_ALL_POLICY,
        )
        logger.info("Deny-all policy attached to role %s", AGENT_ROLE_NAME)
        return True
    except Exception as exc:
        logger.error(
            "First attempt to attach deny-all policy failed: %s", exc
        )

        # Retry exactly once
        try:
            iam_client.put_role_policy(
                RoleName=AGENT_ROLE_NAME,
                PolicyName=DENY_ALL_POLICY_NAME,
                PolicyDocument=DENY_ALL_POLICY,
            )
            logger.info(
                "Deny-all policy attached to role %s on retry", AGENT_ROLE_NAME
            )
            return True
        except Exception as retry_exc:
            logger.error(
                "Retry to attach deny-all policy also failed: %s", retry_exc
            )
            return False


def handler(event, context):
    """Lambda entry point.

    Expected *event* shape::

        {
            "agent_id": "demo-agent",
            "invoker_identity": "operator@example.com"  # optional
        }

    Returns::

        {
            "status": "success" | "partial_success",
            "actions_taken": ["scope_set_to_0", "deny_all_policy_attached"]
        }
    """
    agent_id = event.get("agent_id", "demo-agent")
    invoker_identity = event.get("invoker_identity", "unknown")
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    actions_taken = []

    # --- Step 1: Set scope level to 0 in Scope Table ---
    try:
        _set_scope_to_zero(agent_id)
        actions_taken.append("scope_set_to_0")
        logger.info("Scope level set to 0 for agent %s", agent_id)
    except Exception as exc:
        logger.error(
            "Failed to set scope to 0 for agent %s: %s", agent_id, exc
        )
        # Log activation event even on failure
        logger.info(
            json.dumps({
                "event": "kill_switch_activated",
                "invoker_identity": invoker_identity,
                "timestamp": timestamp,
                "agent_id": agent_id,
                "outcome": "scope_update_failed",
            })
        )
        return {
            "status": "error",
            "actions_taken": actions_taken,
            "error": f"Failed to set scope to 0: {exc}",
        }

    # --- Step 2: Attach deny-all IAM policy (with retry) ---
    policy_attached = _attach_deny_all_policy()
    if policy_attached:
        actions_taken.append("deny_all_policy_attached")

    # --- Step 3: Log activation event ---
    logger.info(
        json.dumps({
            "event": "kill_switch_activated",
            "invoker_identity": invoker_identity,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "actions_taken": actions_taken,
        })
    )

    status = "success" if policy_attached else "partial_success"
    return {
        "status": status,
        "actions_taken": actions_taken,
    }
