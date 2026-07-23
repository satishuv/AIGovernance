"""
Scope Enforcer Lambda for the Bedrock Agent Governance Demo.

Entry point for all user requests. Enforces scope-based governance
before invoking the Bedrock Agent:
1. Optionally updates scope if new_scope is provided (Task 6.4)
2. Reads current scope from Scope Table (Task 6.1)
3. If scope is 0, denies request (kill switch active) (Task 6.1)
4. Invokes Governance Engine Lambda for policy/risk evaluation (Task 11.1)
5. If denied: return denied response with explanation
6. If escalated: create pending approval record and return escalated response
7. If allowed: swap IAM permission boundary on Action Group Lambda role (Task 6.2)
8. Calls bedrock-agent-runtime:InvokeAgent with session attributes (Task 6.3)
9. Collects streamed response and returns it (Task 6.3)

Environment variables:
    AGENT_ID: Bedrock Agent ID
    AGENT_ALIAS_ID: Bedrock Agent Alias ID
    SCOPE_TABLE_NAME: DynamoDB table name for scope
    ACTION_GROUP_LAMBDA_ROLE_NAME: IAM role name for the action group lambda
    SCOPE_BOUNDARY_ARNS: JSON-encoded dict mapping scope levels to permission boundary ARNs
    GOVERNANCE_ENGINE_LAMBDA_ARN: ARN of the Governance Engine Lambda
    PENDING_TABLE_NAME: DynamoDB table for pending approval records
"""

import json
import logging
import os
import re as _re
import uuid
from datetime import datetime, timezone

import boto3

# ---------------------------------------------------------------------------
# Output Guardrails (lightweight, inline for scope enforcer)
# ---------------------------------------------------------------------------
_SENSITIVE_PATTERNS = [
    _re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+"),  # AWS ARNs
    _re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access keys
    _re.compile(r"\b\d{12}\b"),  # Account IDs
    _re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),  # JWT tokens
    _re.compile(r"(?:BEGIN|END) (?:RSA |EC )?PRIVATE KEY"),  # Private keys
]

_INTERNAL_PATTERNS = [
    _re.compile(r"GovernanceBedrockStack-[A-Za-z0-9]+-[A-Za-z0-9]+"),  # Lambda/resource names
    _re.compile(r"s3://[a-z0-9.-]+governance[a-z0-9.-]*"),  # Internal S3 buckets
    _re.compile(r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}"),  # Internal IPs
]


def _validate_agent_output(response_text, canary_tokens=None):
    """Validate agent output for sensitive data leakage.

    Returns (safe, redacted_text, violations).
    """
    violations = []
    redacted = response_text

    for pattern in _SENSITIVE_PATTERNS:
        if pattern.search(response_text):
            violations.append(f"Sensitive data pattern: {pattern.pattern[:40]}")
            redacted = pattern.sub("[REDACTED]", redacted)

    for pattern in _INTERNAL_PATTERNS:
        if pattern.search(response_text):
            violations.append(f"Internal path exposure: {pattern.pattern[:40]}")
            redacted = pattern.sub("[REDACTED]", redacted)

    if canary_tokens:
        for token in canary_tokens:
            if token in response_text:
                violations.append(f"CRITICAL: Canary token leaked: {token}")
                redacted = redacted.replace(token, "[CANARY-REDACTED]")

    safe = len(violations) == 0
    return safe, redacted, violations


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AGENT_ID = os.environ.get("AGENT_ID", "")
AGENT_ALIAS_ID = os.environ.get("AGENT_ALIAS_ID", "")
SCOPE_TABLE_NAME = os.environ.get("SCOPE_TABLE_NAME", "")
ACTION_GROUP_LAMBDA_ROLE_NAME = os.environ.get("ACTION_GROUP_LAMBDA_ROLE_NAME", "")
SCOPE_BOUNDARY_ARNS = json.loads(os.environ.get("SCOPE_BOUNDARY_ARNS", "{}"))
GOVERNANCE_ENGINE_LAMBDA_ARN = os.environ.get("GOVERNANCE_ENGINE_LAMBDA_ARN", "")
PENDING_TABLE_NAME = os.environ.get("PENDING_TABLE_NAME", "")
GOVERNANCE_MODE = os.environ.get("GOVERNANCE_MODE", "lambda")
GOVERNANCE_PIPELINE_ARN = os.environ.get("GOVERNANCE_PIPELINE_ARN", "")

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
bedrock_agent_runtime = boto3.client("bedrock-agent-runtime")
lambda_client = boto3.client("lambda")
sfn_client = boto3.client("stepfunctions")

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
            ":t": datetime.now(timezone.utc).isoformat(),
            ":u": "scope_enforcer",
        },
    )
    logger.info(json.dumps({
        "event": "scope_updated",
        "agent_id": agent_id,
        "new_scope": new_scope,
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))


# ---------------------------------------------------------------------------
# Concurrency safety for the boundary swap.
#
# The permission boundary is mutable state on a single shared execution role.
# Without serialization, two concurrent requests at different scope levels can
# interleave (a scope-4 swap can be in effect while a scope-2 request executes),
# defeating the infrastructure-enforcement guarantee. We serialize the
# swap -> invoke -> release critical section with a DynamoDB conditional-write
# lease on the scope table, and we verify the boundary immediately before
# invoking so a lost race fails closed rather than executing under the wrong
# scope. LEASE_TTL_SECONDS bounds a crashed holder so the lease self-heals.
# ---------------------------------------------------------------------------
BOUNDARY_LEASE_KEY = "__boundary_lease__"
LEASE_TTL_SECONDS = 30
LEASE_MAX_WAIT_SECONDS = 25
LEASE_POLL_SECONDS = 0.25


def acquire_boundary_lease(scope_level, holder_id):
    """Acquire the boundary lease, waiting up to LEASE_MAX_WAIT_SECONDS.

    Uses a DynamoDB conditional put that succeeds only if no live lease exists
    (either no item, or an expired one). Returns True on acquisition.
    """
    import time as _time
    table = dynamodb.Table(SCOPE_TABLE_NAME)
    deadline = _time.time() + LEASE_MAX_WAIT_SECONDS
    while True:
        now_epoch = int(_time.time())
        expires_at = now_epoch + LEASE_TTL_SECONDS
        try:
            table.put_item(
                Item={
                    "agent_id": BOUNDARY_LEASE_KEY,
                    "holder_id": holder_id,
                    "scope_level": scope_level,
                    "expires_at": expires_at,
                    "acquired_at": datetime.now(timezone.utc).isoformat(),
                },
                # Acquire only if there is no lease, or the existing one expired.
                ConditionExpression="attribute_not_exists(agent_id) OR expires_at < :now",
                ExpressionAttributeValues={":now": now_epoch},
            )
            logger.info(json.dumps({
                "event": "boundary_lease_acquired",
                "holder_id": holder_id, "scope_level": scope_level,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return True
        except Exception as exc:
            # ConditionalCheckFailedException means someone else holds the lease.
            name = type(exc).__name__
            if "ConditionalCheckFailed" not in name and "ConditionalCheckFailedException" not in str(exc):
                logger.error(json.dumps({"event": "boundary_lease_error", "error": str(exc)}))
                return False
            if _time.time() >= deadline:
                logger.error(json.dumps({
                    "event": "boundary_lease_timeout",
                    "holder_id": holder_id, "scope_level": scope_level,
                }))
                return False
            _time.sleep(LEASE_POLL_SECONDS)


def release_boundary_lease(holder_id):
    """Release the lease only if we still hold it (conditional delete)."""
    table = dynamodb.Table(SCOPE_TABLE_NAME)
    try:
        table.delete_item(
            Key={"agent_id": BOUNDARY_LEASE_KEY},
            ConditionExpression="holder_id = :h",
            ExpressionAttributeValues={":h": holder_id},
        )
        logger.info(json.dumps({
            "event": "boundary_lease_released", "holder_id": holder_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
    except Exception as exc:
        # We no longer hold it (expired + reacquired by another holder). Safe.
        logger.warning(json.dumps({"event": "boundary_lease_release_noop", "error": str(exc)}))


def verify_boundary(scope_level):
    """Confirm the live boundary matches the expected scope before invoking.

    Returns True if the currently-attached permission boundary equals the ARN
    for scope_level. A mismatch means a concurrent swap won a race; the caller
    must fail closed rather than invoke under the wrong scope.
    """
    expected = SCOPE_BOUNDARY_ARNS.get(str(scope_level))
    try:
        role = iam.get_role(RoleName=ACTION_GROUP_LAMBDA_ROLE_NAME)
        current = role.get("Role", {}).get("PermissionsBoundary", {}).get(
            "PermissionsBoundaryArn")
        ok = bool(expected) and current == expected
        if not ok:
            logger.error(json.dumps({
                "event": "boundary_verification_failed",
                "expected": expected, "current": current,
                "scope_level": scope_level,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
        return ok
    except Exception as exc:
        logger.error(json.dumps({"event": "boundary_verification_error", "error": str(exc)}))
        return False


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
# Task 11.1 -- Requirements 2.1, 4.1-4.5, 17.1, 18.2: Governance Engine invocation
# ---------------------------------------------------------------------------
def _derive_action_group(input_text):
    """Derive an action group name from the user's input text.

    Uses simple keyword matching to map input to known action groups.
    Falls back to 'general' if no match is found.
    """
    text_lower = (input_text or "").lower()
    if any(kw in text_lower for kw in ("deploy", "release", "production")):
        return "ProductionDeployment"
    if any(kw in text_lower for kw in ("staging", "stage")):
        return "StagingDeployment"
    if any(kw in text_lower for kw in ("propose", "change", "modify", "update")):
        return "ProposeChanges"
    if any(kw in text_lower for kw in ("read", "status", "show", "list", "get", "describe")):
        return "ReadPipelineStatus"
    return "general"


def invoke_governance_engine(agent_id, input_text, scope_level, target_resource=""):
    """Invoke the Governance Engine Lambda synchronously.

    Args:
        agent_id: The agent identifier.
        input_text: The user's natural language request.
        scope_level: Current scope level for the agent.
        target_resource: Optional target resource identifier.

    Returns:
        Parsed GovernanceDecision dict from the Governance Engine.

    Raises:
        Exception on invocation failure (timeout, error, bad response).
    """
    action_group = _derive_action_group(input_text)

    payload = {
        "agent_id": agent_id,
        "action_group": action_group,
        "target_resource": target_resource or "default",
        "input_text": input_text,
        "scope_level": scope_level,
    }

    # Invoke governance pipeline (mode-dependent)
    if GOVERNANCE_MODE == "step_functions" and GOVERNANCE_PIPELINE_ARN:
        sfn_response = sfn_client.start_sync_execution(
            stateMachineArn=GOVERNANCE_PIPELINE_ARN,
            input=json.dumps(payload),
        )
        if sfn_response["status"] == "SUCCEEDED":
            response_payload = json.loads(sfn_response.get("output", "{}"))
        else:
            response_payload = {
                "verdict": "deny",
                "error_category": "governance_pipeline_failure",
                "explanation": "Step Functions execution failed (fail-safe deny)",
            }
    else:
        response = lambda_client.invoke(
            FunctionName=GOVERNANCE_ENGINE_LAMBDA_ARN,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )

        # Check for Lambda-level errors (function error, timeout)
        if "FunctionError" in response:
            error_payload = response["Payload"].read().decode("utf-8")
            raise Exception(f"Governance Engine Lambda error: {error_payload}")

        response_payload = json.loads(response["Payload"].read().decode("utf-8"))

    # Validate the response contains a verdict
    if "verdict" not in response_payload:
        raise Exception(
            f"Governance Engine returned invalid response: missing 'verdict' field"
        )

    return response_payload


def create_pending_approval(agent_id, input_text, governance_decision):
    """Create a pending approval record in the PendingTable for escalated actions.

    Args:
        agent_id: The agent identifier.
        input_text: The user's original request.
        governance_decision: The GovernanceDecision dict from the Governance Engine.
    """
    table = dynamodb.Table(PENDING_TABLE_NAME)
    request_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    table.put_item(Item={
        "request_id": request_id,
        "agent_id": agent_id,
        "input_text": input_text,
        "decision_id": governance_decision.get("decision_id", ""),
        "verdict": "escalate",
        "explanation": governance_decision.get("explanation", ""),
        "risk_score": str(governance_decision.get("risk_score", 0)),
        "framework_mapping": governance_decision.get("framework_mapping", []),
        "status": "pending_approval",
        "created_at": timestamp,
        "updated_at": timestamp,
    })

    logger.info(json.dumps({
        "event": "pending_approval_created",
        "request_id": request_id,
        "agent_id": agent_id,
        "decision_id": governance_decision.get("decision_id", ""),
        "timestamp": timestamp,
    }))

    return request_id


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event, context):
    """Orchestrate scope enforcement, governance evaluation, and Bedrock Agent invocation.

    Flow:
        1. Optionally update scope level
        2. Read current scope level
        3. Deny if kill switch active (scope == 0)
        4. Invoke Governance Engine for policy/risk evaluation
           - deny  → return denied response with explanation
           - escalate → create pending approval, return escalated response
           - allow → proceed to Bedrock Agent
        5. Swap IAM permission boundary (allow only)
        6. Build session attributes (allow only)
        7. Invoke Bedrock Agent (allow only)

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

        # Step 4: Invoke Governance Engine (Task 11.1 -- Reqs 2.1, 4.1-4.5, 17.1, 18.2)
        try:
            governance_decision = invoke_governance_engine(
                agent_id, input_text, scope_level
            )
        except Exception as gov_exc:
            # Fail-safe: deny on Governance Engine failure (Req 18.2)
            logger.error(json.dumps({
                "event": "governance_engine_failure",
                "component_name": "GovernanceEngineLambda",
                "failure_type": type(gov_exc).__name__,
                "failure_detail": str(gov_exc),
                "fallback_action_taken": "deny",
                "agent_id": agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return {
                "status": "denied",
                "error": "governance_engine_failure",
                "message": (
                    "Governance Engine is unavailable. "
                    "Request denied as a safety precaution."
                ),
            }

        verdict = governance_decision.get("verdict", "deny")

        # Step 4a: Handle deny verdict (Req 4.2)
        if verdict == "deny":
            explanation = governance_decision.get("explanation", "Action denied by governance policy.")
            logger.info(json.dumps({
                "event": "governance_denied",
                "agent_id": agent_id,
                "decision_id": governance_decision.get("decision_id", ""),
                "explanation": explanation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return {
                "status": "denied",
                "error": "governance_denied",
                "message": explanation,
                "decision_id": governance_decision.get("decision_id", ""),
            }

        # Step 4b: Handle escalate verdict (Reqs 4.4, 4.5)
        if verdict == "escalate":
            explanation = governance_decision.get("explanation", "Action escalated for human review.")
            request_id = create_pending_approval(agent_id, input_text, governance_decision)
            logger.info(json.dumps({
                "event": "governance_escalated",
                "agent_id": agent_id,
                "decision_id": governance_decision.get("decision_id", ""),
                "request_id": request_id,
                "explanation": explanation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return {
                "status": "escalated",
                "message": explanation,
                "decision_id": governance_decision.get("decision_id", ""),
                "request_id": request_id,
            }

        # Step 4c: Handle defer verdict (AARM R4 DEFER). The action is suspended
        # pending additional context (e.g. stated intent / disambiguation). Like
        # escalate it does not execute; unresolved defers time out to deny in the
        # governance engine's pending-approval path.
        if verdict == "defer":
            explanation = governance_decision.get("explanation", "Action deferred pending additional context.")
            request_id = create_pending_approval(agent_id, input_text, governance_decision)
            logger.info(json.dumps({
                "event": "governance_deferred",
                "agent_id": agent_id,
                "decision_id": governance_decision.get("decision_id", ""),
                "request_id": request_id,
                "explanation": explanation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return {
                "status": "deferred",
                "message": explanation,
                "decision_id": governance_decision.get("decision_id", ""),
                "request_id": request_id,
            }

        # Fail-closed guard: only allow and modify proceed to execution. Any
        # unrecognized verdict is denied rather than executed (defense in depth
        # against a malformed/spoofed governance response).
        if verdict not in ("allow", "modify"):
            logger.error(json.dumps({
                "event": "governance_unknown_verdict",
                "agent_id": agent_id,
                "verdict": verdict,
                "decision_id": governance_decision.get("decision_id", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return {
                "status": "denied",
                "error": "unknown_verdict",
                "message": f"Unrecognized governance verdict '{verdict}'; failing closed to deny.",
                "decision_id": governance_decision.get("decision_id", ""),
            }

        # Step 5: Swap permission boundary, on allow or modify (Task 6.2 -- Req 10.6).
        # MODIFY executes the sanitized/transformed request the governance engine
        # already produced, so it proceeds through the same boundary-swap path as
        # allow.
        # The swap and the agent invocation share one mutable boundary on a
        # single role, so we serialize the whole swap -> verify -> invoke
        # section under a distributed lease and verify the boundary immediately
        # before invoking. A lost race fails closed (deny) rather than executing
        # under the wrong scope.
        lease_holder = str(uuid.uuid4())
        if not acquire_boundary_lease(scope_level, lease_holder):
            logger.error(json.dumps({
                "event": "boundary_lease_denied", "agent_id": agent_id,
                "scope_level": scope_level,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return {
                "status": "denied",
                "message": "Unable to obtain an exclusive scope lease; failing "
                           "closed to protect the permission boundary.",
                "decision_id": governance_decision.get("decision_id", "") if governance_decision else "",
            }
        try:
            swap_permission_boundary(scope_level)

            # Verify the boundary is actually the expected one before invoking.
            if not verify_boundary(scope_level):
                return {
                    "status": "denied",
                    "message": "Permission boundary verification failed; failing "
                               "closed rather than invoking under an unverified scope.",
                    "decision_id": governance_decision.get("decision_id", "") if governance_decision else "",
                }

            # Step 6: Build session attributes (Task 6.1 -- Requirement 8.6)
            permitted_groups = get_permitted_action_groups(scope_level)
            session_attributes = {
                "scope_level": str(scope_level),
                "permitted_action_groups": ",".join(permitted_groups),
            }

            # Step 7: Invoke Bedrock Agent (Task 6.3 -- Requirements 9.1-9.4)
            response_text = invoke_bedrock_agent(input_text, session_attributes)
        finally:
            release_boundary_lease(lease_holder)

        # Step 8: Output guardrails -- validate agent response before returning
        canary_tokens = governance_decision.get("_canary_tokens", []) if governance_decision else []
        output_safe, redacted_response, output_violations = _validate_agent_output(
            response_text, canary_tokens
        )
        if not output_safe:
            logger.warning(json.dumps({
                "audit_event": "output_guardrail_triggered",
                "agent_id": agent_id,
                "violations": output_violations,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            response_text = redacted_response

        return {
            "status": "success",
            "scope_level": scope_level,
            "permitted_action_groups": permitted_groups,
            "response": response_text,
            "decision_id": governance_decision.get("decision_id", ""),
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
