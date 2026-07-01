"""
Action Group Lambda for the Bedrock Agent Governance Demo.

Handles all action group invocations from the Bedrock Agent:
- ReadPipelineStatus: getBuildStatus, getTestResults
- ProposeChanges: draftDeploymentPlan, draftRollbackStrategy
- StagingDeployment: deployToStaging, triggerTests
- ProductionDeployment: deployToProduction, rollbackDeployment

Environment variables:
    DATA_BUCKET_NAME: S3 bucket with pipeline data
    PENDING_TABLE_NAME: DynamoDB table for pending proposals
    LOG_GROUP_NAME: CloudWatch log group for audit logs
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

import boto3

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_BUCKET_NAME = os.environ.get("DATA_BUCKET_NAME", "")
PENDING_TABLE_NAME = os.environ.get("PENDING_TABLE_NAME", "")
LOG_GROUP_NAME = os.environ.get("LOG_GROUP_NAME", "")

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

# ---------------------------------------------------------------------------
# Logging setup -- structured JSON output (Requirement 12.1)
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Helper: extract parameters from Bedrock Agent event
# ---------------------------------------------------------------------------
def _get_param(parameters, name):
    """Return the value of the named parameter, or None if missing."""
    if not parameters:
        return None
    for p in parameters:
        if p.get("name") == name:
            return p.get("value")
    return None


def _params_to_dict(parameters):
    """Convert the Bedrock Agent parameters list to a plain dict."""
    if not parameters:
        return {}
    return {p["name"]: p.get("value") for p in parameters}


# ---------------------------------------------------------------------------
# Response builders (Task 5.1 -- Requirement 7.7, 7.8)
# ---------------------------------------------------------------------------
def _build_response(action_group, api_path, http_method, status_code, body):
    """Build the standard Bedrock Agent action group response."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": http_method,
            "httpStatusCode": status_code,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(body) if not isinstance(body, str) else body,
                }
            },
        },
    }


def _error_response(action_group, api_path, http_method, message):
    """Build an error response with HTTP 500."""
    return _build_response(
        action_group,
        api_path,
        http_method,
        500,
        {"error": message},
    )


# ---------------------------------------------------------------------------
# Audit logging (Task 5.6 -- Requirement 12.1)
# ---------------------------------------------------------------------------
def _audit_log(agent_id, action_group, api_path, parameters, outcome):
    """Emit a structured JSON audit log entry."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "action_group": action_group,
        "api_path": api_path,
        "parameters": parameters,
        "outcome": outcome,
    }
    logger.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# ReadPipelineStatus handlers (Task 5.2 -- Requirements 3.3, 3.4, 7.3)
# ---------------------------------------------------------------------------
def handle_get_build_status(event, params):
    """Read builds/{buildId}.json from the Data Bucket."""
    build_id = _get_param(event.get("parameters"), "buildId")
    if not build_id:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameter: buildId",
        )
    key = f"builds/{build_id}.json"
    try:
        obj = s3.get_object(Bucket=DATA_BUCKET_NAME, Key=key)
        body = obj["Body"].read().decode("utf-8")
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200, body,
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to read {key}: {str(exc)}",
        )


def handle_get_test_results(event, params):
    """Read test-results/{buildId}-tests.json from the Data Bucket."""
    build_id = _get_param(event.get("parameters"), "buildId")
    if not build_id:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameter: buildId",
        )
    key = f"test-results/{build_id}-tests.json"
    try:
        obj = s3.get_object(Bucket=DATA_BUCKET_NAME, Key=key)
        body = obj["Body"].read().decode("utf-8")
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200, body,
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to read {key}: {str(exc)}",
        )


# ---------------------------------------------------------------------------
# ProposeChanges handlers (Task 5.3 -- Requirements 4.3, 4.4, 4.5, 7.4)
# ---------------------------------------------------------------------------
def handle_draft_deployment_plan(event, params):
    """Write a deployment plan proposal to the Pending Table."""
    build_id = _get_param(event.get("parameters"), "buildId")
    target_env = _get_param(event.get("parameters"), "targetEnvironment")
    if not build_id or not target_env:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameters: buildId and targetEnvironment",
        )
    agent_id = event.get("agent", {}).get("id", "unknown")
    request_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        table = dynamodb.Table(PENDING_TABLE_NAME)
        table.put_item(Item={
            "request_id": request_id,
            "agent_id": agent_id,
            "proposed_action": "draftDeploymentPlan",
            "target_resource": f"builds/{build_id}",
            "target_environment": target_env,
            "plan_details": f"Deploy {build_id} to {target_env}",
            "timestamp": timestamp,
            "status": "pending",
        })
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200,
            {
                "request_id": request_id,
                "status": "pending",
                "message": f"Deployment plan for {build_id} to {target_env} created",
            },
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to write proposal: {str(exc)}",
        )


def handle_draft_rollback_strategy(event, params):
    """Write a rollback strategy proposal to the Pending Table."""
    build_id = _get_param(event.get("parameters"), "buildId")
    target_env = _get_param(event.get("parameters"), "targetEnvironment")
    if not build_id or not target_env:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameters: buildId and targetEnvironment",
        )
    agent_id = event.get("agent", {}).get("id", "unknown")
    request_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        table = dynamodb.Table(PENDING_TABLE_NAME)
        table.put_item(Item={
            "request_id": request_id,
            "agent_id": agent_id,
            "proposed_action": "draftRollbackStrategy",
            "target_resource": f"builds/{build_id}",
            "target_environment": target_env,
            "plan_details": f"Rollback strategy for {build_id} in {target_env}",
            "timestamp": timestamp,
            "status": "pending",
        })
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200,
            {
                "request_id": request_id,
                "status": "pending",
                "message": f"Rollback strategy for {build_id} in {target_env} created",
            },
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to write proposal: {str(exc)}",
        )


# ---------------------------------------------------------------------------
# StagingDeployment handlers (Task 5.4 -- Requirements 5.3, 5.4, 7.5)
# ---------------------------------------------------------------------------
def handle_deploy_to_staging(event, params):
    """Write deployment record to deployments/staging/{buildId}.json in S3."""
    build_id = _get_param(event.get("parameters"), "buildId")
    if not build_id:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameter: buildId",
        )
    agent_id = event.get("agent", {}).get("id", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "buildId": build_id,
        "environment": "staging",
        "status": "deployed",
        "deployedBy": agent_id,
        "timestamp": timestamp,
    }
    key = f"deployments/staging/{build_id}.json"
    try:
        s3.put_object(
            Bucket=DATA_BUCKET_NAME,
            Key=key,
            Body=json.dumps(record),
            ContentType="application/json",
        )
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200,
            {
                "buildId": build_id,
                "environment": "staging",
                "status": "deployed",
                "message": f"Build {build_id} deployed to staging",
            },
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to deploy to staging: {str(exc)}",
        )


def handle_trigger_tests(event, params):
    """Write test execution record to test-runs/{buildId}-{testSuite}.json in S3."""
    build_id = _get_param(event.get("parameters"), "buildId")
    test_suite = _get_param(event.get("parameters"), "testSuite")
    if not build_id or not test_suite:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameters: buildId and testSuite",
        )
    agent_id = event.get("agent", {}).get("id", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "buildId": build_id,
        "testSuite": test_suite,
        "status": "running",
        "triggeredBy": agent_id,
        "timestamp": timestamp,
    }
    key = f"test-runs/{build_id}-{test_suite}.json"
    try:
        s3.put_object(
            Bucket=DATA_BUCKET_NAME,
            Key=key,
            Body=json.dumps(record),
            ContentType="application/json",
        )
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200,
            {
                "buildId": build_id,
                "testSuite": test_suite,
                "status": "running",
                "message": f"Tests '{test_suite}' triggered for build {build_id}",
            },
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to trigger tests: {str(exc)}",
        )


# ---------------------------------------------------------------------------
# ProductionDeployment handlers (Task 5.5 -- Requirements 6.3, 6.4, 7.6)
# ---------------------------------------------------------------------------
def handle_deploy_to_production(event, params):
    """Write deployment record to deployments/production/{buildId}.json in S3."""
    build_id = _get_param(event.get("parameters"), "buildId")
    if not build_id:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameter: buildId",
        )
    agent_id = event.get("agent", {}).get("id", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "buildId": build_id,
        "environment": "production",
        "status": "deployed",
        "deployedBy": agent_id,
        "timestamp": timestamp,
    }
    key = f"deployments/production/{build_id}.json"
    try:
        s3.put_object(
            Bucket=DATA_BUCKET_NAME,
            Key=key,
            Body=json.dumps(record),
            ContentType="application/json",
        )
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200,
            {
                "buildId": build_id,
                "environment": "production",
                "status": "deployed",
                "message": f"Build {build_id} deployed to production",
            },
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to deploy to production: {str(exc)}",
        )


def handle_rollback_deployment(event, params):
    """Write rollback record to deployments/production/rollback-{buildId}.json."""
    build_id = _get_param(event.get("parameters"), "buildId")
    rollback_target = _get_param(event.get("parameters"), "rollbackTargetBuildId")
    if not build_id or not rollback_target:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            "Missing required parameters: buildId and rollbackTargetBuildId",
        )
    agent_id = event.get("agent", {}).get("id", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "buildId": build_id,
        "rollbackTargetBuildId": rollback_target,
        "environment": "production",
        "status": "rolled_back",
        "rolledBackBy": agent_id,
        "timestamp": timestamp,
    }
    key = f"deployments/production/rollback-{build_id}.json"
    try:
        s3.put_object(
            Bucket=DATA_BUCKET_NAME,
            Key=key,
            Body=json.dumps(record),
            ContentType="application/json",
        )
        return _build_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"], 200,
            {
                "buildId": build_id,
                "rollbackTargetBuildId": rollback_target,
                "status": "rolled_back",
                "message": f"Production rolled back from {build_id} to {rollback_target}",
            },
        )
    except Exception as exc:
        return _error_response(
            event["actionGroup"], event["apiPath"], event["httpMethod"],
            f"Failed to rollback deployment: {str(exc)}",
        )


# ---------------------------------------------------------------------------
# Routing table (Task 5.1 -- Requirements 7.1, 7.2)
# Bedrock Agents sends apiPath with path params substituted, e.g.
# "/getBuildStatus/build-47" for the schema path "/getBuildStatus/{buildId}".
# We match on the base path prefix to handle this.
# ---------------------------------------------------------------------------
ROUTE_TABLE = {
    ("ReadPipelineStatus", "/getBuildStatus"): handle_get_build_status,
    ("ReadPipelineStatus", "/getTestResults"): handle_get_test_results,
    ("ProposeChanges", "/draftDeploymentPlan"): handle_draft_deployment_plan,
    ("ProposeChanges", "/draftRollbackStrategy"): handle_draft_rollback_strategy,
    ("StagingDeployment", "/deployToStaging"): handle_deploy_to_staging,
    ("StagingDeployment", "/triggerTests"): handle_trigger_tests,
    ("ProductionDeployment", "/deployToProduction"): handle_deploy_to_production,
    ("ProductionDeployment", "/rollbackDeployment"): handle_rollback_deployment,
}


def _resolve_route(action_group, api_path):
    """Find the handler for the given action group and API path.

    Tries exact match first, then prefix match to handle path parameters
    (e.g. "/getBuildStatus/build-47" matches "/getBuildStatus").
    """
    # Exact match
    handler_fn = ROUTE_TABLE.get((action_group, api_path))
    if handler_fn:
        return handler_fn

    # Prefix match for path parameters
    for (ag, base_path), fn in ROUTE_TABLE.items():
        if ag == action_group and api_path.startswith(base_path):
            return fn

    return None


# ---------------------------------------------------------------------------
# Per-tool-call security (lightweight, inline, <15ms overhead)
#
# Design rationale: The full 20-step governance pipeline already ran at
# session entry (Scope Enforcer). Re-running it per tool call would be
# redundant and slow. Instead, the action group enforces:
#   1. Scope-action-group mapping (is this tool permitted at current scope?)
#   2. Parameter validation (no injection in param values)
#   3. Output sanitization (strip leaked ARNs/credentials from response)
#
# These are FAST inline checks (~15ms total), not another Lambda invocation.
# ---------------------------------------------------------------------------
import re as _re

SCOPE_ACTION_GROUPS = {
    1: ["ReadPipelineStatus"],
    2: ["ReadPipelineStatus", "ProposeChanges"],
    3: ["ReadPipelineStatus", "ProposeChanges", "StagingDeployment"],
    4: ["ReadPipelineStatus", "ProposeChanges", "StagingDeployment", "ProductionDeployment"],
}

_PARAM_INJECTION_PATTERNS = [
    _re.compile(r"['\";].*(?:DROP|DELETE|INSERT|UPDATE|EXEC)", _re.IGNORECASE),
    _re.compile(r"<script[^>]*>", _re.IGNORECASE),
    _re.compile(r"\.\./\.\./"),
    _re.compile(r"<\|im_start\|>|<\|im_end\|>|\[INST\]"),
    _re.compile(r"(?:^|\s)(?:rm|del|format|shutdown)\s+[-/]", _re.IGNORECASE),
]

_SENSITIVE_OUTPUT_PATTERNS = [
    _re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+"),
    _re.compile(r"AKIA[0-9A-Z]{16}"),
    _re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),
    _re.compile(r"GovernanceBedrockStack-[A-Za-z0-9]+-[A-Za-z0-9]+"),
    _re.compile(r"(?:BEGIN|END)\s+(?:RSA\s+)?PRIVATE\s+KEY"),
]


def _check_scope_permits_action(scope_level, action_group):
    """Verify the current scope allows this action group. O(1) lookup."""
    permitted = SCOPE_ACTION_GROUPS.get(scope_level, [])
    return action_group in permitted


def _check_parameter_safety(params_dict):
    """Scan all parameter values for injection attacks. Returns (safe, violation)."""
    for name, value in params_dict.items():
        if not isinstance(value, str):
            continue
        for pattern in _PARAM_INJECTION_PATTERNS:
            if pattern.search(value):
                return False, f"Injection detected in parameter '{name}': {pattern.pattern[:40]}"
    return True, ""


def _sanitize_output(response_body):
    """Strip sensitive patterns from response. Returns (sanitized, violations)."""
    if not isinstance(response_body, str):
        response_body = json.dumps(response_body)

    violations = []
    sanitized = response_body
    for pattern in _SENSITIVE_OUTPUT_PATTERNS:
        if pattern.search(sanitized):
            violations.append(f"sensitive_pattern: {pattern.pattern[:30]}")
            sanitized = pattern.sub("[REDACTED]", sanitized)

    return sanitized, violations


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event, context):
    """Route Bedrock Agent action group invocations with inline security.

    Per-tool-call defense-in-depth (lightweight, ~15ms overhead):
    1. SCOPE CHECK: Is this action group permitted at current scope level?
    2. PARAMETER CHECK: Do any parameter values contain injection attacks?
    3. EXECUTION: Run the action handler.
    4. OUTPUT CHECK: Strip any leaked ARNs/credentials from the response.
    """
    action_group = event.get("actionGroup", "")
    api_path = event.get("apiPath", "")
    http_method = event.get("httpMethod", "GET")
    parameters = event.get("parameters", [])
    agent_id = event.get("agent", {}).get("id", "unknown")
    session_attributes = event.get("sessionAttributes", {})
    scope_level = int(session_attributes.get("scope_level", "1"))

    params_dict = _params_to_dict(parameters)
    outcome = "success"

    try:
        # -----------------------------------------------------------------
        # CHECK 1: Scope permits this action group?
        # Physical constraint: even if the agent is jailbroken and tries
        # to call ProductionDeployment at scope 1, it's blocked here.
        # -----------------------------------------------------------------
        if not _check_scope_permits_action(scope_level, action_group):
            outcome = "scope_denied"
            logger.warning(json.dumps({
                "audit_event": "tool_scope_violation",
                "agent_id": agent_id,
                "action_group": action_group,
                "scope_level": scope_level,
                "permitted": SCOPE_ACTION_GROUPS.get(scope_level, []),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            _audit_log(agent_id, action_group, api_path, params_dict, outcome)
            return _build_response(
                action_group, api_path, http_method, 403,
                {"error": f"Action '{action_group}' not permitted at scope {scope_level}"},
            )

        # -----------------------------------------------------------------
        # CHECK 2: Parameter injection detection
        # Catches SQL injection, path traversal, script injection in
        # tool parameters. Fast regex scan, <5ms.
        # -----------------------------------------------------------------
        param_safe, param_violation = _check_parameter_safety(params_dict)
        if not param_safe:
            outcome = "param_injection_blocked"
            logger.warning(json.dumps({
                "audit_event": "tool_parameter_injection",
                "agent_id": agent_id,
                "action_group": action_group,
                "violation": param_violation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            _audit_log(agent_id, action_group, api_path, params_dict, outcome)
            return _build_response(
                action_group, api_path, http_method, 403,
                {"error": f"Parameter validation failed: {param_violation}"},
            )

        # -----------------------------------------------------------------
        # EXECUTE: Run the action handler
        # -----------------------------------------------------------------
        handler_fn = _resolve_route(action_group, api_path)

        if handler_fn is None:
            outcome = "error"
            _audit_log(agent_id, action_group, api_path, params_dict, outcome)
            return _error_response(
                action_group, api_path, http_method,
                f"Unknown route: {action_group} {api_path}",
            )

        response = handler_fn(event, params_dict)

        # -----------------------------------------------------------------
        # CHECK 3: Output sanitization
        # Strip any leaked ARNs, credentials, or internal paths from
        # the response before it goes back to the agent's context.
        # -----------------------------------------------------------------
        resp_body = (
            response.get("response", {})
            .get("responseBody", {})
            .get("application/json", {})
            .get("body", "")
        )

        if resp_body:
            sanitized, violations = _sanitize_output(resp_body)
            if violations:
                logger.warning(json.dumps({
                    "audit_event": "output_sanitized",
                    "agent_id": agent_id,
                    "action_group": action_group,
                    "violations": violations,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                response["response"]["responseBody"]["application/json"]["body"] = sanitized

        resp_status = response.get("response", {}).get("httpStatusCode", 200)
        if resp_status >= 400:
            outcome = "error"

        _audit_log(agent_id, action_group, api_path, params_dict, outcome)
        return response

    except Exception as exc:
        outcome = "error"
        _audit_log(agent_id, action_group, api_path, params_dict, outcome)
        return _error_response(
            action_group, api_path, http_method,
            f"Internal error: {str(exc)}",
        )
