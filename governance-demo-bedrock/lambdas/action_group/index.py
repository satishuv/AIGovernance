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
from datetime import datetime

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
        "timestamp": datetime.utcnow().isoformat(),
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
    timestamp = datetime.utcnow().isoformat()
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
    timestamp = datetime.utcnow().isoformat()
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
    timestamp = datetime.utcnow().isoformat()
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
    timestamp = datetime.utcnow().isoformat()
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
    timestamp = datetime.utcnow().isoformat()
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
    timestamp = datetime.utcnow().isoformat()
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
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event, context):
    """Route Bedrock Agent action group invocations to the correct handler."""
    action_group = event.get("actionGroup", "")
    api_path = event.get("apiPath", "")
    http_method = event.get("httpMethod", "GET")
    parameters = event.get("parameters", [])
    agent_id = event.get("agent", {}).get("id", "unknown")

    params_dict = _params_to_dict(parameters)
    outcome = "success"

    try:
        handler_fn = _resolve_route(action_group, api_path)

        if handler_fn is None:
            outcome = "error"
            _audit_log(agent_id, action_group, api_path, params_dict, outcome)
            return _error_response(
                action_group, api_path, http_method,
                f"Unknown route: {action_group} {api_path}",
            )

        response = handler_fn(event, params_dict)

        # Check if the handler returned an error
        resp_status = (
            response.get("response", {}).get("httpStatusCode", 200)
        )
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
