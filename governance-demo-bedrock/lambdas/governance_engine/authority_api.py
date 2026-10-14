"""API Gateway routes for delegated authority (IAM-authorized).

Agent plane
    POST /authority/requests                     evaluate a structured request
    POST /authority-grants/mint                  {approval_id, request}: approved request -> grant
    POST /authority-grants/{grant_id}/execute    verify + consume grant, exchange, execute
    GET  /authority-grants/{grant_id}            grant status and signature check
Admin plane (human principals with governance roles)
    POST /authority-grants/{grant_id}/revoke     {reason}
    POST /admin/agents/{agent_id}/scope          {scope_level, reason}
    POST /admin/agents/{agent_id}/kill-switch    {reason}

Identity comes only from requestContext (SigV4 / IAM). The request body never
names the caller.
"""

import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)

_CONTROL_PLANE = None


def _response(status: int, body: Any) -> Dict[str, Any]:
    return {"statusCode": status, "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body, default=str)}


def _control_plane():
    global _CONTROL_PLANE
    if _CONTROL_PLANE is None:
        from authority_factory import from_environment
        _CONTROL_PLANE = from_environment()
    return _CONTROL_PLANE


def handle_authority_api(event: Dict[str, Any], resource: str, http_method: str,
                         path_params: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    try:
        cp = _control_plane()
    except RuntimeError as exc:
        return _response(503, {"error": str(exc)})

    import boto3
    from authority_factory import caller_from_api_event
    roles_table_name = os.environ.get("GOVERNANCE_ROLES_TABLE_NAME", "")
    roles_table = boto3.resource("dynamodb").Table(roles_table_name) if roles_table_name else None
    caller = caller_from_api_event(event, cp, roles_table)
    if caller is None:
        return _response(401, {"error": "request is not authenticated"})

    grant_id = path_params.get("grant_id", "")
    agent_id = path_params.get("agent_id", "")

    if resource == "/authority/requests" and http_method == "POST":
        return _response(200, cp.request_authority(body, caller))
    if resource == "/authority-grants/mint" and http_method == "POST":
        approval_id = str(body.get("approval_id", ""))
        request = body.get("request") or {}
        if not approval_id or not isinstance(request, dict):
            return _response(400, {"error": "approval_id and request are required"})
        return _response(200, cp.mint_after_approval(approval_id, request, caller))
    if resource.endswith("/execute") and http_method == "POST" and grant_id:
        return _response(200, cp.execute(grant_id, body, caller))
    if resource.endswith("/revoke") and http_method == "POST" and grant_id:
        out = cp.revoke_grant(grant_id, caller, str(body.get("reason", "")))
        return _response(403 if out["status"] == "denied" else 200, out)
    if resource == "/authority-grants/{grant_id}" and http_method == "GET" and grant_id:
        grant = cp.grants.get(grant_id)
        if grant is None:
            return _response(404, {"error": "grant not found"})
        if not (caller.is_human or caller.agent_id == grant.agent_id):
            return _response(403, {"error": "grant details are visible to its agent and to humans only"})
        view = grant.public_view()
        view["signature_verified"] = cp.grants.signer.verify(grant.signing_digest(), grant.signature)
        return _response(200, view)
    if resource.endswith("/scope") and http_method == "POST" and agent_id:
        level = body.get("scope_level")
        out = cp.admin_set_scope(agent_id, level if isinstance(level, int) else -1, caller,
                                 str(body.get("reason", "")))
        return _response(403 if out["status"] == "denied" else 200, out)
    if resource.endswith("/kill-switch") and http_method == "POST" and agent_id:
        out = cp.activate_kill_switch(agent_id, caller, str(body.get("reason", "")))
        return _response(403 if out["status"] == "denied" else 200, out)
    return _response(404, {"error": "Route not found"})


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for the dedicated DelegatedAuthorityLambda."""
    resource = event.get("resource", "")
    method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}
    try:
        body = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        return _response(400, {"error": "body must be JSON"})
    if not isinstance(body, dict):
        return _response(400, {"error": "body must be a JSON object"})
    try:
        return handle_authority_api(event, resource, method, path_params, body)
    except Exception as exc:  # fail closed, never leak internals
        logger.error(json.dumps({"event": "authority_api_error", "error_type": type(exc).__name__,
                                 "resource": resource}))
        return _response(500, {"error": f"internal error ({type(exc).__name__}); request denied"})
