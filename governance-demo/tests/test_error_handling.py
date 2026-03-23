"""Unit tests for error handling scenarios.

Validates: Requirements 3.6, 5.5, 8.6

Tests:
  1. Scope Table unreachable – DynamoDB ClientError → request denied (Req 3.6)
  2. Bedrock failure – invoke_model exception → error response with reason (Req 5.5)
  3. Kill switch IAM retry success – put_role_policy fails once then succeeds (Req 8.6)
  4. Kill switch IAM double failure – put_role_policy fails twice → partial success (Req 8.6)
"""

import json
import os
import importlib.util
from unittest.mock import patch, MagicMock

import pytest
from botocore.exceptions import ClientError


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_client_error(code="InternalServerError", message="Service unavailable"):
    """Build a botocore ClientError for testing."""
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "GetItem",
    )


def _load_module(name, path, env_vars):
    """Load a Lambda module via importlib.util with mocked boto3 and env."""
    with patch.dict(os.environ, env_vars):
        with patch("boto3.client", return_value=MagicMock()):
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
    return mod


# ── Module paths ─────────────────────────────────────────────────────────────

_TESTS_DIR = os.path.dirname(__file__)
_SE_PATH = os.path.join(_TESTS_DIR, "..", "lambdas", "scope_enforcer", "index.py")
_AGENT_PATH = os.path.join(_TESTS_DIR, "..", "lambdas", "agent", "index.py")
_KS_PATH = os.path.join(_TESTS_DIR, "..", "lambdas", "kill_switch", "index.py")

_SE_ENV = {
    "SCOPE_TABLE_NAME": "test-scope-table",
    "PENDING_TABLE_NAME": "test-pending-table",
    "AGENT_FUNCTION_NAME": "test-agent-function",
    "AGENT_ROLE_NAME": "test-agent-role",
    "SCOPE_1_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-1",
    "SCOPE_2_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-2",
    "SCOPE_3_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-3",
    "SCOPE_4_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-4",
}

_AGENT_ENV = {
    "DATA_BUCKET_NAME": "test-data-bucket",
    "AGENT_ID": "demo-agent",
    "BEDROCK_MODEL_ID": "anthropic.claude-3-haiku-20240307-v1:0",
}

_KS_ENV = {
    "SCOPE_TABLE_NAME": "test-scope-table",
    "AGENT_ROLE_NAME": "test-agent-role",
}


# ── Load modules once at import time ─────────────────────────────────────────

scope_enforcer_mod = _load_module("scope_enforcer_eh", _SE_PATH, _SE_ENV)
agent_mod = _load_module("agent_eh", _AGENT_PATH, _AGENT_ENV)
kill_switch_mod = _load_module("kill_switch_eh", _KS_PATH, _KS_ENV)


# ── Test 1: Scope Table unreachable (Req 3.6) ───────────────────────────────

def test_scope_table_unreachable_denies_request():
    """Req 3.6: When the Scope Table is unreachable the request is denied."""
    mock_ddb = MagicMock()
    mock_ddb.get_item.side_effect = _make_client_error()

    with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
        result = scope_enforcer_mod.handler(
            {
                "agent_id": "demo-agent",
                "action": "s3:GetObject",
                "target_resource": "builds/build-47.json",
            },
            None,
        )

    assert result["error"] == "scope_lookup_failure"
    assert "message" in result
    mock_ddb.get_item.assert_called_once()


# ── Test 2: Bedrock failure (Req 5.5) ────────────────────────────────────────

def test_bedrock_failure_returns_error_with_reason():
    """Req 5.5: Bedrock invocation failure returns error with reason."""
    mock_bedrock = MagicMock()
    mock_bedrock.invoke_model.side_effect = RuntimeError("Bedrock model timeout")

    with patch.object(agent_mod, "bedrock_client", mock_bedrock):
        result = agent_mod.handler(
            {
                "action": "s3:GetObject",
                "target_resource": "builds/build-47.json",
                "payload": {},
                "scope_level": 1,
            },
            None,
        )

    assert result["error"] == "bedrock_failure"
    assert "reason" in result
    assert "Bedrock model timeout" in result["reason"]


# ── Test 3: Kill switch IAM retry success (Req 8.6) ─────────────────────────

def test_kill_switch_iam_retry_success():
    """Req 8.6: IAM put_role_policy fails once then succeeds on retry."""
    mock_ddb = MagicMock()
    mock_iam = MagicMock()
    mock_iam.put_role_policy.side_effect = [RuntimeError("Throttling"), None]

    with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
         patch.object(kill_switch_mod, "iam_client", mock_iam):
        result = kill_switch_mod.handler(
            {"agent_id": "demo-agent", "invoker_identity": "operator@test.com"},
            None,
        )

    assert result["status"] == "success"
    assert "deny_all_policy_attached" in result["actions_taken"]
    assert "scope_set_to_0" in result["actions_taken"]
    assert mock_iam.put_role_policy.call_count == 2


# ── Test 4: Kill switch IAM double failure (Req 8.6) ────────────────────────

def test_kill_switch_iam_double_failure():
    """Req 8.6: IAM put_role_policy fails twice → partial_success."""
    mock_ddb = MagicMock()
    mock_iam = MagicMock()
    mock_iam.put_role_policy.side_effect = [
        RuntimeError("IAM unavailable"),
        RuntimeError("IAM still unavailable"),
    ]

    with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
         patch.object(kill_switch_mod, "iam_client", mock_iam):
        result = kill_switch_mod.handler(
            {"agent_id": "demo-agent", "invoker_identity": "operator@test.com"},
            None,
        )

    assert result["status"] == "partial_success"
    assert "deny_all_policy_attached" not in result["actions_taken"]
    assert "scope_set_to_0" in result["actions_taken"]
