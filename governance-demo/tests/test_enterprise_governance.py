"""Enterprise Governance comprehensive test suite.

Validates all 14 pipeline steps across the three governance Lambda modules
(Scope Enforcer, Agent, Kill Switch) with mocked AWS clients.

Validates: Requirements 10.1, 10.2, 10.3, 10.4
"""

import json
import os
import importlib.util
from unittest.mock import patch, MagicMock

import pytest
from botocore.exceptions import ClientError
from hypothesis import given, settings
import hypothesis.strategies as st


# ── Helpers ──────────────────────────────────────────────────────────────────


def _load_module(name, path, env_vars):
    """Load a Lambda module via importlib.util with mocked boto3 and env.

    Prevents real AWS client creation at module import time by patching
    ``boto3.client`` to return a ``MagicMock`` and injecting all required
    environment variables.
    """
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


# ── Environment variable dicts ───────────────────────────────────────────────

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

scope_enforcer_mod = _load_module("scope_enforcer_eg", _SE_PATH, _SE_ENV)
agent_mod = _load_module("agent_eg", _AGENT_PATH, _AGENT_ENV)
kill_switch_mod = _load_module("kill_switch_eg", _KS_PATH, _KS_ENV)


# ── Reusable constants ───────────────────────────────────────────────────────

ALL_ACTIONS = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"]
READ_ACTIONS_SET = ["s3:GetObject"]
WRITE_ACTIONS_SET = ["s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"]
OUTCOMES = ["success", "bedrock_failure", "s3_failure", "unsupported_action"]
REQUIRED_LOG_FIELDS = {"timestamp", "agent_id", "action_type", "target_resource", "scope_level", "outcome"}
REQUIRED_PENDING_FIELDS = {"request_id", "agent_id", "proposed_action", "target_resource", "timestamp", "status"}

# Hypothesis strategy: safe characters for generated strings
safe_chars = st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_")


# -- Scope Enforcer Pipeline Step Tests (Steps 1-5) ---------------------------
# Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5


class TestScopeEnforcerSteps:
    """Unit tests for Scope Enforcer pipeline steps 1 through 5."""

    def test_step1_scope_lookup(self):
        """Step 1: _get_scope_level reads scope_level from DynamoDB.

        Validates: Requirement 1.1
        """
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": {"agent_id": {"S": "demo-agent"}, "scope_level": {"N": "3"}}
        }
        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            result = scope_enforcer_mod._get_scope_level("demo-agent")

        mock_ddb.get_item.assert_called_once_with(
            TableName="test-scope-table",
            Key={"agent_id": {"S": "demo-agent"}},
        )
        assert result == 3

    def test_step2_validate_scope_valid(self):
        """Step 2: validate_scope returns True for valid levels 1-4.

        Validates: Requirement 1.2
        """
        for level in (1, 2, 3, 4):
            assert scope_enforcer_mod.validate_scope(level) is True

    def test_step2_validate_scope_invalid(self):
        """Step 2: validate_scope returns False for invalid levels.

        Validates: Requirement 1.2
        """
        for level in (0, -1, 5, 99):
            assert scope_enforcer_mod.validate_scope(level) is False

    def test_step3_classify_action_read(self):
        """Step 3: classify_action returns "read" for s3:GetObject.

        Validates: Requirement 1.3
        """
        assert scope_enforcer_mod.classify_action("s3:GetObject") == "read"

    def test_step3_classify_action_write(self):
        """Step 3: classify_action returns "write" for write actions.

        Validates: Requirement 1.3
        """
        for action in ("s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"):
            assert scope_enforcer_mod.classify_action(action) == "write"

    def test_step4_route_request(self):
        """Step 4: route_request returns correct decisions for key combos.

        Validates: Requirement 1.4
        """
        event = {"agent_id": "demo-agent", "action": "s3:GetObject"}
        cases = [
            (0, "read", "deny"),
            (1, "read", "permit"),
            (1, "write", "deny"),
            (2, "write", "pending"),
            (3, "read", "permit"),
            (4, "write", "permit"),
        ]
        for scope_level, action_type, expected_decision in cases:
            result = scope_enforcer_mod.route_request(scope_level, action_type, event)
            assert result["decision"] == expected_decision, (
                f"scope={scope_level}, action={action_type}: "
                f"expected {expected_decision}, got {result['decision']}"
            )

    def test_step5_permission_boundary(self):
        """Step 5: _update_permission_boundary calls IAM with correct ARN.

        Validates: Requirement 1.5
        """
        mock_iam = MagicMock()
        with patch.object(scope_enforcer_mod, "iam_client", mock_iam):
            scope_enforcer_mod._update_permission_boundary(2)

        mock_iam.put_role_permissions_boundary.assert_called_once_with(
            RoleName="test-agent-role",
            PermissionsBoundary="arn:aws:iam::123456789012:policy/scope-2",
        )


# -- Property-Based Tests (Scope Enforcer) ------------------------------------


@given(value=st.integers())
@settings(max_examples=100)
def test_prop_scope_level_validation(value):
    """Feature: enterprise-governance-tests, Property 1: Scope level validation

    For any integer value, validate_scope returns True iff value in {1,2,3,4}.

    Validates: Requirements 1.2, 5.3
    """
    result = scope_enforcer_mod.validate_scope(value)
    if value in {1, 2, 3, 4}:
        assert result is True, f"Expected True for scope {value}"
    else:
        assert result is False, f"Expected False for scope {value}"


@given(scope_level=st.sampled_from([0, 1, 2, 3, 4]), action=st.sampled_from(ALL_ACTIONS))
@settings(max_examples=100)
def test_prop_decision_matrix(scope_level, action):
    """Feature: enterprise-governance-tests, Property 2: Decision matrix correctness

    For any scope in {0..4} and any action, route_request matches the governance
    decision matrix.

    Validates: Requirements 1.4, 4.1, 4.2, 4.3, 4.4, 4.5
    """
    action_type = scope_enforcer_mod.classify_action(action)
    event = {"agent_id": "demo-agent", "action": action}
    result = scope_enforcer_mod.route_request(scope_level, action_type, event)

    if scope_level == 0:
        assert result["decision"] == "deny", f"Scope 0 should deny, got {result}"
    elif scope_level == 1:
        if action_type == "read":
            assert result["decision"] == "permit"
        else:
            assert result["decision"] == "deny"
    elif scope_level == 2:
        if action_type == "read":
            assert result["decision"] == "permit"
        else:
            assert result["decision"] == "pending"
    else:
        # scope 3 or 4 — permit everything
        assert result["decision"] == "permit"


@given(new_scope=st.sampled_from([1, 2, 3, 4]))
@settings(max_examples=100)
def test_prop_permission_boundary_arn(new_scope):
    """Feature: enterprise-governance-tests, Property 3: Permission boundary ARN correctness

    For any valid scope in {1..4}, _update_permission_boundary calls IAM with
    the ARN arn:aws:iam::123456789012:policy/scope-{new_scope}.

    Validates: Requirements 1.5
    """
    mock_iam = MagicMock()
    with patch.object(scope_enforcer_mod, "iam_client", mock_iam):
        scope_enforcer_mod._update_permission_boundary(new_scope)

    expected_arn = f"arn:aws:iam::123456789012:policy/scope-{new_scope}"
    mock_iam.put_role_permissions_boundary.assert_called_once_with(
        RoleName="test-agent-role",
        PermissionsBoundary=expected_arn,
    )


# -- Agent Lambda Pipeline Step Tests (Steps 6-10) ----------------------------
# Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6


class TestAgentSteps:
    """Unit tests for Agent Lambda pipeline steps 6 through 10."""

    def test_step6_bedrock_invocation(self):
        """Step 6: _invoke_bedrock sends prompt with action, target, payload."""
        mock_bedrock = MagicMock()
        mock_response_body = MagicMock()
        mock_response_body.read.return_value = json.dumps(
            {"content": [{"text": "ok"}]}
        ).encode()
        mock_bedrock.invoke_model.return_value = {"body": mock_response_body}

        with patch.object(agent_mod, "bedrock_client", mock_bedrock):
            result = agent_mod._invoke_bedrock("s3:GetObject", "builds/b47.json", {"k": "v"})

        call_args = mock_bedrock.invoke_model.call_args
        body = json.loads(call_args[1]["body"])
        prompt = body["messages"][0]["content"]
        assert "s3:GetObject" in prompt
        assert "builds/b47.json" in prompt
        assert "k" in prompt
        assert result == "ok"

    def test_step7_s3_read(self):
        """Step 7: _perform_s3_read returns parsed JSON from S3."""
        mock_s3 = MagicMock()
        body_mock = MagicMock()
        body_mock.read.return_value = json.dumps({"build_id": "47"}).encode()
        mock_s3.get_object.return_value = {"Body": body_mock}

        with patch.object(agent_mod, "s3_client", mock_s3):
            result = agent_mod._perform_s3_read("builds/b47.json")

        mock_s3.get_object.assert_called_once_with(Bucket="test-data-bucket", Key="builds/b47.json")
        assert result == {"build_id": "47"}

    def test_step7_s3_write(self):
        """Step 7: _perform_s3_write writes JSON payload to S3."""
        mock_s3 = MagicMock()
        payload = {"status": "deployed"}

        with patch.object(agent_mod, "s3_client", mock_s3):
            result = agent_mod._perform_s3_write("configs/new.json", payload)

        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-data-bucket"
        assert call_kwargs["Key"] == "configs/new.json"
        assert json.loads(call_kwargs["Body"].decode()) == payload
        assert result == {"written_key": "configs/new.json"}

    def test_step8_structured_log(self):
        """Step 8: _log_action emits structured JSON with all required fields."""
        with patch("builtins.print") as mock_print:
            agent_mod._log_action("s3:GetObject", "builds/b47.json", 1, "success")

        log_entry = json.loads(mock_print.call_args[0][0])
        for field in REQUIRED_LOG_FIELDS:
            assert field in log_entry, f"Missing field: {field}"
        assert log_entry["action_type"] == "s3:GetObject"
        assert log_entry["outcome"] == "success"

    def test_step9_success_response(self):
        """Step 9: handler returns success with bedrock_response and data."""
        mock_bedrock = MagicMock()
        body_mock = MagicMock()
        body_mock.read.return_value = json.dumps({"content": [{"text": "done"}]}).encode()
        mock_bedrock.invoke_model.return_value = {"body": body_mock}

        mock_s3 = MagicMock()
        s3_body = MagicMock()
        s3_body.read.return_value = json.dumps({"data": "value"}).encode()
        mock_s3.get_object.return_value = {"Body": s3_body}

        with patch.object(agent_mod, "bedrock_client", mock_bedrock), \
             patch.object(agent_mod, "s3_client", mock_s3):
            result = agent_mod.handler(
                {"action": "s3:GetObject", "target_resource": "test.json", "payload": {}, "scope_level": 1},
                None,
            )

        assert result["status"] == "success"
        assert "bedrock_response" in result["result"]
        assert "data" in result["result"]

    def test_step10_bedrock_failure(self):
        """Step 10: Bedrock exception returns error bedrock_failure."""
        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.side_effect = RuntimeError("timeout")

        with patch.object(agent_mod, "bedrock_client", mock_bedrock):
            result = agent_mod.handler(
                {"action": "s3:GetObject", "target_resource": "t.json", "payload": {}, "scope_level": 1},
                None,
            )

        assert result["error"] == "bedrock_failure"
        assert "timeout" in result["reason"]

    def test_step10_s3_failure(self):
        """Step 10: S3 exception returns error s3_failure."""
        mock_bedrock = MagicMock()
        body_mock = MagicMock()
        body_mock.read.return_value = json.dumps({"content": [{"text": "ok"}]}).encode()
        mock_bedrock.invoke_model.return_value = {"body": body_mock}

        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = RuntimeError("NoSuchKey")

        with patch.object(agent_mod, "bedrock_client", mock_bedrock), \
             patch.object(agent_mod, "s3_client", mock_s3):
            result = agent_mod.handler(
                {"action": "s3:GetObject", "target_resource": "missing.json", "payload": {}, "scope_level": 1},
                None,
            )

        assert result["error"] == "s3_failure"

    def test_step10_unsupported_action(self):
        """Step 10: Unrecognized action returns error unsupported_action."""
        mock_bedrock = MagicMock()
        body_mock = MagicMock()
        body_mock.read.return_value = json.dumps({"content": [{"text": "ok"}]}).encode()
        mock_bedrock.invoke_model.return_value = {"body": body_mock}

        with patch.object(agent_mod, "bedrock_client", mock_bedrock):
            result = agent_mod.handler(
                {"action": "ec2:RunInstances", "target_resource": "x", "payload": {}, "scope_level": 1},
                None,
            )

        assert result["error"] == "unsupported_action"


# -- Property-Based Tests (Agent) ----------------------------------------------


@given(
    action_type=st.sampled_from(["s3:GetObject", "s3:PutObject", "bedrock:InvokeModel"]),
    target_resource=st.text(min_size=1, max_size=100),
    scope_level=st.sampled_from([1, 2, 3, 4]),
    outcome=st.sampled_from(OUTCOMES),
)
@settings(max_examples=100)
def test_prop_agent_log_completeness(action_type, target_resource, scope_level, outcome):
    """Feature: enterprise-governance-tests, Property 4: Agent log entry completeness

    For any action/target/scope/outcome combo, _log_action emits valid JSON
    with all required fields matching inputs.

    Validates: Requirements 2.4, 8.1
    """
    with patch("builtins.print") as mock_print:
        agent_mod._log_action(action_type, target_resource, scope_level, outcome)

    log_entry = json.loads(mock_print.call_args[0][0])
    assert REQUIRED_LOG_FIELDS.issubset(log_entry.keys())
    assert log_entry["action_type"] == action_type
    assert log_entry["target_resource"] == target_resource
    assert log_entry["scope_level"] == scope_level
    assert log_entry["outcome"] == outcome


# -- Kill Switch Pipeline Step Tests (Steps 11-14) ----------------------------
# Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5


class TestKillSwitchSteps:
    """Unit tests for Kill Switch pipeline steps 11 through 14."""

    def test_step11_scope_zeroing(self):
        """Step 11: _set_scope_to_zero calls update_item with scope_level 0."""
        mock_ddb = MagicMock()
        with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb):
            kill_switch_mod._set_scope_to_zero("demo-agent")

        mock_ddb.update_item.assert_called_once()
        call_kwargs = mock_ddb.update_item.call_args[1]
        assert call_kwargs["Key"]["agent_id"]["S"] == "demo-agent"
        assert call_kwargs["ExpressionAttributeValues"][":zero"]["N"] == "0"

    def test_step12_deny_all_policy(self):
        """Step 12: _attach_deny_all_policy calls put_role_policy with correct args."""
        mock_iam = MagicMock()
        with patch.object(kill_switch_mod, "iam_client", mock_iam):
            result = kill_switch_mod._attach_deny_all_policy()

        assert result is True
        mock_iam.put_role_policy.assert_called_once_with(
            RoleName="test-agent-role",
            PolicyName=kill_switch_mod.DENY_ALL_POLICY_NAME,
            PolicyDocument=kill_switch_mod.DENY_ALL_POLICY,
        )

    def test_step13_retry_success(self):
        """Step 13: IAM fails once then succeeds on retry — returns True."""
        mock_iam = MagicMock()
        mock_iam.put_role_policy.side_effect = [RuntimeError("Throttling"), None]

        with patch.object(kill_switch_mod, "iam_client", mock_iam):
            result = kill_switch_mod._attach_deny_all_policy()

        assert result is True
        assert mock_iam.put_role_policy.call_count == 2

    def test_step13_retry_failure(self):
        """Step 13: IAM fails twice — returns False."""
        mock_iam = MagicMock()
        mock_iam.put_role_policy.side_effect = [
            RuntimeError("IAM unavailable"),
            RuntimeError("IAM still unavailable"),
        ]

        with patch.object(kill_switch_mod, "iam_client", mock_iam):
            result = kill_switch_mod._attach_deny_all_policy()

        assert result is False
        assert mock_iam.put_role_policy.call_count == 2

    def test_step14_activation_log(self):
        """Step 14: handler logs kill_switch_activated with invoker and agent_id."""
        mock_ddb = MagicMock()
        mock_iam = MagicMock()
        event = {"agent_id": "demo-agent", "invoker_identity": "admin@test.com"}

        with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
             patch.object(kill_switch_mod, "iam_client", mock_iam), \
             patch.object(kill_switch_mod, "logger") as mock_logger:
            kill_switch_mod.handler(event, None)

        log_entry = None
        for call in mock_logger.info.call_args_list:
            args = call[0]
            if args:
                try:
                    parsed = json.loads(args[0])
                    if isinstance(parsed, dict) and parsed.get("event") == "kill_switch_activated":
                        log_entry = parsed
                        break
                except (json.JSONDecodeError, TypeError):
                    continue

        assert log_entry is not None, "No kill_switch_activated log entry found"
        assert log_entry["agent_id"] == "demo-agent"
        assert log_entry["invoker_identity"] == "admin@test.com"
        assert "timestamp" in log_entry


# -- Property-Based Tests (Kill Switch) ----------------------------------------


@given(
    agent_id=st.text(alphabet=safe_chars, min_size=1, max_size=50),
    invoker_identity=st.text(alphabet=safe_chars, min_size=1, max_size=80),
)
@settings(max_examples=100)
def test_prop_kill_switch_log_completeness(agent_id, invoker_identity):
    """Feature: enterprise-governance-tests, Property 5: Kill switch activation log completeness

    For any agent_id and invoker_identity, the activation log contains the
    exact values and a non-empty timestamp.

    Validates: Requirements 3.5, 6.3
    """
    mock_ddb = MagicMock()
    mock_iam = MagicMock()
    event = {"agent_id": agent_id, "invoker_identity": invoker_identity}

    with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
         patch.object(kill_switch_mod, "iam_client", mock_iam), \
         patch.object(kill_switch_mod, "logger") as mock_logger:
        kill_switch_mod.handler(event, None)

    log_entry = None
    for call in mock_logger.info.call_args_list:
        args = call[0]
        if args:
            try:
                parsed = json.loads(args[0])
                if isinstance(parsed, dict) and parsed.get("event") == "kill_switch_activated":
                    log_entry = parsed
                    break
            except (json.JSONDecodeError, TypeError):
                continue

    assert log_entry is not None
    assert log_entry["agent_id"] == agent_id
    assert log_entry["invoker_identity"] == invoker_identity
    assert isinstance(log_entry["timestamp"], str) and len(log_entry["timestamp"]) > 0


# -- Decision Matrix Parameterized Tests (Req 4) ------------------------------
# Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5


class TestDecisionMatrix:
    """Exhaustive parameterized test of the scope/action decision matrix."""

    @pytest.mark.parametrize(
        "scope_level, action_type, expected_decision, expected_error",
        [
            (0, "read", "deny", "agent_disabled"),
            (0, "write", "deny", "agent_disabled"),
            (1, "read", "permit", None),
            (1, "write", "deny", "insufficient_scope"),
            (2, "read", "permit", None),
            (2, "write", "pending", None),
            (3, "read", "permit", None),
            (3, "write", "permit", None),
            (4, "read", "permit", None),
            (4, "write", "permit", None),
        ],
    )
    def test_decision_matrix(self, scope_level, action_type, expected_decision, expected_error):
        """Verify each of the 10 scope/action combinations."""
        event = {"agent_id": "test", "action": "s3:GetObject", "target_resource": "t"}
        result = scope_enforcer_mod.route_request(scope_level, action_type, event)
        assert result["decision"] == expected_decision
        if expected_error:
            assert result.get("error") == expected_error


# -- Fail-Safe Default Tests (Req 5) ------------------------------------------
# Validates: Requirements 5.1, 5.2, 5.3


class TestFailSafeDefaults:
    """Tests verifying fail-safe deny when scope data is missing or invalid."""

    def test_missing_scope_item(self):
        """Req 5.1: No item in Scope Table → invalid_scope error."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {}  # no Item key

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            result = scope_enforcer_mod.handler(
                {"agent_id": "unknown-agent", "action": "s3:GetObject", "target_resource": "t"},
                None,
            )

        assert result["error"] == "invalid_scope"

    def test_client_error_on_scope_lookup(self):
        """Req 5.2: DynamoDB ClientError → scope_lookup_failure."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "unavailable"}},
            "GetItem",
        )

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            result = scope_enforcer_mod.handler(
                {"agent_id": "demo-agent", "action": "s3:GetObject", "target_resource": "t"},
                None,
            )

        assert result["error"] == "scope_lookup_failure"

    def test_validate_scope_rejects_invalid(self):
        """Req 5.3: validate_scope returns False for values outside {1,2,3,4}."""
        for val in (-100, -1, 0, 5, 100, 999):
            assert scope_enforcer_mod.validate_scope(val) is False


# -- Property 6: Route request deny for invalid scope -------------------------


@given(
    scope_level=st.integers().filter(lambda x: x not in {0, 1, 2, 3, 4}),
    action_type=st.sampled_from(["read", "write"]),
)
@settings(max_examples=100)
def test_prop_route_request_deny_invalid(scope_level, action_type):
    """Feature: enterprise-governance-tests, Property 6: Route request deny for invalid scope

    For any scope outside {0..4}, route_request returns deny.

    Validates: Requirements 5.4
    """
    event = {"agent_id": "test", "action": "s3:GetObject"}
    result = scope_enforcer_mod.route_request(scope_level, action_type, event)
    assert result["decision"] == "deny"


# -- Kill Switch Dual-Action and Evidence Tests (Req 6) ------------------------
# Validates: Requirements 6.1, 6.2, 6.3, 6.4


class TestKillSwitchDualAction:
    """Tests verifying kill switch dual-action and evidence integrity."""

    def test_dual_action_success(self):
        """Req 6.1: Both scope_set_to_0 and deny_all_policy_attached in actions_taken."""
        mock_ddb = MagicMock()
        mock_iam = MagicMock()

        with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
             patch.object(kill_switch_mod, "iam_client", mock_iam):
            result = kill_switch_mod.handler(
                {"agent_id": "demo-agent", "invoker_identity": "admin"},
                None,
            )

        assert result["status"] == "success"
        assert "scope_set_to_0" in result["actions_taken"]
        assert "deny_all_policy_attached" in result["actions_taken"]

    def test_partial_success(self):
        """Req 6.2: IAM fails twice → partial_success with only scope_set_to_0."""
        mock_ddb = MagicMock()
        mock_iam = MagicMock()
        mock_iam.put_role_policy.side_effect = [RuntimeError("fail1"), RuntimeError("fail2")]

        with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
             patch.object(kill_switch_mod, "iam_client", mock_iam):
            result = kill_switch_mod.handler(
                {"agent_id": "demo-agent", "invoker_identity": "admin"},
                None,
            )

        assert result["status"] == "partial_success"
        assert "scope_set_to_0" in result["actions_taken"]
        assert "deny_all_policy_attached" not in result["actions_taken"]

    def test_evidence_in_log(self):
        """Req 6.3: Activation log contains exact invoker_identity and agent_id."""
        mock_ddb = MagicMock()
        mock_iam = MagicMock()

        with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
             patch.object(kill_switch_mod, "iam_client", mock_iam), \
             patch.object(kill_switch_mod, "logger") as mock_logger:
            kill_switch_mod.handler(
                {"agent_id": "agent-x", "invoker_identity": "sec-team@corp"},
                None,
            )

        log_entry = None
        for call in mock_logger.info.call_args_list:
            args = call[0]
            if args:
                try:
                    parsed = json.loads(args[0])
                    if isinstance(parsed, dict) and parsed.get("event") == "kill_switch_activated":
                        log_entry = parsed
                        break
                except (json.JSONDecodeError, TypeError):
                    continue

        assert log_entry is not None
        assert log_entry["agent_id"] == "agent-x"
        assert log_entry["invoker_identity"] == "sec-team@corp"

    def test_deny_all_policy_constant(self):
        """Req 6.4: DENY_ALL_POLICY has Statement with Deny/*/.*"""
        policy = json.loads(kill_switch_mod.DENY_ALL_POLICY)
        stmt = policy["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Action"] == "*"
        assert stmt["Resource"] == "*"


# -- Property 7: Kill switch dual action --------------------------------------


@given(agent_id=st.text(alphabet=safe_chars, min_size=1, max_size=50))
@settings(max_examples=100)
def test_prop_kill_switch_dual_action(agent_id):
    """Feature: enterprise-governance-tests, Property 7: Kill switch dual action

    For any agent_id, successful handler returns both actions, DynamoDB sets
    scope to 0, and IAM attaches deny-all policy.

    Validates: Requirements 6.1
    """
    mock_ddb = MagicMock()
    mock_iam = MagicMock()

    with patch.object(kill_switch_mod, "dynamodb_client", mock_ddb), \
         patch.object(kill_switch_mod, "iam_client", mock_iam):
        result = kill_switch_mod.handler(
            {"agent_id": agent_id, "invoker_identity": "test"},
            None,
        )

    assert "scope_set_to_0" in result["actions_taken"]
    assert "deny_all_policy_attached" in result["actions_taken"]
    mock_ddb.update_item.assert_called_once()
    mock_iam.put_role_policy.assert_called_once()


# -- Approval Workflow Tests (Req 7) -------------------------------------------
# Validates: Requirements 7.1, 7.2, 7.3, 7.4


class TestApprovalWorkflow:
    """Tests verifying Scope 2 approval workflow."""

    def test_scope2_pending_handler(self):
        """Req 7.1: Write at scope 2 → status pending with approval message."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": {"agent_id": {"S": "demo-agent"}, "scope_level": {"N": "2"}}
        }

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            result = scope_enforcer_mod.handler(
                {"agent_id": "demo-agent", "action": "s3:PutObject", "target_resource": "cfg.json", "payload": {}},
                None,
            )

        assert result["status"] == "pending"
        assert "approval" in result["message"].lower() or "human" in result["message"].lower()

    def test_pending_record_fields(self):
        """Req 7.2: _write_pending_record contains all required fields."""
        mock_ddb = MagicMock()
        event = {"agent_id": "a1", "action": "s3:PutObject", "target_resource": "key.json"}

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            record = scope_enforcer_mod._write_pending_record(event)

        assert REQUIRED_PENDING_FIELDS.issubset(record.keys())
        assert record["status"] == "pending"
        assert record["agent_id"] == "a1"
        assert record["proposed_action"] == "s3:PutObject"

    def test_pending_record_put_item_called(self):
        """Req 7.4: DynamoDB put_item called once with correct TableName."""
        mock_ddb = MagicMock()
        event = {"agent_id": "a1", "action": "s3:PutObject", "target_resource": "k"}

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            scope_enforcer_mod._write_pending_record(event)

        mock_ddb.put_item.assert_called_once()
        call_kwargs = mock_ddb.put_item.call_args[1]
        assert call_kwargs["TableName"] == "test-pending-table"


# -- Property 8: Pending record completeness ----------------------------------


@given(
    agent_id=st.text(min_size=1, max_size=50),
    action=st.sampled_from(WRITE_ACTIONS_SET),
    target=st.text(min_size=1, max_size=100),
)
@settings(max_examples=100)
def test_prop_pending_record_completeness(agent_id, action, target):
    """Feature: enterprise-governance-tests, Property 8: Pending record completeness

    For any agent_id/action/target, _write_pending_record produces a record
    with all required fields, status='pending', and calls put_item once.

    Validates: Requirements 7.2, 7.3, 7.4
    """
    mock_ddb = MagicMock()
    event = {"agent_id": agent_id, "action": action, "target_resource": target}

    with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
        record = scope_enforcer_mod._write_pending_record(event)

    assert REQUIRED_PENDING_FIELDS.issubset(record.keys())
    assert record["status"] == "pending"
    assert record["agent_id"] == agent_id
    assert record["proposed_action"] == action
    mock_ddb.put_item.assert_called_once()


# -- Serialization Integrity Tests (Req 8) ------------------------------------
# Validates: Requirements 8.1, 8.2, 8.3, 8.4


class TestSerializationIntegrity:
    """Tests verifying JSON serialization and data integrity."""

    def test_log_action_valid_json(self):
        """Req 8.1: _log_action output is valid JSON."""
        with patch("builtins.print") as mock_print:
            agent_mod._log_action("s3:GetObject", "key", 1, "success")

        output = mock_print.call_args[0][0]
        parsed = json.loads(output)  # raises if invalid
        assert isinstance(parsed, dict)

    def test_serializable_result(self):
        """Req 8.2: Successful handler result is JSON-serializable."""
        mock_bedrock = MagicMock()
        body_mock = MagicMock()
        body_mock.read.return_value = json.dumps({"content": [{"text": "ok"}]}).encode()
        mock_bedrock.invoke_model.return_value = {"body": body_mock}

        mock_s3 = MagicMock()
        s3_body = MagicMock()
        s3_body.read.return_value = json.dumps({"v": 1}).encode()
        mock_s3.get_object.return_value = {"Body": s3_body}

        with patch.object(agent_mod, "bedrock_client", mock_bedrock), \
             patch.object(agent_mod, "s3_client", mock_s3):
            result = agent_mod.handler(
                {"action": "s3:GetObject", "target_resource": "t.json", "payload": {}, "scope_level": 1},
                None,
            )

        serialized = json.dumps(result)  # raises if not serializable
        assert isinstance(serialized, str)

    def test_non_json_s3_read(self):
        """Req 8.3: Non-JSON S3 content returns {"raw": content}."""
        mock_s3 = MagicMock()
        body_mock = MagicMock()
        body_mock.read.return_value = b"plain text content"
        mock_s3.get_object.return_value = {"Body": body_mock}

        with patch.object(agent_mod, "s3_client", mock_s3):
            result = agent_mod._perform_s3_read("readme.txt")

        assert "raw" in result
        assert result["raw"] == "plain text content"

    def test_nested_dict_s3_write(self):
        """Req 8.4: Nested dict payload serialized as JSON bytes to S3."""
        mock_s3 = MagicMock()
        payload = {"config": {"nested": {"deep": True}}, "list": [1, 2, 3]}

        with patch.object(agent_mod, "s3_client", mock_s3):
            agent_mod._perform_s3_write("out.json", payload)

        call_kwargs = mock_s3.put_object.call_args[1]
        body_bytes = call_kwargs["Body"]
        assert isinstance(body_bytes, bytes)
        assert json.loads(body_bytes.decode()) == payload


# -- Scope Enforcer Integration Tests (Req 9) ---------------------------------
# Validates: Requirements 9.1, 9.2, 9.3, 9.4


class TestScopeEnforcerIntegration:
    """Integration-level tests of the Scope Enforcer handler with all mocks."""

    def test_read_at_scope1(self):
        """Req 9.1: Read at scope 1 → invokes Agent Lambda, returns success."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": {"agent_id": {"S": "demo-agent"}, "scope_level": {"N": "1"}}
        }
        mock_lambda = MagicMock()
        payload_mock = MagicMock()
        payload_mock.read.return_value = json.dumps({"status": "success", "result": {}}).encode()
        mock_lambda.invoke.return_value = {"Payload": payload_mock}

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb), \
             patch.object(scope_enforcer_mod, "lambda_client", mock_lambda):
            result = scope_enforcer_mod.handler(
                {"agent_id": "demo-agent", "action": "s3:GetObject", "target_resource": "t.json"},
                None,
            )

        assert result["status"] == "success"
        mock_lambda.invoke.assert_called_once()

    def test_write_at_scope2(self):
        """Req 9.2: Write at scope 2 → pending record, returns pending."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": {"agent_id": {"S": "demo-agent"}, "scope_level": {"N": "2"}}
        }

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb):
            result = scope_enforcer_mod.handler(
                {"agent_id": "demo-agent", "action": "s3:PutObject", "target_resource": "c.json", "payload": {}},
                None,
            )

        assert result["status"] == "pending"
        mock_ddb.put_item.assert_called_once()

    def test_new_scope_boundary_swap(self):
        """Req 9.3: new_scope triggers put_role_permissions_boundary."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": {"agent_id": {"S": "demo-agent"}, "scope_level": {"N": "3"}}
        }
        mock_iam = MagicMock()
        mock_lambda = MagicMock()
        payload_mock = MagicMock()
        payload_mock.read.return_value = json.dumps({"status": "success", "result": {}}).encode()
        mock_lambda.invoke.return_value = {"Payload": payload_mock}

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb), \
             patch.object(scope_enforcer_mod, "iam_client", mock_iam), \
             patch.object(scope_enforcer_mod, "lambda_client", mock_lambda):
            result = scope_enforcer_mod.handler(
                {"agent_id": "demo-agent", "action": "s3:GetObject", "target_resource": "t.json", "new_scope": 3},
                None,
            )

        mock_iam.put_role_permissions_boundary.assert_called_once()

    def test_agent_invocation_failure(self):
        """Req 9.4: Agent Lambda exception → agent_invocation_failure."""
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": {"agent_id": {"S": "demo-agent"}, "scope_level": {"N": "1"}}
        }
        mock_lambda = MagicMock()
        mock_lambda.invoke.side_effect = RuntimeError("Lambda timeout")

        with patch.object(scope_enforcer_mod, "dynamodb_client", mock_ddb), \
             patch.object(scope_enforcer_mod, "lambda_client", mock_lambda):
            result = scope_enforcer_mod.handler(
                {"agent_id": "demo-agent", "action": "s3:GetObject", "target_resource": "t.json"},
                None,
            )

        assert result["error"] == "agent_invocation_failure"
