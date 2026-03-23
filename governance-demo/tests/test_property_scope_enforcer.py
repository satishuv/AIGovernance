"""Property-based tests for the Scope Enforcer Lambda.

Uses Hypothesis to verify correctness properties across random inputs.
"""

import json
import sys
import os
from unittest.mock import patch, MagicMock

# Add the scope_enforcer Lambda directory to sys.path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "scope_enforcer")
)

# Mock boto3 clients and environment variables before importing the module,
# since index.py creates boto3 clients at module level.
with patch.dict(
    os.environ,
    {
        "SCOPE_TABLE_NAME": "test-scope-table",
        "PENDING_TABLE_NAME": "test-pending-table",
        "AGENT_FUNCTION_NAME": "test-agent-function",
        "AGENT_ROLE_NAME": "test-agent-role",
        "SCOPE_1_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-1",
        "SCOPE_2_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-2",
        "SCOPE_3_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-3",
        "SCOPE_4_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-4",
    },
):
    with patch("boto3.client", return_value=MagicMock()):
        from index import validate_scope

from hypothesis import given, settings
import hypothesis.strategies as st


# ---------------------------------------------------------------------------
# Property 1: Scope level validation
# **Validates: Requirements 2.2, 2.4**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(level=st.integers())
def test_scope_level_validation(level):
    """Property 1: validate_scope returns True iff level in {1,2,3,4}.

    For any integer value provided as a scope level, validate_scope SHALL
    return True if and only if the value is in the set {1, 2, 3, 4}.
    """
    result = validate_scope(level)
    expected = level in {1, 2, 3, 4}
    assert result == expected, (
        f"validate_scope({level}) returned {result}, expected {expected}"
    )


# We need additional imports for the remaining property tests.
# Re-import route_request and classify_action from the scope enforcer module
# using the same patching approach.
with patch.dict(
    os.environ,
    {
        "SCOPE_TABLE_NAME": "test-scope-table",
        "PENDING_TABLE_NAME": "test-pending-table",
        "AGENT_FUNCTION_NAME": "test-agent-function",
        "AGENT_ROLE_NAME": "test-agent-role",
        "SCOPE_1_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-1",
        "SCOPE_2_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-2",
        "SCOPE_3_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-3",
        "SCOPE_4_BOUNDARY_ARN": "arn:aws:iam::123456789012:policy/scope-4",
    },
):
    with patch("boto3.client", return_value=MagicMock()):
        import index as _scope_enforcer_module
        from index import route_request, classify_action, _write_pending_record, _update_permission_boundary


# ---------------------------------------------------------------------------
# Property 2: Scope-based access control decision matrix
# **Validates: Requirements 3.2, 3.3, 3.4, 3.5**
# ---------------------------------------------------------------------------

VALID_SCOPES = [0, 1, 2, 3, 4]
READ_ACTIONS_SET = ["s3:GetObject"]
WRITE_ACTIONS_SET = ["s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"]
ALL_ACTIONS = READ_ACTIONS_SET + WRITE_ACTIONS_SET


@settings(max_examples=100)
@given(
    scope_level=st.sampled_from(VALID_SCOPES),
    action=st.sampled_from(ALL_ACTIONS),
)
def test_scope_access_control_decision_matrix(scope_level, action):
    """Property 2: routing decision matches the expected outcome for each
    (scope_level, action_type) combination.

    - Scope 0 + any -> deny
    - Scope 1 + read -> permit
    - Scope 1 + write -> deny
    - Scope 2 + read -> permit
    - Scope 2 + write -> pending
    - Scope 3 + any -> permit
    - Scope 4 + any -> permit
    """
    action_type = classify_action(action)
    event = {"agent_id": "test", "action": action, "target_resource": "test/key"}
    decision = route_request(scope_level, action_type, event)

    if scope_level == 0:
        assert decision["decision"] == "deny", (
            f"Scope 0 should deny all, got {decision}"
        )
    elif scope_level == 1:
        if action_type == "read":
            assert decision["decision"] == "permit", (
                f"Scope 1 + read should permit, got {decision}"
            )
        else:
            assert decision["decision"] == "deny", (
                f"Scope 1 + write should deny, got {decision}"
            )
    elif scope_level == 2:
        if action_type == "read":
            assert decision["decision"] == "permit", (
                f"Scope 2 + read should permit, got {decision}"
            )
        else:
            assert decision["decision"] == "pending", (
                f"Scope 2 + write should be pending, got {decision}"
            )
    elif scope_level == 3:
        assert decision["decision"] == "permit", (
            f"Scope 3 should permit all, got {decision}"
        )
    elif scope_level == 4:
        assert decision["decision"] == "permit", (
            f"Scope 4 should permit all, got {decision}"
        )


# ---------------------------------------------------------------------------
# Property 3: Permission boundary swap on scope change
# **Validates: Requirements 4.6**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    new_scope=st.sampled_from([1, 2, 3, 4]),
)
def test_permission_boundary_swap(new_scope):
    """Property 3: on scope change, the correct boundary ARN is used.

    For any valid scope transition, _update_permission_boundary SHALL call
    iam:PutRolePermissionsBoundary with the ARN matching the target scope.
    """
    expected_arn = f"arn:aws:iam::123456789012:policy/scope-{new_scope}"

    with patch.object(_scope_enforcer_module, "iam_client") as mock_iam:
        _update_permission_boundary(new_scope)
        mock_iam.put_role_permissions_boundary.assert_called_once_with(
            RoleName="test-agent-role",
            PermissionsBoundary=expected_arn,
        )


# ---------------------------------------------------------------------------
# Property 4: Pending record completeness at Scope 2
# **Validates: Requirements 6.2, 6.3**
# ---------------------------------------------------------------------------

REQUIRED_PENDING_FIELDS = {"request_id", "agent_id", "proposed_action",
                           "target_resource", "timestamp", "status"}


@settings(max_examples=100)
@given(
    agent_id=st.text(min_size=1, max_size=50),
    action=st.sampled_from(WRITE_ACTIONS_SET),
    target=st.text(min_size=1, max_size=100),
)
def test_pending_record_completeness(agent_id, action, target):
    """Property 4: pending records contain all required fields with status='pending'.

    For any write operation at Scope 2, the record written to the Pending
    Table SHALL contain all required fields and status SHALL be 'pending'.
    """
    event = {
        "agent_id": agent_id,
        "action": action,
        "target_resource": target,
    }

    with patch.object(_scope_enforcer_module, "dynamodb_client") as mock_ddb:
        record = _write_pending_record(event)

        # All required fields present
        assert REQUIRED_PENDING_FIELDS.issubset(record.keys()), (
            f"Missing fields: {REQUIRED_PENDING_FIELDS - record.keys()}"
        )
        # Status is always "pending"
        assert record["status"] == "pending", (
            f"Expected status='pending', got '{record['status']}'"
        )
        # agent_id matches input
        assert record["agent_id"] == agent_id
        # proposed_action matches input
        assert record["proposed_action"] == action
        # target_resource matches input
        assert record["target_resource"] == target
        # DynamoDB PutItem was called
        mock_ddb.put_item.assert_called_once()


# ---------------------------------------------------------------------------
# Property 5: Agent action log completeness
# **Validates: Requirements 7.2**
# ---------------------------------------------------------------------------

# Import the agent module's _log_action using importlib.util to avoid
# name collision with the scope_enforcer's index module already loaded.
import importlib.util

_agent_module_path = os.path.join(
    os.path.dirname(__file__), "..", "lambdas", "agent", "index.py"
)

with patch.dict(
    os.environ,
    {
        "DATA_BUCKET_NAME": "test-data-bucket",
        "AGENT_ID": "demo-agent",
        "BEDROCK_MODEL_ID": "anthropic.claude-3-haiku-20240307-v1:0",
    },
):
    with patch("boto3.client", return_value=MagicMock()):
        _agent_spec = importlib.util.spec_from_file_location(
            "agent_index", _agent_module_path
        )
        agent_index = importlib.util.module_from_spec(_agent_spec)
        _agent_spec.loader.exec_module(agent_index)

_log_action = agent_index._log_action

REQUIRED_LOG_FIELDS = {"timestamp", "agent_id", "action_type",
                       "target_resource", "scope_level", "outcome"}

AGENT_ACTIONS = ["s3:GetObject", "s3:PutObject", "bedrock:InvokeModel"]
OUTCOMES = ["success", "bedrock_failure", "s3_failure", "unsupported_action"]


@settings(max_examples=100)
@given(
    action_type=st.sampled_from(AGENT_ACTIONS),
    target_resource=st.text(min_size=1, max_size=100),
    scope_level=st.sampled_from([1, 2, 3, 4]),
    outcome=st.sampled_from(OUTCOMES),
)
def test_agent_action_log_completeness(action_type, target_resource, scope_level, outcome):
    """Property 5: agent action logs contain all required fields.

    For any action performed by the Agent Lambda, the structured JSON log
    entry SHALL contain all required fields: timestamp, agent_id,
    action_type, target_resource, scope_level, and outcome.

    **Validates: Requirements 7.2**
    """
    with patch("builtins.print") as mock_print:
        _log_action(action_type, target_resource, scope_level, outcome)

        mock_print.assert_called_once()
        log_output = mock_print.call_args[0][0]
        log_entry = json.loads(log_output)

        # All required fields must be present
        assert REQUIRED_LOG_FIELDS.issubset(log_entry.keys()), (
            f"Missing fields: {REQUIRED_LOG_FIELDS - log_entry.keys()}"
        )

        # Field values must match inputs
        assert log_entry["action_type"] == action_type
        assert log_entry["target_resource"] == target_resource
        assert log_entry["scope_level"] == scope_level
        assert log_entry["outcome"] == outcome
        assert log_entry["agent_id"] == "demo-agent"

        # Timestamp must be a non-empty string
        assert isinstance(log_entry["timestamp"], str)
        assert len(log_entry["timestamp"]) > 0


# ---------------------------------------------------------------------------
# Property 6: Kill switch dual action
# **Validates: Requirements 8.2, 8.3**
# ---------------------------------------------------------------------------

# Import the kill_switch module using importlib.util to avoid name collision
# with the scope_enforcer's index module already loaded (same pattern as
# Property 5 for the agent module).

_kill_switch_module_path = os.path.join(
    os.path.dirname(__file__), "..", "lambdas", "kill_switch", "index.py"
)

with patch.dict(
    os.environ,
    {
        "SCOPE_TABLE_NAME": "test-scope-table",
        "AGENT_ROLE_NAME": "test-agent-role",
    },
):
    with patch("boto3.client", return_value=MagicMock()):
        _ks_spec = importlib.util.spec_from_file_location(
            "kill_switch_index", _kill_switch_module_path
        )
        kill_switch_index = importlib.util.module_from_spec(_ks_spec)
        _ks_spec.loader.exec_module(kill_switch_index)


@settings(max_examples=100)
@given(
    agent_id=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_"),
        min_size=1,
        max_size=50,
    ),
)
def test_kill_switch_dual_action(agent_id):
    """Property 6: kill switch sets scope to 0 AND attaches deny-all policy.

    For any kill switch invocation with a valid agent_id, the Kill Switch
    Lambda SHALL both set the agent's scope_level to 0 in the Scope Table
    AND attach a deny-all IAM policy to the Agent Lambda's execution role.

    **Validates: Requirements 8.2, 8.3**
    """
    mock_ddb = MagicMock()
    mock_iam = MagicMock()

    event = {"agent_id": agent_id, "invoker_identity": "test-operator"}

    with patch.object(kill_switch_index, "dynamodb_client", mock_ddb), \
         patch.object(kill_switch_index, "iam_client", mock_iam):
        result = kill_switch_index.handler(event, None)

    # 1. DynamoDB update_item was called to set scope to 0
    mock_ddb.update_item.assert_called_once()
    call_kwargs = mock_ddb.update_item.call_args
    ddb_args = call_kwargs[1] if call_kwargs[1] else call_kwargs[0]
    assert ddb_args["Key"]["agent_id"]["S"] == agent_id
    assert ":zero" in ddb_args["ExpressionAttributeValues"]
    assert ddb_args["ExpressionAttributeValues"][":zero"]["N"] == "0"

    # 2. IAM put_role_policy was called to attach deny-all policy
    mock_iam.put_role_policy.assert_called_once_with(
        RoleName="test-agent-role",
        PolicyName="kill-switch-deny-all",
        PolicyDocument=kill_switch_index.DENY_ALL_POLICY,
    )

    # 3. Both actions are reported in actions_taken
    assert "scope_set_to_0" in result["actions_taken"], (
        f"Expected 'scope_set_to_0' in actions_taken, got {result['actions_taken']}"
    )
    assert "deny_all_policy_attached" in result["actions_taken"], (
        f"Expected 'deny_all_policy_attached' in actions_taken, got {result['actions_taken']}"
    )

    # 4. Status is "success"
    assert result["status"] == "success", (
        f"Expected status='success', got '{result['status']}'"
    )


# ---------------------------------------------------------------------------
# Property 7: Kill switch log completeness
# **Validates: Requirements 8.5**
# ---------------------------------------------------------------------------

REQUIRED_KILL_SWITCH_LOG_FIELDS = {"invoker_identity", "timestamp", "agent_id"}


@settings(max_examples=100)
@given(
    agent_id=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_"),
        min_size=1,
        max_size=50,
    ),
    invoker_identity=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_@."),
        min_size=1,
        max_size=80,
    ),
)
def test_kill_switch_log_completeness(agent_id, invoker_identity):
    """Property 7: kill switch activation log contains all required fields.

    For any kill switch invocation, the activation log entry SHALL contain
    the invoker identity, timestamp, and affected agent_id.

    **Validates: Requirements 8.5**
    """
    mock_ddb = MagicMock()
    mock_iam = MagicMock()

    event = {"agent_id": agent_id, "invoker_identity": invoker_identity}

    with patch.object(kill_switch_index, "dynamodb_client", mock_ddb), \
         patch.object(kill_switch_index, "iam_client", mock_iam), \
         patch.object(kill_switch_index, "logger") as mock_logger:
        kill_switch_index.handler(event, None)

    # Find the structured JSON activation log entry among logger.info calls
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

    assert log_entry is not None, "No structured kill_switch_activated log entry found"

    # All required fields must be present
    assert REQUIRED_KILL_SWITCH_LOG_FIELDS.issubset(log_entry.keys()), (
        f"Missing fields: {REQUIRED_KILL_SWITCH_LOG_FIELDS - log_entry.keys()}"
    )

    # Field values must match inputs
    assert log_entry["agent_id"] == agent_id, (
        f"Expected agent_id='{agent_id}', got '{log_entry['agent_id']}'"
    )
    assert log_entry["invoker_identity"] == invoker_identity, (
        f"Expected invoker_identity='{invoker_identity}', got '{log_entry['invoker_identity']}'"
    )

    # Timestamp must be a non-empty string
    assert isinstance(log_entry["timestamp"], str), (
        f"Expected timestamp to be a string, got {type(log_entry['timestamp'])}"
    )
    assert len(log_entry["timestamp"]) > 0, "Timestamp must not be empty"
