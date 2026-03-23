"""Property-based tests for the Agent Lambda and Kill Switch Lambda.

Uses Hypothesis to verify correctness properties across random inputs.
"""

import sys
import os
import json
from unittest.mock import patch, MagicMock, call
from io import BytesIO

# ---------------------------------------------------------------------------
# Property 5: Agent action log completeness
# **Validates: Requirements 7.2**
# ---------------------------------------------------------------------------

# Add the agent Lambda directory to sys.path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "agent")
)

# Mock boto3 clients and environment variables before importing
with patch.dict(
    os.environ,
    {
        "DATA_BUCKET_NAME": "test-data-bucket",
        "AGENT_ID": "test-agent",
        "BEDROCK_MODEL_ID": "anthropic.claude-3-haiku-20240307-v1:0",
    },
):
    with patch("boto3.client", return_value=MagicMock()):
        from lambdas.agent.index import handler as agent_handler, _log_action

from hypothesis import given, settings
import hypothesis.strategies as st


REQUIRED_LOG_FIELDS = {"timestamp", "agent_id", "action_type",
                       "target_resource", "scope_level", "outcome"}


@settings(max_examples=100)
@given(
    action_type=st.sampled_from(["s3:GetObject", "s3:PutObject"]),
    target_resource=st.text(min_size=1, max_size=100),
    scope_level=st.sampled_from([1, 2, 3, 4]),
    outcome=st.sampled_from(["success", "bedrock_failure", "s3_failure"]),
)
def test_agent_action_log_completeness(action_type, target_resource, scope_level, outcome):
    """Property 5: every agent action log entry contains all required fields.

    For any action performed by the Agent Lambda, the structured JSON log
    entry SHALL contain: timestamp, agent_id, action_type, target_resource,
    scope_level, and outcome.
    """
    with patch("lambdas.agent.index.AGENT_ID", "test-agent"):
        captured = {}

        original_print = __builtins__["print"] if isinstance(__builtins__, dict) else __builtins__.print

        def capture_print(msg, *args, **kwargs):
            try:
                parsed = json.loads(msg)
                captured.update(parsed)
            except (json.JSONDecodeError, TypeError):
                pass

        with patch("builtins.print", side_effect=capture_print):
            _log_action(action_type, target_resource, scope_level, outcome)

        assert REQUIRED_LOG_FIELDS.issubset(captured.keys()), (
            f"Missing log fields: {REQUIRED_LOG_FIELDS - captured.keys()}"
        )
        assert captured["action_type"] == action_type
        assert captured["target_resource"] == target_resource
        assert captured["scope_level"] == scope_level
        assert captured["outcome"] == outcome


# ---------------------------------------------------------------------------
# Property 6: Kill switch dual action
# **Validates: Requirements 8.2, 8.3**
# ---------------------------------------------------------------------------

# Add the kill_switch Lambda directory to sys.path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "kill_switch")
)

# Import kill switch handler with mocked environment
with patch.dict(
    os.environ,
    {
        "SCOPE_TABLE_NAME": "test-scope-table",
        "AGENT_ROLE_NAME": "test-agent-role",
    },
):
    with patch("boto3.client", return_value=MagicMock()):
        from lambdas.kill_switch.index import handler as ks_handler


@settings(max_examples=100)
@given(
    agent_id=st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=("L", "N"), whitelist_characters="-_"
    )),
)
def test_kill_switch_dual_action(agent_id):
    """Property 6: kill switch both sets scope to 0 AND attaches deny-all policy.

    For any kill switch invocation with a valid agent_id, the Kill Switch
    Lambda SHALL both set scope_level to 0 in the Scope Table AND attach
    a deny-all IAM policy to the Agent Lambda's execution role.
    """
    event = {"agent_id": agent_id, "invoker_identity": "test-operator"}

    with patch("lambdas.kill_switch.index.dynamodb_client") as mock_ddb, \
         patch("lambdas.kill_switch.index.iam_client") as mock_iam:

        result = ks_handler(event, None)

        # Scope was set to 0
        mock_ddb.update_item.assert_called_once()
        update_call = mock_ddb.update_item.call_args
        assert update_call.kwargs["Key"]["agent_id"]["S"] == agent_id
        assert ":zero" in update_call.kwargs["ExpressionAttributeValues"]
        assert update_call.kwargs["ExpressionAttributeValues"][":zero"]["N"] == "0"

        # Deny-all policy was attached
        mock_iam.put_role_policy.assert_called_once_with(
            RoleName="test-agent-role",
            PolicyName="kill-switch-deny-all",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }],
            }),
        )

        # Both actions reported
        assert "scope_set_to_0" in result["actions_taken"]
        assert "deny_all_policy_attached" in result["actions_taken"]
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# Property 7: Kill switch log completeness
# **Validates: Requirements 8.5**
# ---------------------------------------------------------------------------

REQUIRED_KS_LOG_FIELDS = {"invoker_identity", "timestamp", "agent_id"}


@settings(max_examples=100)
@given(
    agent_id=st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=("L", "N"), whitelist_characters="-_"
    )),
    invoker_identity=st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=("L", "N"), whitelist_characters="-_@."
    )),
)
def test_kill_switch_log_completeness(agent_id, invoker_identity):
    """Property 7: kill switch log entry contains invoker_identity, timestamp, agent_id.

    For any kill switch invocation, the activation log entry SHALL contain
    the invoker identity, timestamp, and affected agent_id.
    """
    event = {"agent_id": agent_id, "invoker_identity": invoker_identity}
    log_entries = []

    def capture_log(msg, *args):
        try:
            parsed = json.loads(msg if not args else msg % args)
            if "event" in parsed and parsed["event"] == "kill_switch_activated":
                log_entries.append(parsed)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    with patch("lambdas.kill_switch.index.dynamodb_client") as mock_ddb, \
         patch("lambdas.kill_switch.index.iam_client") as mock_iam, \
         patch("lambdas.kill_switch.index.logger") as mock_logger:

        mock_logger.info = MagicMock(side_effect=capture_log)
        mock_logger.error = MagicMock()

        ks_handler(event, None)

        # At least one kill_switch_activated log entry was emitted
        assert len(log_entries) >= 1, "No kill_switch_activated log entry found"

        entry = log_entries[-1]
        assert REQUIRED_KS_LOG_FIELDS.issubset(entry.keys()), (
            f"Missing log fields: {REQUIRED_KS_LOG_FIELDS - entry.keys()}"
        )
        assert entry["agent_id"] == agent_id
        assert entry["invoker_identity"] == invoker_identity
        assert "timestamp" in entry and len(entry["timestamp"]) > 0
