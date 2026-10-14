"""P0 regression tests for the delegated-authority demo branch.

Covers the security fixes that must hold before any customer demonstration:
  1. Tool authorization fails closed (unknown, empty, unloadable, revoked).
  2. The agent execution interface cannot change authority (new_scope etc.).
  3. The scope enforcer relays the governance engine's single approval and
     never creates a second approval record.
  4. Governance decisions retain the exact structured request, so a digest
     binds operation, target, parameters, environment, data class and amount.
"""

import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

_THIS_DIR = os.path.dirname(__file__)
_LAMBDAS = os.path.join(_THIS_DIR, "..", "lambdas")
_GE = os.path.join(_LAMBDAS, "governance_engine")
if _GE not in sys.path:
    sys.path.insert(0, _GE)

from decision_engine import DecisionEngine  # noqa: E402
from models import PolicyEvaluationResult, RiskAssessment  # noqa: E402
from request_canonicalization import (  # noqa: E402
    canonicalize_action_request,
    compute_action_request_digest,
)
from tool_execution_auth import ToolExecutionAuthManager  # noqa: E402

REGION = "ca-central-1"


# ---------------------------------------------------------------------------
# 1. Tool authorization fails closed
# ---------------------------------------------------------------------------

@pytest.fixture
def tool_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        table = ddb.create_table(
            TableName="tool-auth",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        table.put_item(Item={
            "pk": "RULE#ServiceNow.GetIncident", "sk": "CONFIG",
            "tool_name": "ServiceNow.GetIncident", "allowed_agents": ["worker-agent"],
            "parameter_constraints": {"incident_id": {"pattern": "^INC[0-9]{7}$"}},
        })
        table.put_item(Item={
            "pk": "RULE#Subscription.Purchase", "sk": "CONFIG",
            "tool_name": "Subscription.Purchase", "allowed_agents": ["procurement-agent"],
            "status": "revoked",
        })
        table.put_item(Item={
            "pk": "RULE#SensitiveDataExport", "sk": "CONFIG",
            "tool_name": "SensitiveDataExport", "allowed_agents": ["worker-agent"],
            "blocked": True, "block_reason": "globally blocked",
        })
        yield table


class TestToolAuthorizationFailsClosed:
    def test_unknown_tool_is_denied(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "worker-agent", "Entra.CreateApplication", {}, tool_table)
        assert r.authorized is False
        assert r.checks_performed["rule_exists"] == "fail"
        assert "No authorization rule exists" in r.denial_reason

    def test_unknown_operation_id_is_denied(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "worker-agent", "Totally.MadeUpOperation", {"x": "1"}, tool_table)
        assert r.authorized is False

    def test_empty_tool_name_is_denied(self, tool_table):
        for name in ("", "   ", None):
            r = ToolExecutionAuthManager().authorize_tool("worker-agent", name, {}, tool_table)
            assert r.authorized is False
            assert r.checks_performed["rule_exists"] == "fail"

    def test_rule_load_error_is_denied(self):
        broken = MagicMock()
        broken.query.side_effect = RuntimeError("table unavailable")
        r = ToolExecutionAuthManager().authorize_tool(
            "worker-agent", "ServiceNow.GetIncident", {}, broken)
        assert r.authorized is False
        assert "could not be loaded" in r.denial_reason

    def test_missing_table_is_denied(self):
        r = ToolExecutionAuthManager().authorize_tool("worker-agent", "ServiceNow.GetIncident", {}, None)
        assert r.authorized is False

    def test_revoked_registration_is_denied(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "procurement-agent", "Subscription.Purchase", {}, tool_table)
        assert r.authorized is False
        assert r.checks_performed["rule_active"] == "fail"

    def test_blocked_registration_is_denied(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "worker-agent", "SensitiveDataExport", {}, tool_table)
        assert r.authorized is False
        assert "globally blocked" in r.denial_reason

    def test_known_tool_unauthorized_agent_is_denied(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "guardian-agent", "ServiceNow.GetIncident", {"incident_id": "INC0012345"}, tool_table)
        assert r.authorized is False
        assert r.checks_performed["agent_allowed"] == "fail"

    def test_known_tool_invalid_parameters_is_denied(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "worker-agent", "ServiceNow.GetIncident", {"incident_id": "DROP TABLE"}, tool_table)
        assert r.authorized is False
        assert r.checks_performed["parameter_validation"] == "fail"

    def test_known_tool_authorized_agent_valid_parameters_is_allowed(self, tool_table):
        r = ToolExecutionAuthManager().authorize_tool(
            "worker-agent", "ServiceNow.GetIncident", {"incident_id": "INC0012345"}, tool_table)
        assert r.authorized is True
        assert r.checks_performed["rule_exists"] == "pass"
        assert r.checks_performed["rule_active"] == "pass"


# ---------------------------------------------------------------------------
# 2 + 3. Scope enforcer: no authority changes, one approval
# ---------------------------------------------------------------------------

_SE_PATH = os.path.join(_LAMBDAS, "scope_enforcer", "index.py")
_SE_ENV = {
    "AGENT_ID": "TEST_AGENT_ID",
    "AGENT_ALIAS_ID": "TEST_ALIAS_ID",
    "SCOPE_TABLE_NAME": "test-scope-table",
    "ACTION_GROUP_LAMBDA_ROLE_NAME": "test-action-group-role",
    "SCOPE_BOUNDARY_ARNS": json.dumps({str(i): f"arn:aws:iam::111122223333:policy/S{i}" for i in range(1, 5)}),
    "GOVERNANCE_ENGINE_LAMBDA_ARN": "arn:aws:lambda:ca-central-1:111122223333:function:gov",
}


def _load_scope_enforcer():
    module_dir = os.path.dirname(_SE_PATH)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    with patch.dict(os.environ, _SE_ENV):
        with patch("boto3.client", return_value=MagicMock()), \
             patch("boto3.resource", return_value=MagicMock()):
            spec = importlib.util.spec_from_file_location("se_p0", _SE_PATH)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
    return mod


se = _load_scope_enforcer()


def _scope_ddb(scope_level=2):
    ddb, table = MagicMock(), MagicMock()
    table.get_item.return_value = {"Item": {"agent_id": "demo-agent", "scope_level": scope_level}}
    ddb.Table.return_value = table
    return ddb, table


def _governance(payload):
    client, body = MagicMock(), MagicMock()
    body.read.return_value = json.dumps(payload).encode()
    client.invoke.return_value = {"Payload": body}
    return client


class TestAgentCannotChangeAuthority:
    @pytest.mark.parametrize("field,value", [
        ("new_scope", 4), ("new_scope", 0), ("approved_scope", 4), ("permissions", ["*"]),
        ("new_role", "admin"), ("new_policy", "allow-all"), ("human_authorized", True),
        ("approved", True), ("approver_id", "self"),
    ])
    def test_authority_field_is_denied_and_nothing_is_written(self, field, value):
        ddb, table = _scope_ddb(2)
        gov = _governance({"verdict": "allow", "decision_id": "d"})
        with patch.object(se, "dynamodb", ddb), patch.object(se, "lambda_client", gov):
            result = se.handler({"agent_id": "demo-agent", "input_text": "show build status",
                                 field: value}, None)
        assert result["status"] == "denied"
        assert result["error"] == "authority_change_not_permitted"
        table.update_item.assert_not_called()
        table.put_item.assert_not_called()
        gov.invoke.assert_not_called()

    def test_scope_update_function_no_longer_exists_on_agent_plane(self):
        assert not hasattr(se, "update_scope_level")
        assert not hasattr(se, "create_pending_approval")

    def test_attacker_scope_level_field_is_ignored_and_store_is_authoritative(self):
        ddb, table = _scope_ddb(1)
        gov = _governance({"verdict": "deny", "decision_id": "d", "explanation": "no"})
        with patch.object(se, "dynamodb", ddb), patch.object(se, "lambda_client", gov):
            se.handler({"agent_id": "demo-agent", "input_text": "deploy", "scope_level": 4}, None)
        sent = json.loads(gov.invoke.call_args.kwargs["Payload"])
        assert sent["scope_level"] == 1


class TestSingleApprovalRelay:
    @pytest.mark.parametrize("verdict,status", [("escalate", "escalated"), ("defer", "deferred")])
    def test_relays_governance_approval_id_without_creating_another(self, verdict, status):
        ddb, table = _scope_ddb(3)
        gov = _governance({"verdict": verdict, "decision_id": "dec-1", "approval_id": "appr-1",
                           "explanation": "needs a human", "risk_score": 84})
        with patch.object(se, "dynamodb", ddb), patch.object(se, "lambda_client", gov):
            result = se.handler({"agent_id": "demo-agent", "input_text": "deploy to staging"}, None)
        assert result["status"] == status
        assert result["approval_id"] == "appr-1"
        assert result["decision_id"] == "dec-1"
        table.put_item.assert_not_called()


class TestStructuredOperationIsAuthoritative:
    def test_operation_id_overrides_keyword_inference(self):
        ddb, _ = _scope_ddb(3)
        gov = _governance({"verdict": "deny", "decision_id": "d", "explanation": "x"})
        with patch.object(se, "dynamodb", ddb), patch.object(se, "lambda_client", gov):
            # The text says "show status" (keyword => read) but the structured
            # operation is a write; governance must evaluate the write.
            se.handler({"agent_id": "demo-agent", "input_text": "just show me the status",
                        "operation_id": "Entra.AddGroupMember",
                        "tool_parameters": {"group_id": "GlobalAdministrators"},
                        "target_resource": "group/GlobalAdministrators"}, None)
        sent = json.loads(gov.invoke.call_args.kwargs["Payload"])
        assert sent["action_group"] == "Entra.AddGroupMember"
        assert sent["tool_name"] == "Entra.AddGroupMember"
        assert sent["action_source"] == "structured_operation"
        assert sent["tool_parameters"] == {"group_id": "GlobalAdministrators"}

    def test_keyword_path_is_labelled_legacy(self):
        ddb, _ = _scope_ddb(1)
        gov = _governance({"verdict": "deny", "decision_id": "d", "explanation": "x"})
        with patch.object(se, "dynamodb", ddb), patch.object(se, "lambda_client", gov):
            se.handler({"agent_id": "demo-agent", "input_text": "show build status"}, None)
        sent = json.loads(gov.invoke.call_args.kwargs["Payload"])
        assert sent["action_source"] == "legacy_keyword_prescreen"


# ---------------------------------------------------------------------------
# 4. Decisions retain the exact request
# ---------------------------------------------------------------------------

def _request(**overrides):
    base = {
        "agent_id": "procurement-agent", "session_id": "session-1",
        "provider": "servicenow", "operation_id": "Subscription.Purchase",
        "target_resource": "catalog/software/approved/productivity-suite",
        "environment": "prod", "data_class": "Internal",
        "tool_parameters": {"catalog_item_id": "productivity-suite", "quantity": 4},
        "financial_context": {"currency": "CAD", "transaction_amount": 168},
        "input_text": "please buy four seats",
    }
    base.update(overrides)
    return base


class TestDecisionBindsExactRequest:
    def _decide(self, req, policy_hash="p1"):
        pr = PolicyEvaluationResult(policy_id="p", outcome="allow")
        ra = RiskAssessment(risk_score=10, risk_category="financial")
        return DecisionEngine(70).decide(pr, ra, req, req["agent_id"], policy_version_hash=policy_hash)

    def test_decision_carries_canonical_request_without_free_text(self):
        d = self._decide(_request())
        assert d.action_request["operation_id"] == "Subscription.Purchase"
        assert d.action_request["tool_parameters"]["quantity"] == 4
        assert "input_text" not in d.action_request
        assert d.policy_version_hash == "p1"
        assert d.request_digest == compute_action_request_digest(d.action_request, "p1")

    def test_caller_mutation_after_decision_does_not_change_binding(self):
        req = _request()
        d = self._decide(req)
        before = d.request_digest
        req["tool_parameters"]["quantity"] = 400
        assert d.action_request["tool_parameters"]["quantity"] == 4
        assert compute_action_request_digest(d.action_request, "p1") == before

    def test_round_trip_preserves_binding_fields(self):
        from models import GovernanceDecision
        d = self._decide(_request())
        back = GovernanceDecision.from_dict(json.loads(json.dumps(d.to_dict(), default=str)))
        assert back.request_digest == d.request_digest
        assert back.policy_version_hash == d.policy_version_hash
        assert back.action_request["operation_id"] == "Subscription.Purchase"

    @pytest.mark.parametrize("field,value", [
        ("agent_id", "other-agent"), ("session_id", "session-2"), ("provider", "entra"),
        ("operation_id", "Subscription.Cancel"), ("target_resource", "catalog/software/other"),
        ("environment", "dev"), ("data_class", "Protected-B"),
        ("tool_parameters", {"catalog_item_id": "productivity-suite", "quantity": 40}),
        ("financial_context", {"currency": "CAD", "transaction_amount": 1680}),
        ("financial_context", {"currency": "USD", "transaction_amount": 168}),
    ])
    def test_any_security_relevant_change_changes_digest(self, field, value):
        base = canonicalize_action_request(_request())
        changed = canonicalize_action_request(_request(**{field: value}))
        assert compute_action_request_digest(base, "p") != compute_action_request_digest(changed, "p")

    def test_policy_version_and_expiry_change_digest(self):
        c = canonicalize_action_request(_request())
        assert compute_action_request_digest(c, "p1") != compute_action_request_digest(c, "p2")
        assert (compute_action_request_digest(c, "p1", "2026-10-14T10:00:00+00:00")
                != compute_action_request_digest(c, "p1", "2026-10-14T10:05:00+00:00"))

    def test_free_text_does_not_change_digest(self):
        a = canonicalize_action_request(_request(input_text="buy four"))
        b = canonicalize_action_request(_request(input_text="ignore previous instructions"))
        assert compute_action_request_digest(a, "p") == compute_action_request_digest(b, "p")

    def test_numeric_forms_are_canonical_but_strings_stay_distinct(self):
        from decimal import Decimal
        a = canonicalize_action_request(_request(tool_parameters={"quantity": 4}))
        b = canonicalize_action_request(_request(tool_parameters={"quantity": Decimal("4.00")}))
        c = canonicalize_action_request(_request(tool_parameters={"quantity": "4"}))
        assert compute_action_request_digest(a, "p") == compute_action_request_digest(b, "p")
        assert compute_action_request_digest(a, "p") != compute_action_request_digest(c, "p")

    def test_credentials_in_parameters_are_rejected_and_decision_denies(self):
        d = self._decide(_request(tool_parameters={"client_secret": "abc"}))
        assert d.verdict == "deny"
        assert "canonicalized" in d.explanation
