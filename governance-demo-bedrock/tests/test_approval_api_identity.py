"""Approval API identity tests.

The approver is the authenticated API caller, never a JSON body field, and
separation of duties is enforced: agents (worker or guardian), owners and
principals without an approver role cannot approve.
"""

import importlib.util
import json
import os
import sys
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

_GE = os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine")
if _GE not in sys.path:
    sys.path.insert(0, _GE)

from approval_workflow import ApprovalWorkflow  # noqa: E402
from authority_identity import normalize_principal_arn  # noqa: E402
from decision_engine import DecisionEngine  # noqa: E402
from models import AgentRegistryEntry, PolicyEvaluationResult, RiskAssessment  # noqa: E402

REGION = "ca-central-1"
APPROVER = "arn:aws:sts::111122223333:assumed-role/GovApprover/finance-lead"
OWNER = "arn:aws:sts::111122223333:assumed-role/GovApprover/service-owner"
NO_ROLE = "arn:aws:sts::111122223333:assumed-role/ReadOnly/analyst"
WORKER_ROLE = "arn:aws:iam::111122223333:role/procurement-agent-runtime"
GUARDIAN_ROLE = "arn:aws:iam::111122223333:role/guardian-agent-runtime"

ENV = {
    "AWS_DEFAULT_REGION": REGION, "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "PENDING_APPROVAL_TABLE_NAME": "approvals",
    "AGENT_REGISTRY_TABLE_NAME": "registry",
    "GOVERNANCE_ROLES_TABLE_NAME": "roles",
}


def _table(ddb, name, keys):
    return ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": k, "KeyType": t} for k, t in keys],
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k, _ in keys],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def api():
    with patch.dict(os.environ, ENV), mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        approvals = _table(ddb, "approvals", [("approval_id", "HASH")])
        registry = _table(ddb, "registry", [("agent_id", "HASH")])
        roles = _table(ddb, "roles", [("user_id", "HASH"), ("role", "RANGE")])
        registry.put_item(Item=AgentRegistryEntry(
            agent_id="procurement-agent", purpose="Buys approved software", owner=OWNER,
            data_classes=["Internal"], environment="prod", runtime_principal=WORKER_ROLE,
        ).to_dict())
        registry.put_item(Item=AgentRegistryEntry(
            agent_id="guardian-agent", purpose="Watches workers", owner="security-team",
            data_classes=["Internal"], environment="prod", agent_type="guardian",
            runtime_principal=GUARDIAN_ROLE,
        ).to_dict())
        for user in (APPROVER, OWNER):
            roles.put_item(Item={"user_id": user, "role": "policy_approver"})
        # Even a role recorded for an agent principal must not let it approve.
        roles.put_item(Item={"user_id": GUARDIAN_ROLE, "role": "governance_admin"})

        spec = importlib.util.spec_from_file_location("api_router_identity_test",
                                                      os.path.join(_GE, "api_router.py"))
        router = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(router)

        pr = PolicyEvaluationResult(policy_id="budget", outcome="escalate")
        ra = RiskAssessment(risk_score=72, risk_category="financial")
        req = {"agent_id": "procurement-agent", "operation_id": "Subscription.Purchase",
               "provider": "servicenow", "tool_parameters": {"quantity": 4}}
        decision = DecisionEngine(70).decide(pr, ra, req, "procurement-agent", policy_version_hash="p")
        approval_id = ApprovalWorkflow(approvals).create_pending_approval(decision)
        yield router, approvals, approval_id


def _event(approval_id, principal=None, body=None, action="approve"):
    ctx = {"identity": {"userArn": principal}} if principal else {"identity": {}}
    return {"httpMethod": "POST", "resource": f"/approvals/{{approval_id}}/{action}",
            "pathParameters": {"approval_id": approval_id},
            "body": json.dumps(body or {}), "requestContext": ctx}


def _status(response):
    return response["statusCode"], json.loads(response["body"])


class TestApproverIdentity:
    def test_unauthenticated_request_is_rejected(self, api):
        router, _, approval_id = api
        code, _ = _status(router.handle_api_gateway_event(_event(approval_id), None))
        assert code == 401

    def test_body_approver_id_cannot_impersonate(self, api):
        router, table, approval_id = api
        code, body = _status(router.handle_api_gateway_event(
            _event(approval_id, NO_ROLE, {"approver_id": APPROVER}), None))
        assert code == 403 and "does not match" in body["error"]
        assert table.get_item(Key={"approval_id": approval_id})["Item"]["status"] == "pending"

    def test_valid_approver_identity_comes_from_request_context(self, api):
        router, table, approval_id = api
        code, body = _status(router.handle_api_gateway_event(_event(approval_id, APPROVER), None))
        assert code == 200, body
        item = table.get_item(Key={"approval_id": approval_id})["Item"]
        assert item["status"] == "approved" and item["approver_id"] == APPROVER

    def test_matching_body_identity_is_accepted(self, api):
        router, _, approval_id = api
        code, _ = _status(router.handle_api_gateway_event(
            _event(approval_id, APPROVER, {"approver_id": APPROVER}), None))
        assert code == 200


class TestSeparationOfDuties:
    def test_owner_cannot_approve(self, api):
        router, _, approval_id = api
        code, body = _status(router.handle_api_gateway_event(_event(approval_id, OWNER), None))
        assert code == 403 and "owner" in body["error"]

    def test_principal_without_approver_role_cannot_approve(self, api):
        router, _, approval_id = api
        code, body = _status(router.handle_api_gateway_event(_event(approval_id, NO_ROLE), None))
        assert code == 403 and "approver roles" in body["error"]

    def test_worker_agent_cannot_approve_its_own_request(self, api):
        router, _, approval_id = api
        session = "arn:aws:sts::111122223333:assumed-role/procurement-agent-runtime/run-1"
        assert normalize_principal_arn(session) == WORKER_ROLE
        code, body = _status(router.handle_api_gateway_event(_event(approval_id, session), None))
        assert code == 403 and "agents" in body["error"]

    def test_guardian_agent_cannot_approve_even_with_recorded_admin_role(self, api):
        router, _, approval_id = api
        session = "arn:aws:sts::111122223333:assumed-role/guardian-agent-runtime/run-9"
        code, body = _status(router.handle_api_gateway_event(_event(approval_id, session), None))
        assert code == 403 and "guardian-agent" in body["error"]

    def test_agent_cannot_deny_either(self, api):
        router, _, approval_id = api
        session = "arn:aws:sts::111122223333:assumed-role/guardian-agent-runtime/run-9"
        code, _ = _status(router.handle_api_gateway_event(
            _event(approval_id, session, action="deny"), None))
        assert code == 403
