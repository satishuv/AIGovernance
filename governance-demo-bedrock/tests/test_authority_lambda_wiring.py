"""The deployed path: authority_api.lambda_handler wired by from_environment().

Uses moto for DynamoDB, KMS, S3 and STS. Identity comes from requestContext,
exactly as API Gateway IAM authorization provides it.
"""

import importlib
import json
import os
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from tests.authority_test_support import FAKE_ENV, GE, REGION, purchase  # noqa: F401

ACCOUNT = "111122223333"
AGENT_SESSION = f"arn:aws:sts::{ACCOUNT}:assumed-role/procurement-agent-runtime/run-1"
GUARDIAN_SESSION = f"arn:aws:sts::{ACCOUNT}:assumed-role/guardian-agent-runtime/run-1"
ADMIN = f"arn:aws:sts::{ACCOUNT}:assumed-role/GovAdmin/governance-admin"


@pytest.fixture
def handler():
    with patch.dict(os.environ, FAKE_ENV), mock_aws():
        from authority_factory import create_demo_tables, seed_demo
        from operation_registry import OperationRegistry
        ddb = boto3.resource("dynamodb", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        tables = create_demo_tables(ddb, "wired-")
        seed_demo(tables, OperationRegistry.load())
        roles = ddb.create_table(
            TableName="wired-roles",
            KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}, {"AttributeName": "role", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"},
                                  {"AttributeName": "role", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST")
        roles.put_item(Item={"user_id": ADMIN, "role": "governance_admin"})
        s3.create_bucket(Bucket="wired-evidence", CreateBucketConfiguration={"LocationConstraint": REGION})
        key = lambda: kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256")["KeyMetadata"]["KeyId"]
        env = {
            "SCOPE_TABLE_NAME": "wired-scope", "AGENT_REGISTRY_TABLE_NAME": "wired-registry",
            "PENDING_APPROVAL_TABLE_NAME": "wired-approvals", "TOOL_AUTH_TABLE_NAME": "wired-tool_auth",
            "AUTHORITY_GRANT_TABLE_NAME": "wired-grants", "SPEND_LEDGER_TABLE_NAME": "wired-ledger",
            "DECISION_TRACE_TABLE_NAME": "wired-decisions", "GOVERNANCE_ROLES_TABLE_NAME": "wired-roles",
            "EVIDENCE_BUCKET_NAME": "wired-evidence", "GRANT_SIGNING_KEY_ID": key(),
            "EVIDENCE_SIGNING_KEY_ID": key(), "PROVIDER_MODE": "mock", "AWS_PROVIDER_MODE": "mock",
        }
        with patch.dict(os.environ, env):
            import authority_api
            importlib.reload(authority_api)  # fresh control plane for this environment
            yield authority_api.lambda_handler


def _event(method, resource, principal=None, body=None, path=None):
    ctx = {"identity": {"userArn": principal}} if principal else {"identity": {}}
    return {"httpMethod": method, "resource": resource, "pathParameters": path or {},
            "body": json.dumps(body) if body is not None else None, "requestContext": ctx}


def _call(handler, *args, **kwargs):
    resp = handler(_event(*args, **kwargs), None)
    return resp["statusCode"], json.loads(resp["body"])


def test_unauthenticated_requests_are_rejected(handler):
    code, _ = _call(handler, "POST", "/authority/requests", None, purchase())
    assert code == 401


def test_agent_request_execute_and_replay_through_the_api(handler):
    code, body = _call(handler, "POST", "/authority/requests", AGENT_SESSION, purchase())
    assert code == 200 and body["verdict"] == "allow"
    grant_id = body["grant"]["grant_id"]
    code, out = _call(handler, "POST", "/authority-grants/{grant_id}/execute", AGENT_SESSION, purchase(),
                      {"grant_id": grant_id})
    assert code == 200 and out["status"] == "executed" and out["evidence_chain_verified"]
    _, again = _call(handler, "POST", "/authority-grants/{grant_id}/execute", AGENT_SESSION, purchase(),
                     {"grant_id": grant_id})
    assert again["status"] == "denied"


def test_body_cannot_claim_a_different_agent(handler):
    req = purchase(agent_id="records-agent")
    _, body = _call(handler, "POST", "/authority/requests", AGENT_SESSION, req)
    assert body["verdict"] == "deny"
    assert any(s["stage"] == "identity" and s["result"] == "fail" for s in body["stages"])


def test_grant_details_are_hidden_from_other_agents(handler):
    _, body = _call(handler, "POST", "/authority/requests", AGENT_SESSION, purchase())
    grant_id = body["grant"]["grant_id"]
    code, _ = _call(handler, "GET", "/authority-grants/{grant_id}", GUARDIAN_SESSION, None, {"grant_id": grant_id})
    assert code == 403
    code, view = _call(handler, "GET", "/authority-grants/{grant_id}", AGENT_SESSION, None, {"grant_id": grant_id})
    assert code == 200 and view["signature_verified"] is True


def test_admin_plane_is_human_only(handler):
    code, out = _call(handler, "POST", "/admin/agents/{agent_id}/scope", AGENT_SESSION,
                      {"scope_level": 3}, {"agent_id": "procurement-agent"})
    assert code == 403
    code, out = _call(handler, "POST", "/admin/agents/{agent_id}/scope", ADMIN,
                      {"scope_level": 2, "reason": "review"}, {"agent_id": "procurement-agent"})
    assert code == 200 and out["scope_level"] == 2


def test_missing_configuration_fails_closed():
    with patch.dict(os.environ, FAKE_ENV, clear=False):
        import authority_api
        importlib.reload(authority_api)
        with patch.dict(os.environ, {"AUTHORITY_GRANT_TABLE_NAME": ""}):
            resp = authority_api.lambda_handler(_event("POST", "/authority/requests", AGENT_SESSION, purchase()), None)
        assert resp["statusCode"] == 503
