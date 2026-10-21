"""Policy versions take effect only after approval (P0-16, finding F-1).

Runs the real PolicyLifecycle against moto S3 and DynamoDB with the
production table key (policy_id + version), then checks what the real
policy loaders enforce.
"""
import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))

from opa_engine import OPAEngine  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from policy_lifecycle import PolicyLifecycle, active_key, is_enforceable_policy_key  # noqa: E402

BUCKET = "policy-bucket"
ROLES = ["policy_approver"]


def _policy(version, outcome):
    return {
        "policy_id": "p1", "version": version, "priority": 10,
        "conditions": {"action_group": "deployment_config"}, "outcome": outcome,
        "name": "p1", "description": "lifecycle test", "owner": "author-a",
        "approval_status": "pending",
        "created_at": "2026-10-21T00:00:00+00:00", "updated_at": "2026-10-21T00:00:00+00:00",
    }


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("CHANGE_LOG_TABLE_NAME", "")
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        table = boto3.resource("dynamodb", region_name="us-east-1").create_table(
            TableName="PolicyMetadata",
            KeySchema=[{"AttributeName": "policy_id", "KeyType": "HASH"},
                       {"AttributeName": "version", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "policy_id", "AttributeType": "S"},
                                  {"AttributeName": "version", "AttributeType": "N"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield s3, table


def _approve(lc, s3, table, version, approver="approver-b", author="author-a", roles=ROLES):
    return lc.approve_policy("p1", version, approver, roles, author,
                             s3_client=s3, bucket=BUCKET, dynamodb_table=table)


def _enforced(s3):
    engine = PolicyEngine()
    engine.load_policies(s3, BUCKET, "policies/")
    return engine.policies.get("p1")


def _status(table, version):
    return table.get_item(Key={"policy_id": "p1", "version": version})["Item"]["approval_status"]


def test_submitted_version_has_no_effect_until_approved(store):
    s3, table = store
    lc = PolicyLifecycle()
    lc.update_policy("p1", _policy(1, "allow"), "author-a", s3, BUCKET, table)
    assert _enforced(s3) is None
    _approve(lc, s3, table, 1)
    assert _enforced(s3).outcome == "allow"


def test_tightened_policy_takes_effect_and_supersedes_the_old_version(store):
    s3, table = store
    lc = PolicyLifecycle()
    lc.update_policy("p1", _policy(1, "allow"), "author-a", s3, BUCKET, table)
    _approve(lc, s3, table, 1)
    # A second submission used to crash on DynamoDB Decimal versions.
    assert lc.update_policy("p1", _policy(2, "deny"), "author-a", s3, BUCKET, table).version == 2
    assert _enforced(s3).outcome == "allow"           # still version 1 until approval
    _approve(lc, s3, table, 2)
    assert _enforced(s3).outcome == "deny"
    assert (_status(table, 1), _status(table, 2)) == ("superseded", "approved")


def test_author_cannot_approve_own_version_by_naming_someone_else(store):
    s3, table = store
    lc = PolicyLifecycle()
    lc.update_policy("p1", _policy(1, "allow"), "author-a", s3, BUCKET, table)
    with pytest.raises(ValueError, match="Separation of duties"):
        _approve(lc, s3, table, 1, approver="author-a", author="someone-else")
    assert _enforced(s3) is None and _status(table, 1) == "pending"


def test_version_cannot_be_approved_twice(store):
    s3, table = store
    lc = PolicyLifecycle()
    lc.update_policy("p1", _policy(1, "allow"), "author-a", s3, BUCKET, table)
    _approve(lc, s3, table, 1)
    with pytest.raises(ValueError, match="not pending"):
        _approve(lc, s3, table, 1, approver="approver-c")


def test_approval_needs_the_role_and_the_store(store):
    s3, table = store
    lc = PolicyLifecycle()
    lc.update_policy("p1", _policy(1, "allow"), "author-a", s3, BUCKET, table)
    with pytest.raises(ValueError, match="policy_approver"):
        _approve(lc, s3, table, 1, roles=[])
    with pytest.raises(ValueError, match="needs the policy bucket"):
        lc.approve_policy("p1", 1, "approver-b", ROLES, "author-a")
    with pytest.raises(ValueError, match="does not exist"):
        _approve(lc, s3, table, 7)
    assert _status(table, 1) == "pending" and _enforced(s3) is None


def test_rollback_restores_only_previously_approved_content(store):
    s3, table = store
    lc = PolicyLifecycle()
    lc.update_policy("p1", _policy(1, "allow"), "author-a", s3, BUCKET, table)
    _approve(lc, s3, table, 1)
    lc.update_policy("p1", _policy(2, "deny"), "author-a", s3, BUCKET, table)
    _approve(lc, s3, table, 2)
    lc.update_policy("p1", _policy(3, "escalate"), "author-a", s3, BUCKET, table)  # never approved
    with pytest.raises(ValueError, match="never approved"):
        lc.rollback_policy("p1", 3, "operator-c", s3, BUCKET, table)
    assert _enforced(s3).outcome == "deny"
    restored = lc.rollback_policy("p1", 1, "operator-c", s3, BUCKET, table)
    assert restored.version == 4
    assert _enforced(s3).outcome == "allow"
    assert (_status(table, 2), _status(table, 4)) == ("superseded", "approved")


def test_archived_and_pending_copies_are_never_loaded(store):
    s3, _ = store
    for key in ("policies/archive/p1/v1.json", "policies/pending/p1/v9.json"):
        s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(_policy(1, "allow")))
    assert _enforced(s3) is None
    opa = OPAEngine()
    opa.load_policies_from_s3(s3, BUCKET, "policies/")
    assert [r for r in opa._rules if r.name == "p1"] == []


def test_enforceable_key_filter():
    assert is_enforceable_policy_key("policies/allow-read-at-scope-1.json")
    assert is_enforceable_policy_key("policies/rego/governance.rego")
    assert is_enforceable_policy_key(active_key("p1"))
    assert not is_enforceable_policy_key("policies/archive/p1/v1.json")
    assert not is_enforceable_policy_key("policies/pending/p1/v2.json")
