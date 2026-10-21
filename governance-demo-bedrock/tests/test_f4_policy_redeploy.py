"""F-4: a redeploy must not revert approved policy changes.

Source of truth: the deployment owns the baseline under policies/, the policy
lifecycle owns policies/active/. The deployment never deletes lifecycle keys
(asserted on the synthesized template), and both engines enforce an approved
lifecycle version over the baseline policy with the same identity, whatever
order S3 lists the keys in.
"""

import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

_HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_HERE, "..", "lambdas", "governance_engine"))
sys.path.insert(0, os.path.join(_HERE, ".."))

from opa_engine import OPAEngine  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from policy_lifecycle import PolicyLifecycle, is_lifecycle_active_key, lifecycle_first  # noqa: E402

BUCKET = "policy-bucket"


def _policy(version, outcome, policy_id="p1"):
    return {
        "policy_id": policy_id, "version": version, "priority": 10,
        "conditions": {"action_group": "deployment_config"}, "outcome": outcome,
        "name": policy_id, "description": "redeploy test", "owner": "author-a",
        "approval_status": "approved",
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


def _tighten_through_lifecycle(s3, table):
    """The deployed baseline allows p1; the lifecycle approves a deny."""
    # "z-baseline.json" lists after "active/", so before F-4 the baseline
    # loaded last and replaced the approved version in the JSON engine.
    s3.put_object(Bucket=BUCKET, Key="policies/z-baseline.json", Body=json.dumps(_policy(1, "allow")))
    s3.put_object(Bucket=BUCKET, Key="policies/other.json",
                  Body=json.dumps(_policy(1, "allow", policy_id="p2")))
    lifecycle = PolicyLifecycle()
    submitted = lifecycle.update_policy("p1", _policy(2, "deny"), "author-a", s3, BUCKET, table)
    lifecycle.approve_policy("p1", submitted.version, "approver-b", ["policy_approver"], "author-a",
                             s3_client=s3, bucket=BUCKET, dynamodb_table=table)


def test_json_engine_enforces_the_approved_version_over_the_baseline(store):
    s3, table = store
    _tighten_through_lifecycle(s3, table)
    engine = PolicyEngine()
    engine.load_policies(s3, BUCKET, "policies/")
    assert engine.policies["p1"].outcome == "deny"
    assert engine.policies["p2"].outcome == "allow"  # baseline without a lifecycle version


def test_opa_engine_drops_the_overridden_baseline_rule(store):
    s3, table = store
    _tighten_through_lifecycle(s3, table)
    engine = OPAEngine()
    engine.load_policies_from_s3(s3, BUCKET, "policies/")
    p1_rules = [r.outcome for r in engine._rules if r.name == "p1"]
    assert p1_rules == ["deny"]
    assert [r.outcome for r in engine._rules if r.name == "p2"] == ["allow"]


def test_active_keys_are_recognized_and_ordered_first():
    keys = ["policies/allow.json", "policies/active/p1.json", "policies/archive/p1.json"]
    assert [is_lifecycle_active_key(k) for k in keys] == [False, True, False]
    assert lifecycle_first(keys)[0] == "policies/active/p1.json"


def test_redeploy_never_deletes_lifecycle_policies():
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    from governance_bedrock_stack import GovernanceBedrockStack

    app = cdk.App(context={"skip_cloudtrail": True})
    stack = GovernanceBedrockStack(app, "F4Stack", env=cdk.Environment(region="ca-central-1"))
    deployments = Template.from_stack(stack).find_resources("Custom::CDKBucketDeployment", {
        "Properties": {"DestinationBucketKeyPrefix": "policies/"}})
    assert len(deployments) == 1
    props = next(iter(deployments.values()))["Properties"]
    # Prune stays on for the baseline; the lifecycle prefixes are excluded
    # from the sync, so they are neither overwritten nor deleted.
    assert props.get("Prune", True) is True
    assert set(props["Exclude"]) == {"active/*", "archive/*", "pending/*"}
