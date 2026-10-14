"""Credential broker tests: same governance contract, provider-native enforcement."""

import copy
import json
from unittest.mock import MagicMock

import pytest

from tests.authority_test_support import offline_demo, purchase

from credential_broker import (  # noqa: E402
    AwsStsAdapter, BrokerRefusal, EntraAdapter, ProviderNotConfigured, ServiceNowAdapter,
    build_session_policy, resource_arn_for,
)
from delegated_authority import GrantStore, LocalDemoSigner, VerifiedGrant  # noqa: E402


def _aws_request(bucket, key="reports/approved/price-benchmark-2026.csv"):
    return {"agent_id": "procurement-agent", "session_id": "s-aws", "provider": "aws",
            "operation_id": "AWS.ReadObject", "target_resource": f"aws/s3/{bucket}/{key}",
            "environment": "prod", "tool_parameters": {}}


class TestBrokerRefusesUnverifiedAuthority:
    def test_requires_verified_and_consumed_grant_from_this_store(self):
        with offline_demo() as demo:
            cp = demo.control_plane
            req = purchase()
            grant_id = cp.request_authority(req, demo.agent("procurement-agent"))["grant"]["grant_id"]
            grant = cp.grants.get(grant_id)
            spec = cp.operations.get("Subscription.Purchase")
            with pytest.raises(BrokerRefusal):
                cp.broker.exchange(grant, spec)  # a raw grant is not proof
            foreign = GrantStore(demo.tables["grants"], LocalDemoSigner())
            with pytest.raises(BrokerRefusal):
                cp.broker.exchange(VerifiedGrant(grant, {}, foreign), spec)
            with pytest.raises(BrokerRefusal):
                cp.broker.exchange(VerifiedGrant(grant, {}, cp.grants),
                                   cp.operations.get("Subscription.ListCatalog"))

    def test_execution_never_returns_or_records_the_secret(self):
        with offline_demo() as demo:
            cp = demo.control_plane
            req = purchase()
            grant_id = cp.request_authority(req, demo.agent("procurement-agent"))["grant"]["grant_id"]
            out = cp.execute(grant_id, req, demo.agent("procurement-agent"))
            assert out["credential"]["secret_preview"] == "********"
            assert "_secret" not in json.dumps(out)
            for record in cp.evidence.for_agent("procurement-agent"):
                assert "_secret" not in json.dumps(record)
            assert out["evidence_chain_verified"] is True


class TestAwsSessionPolicy:
    def test_policy_allows_one_action_on_one_arn_until_grant_expiry(self):
        grant = MagicMock(expires_at="2026-10-14T12:05:00+00:00", target_resource="aws/s3/b/reports/approved/x.csv")
        spec = MagicMock(aws_actions=("s3:GetObject",), operation_id="AWS.ReadObject")
        policy = build_session_policy(grant, spec, resource_arn_for(grant.target_resource))
        stmt = policy["Statement"][0]
        assert stmt["Effect"] == "Allow" and stmt["Action"] == ["s3:GetObject"]
        assert stmt["Resource"] == ["arn:aws:s3:::b/reports/approved/x.csv"]
        assert stmt["Condition"] == {"DateLessThan": {"aws:CurrentTime": "2026-10-14T12:05:00Z"}}
        assert len(policy["Statement"]) == 1

    @pytest.mark.parametrize("target", ["aws/s3/b/reports/*", "aws/s3/b/", "azure/blob/x", "aws/s3/b"])
    def test_wildcard_or_foreign_targets_are_refused(self, target):
        with pytest.raises(BrokerRefusal):
            resource_arn_for(target)

    def test_live_mode_assumes_role_with_grant_session_policy_and_tags(self):
        with offline_demo(aws_mode="live") as demo:
            cp = demo.control_plane
            adapter = demo.adapters["aws"]
            calls = []
            original = adapter._sts.assume_role

            def spy(**kwargs):
                calls.append(copy.deepcopy(kwargs))
                return original(**kwargs)

            adapter._sts.assume_role = spy
            req = _aws_request(demo.bucket)
            resp = cp.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "allow"
            out = cp.execute(resp["grant"]["grant_id"], req, demo.agent("procurement-agent"))
            assert out["status"] == "executed"
            assert len(calls) == 1
            sent = calls[0]
            policy = json.loads(sent["Policy"])
            assert policy["Statement"][0]["Resource"] == [
                f"arn:aws:s3:::{demo.bucket}/reports/approved/price-benchmark-2026.csv"]
            assert sent["RoleSessionName"] == resp["grant"]["grant_id"]
            assert {t["Key"] for t in sent["Tags"]} == {"grant_id", "agent_id", "decision_id"}
            assert sent["SourceIdentity"] == "procurement-agent"
            assert out["credential"]["effective_until"] == resp["grant"]["expires_at"]
            assert out["execution"]["summary"]["bytes"] > 0 and "sha256" in out["execution"]["summary"]

    def test_object_outside_the_approved_prefix_is_denied_before_any_credential(self):
        with offline_demo(aws_mode="live") as demo:
            req = _aws_request(demo.bucket, "reports/restricted/salary-bands.csv")
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny" and "grant" not in resp


class TestSaasAdapters:
    @pytest.mark.parametrize("adapter_cls", [ServiceNowAdapter, EntraAdapter])
    def test_live_mode_refuses_without_federation_settings(self, adapter_cls):
        adapter = adapter_cls(mode="live")
        verified = MagicMock(grant=MagicMock(expires_at="2026-10-14T12:05:00+00:00"))
        with pytest.raises(ProviderNotConfigured):
            adapter.exchange(verified, MagicMock(provider_scopes=("x",)))

    def test_handle_cannot_be_copied_or_serialized(self):
        with offline_demo() as demo:
            cp = demo.control_plane
            req = purchase()
            grant_id = cp.request_authority(req, demo.agent("procurement-agent"))["grant"]["grant_id"]
            _, verified = cp.grants.verify_and_consume(grant_id, req)
            handle = cp.broker.exchange(verified, cp.operations.get("Subscription.Purchase"))
            assert "_secret" not in repr(handle)
            with pytest.raises(TypeError):
                copy.deepcopy(handle)

    def test_same_contract_for_every_provider(self):
        with offline_demo() as demo:
            cp = demo.control_plane
            records = {"agent_id": "records-agent", "session_id": "r-1", "environment": "prod"}
            cases = [
                dict(records, provider="entra", operation_id="Entra.GetUser",
                     target_resource="entra/user/j.doe", tool_parameters={"user_id": "j.doe"}),
                dict(records, provider="google", operation_id="Google.ReadDriveFile",
                     target_resource="google/drive/file/doc-000123", tool_parameters={"file_id": "doc-000123"}),
            ]
            for req in cases:
                resp = cp.request_authority(req, demo.agent("records-agent"))
                assert resp["verdict"] == "allow", resp["explanation"]
                out = cp.execute(resp["grant"]["grant_id"], req, demo.agent("records-agent"))
                assert out["status"] == "executed" and out["credential"]["provider"] == req["provider"]
            assert cp.broker.adapter_modes()["entra"] == "mock"

    def test_aws_mock_mode_is_labelled(self):
        assert AwsStsAdapter("mock").mode == "mock"
