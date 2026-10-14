"""Delegated Authority Grant (hall pass) lifecycle tests."""

import threading
from datetime import datetime, timedelta, timezone

import pytest

from tests.authority_test_support import offline_demo, purchase, serialize_conditional_writes

from delegated_authority import (  # noqa: E402  (path set by authority_test_support)
    ACTIVE, CONSUMED, EXPIRED, REVOKED, GrantStore, LocalDemoSigner,
)


@pytest.fixture
def demo():
    with offline_demo() as d:
        yield d


def _allow(demo, **kw):
    req = purchase(**kw)
    resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
    assert resp["verdict"] == "allow", resp["explanation"]
    return req, resp["grant"]["grant_id"]


class TestMint:
    def test_allowed_request_mints_signed_active_one_use_grant(self, demo):
        req, grant_id = _allow(demo)
        grant = demo.control_plane.grants.get(grant_id)
        assert grant.status == ACTIVE and grant.max_uses == 1 and grant.uses_remaining == 1
        assert grant.operation_id == "Subscription.Purchase" and grant.provider == "servicenow"
        assert grant.target_resource == "catalog/software/approved/productivity-suite"
        assert grant.spend_limit == {"currency": "CAD", "amount": 500}
        assert grant.signature and grant.signature_algorithm == "ECDSA_SHA_256"
        lifetime = datetime.fromisoformat(grant.expires_at) - datetime.fromisoformat(grant.issued_at)
        assert lifetime == timedelta(seconds=300)

    def test_grant_record_contains_no_credential(self, demo):
        _, grant_id = _allow(demo)
        item = demo.tables["grants"].get_item(Key={"grant_id": grant_id})["Item"]
        flat = repr(item).lower()
        for marker in ("secret", "token", "accesskey", "password"):
            assert marker not in flat

    def test_grant_links_to_its_decision(self, demo):
        _, grant_id = _allow(demo)
        grant = demo.control_plane.grants.get(grant_id)
        assert demo.tables["decisions"].get_item(Key={"decision_id": grant.decision_id}).get("Item")


class TestVerify:
    def test_exact_request_verifies(self, demo):
        req, grant_id = _allow(demo)
        v = demo.control_plane.grants.verify(grant_id, req)
        assert v.ok, v.reason
        assert {c.name for c in v.checks} >= {"signature", "status", "binding", "resource", "request_digest"}

    def test_tampered_stored_grant_fails_signature(self, demo):
        req, grant_id = _allow(demo)
        demo.tables["grants"].update_item(
            Key={"grant_id": grant_id}, UpdateExpression="SET target_resource = :t, resource_patterns = :p",
            ExpressionAttributeValues={":t": "catalog/software/approved/analytics-suite",
                                       ":p": ["catalog/software/approved/*"]})
        v = demo.control_plane.grants.verify(grant_id, dict(req, target_resource="catalog/software/approved/analytics-suite"))
        assert not v.ok and "signature" in v.reason

    def test_grant_from_another_signing_key_is_rejected(self, demo):
        req, grant_id = _allow(demo)
        foreign = GrantStore(demo.tables["grants"], LocalDemoSigner())
        v = foreign.verify(grant_id, req)
        assert not v.ok and "not signed by the configured authority key" in v.reason

    @pytest.mark.parametrize("change,needle", [
        ({"agent_id": "records-agent"}, "agent mismatch"),
        ({"session_id": "other-session"}, "session mismatch"),
        ({"provider": "entra"}, "provider mismatch"),
        ({"operation_id": "Subscription.ListCatalog"}, "operation mismatch"),
        ({"environment": "dev"}, "environment mismatch"),
        ({"target_resource": "catalog/software/approved/analytics-suite"}, "outside the granted resource"),
        ({"tool_parameters": {"catalog_item_id": "productivity-suite", "quantity": 5, "cost_centre": "CC-1234"}},
         "differs from the granted value"),
        ({"financial_context": {"currency": "CAD", "transaction_amount": 900}}, "exceeds the granted"),
        ({"financial_context": {"currency": "CAD", "transaction_amount": 167}}, "exact request"),
    ])
    def test_any_deviation_from_the_granted_request_fails(self, demo, change, needle):
        req, grant_id = _allow(demo)
        v = demo.control_plane.grants.verify(grant_id, {**req, **change})
        assert not v.ok and needle in v.reason

    def test_expired_grant_fails_and_is_marked_expired(self, demo):
        req, grant_id = _allow(demo)
        store = demo.control_plane.grants
        later = GrantStore(demo.tables["grants"], store.signer,
                           clock=lambda: datetime.now(timezone.utc) + timedelta(minutes=6))
        v = later.verify(grant_id, req)
        assert not v.ok and "expired" in v.reason
        assert store.get(grant_id).status == EXPIRED

    def test_unknown_grant_fails_closed(self, demo):
        v = demo.control_plane.grants.verify("dag-does-not-exist", purchase())
        assert not v.ok and "does not exist" in v.reason


class TestConsumeAndReplay:
    def test_execute_consumes_and_replay_is_denied(self, demo):
        req, grant_id = _allow(demo)
        cp = demo.control_plane
        first = cp.execute(grant_id, req, demo.agent("procurement-agent"))
        assert first["status"] == "executed" and first["grant_status_after"] == CONSUMED
        second = cp.execute(grant_id, req, demo.agent("procurement-agent"))
        assert second["status"] == "denied" and "CONSUMED" in second["reason"]

    def test_concurrent_consume_permits_exactly_one(self, demo):
        _, grant_id = _allow(demo)
        serialize_conditional_writes(demo.tables["grants"])
        store = demo.control_plane.grants
        outcomes, barrier = [], threading.Barrier(8)

        def attempt():
            barrier.wait()
            outcomes.append(store.consume(grant_id)[0])

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes.count(True) == 1 and outcomes.count(False) == 7
        assert store.get(grant_id).status == CONSUMED

    def test_other_agent_cannot_execute_the_grant(self, demo):
        req, grant_id = _allow(demo)
        out = demo.control_plane.execute(grant_id, req, demo.agent("records-agent"))
        assert out["status"] == "denied"
        assert demo.control_plane.grants.get(grant_id).status == ACTIVE


class TestRevocation:
    def test_revoked_grant_cannot_execute(self, demo):
        req, grant_id = _allow(demo)
        cp = demo.control_plane
        assert cp.revoke_grant(grant_id, demo.human("security_operator"), "suspicious timing")["status"] == "revoked"
        out = cp.execute(grant_id, req, demo.agent("procurement-agent"))
        assert out["status"] == "denied" and "REVOKED" in out["reason"]

    def test_agents_cannot_revoke(self, demo):
        _, grant_id = _allow(demo)
        out = demo.control_plane.revoke_grant(grant_id, demo.agent("guardian-agent"), "I think so")
        assert out["status"] == "denied"
        assert demo.control_plane.grants.get(grant_id).status == ACTIVE

    def test_kill_switch_revokes_active_grants_and_blocks_new_requests(self, demo):
        req, grant_id = _allow(demo)
        cp = demo.control_plane
        out = cp.activate_kill_switch("procurement-agent", demo.human("security_operator"), "drill")
        assert out["revoked_grants"] == [grant_id]
        assert cp.grants.get(grant_id).status == REVOKED
        again = cp.request_authority(purchase(session="s-9"), demo.agent("procurement-agent"))
        assert again["verdict"] == "deny"
        assert next(s for s in again["stages"] if s["stage"] == "kill_switch")["result"] == "fail"
