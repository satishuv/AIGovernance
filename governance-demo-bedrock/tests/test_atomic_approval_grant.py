"""Approval consumption and grant minting are one DynamoDB transaction (P0-07).

Before this change the approval was consumed by one write and the grant
written by a second; if the second failed, the approval was used up and no
grant existed.
"""
import uuid as _uuid

import pytest
from botocore.exceptions import ClientError

from tests.authority_test_support import offline_demo, purchase

import authority_control_plane  # noqa: E402  (path set by authority_test_support)
import delegated_authority  # noqa: E402


@pytest.fixture
def demo():
    with offline_demo() as d:
        yield d


def _approved_over_limit_request(demo):
    """An over-limit purchase that a finance approver has approved."""
    req = purchase(quantity=40, amount=1680)
    cp = demo.control_plane
    step_up = cp.request_authority(req, demo.agent("procurement-agent"))
    assert step_up["verdict"] == "escalate", step_up.get("explanation")
    approved = cp.approve_request(step_up["approval_id"], demo.human("finance_approver"))
    assert approved["status"] == "approved", approved
    return req, step_up["approval_id"]


def _approval(demo, approval_id):
    return demo.tables["approvals"].get_item(Key={"approval_id": approval_id}, ConsistentRead=True)["Item"]


def test_mint_consumes_the_approval_and_records_the_grant(demo):
    req, approval_id = _approved_over_limit_request(demo)
    out = demo.control_plane.mint_after_approval(approval_id, req, demo.agent("procurement-agent"))
    assert out["verdict"] == "allow", out.get("reason")
    grant_id = out["grant"]["grant_id"]
    record = _approval(demo, approval_id)
    assert record["consumed"] is True and record["grant_id"] == grant_id
    assert demo.control_plane.grants.get(grant_id) is not None


def test_replayed_approval_writes_no_second_grant(demo):
    req, approval_id = _approved_over_limit_request(demo)
    cp = demo.control_plane
    first = cp.mint_after_approval(approval_id, req, demo.agent("procurement-agent"))
    again = cp.mint_after_approval(approval_id, req, demo.agent("procurement-agent"))
    assert first["verdict"] == "allow" and again["verdict"] == "deny"
    grants = demo.tables["grants"].scan()["Items"]
    assert [g["grant_id"] for g in grants if g.get("approval_id") == approval_id] == [first["grant"]["grant_id"]]


def test_failed_grant_write_leaves_the_approval_unused(demo, monkeypatch):
    req, approval_id = _approved_over_limit_request(demo)
    # Force the grant write to fail: a grant with the next ID already exists.
    fixed = _uuid.UUID(int=7)
    monkeypatch.setattr(delegated_authority.uuid, "uuid4", lambda: fixed)
    demo.tables["grants"].put_item(Item={"grant_id": "dag-" + fixed.hex, "agent_id": "someone-else"})

    out = demo.control_plane.mint_after_approval(approval_id, req, demo.agent("procurement-agent"))

    assert out["verdict"] == "deny"
    assert _approval(demo, approval_id)["consumed"] is False      # still usable after the failure
    monkeypatch.undo()
    retry = demo.control_plane.mint_after_approval(approval_id, req, demo.agent("procurement-agent"))
    assert retry["verdict"] == "allow"


def test_cancelled_transaction_is_recognized():
    cancelled = ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "x"}},
                            "TransactWriteItems")
    other = ClientError({"Error": {"Code": "ThrottlingException", "Message": "x"}}, "TransactWriteItems")
    assert authority_control_plane._transaction_cancelled(cancelled) is True
    assert authority_control_plane._transaction_cancelled(other) is False
    assert authority_control_plane._transaction_cancelled(ValueError("x")) is False
