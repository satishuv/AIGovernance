"""Fixes for the 2026-10-21 security audit (security-audit skill run-1 and ASH 3.7.1).

- Separation of duties compared IAM principal strings only, so an agent's owner who also held an
  approver role could approve their own agent's requests under that role.
- retrieval_validator held its invisible-character class as literal invisible characters,
  including bidirectional marks (bandit B613); it is now written with escapes and must match the
  same 11 code points.
"""

import os
import sys
import types

_GE = os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine")
if _GE not in sys.path:
    sys.path.insert(0, _GE)

from authority_identity import (  # noqa: E402
    AuthenticatedCaller,
    check_approver_eligibility,
)
from retrieval_validator import RetrievalContentValidator  # noqa: E402

ACCOUNT = "111122223333"
OWNER = f"arn:aws:sts::{ACCOUNT}:assumed-role/ServiceOwner/digital-services-owner"
ITEM = {"agent_id": "procurement-agent", "approval_id": "a-1"}


def _approver(principal: str) -> AuthenticatedCaller:
    return AuthenticatedCaller(principal_id=principal, principal_type="human",
                               roles={"policy_approver"}, source="iam")


def _agent(owner: str = OWNER, business_owner: str = "", technical_owner: str = "platform-team"):
    return types.SimpleNamespace(owner=owner, business_owner=business_owner or owner,
                                 technical_owner=technical_owner)


def test_the_owner_cannot_approve_under_another_role():
    approver = _approver(f"arn:aws:sts::{ACCOUNT}:assumed-role/HumanApproverRole/digital-services-owner")
    ok, why = check_approver_eligibility(approver, ITEM, _agent())
    assert not ok and "same person" in why


def test_the_same_person_is_matched_case_insensitively():
    approver = _approver(f"arn:aws:sts::{ACCOUNT}:assumed-role/HumanApproverRole/Digital-Services-Owner")
    assert not check_approver_eligibility(approver, ITEM, _agent())[0]


def test_an_iam_user_owner_cannot_approve_through_a_role_session_named_after_them():
    owner = f"arn:aws:iam::{ACCOUNT}:user/engineering/alice"
    approver = _approver(f"arn:aws:sts::{ACCOUNT}:assumed-role/HumanApproverRole/alice")
    ok, why = check_approver_eligibility(approver, ITEM, _agent(owner=owner))
    assert not ok and "same person" in why


def test_a_different_person_can_still_approve():
    # Regression check: separation of duties must not block an independent approver.
    approver = _approver(f"arn:aws:sts::{ACCOUNT}:assumed-role/HumanApproverRole/finance-approver")
    assert check_approver_eligibility(approver, ITEM, _agent()) == (True, "")


def test_the_existing_exact_owner_check_still_applies():
    # Regression check: the owner's own session is refused with the original reason.
    ok, why = check_approver_eligibility(_approver(OWNER), ITEM, _agent())
    assert not ok and "owner cannot approve" in why


def test_the_invisible_character_class_matches_the_same_11_code_points():
    expected = {*range(0x200B, 0x2010), *range(0x2060, 0x2065), 0xFEFF}
    pattern = RetrievalContentValidator._INVISIBLE_CHARS
    probe = [*range(0x2000, 0x2070), 0xFEFE, 0xFEFF, 0xFF00, 0x0020, 0x00A0]
    assert {cp for cp in probe if pattern.fullmatch(chr(cp))} == expected


def test_the_validator_source_has_no_literal_invisible_characters():
    with open(os.path.join(_GE, "retrieval_validator.py"), encoding="utf-8") as handle:
        source = handle.read()
    assert not [c for c in source if 0x200B <= ord(c) <= 0x2064 or ord(c) == 0xFEFF]


class _NoScan:
    """Forwards every call to the real table except scan(), which fails the test."""

    def __init__(self, table):
        self._table = table

    def scan(self, **kwargs):
        raise AssertionError("decision_summaries scanned the decision trace table")

    def __getattr__(self, name):
        return getattr(self._table, name)


def test_guardian_inspection_reads_one_agents_traces_with_an_index_query():
    from tests.authority_test_support import offline_demo, purchase

    with offline_demo() as demo:
        cp = demo.control_plane
        for n in range(3):
            cp.request_authority(purchase(session=f"s-{n}"), demo.agent("procurement-agent"))
        cp.request_authority(purchase(agent_id="records-agent"), demo.agent("records-agent"))
        cp.decision_table = _NoScan(cp.decision_table)
        rows = cp.decision_summaries("procurement-agent", limit=2)
        assert len(rows) == 2
        assert rows[0]["timestamp"] >= rows[1]["timestamp"]
        assert all(r["signature_verified"] for r in rows)
        assert len(cp.decision_summaries("procurement-agent", limit=10)) == 3
        assert cp.decision_summaries("", limit=10) == []
