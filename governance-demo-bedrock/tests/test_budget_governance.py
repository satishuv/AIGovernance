"""Budget governance tests. Budget is never authorization."""

import threading
from decimal import Decimal

import pytest

from tests.authority_test_support import offline_demo, purchase, serialize_conditional_writes, stage

from budget_governance import (  # noqa: E402
    ALLOW, DENY, NOT_APPLICABLE, STEP_UP, ApprovedCatalog, SpendLedger, SpendPolicy, evaluate_budget,
)

CATALOG = ApprovedCatalog({
    "seat": {"name": "Seat", "unit_price": Decimal("42.00"), "currency": "CAD", "approved": True},
    "blocked": {"name": "Blocked", "unit_price": Decimal("10.00"), "currency": "CAD", "approved": False},
})
POLICY = SpendPolicy("CAD", Decimal("500"), Decimal("1000"), Decimal("2000"), Decimal("5000"))
DERIVE = {"source": "approved_catalog", "item_param": "catalog_item_id", "quantity_param": "quantity"}


def _eval(qty=4, item="seat", claimed=None, session=Decimal("0"), daily=Decimal("0"), policy=POLICY,
          financial=True):
    amount = claimed if claimed is not None else Decimal("42.00") * qty
    return evaluate_budget(financial_impact=financial, amount_derivation=DERIVE,
                           tool_parameters={"catalog_item_id": item, "quantity": qty},
                           claimed_financial_context={"currency": "CAD", "transaction_amount": amount},
                           spend_policy=policy, catalog=CATALOG, session_spent=session, daily_spent=daily)


class TestEvaluateBudget:
    def test_within_limits_allows(self):
        r = _eval(qty=4)
        assert r.outcome == ALLOW and r.transaction_amount == Decimal("168.00")

    def test_over_per_transaction_limit_steps_up(self):
        assert _eval(qty=12).outcome == STEP_UP

    def test_session_total_steps_up(self):
        assert _eval(qty=4, session=Decimal("900")).outcome == STEP_UP

    def test_daily_total_steps_up(self):
        assert _eval(qty=4, daily=Decimal("1900")).outcome == STEP_UP

    def test_above_hard_maximum_denies_even_though_approval_exists(self):
        r = _eval(qty=200)
        assert r.outcome == DENY and "hard transaction maximum" in r.reasons[0]

    def test_unknown_catalog_item_denies(self):
        assert _eval(item="crypto-miner", claimed=Decimal("168")).outcome == DENY

    def test_unapproved_catalog_item_denies(self):
        assert _eval(item="blocked", claimed=Decimal("40")).outcome == DENY

    def test_understated_claimed_amount_denies(self):
        r = _eval(qty=12, claimed=Decimal("168"))
        assert r.outcome == DENY and "does not match the server-derived amount" in r.reasons[0]

    def test_currency_mismatch_denies(self):
        r = evaluate_budget(financial_impact=True, amount_derivation=DERIVE,
                            tool_parameters={"catalog_item_id": "seat", "quantity": 1},
                            claimed_financial_context={"currency": "USD", "transaction_amount": 42},
                            spend_policy=POLICY, catalog=CATALOG, session_spent=Decimal("0"),
                            daily_spent=Decimal("0"))
        assert r.outcome == DENY

    def test_agent_without_spend_policy_has_no_spending_authority(self):
        assert _eval(policy=None).outcome == DENY

    def test_amount_on_non_financial_operation_denies(self):
        assert _eval(financial=False).outcome == DENY

    def test_non_financial_without_amount_is_not_applicable(self):
        r = evaluate_budget(financial_impact=False, amount_derivation={}, tool_parameters={},
                            claimed_financial_context={}, spend_policy=POLICY, catalog=CATALOG,
                            session_spent=Decimal("0"), daily_spent=Decimal("0"))
        assert r.outcome == NOT_APPLICABLE


class TestSpendLedger:
    def test_caps_are_atomic_under_concurrency(self):
        with offline_demo() as demo:
            ledger = SpendLedger(serialize_conditional_writes(demo.tables["ledger"]))
            results, barrier = [], threading.Barrier(6)

            def spend():
                barrier.wait()
                results.append(ledger.record("procurement-agent", "s-race", Decimal("400"), "CAD", "g",
                                             session_cap=Decimal("1000"), daily_cap=Decimal("2000"))[0])

            threads = [threading.Thread(target=spend) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert results.count(True) == 2  # 800 fits under 1000, a third 400 does not
            session_total, _ = ledger.totals("procurement-agent", "s-race")
            assert session_total == Decimal("800")


class TestBudgetThroughTheControlPlane:
    def test_spending_authority_does_not_grant_security_authority(self):
        with offline_demo() as demo:
            req = {"agent_id": "procurement-agent", "session_id": "s-1", "provider": "entra",
                   "operation_id": "Entra.AddGroupMember", "target_resource": "entra/group/GlobalAdministrators",
                   "environment": "prod", "tool_parameters": {"group_id": "GlobalAdministrators", "user_id": "j.doe"}}
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert stage(resp, "role_boundary")["result"] == "fail"
            assert "human-only" in stage(resp, "role_boundary")["detail"]

    def test_privilege_smuggled_into_a_purchase_is_rejected(self):
        with offline_demo() as demo:
            req = purchase()
            req["tool_parameters"]["assign_directory_role"] = "GlobalAdministrator"
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert "not an allowed parameter" in stage(resp, "parameters")["detail"]

    def test_autonomous_spend_is_recorded_server_side(self):
        with offline_demo() as demo:
            cp = demo.control_plane
            req = purchase()
            grant_id = cp.request_authority(req, demo.agent("procurement-agent"))["grant"]["grant_id"]
            assert cp.execute(grant_id, req, demo.agent("procurement-agent"))["status"] == "executed"
            session_total, daily_total = cp.ledger.totals("procurement-agent", "s-1")
            assert session_total == Decimal("168") and daily_total == Decimal("168")

    def test_approved_spend_is_recorded_but_outside_the_autonomous_budget(self):
        with offline_demo() as demo:
            ledger = demo.control_plane.ledger
            ok, _ = ledger.record("procurement-agent", "s-a", Decimal("1800"), "CAD", "g-approved",
                                  autonomous=False)
            assert ok
            assert ledger.totals("procurement-agent", "s-a") == (Decimal("0"), Decimal("0"))
            assert ledger.total_spend_today("procurement-agent") == Decimal("1800")

    @pytest.mark.parametrize("claimed", [0, 1, 167.99])
    def test_claimed_session_totals_from_the_agent_are_ignored(self, claimed):
        with offline_demo() as demo:
            cp = demo.control_plane
            cp.ledger.record("procurement-agent", "s-1", Decimal("950"), "CAD", "earlier")
            req = purchase()
            req["financial_context"]["session_spend"] = claimed  # agent lies about its spend
            resp = cp.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "escalate"
            assert "session total" in stage(resp, "budget")["detail"]
