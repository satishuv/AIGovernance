"""Budget governance for agents with spending authority.

Principles:
  * The amount is derived server-side. For a catalog purchase the control plane
    computes unit price x quantity from the approved catalog; an agent cannot
    claim a lower price. A claimed amount that differs is denied.
  * Running totals come from the control plane's own spend ledger, never from
    the agent's request.
  * Budget is not authorization. Spending authority lets an agent buy an
    approved item; it never grants security authority. Granting privileges is
    a separate operation with its own governance (and is human-only for
    privileged targets).
  * Money uses Decimal throughout.

Outcomes: allow, step_up (human approval required), deny, not_applicable.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ALLOW = "allow"
STEP_UP = "step_up"
DENY = "deny"
NOT_APPLICABLE = "not_applicable"


def _dec(value: Any) -> Optional[Decimal]:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        dec = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return dec if dec.is_finite() else None


@dataclass
class SpendPolicy:
    currency: str
    per_transaction_max: Decimal
    per_session_max: Decimal
    daily_max: Decimal
    hard_transaction_max: Optional[Decimal] = None

    @classmethod
    def from_registry(cls, data: Dict[str, Any]) -> Optional["SpendPolicy"]:
        if not data:
            return None
        currency = str(data.get("currency", "")).strip().upper()
        per_txn = _dec(data.get("per_transaction_max"))
        per_session = _dec(data.get("per_session_max"))
        daily = _dec(data.get("daily_max"))
        if not currency or per_txn is None or per_session is None or daily is None:
            return None
        return cls(currency, per_txn, per_session, daily, _dec(data.get("hard_transaction_max")))

    def to_dict(self) -> Dict[str, Any]:
        out = {"currency": self.currency, "per_transaction_max": self.per_transaction_max,
               "per_session_max": self.per_session_max, "daily_max": self.daily_max}
        if self.hard_transaction_max is not None:
            out["hard_transaction_max"] = self.hard_transaction_max
        return out


class ApprovedCatalog:
    """Approved items with list prices (the organization's purchasing policy)."""

    def __init__(self, items: Dict[str, Dict[str, Any]]):
        self._items = {k: dict(v) for k, v in (items or {}).items()}

    def get(self, item_id: str) -> Optional[Dict[str, Any]]:
        item = self._items.get(item_id or "")
        return dict(item) if item else None

    def all(self) -> List[Dict[str, Any]]:
        return [{"catalog_item_id": k, **v} for k, v in sorted(self._items.items())]

    def to_policy_input(self) -> Dict[str, Any]:
        return {k: {"unit_price": str(v.get("unit_price")), "currency": v.get("currency"),
                    "approved": bool(v.get("approved"))} for k, v in sorted(self._items.items())}


@dataclass
class BudgetEvaluation:
    outcome: str
    reasons: List[str] = field(default_factory=list)
    transaction_amount: Optional[Decimal] = None
    currency: str = ""
    session_total_after: Optional[Decimal] = None
    daily_total_after: Optional[Decimal] = None
    limits: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        def s(v):
            return None if v is None else str(v)
        return {"outcome": self.outcome, "reasons": list(self.reasons),
                "transaction_amount": s(self.transaction_amount), "currency": self.currency,
                "session_total_after": s(self.session_total_after),
                "daily_total_after": s(self.daily_total_after),
                "limits": {k: s(v) for k, v in self.limits.items()}}


def derive_transaction_amount(amount_derivation: Dict[str, Any], tool_parameters: Dict[str, Any],
                              catalog: ApprovedCatalog) -> Tuple[Optional[Decimal], str, str, Optional[Dict[str, Any]]]:
    """Return (amount, currency, error, catalog_item) computed server-side."""
    if amount_derivation.get("source") != "approved_catalog":
        return None, "", "operation has no server-side amount derivation", None
    item_id = tool_parameters.get(amount_derivation.get("item_param", "catalog_item_id"))
    quantity = _dec(tool_parameters.get(amount_derivation.get("quantity_param", "quantity")))
    item = catalog.get(str(item_id or ""))
    if item is None:
        return None, "", f"catalog item '{item_id}' is not in the approved catalog", None
    if not item.get("approved"):
        return None, "", f"catalog item '{item_id}' is not approved for purchase", item
    price = _dec(item.get("unit_price"))
    if price is None or quantity is None or quantity <= 0 or quantity != quantity.to_integral_value():
        return None, "", "price or quantity is invalid", item
    return (price * quantity).quantize(Decimal("0.01")), str(item.get("currency", "")).upper(), "", item


def evaluate_budget(*, financial_impact: bool, amount_derivation: Dict[str, Any],
                    tool_parameters: Dict[str, Any], claimed_financial_context: Dict[str, Any],
                    spend_policy: Optional[SpendPolicy], catalog: ApprovedCatalog,
                    session_spent: Decimal, daily_spent: Decimal) -> BudgetEvaluation:
    """Evaluate a request against the agent's spend policy."""
    claimed = claimed_financial_context or {}
    if not financial_impact:
        if claimed.get("transaction_amount") not in (None, "", 0, "0"):
            return BudgetEvaluation(DENY, ["a financial amount was supplied for an operation "
                                           "with no financial impact"])
        return BudgetEvaluation(NOT_APPLICABLE, ["operation has no financial impact"])
    if spend_policy is None:
        return BudgetEvaluation(DENY, ["agent has no spending authority (no spend policy)"])

    amount, currency, error, _item = derive_transaction_amount(amount_derivation, tool_parameters, catalog)
    if amount is None:
        return BudgetEvaluation(DENY, [error])

    reasons: List[str] = []
    claimed_amount = _dec(claimed.get("transaction_amount"))
    claimed_currency = str(claimed.get("currency", "") or "").upper()
    if claimed_amount is None or not claimed_currency:
        return BudgetEvaluation(DENY, ["financial_context with currency and transaction_amount is required"],
                                amount, currency)
    if claimed_currency != currency or claimed_amount.quantize(Decimal("0.01")) != amount:
        return BudgetEvaluation(DENY, [
            f"claimed amount {claimed_currency} {claimed_amount} does not match the server-derived "
            f"amount {currency} {amount} (catalog price x quantity)"], amount, currency)
    if currency != spend_policy.currency:
        return BudgetEvaluation(DENY, [f"currency {currency} differs from the spend policy currency "
                                       f"{spend_policy.currency}"], amount, currency)

    session_after = (session_spent or Decimal("0")) + amount
    daily_after = (daily_spent or Decimal("0")) + amount
    limits = spend_policy.to_dict()
    if spend_policy.hard_transaction_max is not None and amount > spend_policy.hard_transaction_max:
        return BudgetEvaluation(DENY, [f"{currency} {amount} exceeds the hard transaction maximum "
                                       f"{spend_policy.hard_transaction_max}; no approval can lift it"],
                                amount, currency, session_after, daily_after, limits)

    outcome = ALLOW
    if amount > spend_policy.per_transaction_max:
        outcome = STEP_UP
        reasons.append(f"{currency} {amount} exceeds the autonomous per-transaction limit "
                       f"{spend_policy.per_transaction_max}")
    if session_after > spend_policy.per_session_max:
        outcome = STEP_UP
        reasons.append(f"session total {session_after} would exceed {spend_policy.per_session_max}")
    if daily_after > spend_policy.daily_max:
        outcome = STEP_UP
        reasons.append(f"daily total {daily_after} would exceed {spend_policy.daily_max}")
    if outcome == ALLOW:
        reasons.append(f"{currency} {amount} is within the autonomous limits")
    return BudgetEvaluation(outcome, reasons, amount, currency, session_after, daily_after, limits)


class SpendLedger:
    """Server-side running totals per agent session and per agent day.

    record() is an atomic ADD. For autonomous spending it carries a condition
    that the new total stays within the cap, so two grants that were each
    within budget when evaluated cannot together exceed it at execution.
    """

    def __init__(self, table):
        self._table = table

    @staticmethod
    def _day(now: Optional[datetime] = None) -> str:
        return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")

    def _total(self, key: str) -> Decimal:
        try:
            item = self._table.get_item(Key={"ledger_key": key}).get("Item") or {}
        except Exception as exc:
            raise RuntimeError(f"spend ledger unavailable: {exc}") from exc
        return _dec(item.get("total")) or Decimal("0")

    def totals(self, agent_id: str, session_id: str, now: Optional[datetime] = None) -> Tuple[Decimal, Decimal]:
        """AUTONOMOUS spend in this session and today (what the caps limit)."""
        return (self._total(f"SESSION#{agent_id}#{session_id}"),
                self._total(f"DAY#{agent_id}#{self._day(now)}"))

    def total_spend_today(self, agent_id: str, now: Optional[datetime] = None) -> Decimal:
        """All spend today, autonomous and human-approved."""
        return self._total(f"TOTAL#{agent_id}#{self._day(now)}")

    def record(self, agent_id: str, session_id: str, amount: Decimal, currency: str,
               grant_id: str, session_cap: Optional[Decimal] = None,
               daily_cap: Optional[Decimal] = None, autonomous: bool = True) -> Tuple[bool, str]:
        """Record spend. Autonomous spend counts against the caps atomically.

        Human-approved spend is outside the autonomous budget: a human
        authorized that exact transaction, so it is recorded in the daily total
        (visible to oversight) without consuming the agent's autonomous headroom.

        The session total is updated first. If the daily update is rejected the
        session increment is reversed; in the brief window between the two the
        totals can only overstate spending, which errs toward step-up, never
        toward overspend.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        applied: List[str] = []
        keyed = []
        if autonomous:
            keyed = [(f"SESSION#{agent_id}#{session_id}", session_cap),
                     (f"DAY#{agent_id}#{self._day()}", daily_cap)]
        keyed.append((f"TOTAL#{agent_id}#{self._day()}", None))
        for key, cap in keyed:
            kwargs: Dict[str, Any] = {
                "Key": {"ledger_key": key},
                "UpdateExpression": "ADD #t :amt SET #c = :cur, #u = :now, #g = :grant",
                "ExpressionAttributeNames": {"#t": "total", "#c": "currency", "#u": "updated_at",
                                             "#g": "last_grant_id"},
                "ExpressionAttributeValues": {":amt": amount, ":cur": currency, ":now": now_iso,
                                              ":grant": grant_id},
            }
            if cap is not None:
                kwargs["ConditionExpression"] = "attribute_not_exists(#t) OR #t <= :room"
                kwargs["ExpressionAttributeValues"][":room"] = cap - amount
            try:
                self._table.update_item(**kwargs)
                applied.append(key)
            except Exception as exc:
                self._reverse(applied, amount)
                if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                    scope = "session" if key.startswith("SESSION#") else "daily"
                    return False, f"recording {currency} {amount} would exceed the {scope} cap"
                logger.error(json.dumps({"event": "spend_ledger_write_failed", "error": str(exc)}))
                return False, "spend ledger unavailable; failing closed"
        return True, "recorded"

    def _reverse(self, keys: List[str], amount: Decimal) -> None:
        for key in keys:
            try:
                self._table.update_item(
                    Key={"ledger_key": key}, UpdateExpression="ADD #t :neg",
                    ExpressionAttributeNames={"#t": "total"},
                    ExpressionAttributeValues={":neg": -amount})
            except Exception as exc:
                logger.error(json.dumps({"event": "spend_ledger_reverse_failed", "key": key,
                                         "error": str(exc)}))
