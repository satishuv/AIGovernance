"""Verified agent-to-agent delegation (P0-11).

A delegation is valid only when the governance plane issued it. When a parent
agent's request is allowed and names a child agent to delegate to, the
pipeline writes a DelegationReceipt server-side. The child's request carries
only the receipt_id; the parent, the delegation chain and the scope cap are
read from the receipt, never from request fields a model can write.

A receipt binds:
  parent_agent_id   the agent whose allowed decision issued it
  child_agent_id    the only agent that may use it
  scope_cap         the parent's effective scope when it was issued
  chain             originator .. parent, built server-side from the
                    parent's own verified receipt (if it was delegated)
  allowed_operations optional: the operation ids the parent delegated
  expires_at_epoch  absolute expiry
  max_uses / uses   consumption, enforced with a conditional write

Table: DelegationReceiptTable, partition key receipt_id, TTL on ttl_expiry
(cleanup only; expiry is enforced by expires_at_epoch in every check).
"""

import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 3600
DEFAULT_MAX_USES = 1
MAX_USES_LIMIT = 25
# Cleanup lag after expiry before DynamoDB TTL may delete the item.
_TTL_GRACE_SECONDS = 86400


def receipt_table_definition(table_name: str) -> Dict[str, Any]:
    """create_table arguments matching the deployed DelegationReceiptTable."""
    return {
        "TableName": table_name,
        "KeySchema": [{"AttributeName": "receipt_id", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "receipt_id", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class DelegationReceipt:
    receipt_id: str
    parent_agent_id: str
    child_agent_id: str
    scope_cap: int
    chain: List[str]
    parent_decision_id: str = ""
    allowed_operations: List[str] = field(default_factory=list)
    issued_at: str = ""
    expires_at_epoch: int = 0
    max_uses: int = DEFAULT_MAX_USES
    uses: int = 0
    status: str = "active"

    @property
    def depth(self) -> int:
        return len(self.chain)

    def to_item(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "parent_agent_id": self.parent_agent_id,
            "child_agent_id": self.child_agent_id,
            "scope_cap": self.scope_cap,
            "chain": list(self.chain),
            "parent_decision_id": self.parent_decision_id,
            "allowed_operations": list(self.allowed_operations),
            "issued_at": self.issued_at,
            "expires_at_epoch": self.expires_at_epoch,
            "max_uses": self.max_uses,
            "uses": self.uses,
            "status": self.status,
            "ttl_expiry": self.expires_at_epoch + _TTL_GRACE_SECONDS,
        }

    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "DelegationReceipt":
        return cls(
            receipt_id=str(item["receipt_id"]),
            parent_agent_id=str(item.get("parent_agent_id", "")),
            child_agent_id=str(item.get("child_agent_id", "")),
            scope_cap=_int(item.get("scope_cap"), 0),
            chain=[str(a) for a in (item.get("chain") or [])],
            parent_decision_id=str(item.get("parent_decision_id", "")),
            allowed_operations=[str(o) for o in (item.get("allowed_operations") or [])],
            issued_at=str(item.get("issued_at", "")),
            expires_at_epoch=_int(item.get("expires_at_epoch"), 0),
            max_uses=_int(item.get("max_uses"), DEFAULT_MAX_USES),
            uses=_int(item.get("uses"), 0),
            status=str(item.get("status", "")),
        )

    def summary(self) -> Dict[str, Any]:
        """Receipt fields safe to return to the parent agent."""
        return {
            "delegation_receipt_id": self.receipt_id,
            "child_agent_id": self.child_agent_id,
            "scope_cap": self.scope_cap,
            "chain": list(self.chain),
            "allowed_operations": list(self.allowed_operations),
            "expires_at_epoch": self.expires_at_epoch,
            "max_uses": self.max_uses,
        }


class DelegationError(Exception):
    """A delegation could not be issued."""


class DelegationReceiptStore:
    """Issue, consume and revoke delegation receipts in DynamoDB."""

    def __init__(self, table, clock=time.time):
        self._table = table
        self._clock = clock

    def issue(self, *, parent_agent_id: str, child_agent_id: str, parent_scope: int,
              parent_chain: Optional[List[str]] = None, parent_decision_id: str = "",
              allowed_operations: Optional[List[str]] = None,
              ttl_seconds: int = DEFAULT_TTL_SECONDS, max_uses: int = DEFAULT_MAX_USES,
              max_depth: int = 4) -> DelegationReceipt:
        """Write a receipt for a delegation the governance plane has allowed.

        parent_scope must be the parent's trusted effective scope for the
        allowed decision; parent_chain is the chain of the parent's own
        verified receipt, or empty when the parent was not delegated.
        """
        if not parent_agent_id or not child_agent_id:
            raise DelegationError("delegation needs a parent and a child agent")
        if parent_agent_id == child_agent_id:
            raise DelegationError("an agent cannot delegate to itself")
        chain = [str(a) for a in (parent_chain or [])] + [parent_agent_id]
        if child_agent_id in chain:
            raise DelegationError(f"delegation cycle: {child_agent_id} is already in the chain {chain}")
        if len(chain) >= max_depth:
            raise DelegationError(f"delegation depth {len(chain)} would reach the maximum {max_depth}")
        if not 1 <= int(ttl_seconds) <= MAX_TTL_SECONDS:
            raise DelegationError(f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}")
        if not 1 <= int(max_uses) <= MAX_USES_LIMIT:
            raise DelegationError(f"max_uses must be between 1 and {MAX_USES_LIMIT}")
        now = self._clock()
        receipt = DelegationReceipt(
            receipt_id="dlg-" + secrets.token_hex(16),
            parent_agent_id=parent_agent_id,
            child_agent_id=child_agent_id,
            scope_cap=max(0, int(parent_scope)),
            chain=chain,
            parent_decision_id=parent_decision_id,
            allowed_operations=sorted({str(o) for o in (allowed_operations or []) if o}),
            issued_at=datetime.fromtimestamp(now, timezone.utc).isoformat(),
            expires_at_epoch=int(now) + int(ttl_seconds),
            max_uses=int(max_uses),
        )
        self._table.put_item(Item=receipt.to_item(),
                             ConditionExpression="attribute_not_exists(receipt_id)")
        logger.info(json.dumps({"audit_event": "delegation_receipt_issued", **receipt.summary(),
                                "parent_agent_id": parent_agent_id,
                                "parent_decision_id": parent_decision_id}))
        return receipt

    def _checked(self, receipt_id: str, child_agent_id: str,
                 operation_id: str) -> Tuple[Optional[DelegationReceipt], str]:
        if not receipt_id:
            return None, "no delegation receipt presented"
        try:
            item = self._table.get_item(Key={"receipt_id": receipt_id}, ConsistentRead=True).get("Item")
        except Exception as exc:
            logger.error(json.dumps({"event": "delegation_receipt_read_failed", "error": str(exc)}))
            return None, "delegation receipt store unavailable"
        if not item:
            return None, "delegation receipt not found"
        receipt = DelegationReceipt.from_item(item)
        now = int(self._clock())
        # Parent, child, chain, cap and operations never change after issue,
        # so checking them from this read is race-free.
        if receipt.child_agent_id != child_agent_id:
            return None, "delegation receipt was issued to a different agent"
        if receipt.allowed_operations and operation_id not in receipt.allowed_operations:
            return None, (f"operation '{operation_id or '(none)'}' is not in the delegated operations "
                          f"{receipt.allowed_operations}")
        if receipt.status != "active":
            return None, f"delegation receipt is {receipt.status or 'invalid'}"
        if now >= receipt.expires_at_epoch:
            return None, "delegation receipt has expired"
        if receipt.uses >= receipt.max_uses:
            return None, "delegation receipt has already been used"
        return receipt, ""

    def verify(self, receipt_id: str, child_agent_id: str,
               operation_id: str = "") -> Tuple[Optional[DelegationReceipt], str]:
        """Check a receipt without using it (simulation and dry runs)."""
        return self._checked(receipt_id, child_agent_id, operation_id)

    def consume(self, receipt_id: str, child_agent_id: str,
                operation_id: str = "") -> Tuple[Optional[DelegationReceipt], str]:
        """Verify a receipt for this child and use it once.

        Returns (receipt, "") on success or (None, reason) on any failure.
        The use is recorded with a conditional write, so concurrent requests
        cannot use a receipt more than max_uses times.
        """
        receipt, reason = self._checked(receipt_id, child_agent_id, operation_id)
        if receipt is None:
            return None, reason
        now = int(self._clock())
        try:
            self._table.update_item(
                Key={"receipt_id": receipt_id},
                UpdateExpression="SET #uses = #uses + :one, last_used_at = :at",
                ConditionExpression=("#status = :active AND expires_at_epoch > :now "
                                     "AND #uses < max_uses AND child_agent_id = :child"),
                ExpressionAttributeNames={"#uses": "uses", "#status": "status"},
                ExpressionAttributeValues={":one": 1, ":active": "active", ":now": Decimal(now),
                                           ":child": child_agent_id,
                                           ":at": datetime.fromtimestamp(now, timezone.utc).isoformat()},
            )
        except Exception as exc:
            if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                return None, "delegation receipt was used, revoked or expired concurrently"
            logger.error(json.dumps({"event": "delegation_receipt_consume_failed", "error": str(exc)}))
            return None, "delegation receipt store unavailable"
        receipt.uses += 1
        logger.info(json.dumps({"audit_event": "delegation_receipt_used", "receipt_id": receipt_id,
                                "child_agent_id": child_agent_id, "operation_id": operation_id,
                                "uses": receipt.uses, "max_uses": receipt.max_uses}))
        return receipt, ""

    def revoke(self, receipt_id: str, revoked_by: str) -> bool:
        """Revoke a receipt; returns False when it does not exist."""
        try:
            self._table.update_item(
                Key={"receipt_id": receipt_id},
                UpdateExpression="SET #status = :revoked, revoked_by = :by",
                ConditionExpression="attribute_exists(receipt_id)",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":revoked": "revoked", ":by": revoked_by},
            )
        except Exception as exc:
            if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                return False
            raise
        logger.info(json.dumps({"audit_event": "delegation_receipt_revoked", "receipt_id": receipt_id,
                                "revoked_by": revoked_by}))
        return True
