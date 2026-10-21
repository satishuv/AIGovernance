"""Multi-agent trust chain enforcement.

Three controls:
  1. Scope laundering prevention: a sub-agent cannot execute at a scope
     level higher than the calling agent was authorized for.
  2. Delegation depth limit: chains longer than MAX_DELEGATION_DEPTH are
     blocked unconditionally (prevents unbounded orchestrator nesting).
  3. Cross-agent prompt injection tagging: requests whose source is another
     agent are marked so the input sanitizer can apply stricter scrutiny.

These controls fire before scope enforcement in the pipeline so that a
compromised orchestrator cannot bootstrap a sub-agent to bypass the
per-agent scope table.

Verified delegation (P0-11). The calling agent, the delegation chain and the
calling agent's scope come only from a DelegationReceipt the governance plane
issued server-side (delegation_receipts.py). Before this change they were read
from the request (calling_agent_id, delegation_chain, calling_agent_scope),
so a caller that omitted or inflated calling_agent_scope removed the parent's
cap. Those request fields are now claims: a request that makes any of them
without a verified receipt is denied, and a claim that disagrees with the
receipt is denied as tampering.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_DELEGATION_DEPTH = int(4)

# Request fields that claim a delegation. None of them is trusted.
DELEGATION_CLAIM_FIELDS = ("calling_agent_id", "delegation_chain", "calling_agent_scope")

# Phrases that look like injected instructions embedded in agent-to-agent
# traffic (orchestrator output becoming sub-agent input).
_INJECTION_IN_AGENT_MSG = re.compile(
    r"(?:"
    r"ignore (?:previous|prior|all|above) instructions?"
    r"|disregard (?:your |the )?(?:previous |prior |system )?instructions?"
    r"|new (?:primary )?(?:objective|goal|task|directive)"
    r"|you are now (?:a |an )?"
    r"|forget (?:everything|all) (?:you (?:know|were told)|above)"
    r"|act as (?:a |an )?"
    r"|override (?:your |all )?(?:previous |prior )?(?:instructions?|rules?|guidelines?)"
    r"|system prompt[:\s]"
    r"|<\s*system\s*>"
    r")",
    re.IGNORECASE,
)


@dataclass
class TrustChainResult:
    allowed: bool
    reason: str
    violations: List[str] = field(default_factory=list)
    # True when the request was flagged as inter-agent traffic
    inter_agent: bool = False
    # True when injection patterns were found in an inter-agent message
    injection_suspected: bool = False
    effective_scope_cap: Optional[int] = None
    # Why the request was denied: depth, scope_laundering, injection,
    # unverified_delegation or delegation_mismatch ("" when allowed).
    category: str = ""
    # Verified values, from the receipt (empty for a direct call).
    calling_agent_id: str = ""
    delegation_chain: List[str] = field(default_factory=list)


def has_delegation_claim(action_request: Dict[str, Any]) -> bool:
    """True when the request claims to be delegated by another agent."""
    for name in DELEGATION_CLAIM_FIELDS:
        value = action_request.get(name)
        if value not in (None, "", [], ()):
            return True
    return False


def _claim_mismatch(action_request: Dict[str, Any], receipt: Any) -> str:
    claimed_caller = action_request.get("calling_agent_id")
    if claimed_caller not in (None, "") and str(claimed_caller) != receipt.parent_agent_id:
        return (f"calling_agent_id '{claimed_caller}' does not match the verified parent "
                f"'{receipt.parent_agent_id}'")
    claimed_chain = action_request.get("delegation_chain")
    if claimed_chain not in (None, "", [], ()) and [str(a) for a in claimed_chain] != list(receipt.chain):
        return f"delegation_chain {list(claimed_chain)} does not match the verified chain {receipt.chain}"
    claimed_scope = action_request.get("calling_agent_scope")
    if claimed_scope not in (None, ""):
        try:
            if int(claimed_scope) != receipt.scope_cap:
                return (f"calling_agent_scope {claimed_scope} does not match the verified scope cap "
                        f"{receipt.scope_cap}")
        except (TypeError, ValueError):
            return f"calling_agent_scope {claimed_scope!r} is not a scope level"
    return ""


class TrustChainValidator:
    """Enforce scope, depth, and injection constraints across agent calls."""

    def validate(
        self,
        agent_id: str,
        requested_scope: int,
        action_request: Dict[str, Any],
        verified_delegation: Any = None,
    ) -> TrustChainResult:
        """Run the trust-chain checks.

        Args:
            agent_id: The agent that is about to execute the action.
            requested_scope: The scope the request would run at.
            action_request: Full action request dict.
            verified_delegation: The DelegationReceipt consumed for this
                request, or None for a direct (non-delegated) call.

        Returns:
            TrustChainResult. If allowed=False the pipeline must deny.
        """
        now = datetime.now(timezone.utc).isoformat()
        claimed = has_delegation_claim(action_request)

        if verified_delegation is None:
            if claimed:
                reason = (
                    "Unverified delegation: the request claims a calling agent, delegation chain "
                    "or calling-agent scope without a delegation receipt issued by the governance "
                    "plane. Delegation is accepted only through delegation_receipt_id."
                )
                logger.warning(json.dumps({
                    "event": "trust_chain_unverified_delegation",
                    "agent_id": agent_id,
                    "claimed_fields": [f for f in DELEGATION_CLAIM_FIELDS if action_request.get(f)],
                    "timestamp": now,
                }))
                return TrustChainResult(allowed=False, reason=reason, violations=[reason],
                                        inter_agent=True, category="unverified_delegation")
            logger.info(json.dumps({"event": "trust_chain_validated", "agent_id": agent_id,
                                    "inter_agent": False, "requested_scope": requested_scope,
                                    "timestamp": now}))
            return TrustChainResult(allowed=True, reason="")

        receipt = verified_delegation
        calling_agent_id = receipt.parent_agent_id
        delegation_chain = list(receipt.chain)
        calling_agent_scope = receipt.scope_cap

        mismatch = _claim_mismatch(action_request, receipt)
        if mismatch:
            reason = f"Delegation claim does not match the verified receipt: {mismatch}"
            logger.warning(json.dumps({"event": "trust_chain_delegation_mismatch", "agent_id": agent_id,
                                       "receipt_id": receipt.receipt_id, "detail": mismatch,
                                       "timestamp": now}))
            return TrustChainResult(allowed=False, reason=reason, violations=[reason], inter_agent=True,
                                    category="delegation_mismatch", calling_agent_id=calling_agent_id,
                                    delegation_chain=delegation_chain)

        # 1. Delegation depth (receipt issuance also refuses chains at the limit)
        depth = len(delegation_chain)
        if depth >= MAX_DELEGATION_DEPTH:
            reason = (
                f"Delegation depth {depth} exceeds maximum {MAX_DELEGATION_DEPTH}. "
                f"Chain: {delegation_chain}"
            )
            logger.warning(json.dumps({
                "event": "trust_chain_depth_exceeded",
                "agent_id": agent_id,
                "calling_agent_id": calling_agent_id,
                "delegation_chain": delegation_chain,
                "depth": depth,
                "max": MAX_DELEGATION_DEPTH,
                "timestamp": now,
            }))
            return TrustChainResult(allowed=False, reason=reason, violations=[reason], inter_agent=True,
                                    category="depth", calling_agent_id=calling_agent_id,
                                    delegation_chain=delegation_chain)

        # 2. Scope laundering: sub-agent scope cannot exceed calling agent scope
        if requested_scope > calling_agent_scope:
            reason = (
                f"Scope laundering blocked: agent '{agent_id}' requested "
                f"scope {requested_scope} but calling agent '{calling_agent_id}' "
                f"was only authorized at scope {calling_agent_scope}. "
                f"Sub-agent scope capped at calling agent scope."
            )
            logger.warning(json.dumps({
                "event": "scope_laundering_blocked",
                "agent_id": agent_id,
                "calling_agent_id": calling_agent_id,
                "requested_scope": requested_scope,
                "calling_agent_scope": calling_agent_scope,
                "delegation_chain": delegation_chain,
                "timestamp": now,
            }))
            return TrustChainResult(allowed=False, reason=reason, violations=[reason], inter_agent=True,
                                    effective_scope_cap=calling_agent_scope, category="scope_laundering",
                                    calling_agent_id=calling_agent_id, delegation_chain=delegation_chain)

        # 3. Cross-agent prompt injection detection
        probe = " ".join(
            str(action_request.get(k, ""))
            for k in ("input_text", "context", "agent_reasoning")
        )
        if probe.strip() and _INJECTION_IN_AGENT_MSG.search(probe):
            reason = (
                f"Cross-agent prompt injection suspected in message from "
                f"'{calling_agent_id}' to '{agent_id}'. "
                f"Action blocked pending operator review."
            )
            logger.critical(json.dumps({
                "event": "CROSS_AGENT_INJECTION_SUSPECTED",
                "severity": "CRITICAL",
                "agent_id": agent_id,
                "calling_agent_id": calling_agent_id,
                "delegation_chain": delegation_chain,
                "timestamp": now,
            }))
            return TrustChainResult(allowed=False, reason=reason, violations=[reason], inter_agent=True,
                                    injection_suspected=True, category="injection",
                                    calling_agent_id=calling_agent_id, delegation_chain=delegation_chain)

        # All checks passed
        logger.info(json.dumps({
            "event": "trust_chain_validated",
            "agent_id": agent_id,
            "calling_agent_id": calling_agent_id,
            "receipt_id": receipt.receipt_id,
            "inter_agent": True,
            "delegation_depth": depth,
            "requested_scope": requested_scope,
            "calling_agent_scope": calling_agent_scope,
            "timestamp": now,
        }))
        return TrustChainResult(allowed=True, reason="", inter_agent=True,
                                effective_scope_cap=calling_agent_scope,
                                calling_agent_id=calling_agent_id, delegation_chain=delegation_chain)
