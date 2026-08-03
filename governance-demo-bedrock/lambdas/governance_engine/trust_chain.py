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

Request fields consumed (all optional -- absent means human/direct call):
  calling_agent_id   : str   -- agent_id of the orchestrator that delegated
  delegation_chain   : list  -- ordered list of agent_ids from originator to
                                current caller (not including this agent)
  calling_agent_scope: int   -- scope level the calling agent was authorized
                                for (supplied by the calling agent's own
                                governance decision receipt)
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_DELEGATION_DEPTH = int(4)

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


class TrustChainValidator:
    """Enforce scope, depth, and injection constraints across agent calls."""

    def validate(
        self,
        agent_id: str,
        requested_scope: int,
        action_request: Dict[str, Any],
    ) -> TrustChainResult:
        """Run all three trust-chain checks.

        Args:
            agent_id: The agent that is about to execute the action.
            requested_scope: The scope_level from the inbound request.
            action_request: Full action request dict.

        Returns:
            TrustChainResult. If allowed=False the pipeline must deny.
        """
        calling_agent_id: str = action_request.get("calling_agent_id", "") or ""
        delegation_chain: List[str] = list(
            action_request.get("delegation_chain", []) or []
        )
        calling_agent_scope: Optional[int] = action_request.get("calling_agent_scope")
        if calling_agent_scope is not None:
            try:
                calling_agent_scope = int(calling_agent_scope)
            except (TypeError, ValueError):
                calling_agent_scope = None

        inter_agent = bool(calling_agent_id)
        violations: List[str] = []
        now = datetime.now(timezone.utc).isoformat()

        # 1. Delegation depth
        depth = len(delegation_chain)
        if depth >= MAX_DELEGATION_DEPTH:
            reason = (
                f"Delegation depth {depth} exceeds maximum {MAX_DELEGATION_DEPTH}. "
                f"Chain: {delegation_chain}"
            )
            violations.append(reason)
            logger.warning(json.dumps({
                "event": "trust_chain_depth_exceeded",
                "agent_id": agent_id,
                "calling_agent_id": calling_agent_id,
                "delegation_chain": delegation_chain,
                "depth": depth,
                "max": MAX_DELEGATION_DEPTH,
                "timestamp": now,
            }))
            return TrustChainResult(
                allowed=False,
                reason=reason,
                violations=violations,
                inter_agent=inter_agent,
            )

        # 2. Scope laundering: sub-agent scope cannot exceed calling agent scope
        effective_scope_cap: Optional[int] = None
        if inter_agent and calling_agent_scope is not None:
            if requested_scope > calling_agent_scope:
                reason = (
                    f"Scope laundering blocked: agent '{agent_id}' requested "
                    f"scope {requested_scope} but calling agent '{calling_agent_id}' "
                    f"was only authorized at scope {calling_agent_scope}. "
                    f"Sub-agent scope capped at calling agent scope."
                )
                violations.append(reason)
                effective_scope_cap = calling_agent_scope
                logger.warning(json.dumps({
                    "event": "scope_laundering_blocked",
                    "agent_id": agent_id,
                    "calling_agent_id": calling_agent_id,
                    "requested_scope": requested_scope,
                    "calling_agent_scope": calling_agent_scope,
                    "delegation_chain": delegation_chain,
                    "timestamp": now,
                }))
                return TrustChainResult(
                    allowed=False,
                    reason=reason,
                    violations=violations,
                    inter_agent=True,
                    effective_scope_cap=effective_scope_cap,
                )

        # 3. Cross-agent prompt injection detection
        injection_suspected = False
        if inter_agent:
            probe = " ".join(
                str(action_request.get(k, ""))
                for k in ("input_text", "context", "agent_reasoning")
            )
            if probe.strip() and _INJECTION_IN_AGENT_MSG.search(probe):
                injection_suspected = True
                reason = (
                    f"Cross-agent prompt injection suspected in message from "
                    f"'{calling_agent_id}' to '{agent_id}'. "
                    f"Action blocked pending operator review."
                )
                violations.append(reason)
                logger.critical(json.dumps({
                    "event": "CROSS_AGENT_INJECTION_SUSPECTED",
                    "severity": "CRITICAL",
                    "agent_id": agent_id,
                    "calling_agent_id": calling_agent_id,
                    "delegation_chain": delegation_chain,
                    "timestamp": now,
                }))
                return TrustChainResult(
                    allowed=False,
                    reason=reason,
                    violations=violations,
                    inter_agent=True,
                    injection_suspected=True,
                )

        # All checks passed
        logger.info(json.dumps({
            "event": "trust_chain_validated",
            "agent_id": agent_id,
            "calling_agent_id": calling_agent_id or None,
            "inter_agent": inter_agent,
            "delegation_depth": depth,
            "requested_scope": requested_scope,
            "calling_agent_scope": calling_agent_scope,
            "timestamp": now,
        }))
        return TrustChainResult(
            allowed=True,
            reason="",
            violations=[],
            inter_agent=inter_agent,
            injection_suspected=False,
            effective_scope_cap=None,
        )
