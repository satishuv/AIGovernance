"""Identity freshness and revocation validation (AARM R6).

AARM R6 requires that each action's identity be validated against a trusted
source, including freshness (not expired / within validity window) and
revocation (not suspended/revoked), with actions lacking verifiable identity
denied or flagged, and identity preserved across deferral and delegation.

The building blocks already exist:
  - agent_identity.is_suspended()  -> revocation via registry status
  - agent_token_exchange token is_expired()/is_valid()/status -> freshness + revocation

This module consolidates them into a single validation gate the pipeline calls
before a decision, returning a clear verdict so identity problems are handled
uniformly rather than scattered across checks.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class IdentityValidationResult:
    """Outcome of identity validation for an action (AARM R6).

    Attributes:
        verified: True when identity is present, fresh, and not revoked.
        deny: True when the action must be denied (no verifiable identity or revoked).
        flags: Non-fatal issues to record on the receipt (e.g. missing session).
        principal: The bound principal/agent identifier.
        reason: Human-readable explanation.
    """
    verified: bool
    deny: bool = False
    flags: List[str] = field(default_factory=list)
    principal: str = ""
    reason: str = ""


def validate_identity(
    agent_id: str,
    identity_manager: Any = None,
    token: Optional[Dict[str, Any]] = None,
    now_iso: Optional[str] = None,
) -> IdentityValidationResult:
    """Validate identity freshness + revocation against trusted sources.

    Args:
        agent_id: The acting agent/principal identifier.
        identity_manager: AgentIdentityManager (trusted registry source) or None.
        token: Optional token dict with issued_at/expires_at/status for freshness.
        now_iso: Optional ISO timestamp override (tests).

    Returns:
        IdentityValidationResult. deny=True means the action must not proceed.
    """
    flags: List[str] = []

    # 1. Identity must be present and verifiable (deny if absent).
    if not agent_id:
        return IdentityValidationResult(
            verified=False, deny=True, reason="No verifiable identity on the action; denying (AARM R6).",
        )

    # 2. Revocation: check the trusted registry source for suspension/revocation.
    if identity_manager is not None:
        try:
            if identity_manager.is_suspended(agent_id):
                return IdentityValidationResult(
                    verified=False, deny=True, principal=agent_id,
                    reason=f"Identity '{agent_id}' is revoked/suspended in the registry; denying (AARM R6).",
                )
        except Exception:
            # Trusted source unavailable -> cannot confirm identity is valid.
            # Flag rather than silently trust.
            flags.append("registry_unavailable_identity_unconfirmed")

    # 3. Freshness + token revocation, when a token is presented.
    if token is not None:
        status = token.get("status", "active")
        expires_at = token.get("expires_at", "")
        now = now_iso or datetime.now(timezone.utc).isoformat()
        if status != "active":
            return IdentityValidationResult(
                verified=False, deny=True, principal=agent_id,
                reason=f"Identity token status is '{status}' (revoked); denying (AARM R6).",
            )
        if expires_at and now > expires_at:
            return IdentityValidationResult(
                verified=False, deny=True, principal=agent_id,
                reason="Identity token is expired (stale); denying (AARM R6).",
            )

    return IdentityValidationResult(
        verified=True, deny=False, flags=flags, principal=agent_id,
        reason="Identity present, fresh, and not revoked." if not flags else "Identity accepted with flags.",
    )
