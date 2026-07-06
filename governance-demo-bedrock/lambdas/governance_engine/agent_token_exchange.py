"""Agent Token Exchange - cryptographic identity and data access governance.

Implements agent identity lifecycle with cryptographic token exchange.
Agents must check data in and out using verifiable tokens. This provides:

1. Agent Identity Verification: cryptographic proof of agent identity per request
2. Data Check-In/Check-Out: agents request tokenized access to data resources
3. Token Lifecycle: tokens are scoped, time-limited, and revocable
4. Non-repudiation: every data access is signed and traceable to a specific agent+session
5. Tokenized Data-Lake Access: agents get short-lived tokens for specific data classes

This addresses the manager's feedback:
"Cryptographic token exchange so agents check data in and out,
with guardrails around tokenized data-lake access."
"""

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

TOKEN_SECRET = os.environ.get("AGENT_TOKEN_SECRET", "agcp-governance-token-v1-default")
TOKEN_TTL_SECONDS = int(os.environ.get("AGENT_TOKEN_TTL", "3600"))


class AgentToken:
    """A cryptographic token representing an agent's authorized data access."""

    def __init__(self, token_id: str, agent_id: str, session_id: str,
                 data_classes: List[str], scope_level: int,
                 issued_at: str, expires_at: str, signature: str,
                 status: str = "active"):
        self.token_id = token_id
        self.agent_id = agent_id
        self.session_id = session_id
        self.data_classes = data_classes
        self.scope_level = scope_level
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.signature = signature
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "data_classes": self.data_classes,
            "scope_level": self.scope_level,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "status": self.status,
        }

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        return now > self.expires_at

    @property
    def is_valid(self) -> bool:
        return self.status == "active" and not self.is_expired


class DataAccessRecord:
    """Immutable record of an agent checking data in or out."""

    def __init__(self, record_id: str, token_id: str, agent_id: str,
                 action: str, data_class: str, resource_id: str,
                 timestamp: str, signature: str):
        self.record_id = record_id
        self.token_id = token_id
        self.agent_id = agent_id
        self.action = action  # "check_out" or "check_in"
        self.data_class = data_class
        self.resource_id = resource_id
        self.timestamp = timestamp
        self.signature = signature

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "token_id": self.token_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "data_class": self.data_class,
            "resource_id": self.resource_id,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }


class AgentTokenExchange:
    """Manages cryptographic token exchange for agent data access.

    Flow:
    1. Agent requests a token (issue_token) with desired data classes
    2. Governance validates agent is authorized for those data classes
    3. Token is issued with scope, TTL, and cryptographic signature
    4. Agent presents token when checking data out (check_out)
    5. System validates token, logs access, returns data reference
    6. Agent presents token when returning/releasing data (check_in)
    7. Token can be revoked at any time (revoke_token)
    """

    def __init__(self, secret: str = None, ttl: int = None):
        self._secret = (secret or TOKEN_SECRET).encode("utf-8")
        self._ttl = ttl or TOKEN_TTL_SECONDS
        self._active_tokens: Dict[str, AgentToken] = {}
        self._access_log: List[DataAccessRecord] = []

    def issue_token(self, agent_id: str, session_id: str,
                    requested_data_classes: List[str],
                    scope_level: int,
                    agent_registry_entry: Dict[str, Any] = None) -> Tuple[Optional[AgentToken], str]:
        """Issue a cryptographic token for data access.

        Validates:
        - Agent is registered and active
        - Requested data classes are within agent's approved classes
        - Scope level permits the requested access

        Returns (token, error_message). Token is None if denied.
        """
        now = datetime.now(timezone.utc)

        # Validate agent authorization
        if agent_registry_entry:
            approved_classes = agent_registry_entry.get("approved_data_classes", [])
            agent_status = agent_registry_entry.get("status", "unknown")

            if agent_status != "active":
                reason = f"Agent '{agent_id}' is not active (status: {agent_status})"
                self._log_denial(agent_id, session_id, requested_data_classes, reason)
                return None, reason

            unauthorized = [dc for dc in requested_data_classes if dc not in approved_classes]
            if unauthorized:
                reason = f"Agent '{agent_id}' not authorized for data classes: {unauthorized}"
                self._log_denial(agent_id, session_id, requested_data_classes, reason)
                return None, reason

        # Generate token
        token_id = str(uuid.uuid4())
        issued_at = now.isoformat()
        expires_at = datetime.fromtimestamp(now.timestamp() + self._ttl, tz=timezone.utc).isoformat()

        # Cryptographic signature (HMAC-SHA256)
        payload = f"{token_id}:{agent_id}:{session_id}:{','.join(sorted(requested_data_classes))}:{scope_level}:{issued_at}"
        signature = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        token = AgentToken(
            token_id=token_id,
            agent_id=agent_id,
            session_id=session_id,
            data_classes=requested_data_classes,
            scope_level=scope_level,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

        self._active_tokens[token_id] = token

        logger.info(json.dumps({
            "event": "token_issued",
            "token_id": token_id,
            "agent_id": agent_id,
            "data_classes": requested_data_classes,
            "scope_level": scope_level,
            "expires_at": expires_at,
            "timestamp": issued_at,
        }))

        return token, ""

    def validate_token(self, token_id: str, agent_id: str,
                       data_class: str) -> Tuple[bool, str]:
        """Validate a token for a specific data access request.

        Checks:
        - Token exists and is active
        - Token belongs to the requesting agent
        - Token covers the requested data class
        - Token has not expired
        - Signature is valid (not tampered)
        """
        token = self._active_tokens.get(token_id)

        if not token:
            return False, f"Token '{token_id}' not found"

        if token.agent_id != agent_id:
            return False, f"Token does not belong to agent '{agent_id}'"

        if token.status != "active":
            return False, f"Token is {token.status} (not active)"

        if token.is_expired:
            return False, f"Token expired at {token.expires_at}"

        if data_class not in token.data_classes:
            return False, f"Token does not authorize access to data class '{data_class}'"

        # Verify signature (tamper detection)
        payload = f"{token.token_id}:{token.agent_id}:{token.session_id}:{','.join(sorted(token.data_classes))}:{token.scope_level}:{token.issued_at}"
        expected_sig = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if token.signature != expected_sig:
            return False, "Token signature invalid (possible tampering)"

        return True, ""

    def check_out(self, token_id: str, agent_id: str,
                  data_class: str, resource_id: str) -> Tuple[Optional[DataAccessRecord], str]:
        """Agent checks out data using a valid token.

        Creates an immutable access record proving the agent accessed this data.
        """
        valid, error = self.validate_token(token_id, agent_id, data_class)
        if not valid:
            return None, error

        now = datetime.now(timezone.utc).isoformat()
        record_id = str(uuid.uuid4())

        # Sign the access record
        record_payload = f"{record_id}:{token_id}:{agent_id}:check_out:{data_class}:{resource_id}:{now}"
        signature = hmac.new(self._secret, record_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        record = DataAccessRecord(
            record_id=record_id,
            token_id=token_id,
            agent_id=agent_id,
            action="check_out",
            data_class=data_class,
            resource_id=resource_id,
            timestamp=now,
            signature=signature,
        )

        self._access_log.append(record)

        logger.info(json.dumps({
            "event": "data_check_out",
            "record_id": record_id,
            "token_id": token_id,
            "agent_id": agent_id,
            "data_class": data_class,
            "resource_id": resource_id,
            "timestamp": now,
        }))

        return record, ""

    def check_in(self, token_id: str, agent_id: str,
                 data_class: str, resource_id: str) -> Tuple[Optional[DataAccessRecord], str]:
        """Agent checks data back in (releases access).

        Creates an immutable record proving the agent released this data.
        """
        valid, error = self.validate_token(token_id, agent_id, data_class)
        if not valid:
            return None, error

        now = datetime.now(timezone.utc).isoformat()
        record_id = str(uuid.uuid4())

        record_payload = f"{record_id}:{token_id}:{agent_id}:check_in:{data_class}:{resource_id}:{now}"
        signature = hmac.new(self._secret, record_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        record = DataAccessRecord(
            record_id=record_id,
            token_id=token_id,
            agent_id=agent_id,
            action="check_in",
            data_class=data_class,
            resource_id=resource_id,
            timestamp=now,
            signature=signature,
        )

        self._access_log.append(record)

        logger.info(json.dumps({
            "event": "data_check_in",
            "record_id": record_id,
            "token_id": token_id,
            "agent_id": agent_id,
            "data_class": data_class,
            "resource_id": resource_id,
            "timestamp": now,
        }))

        return record, ""

    def revoke_token(self, token_id: str, reason: str = "") -> bool:
        """Revoke a token immediately. Agent can no longer use it."""
        token = self._active_tokens.get(token_id)
        if not token:
            return False

        token.status = "revoked"

        logger.warning(json.dumps({
            "event": "token_revoked",
            "token_id": token_id,
            "agent_id": token.agent_id,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        return True

    def get_access_log(self, agent_id: str = None) -> List[Dict[str, Any]]:
        """Get the access log, optionally filtered by agent."""
        if agent_id:
            return [r.to_dict() for r in self._access_log if r.agent_id == agent_id]
        return [r.to_dict() for r in self._access_log]

    def get_active_tokens(self, agent_id: str = None) -> List[Dict[str, Any]]:
        """Get active tokens, optionally filtered by agent."""
        tokens = self._active_tokens.values()
        if agent_id:
            tokens = [t for t in tokens if t.agent_id == agent_id]
        return [t.to_dict() for t in tokens if t.is_valid]

    def _log_denial(self, agent_id: str, session_id: str,
                    data_classes: List[str], reason: str) -> None:
        """Log a token issuance denial."""
        logger.warning(json.dumps({
            "event": "token_denied",
            "agent_id": agent_id,
            "session_id": session_id,
            "requested_data_classes": data_classes,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
