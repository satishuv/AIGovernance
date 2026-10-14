"""Provider-neutral credential broker interfaces.

The broker receives a VERIFIED, CONSUMED DelegatedAuthorityGrant and asks a
provider adapter for a provider-native credential that is no broader than the
grant. Adapters return a CredentialHandle: safe metadata plus a secret that
stays inside the handle. The secret is never logged, serialized, returned to a
UI or written to evidence; only a credential_reference is recorded.
"""

import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from request_canonicalization import canonical_json, to_json_safe

MODE_MOCK = "mock"
MODE_LIVE = "live"


class BrokerRefusal(RuntimeError):
    """The broker refused to issue a credential (fail closed)."""


class ProviderNotConfigured(BrokerRefusal):
    """A live adapter was selected but its federation/OAuth settings are absent."""


def new_credential_reference() -> str:
    return "cred-" + secrets.token_hex(4)


@dataclass
class CredentialHandle:
    provider: str
    credential_type: str
    credential_reference: str
    issued_at: str
    expires_at: str
    effective_until: str
    scopes: List[str]
    grant_id: str
    mode: str
    details: Dict[str, Any] = field(default_factory=dict)
    _secret: Any = field(default=None, repr=False, compare=False)

    def metadata(self) -> Dict[str, Any]:
        """Everything about the credential except the credential."""
        return to_json_safe({
            "provider": self.provider,
            "credential_type": self.credential_type,
            "credential_reference": self.credential_reference,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "effective_until": self.effective_until,
            "scopes": list(self.scopes),
            "grant_id": self.grant_id,
            "mode": self.mode,
            "secret_preview": "********",
            "details": dict(self.details),
        })

    def __getstate__(self):  # never pickle a live secret
        raise TypeError("CredentialHandle cannot be serialized")


@dataclass
class ExecutionResult:
    provider: str
    operation_id: str
    status: str  # success | failed
    summary: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def result_hash(self) -> str:
        return hashlib.sha256(canonical_json(to_json_safe(self.summary)).encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "operation_id": self.operation_id, "status": self.status,
                "summary": to_json_safe(self.summary), "error": self.error,
                "result_hash": self.result_hash}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def bounded_expiry(grant, ttl_seconds: int) -> datetime:
    """A credential never outlives its grant."""
    grant_expiry = datetime.fromisoformat(grant.expires_at)
    return min(utc_now() + timedelta(seconds=ttl_seconds), grant_expiry)


class CredentialProvider(ABC):
    """One enforcement target (AWS, Entra, ServiceNow, Google, governance)."""

    name: str = ""
    mode: str = MODE_MOCK

    @abstractmethod
    def exchange(self, verified, spec) -> CredentialHandle:
        """Issue a credential scoped to exactly the grant's operation and target."""

    @abstractmethod
    def execute(self, handle: CredentialHandle, verified, spec) -> ExecutionResult:
        """Perform the granted operation using the handle's credential."""
