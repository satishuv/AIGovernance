"""Credential broker: verified grant in, target-specific credential out."""

import json
import logging
from datetime import datetime
from typing import Dict

from delegated_authority import VerifiedGrant

from .base import BrokerRefusal, CredentialHandle, CredentialProvider, ExecutionResult

logger = logging.getLogger(__name__)


class CredentialBroker:
    """Routes a verified grant to the provider adapter that enforces it.

    The broker refuses (fails closed) when:
      * the grant proof was not produced by this deployment's grant store, or
        was not consumed for this use;
      * no adapter is registered for the grant's provider;
      * the operation spec does not match the grant;
      * the adapter returns scopes outside the operation's provider scopes, or
        a credential whose effective lifetime exceeds the grant's.
    """

    def __init__(self, adapters: Dict[str, CredentialProvider], grant_store):
        self._adapters = dict(adapters)
        self._store = grant_store

    def adapter_modes(self) -> Dict[str, str]:
        return {name: adapter.mode for name, adapter in sorted(self._adapters.items())}

    def _check_proof(self, verified, spec) -> None:
        if not isinstance(verified, VerifiedGrant) or not verified.consumed or not verified.issued_by(self._store):
            raise BrokerRefusal("credential exchange requires a grant verified and consumed by this control plane")
        grant = verified.grant
        if spec is None or spec.operation_id != grant.operation_id or spec.provider != grant.provider:
            raise BrokerRefusal("operation specification does not match the grant")

    def exchange(self, verified, spec) -> CredentialHandle:
        self._check_proof(verified, spec)
        grant = verified.grant
        adapter = self._adapters.get(grant.provider)
        if adapter is None:
            raise BrokerRefusal(f"no credential adapter is registered for provider '{grant.provider}'")
        handle = adapter.exchange(verified, spec)
        extra = set(handle.scopes) - set(spec.provider_scopes)
        if extra:
            raise BrokerRefusal(f"adapter requested scopes beyond the operation: {sorted(extra)}")
        if datetime.fromisoformat(handle.effective_until) > datetime.fromisoformat(grant.expires_at):
            raise BrokerRefusal("credential would remain usable after the grant expires")
        logger.info(json.dumps({"audit_event": "credential_issued", "grant_id": grant.grant_id,
                                "provider": grant.provider, "mode": adapter.mode,
                                "credential_reference": handle.credential_reference,
                                "effective_until": handle.effective_until}))
        return handle

    def execute(self, handle: CredentialHandle, verified, spec) -> ExecutionResult:
        self._check_proof(verified, spec)
        if handle.grant_id != verified.grant.grant_id:
            raise BrokerRefusal("credential was issued for a different grant")
        adapter = self._adapters[verified.grant.provider]
        try:
            return adapter.execute(handle, verified, spec)
        except BrokerRefusal:
            raise
        except Exception as exc:  # provider failure is reported, never retried silently
            return ExecutionResult(verified.grant.provider, spec.operation_id, "failed",
                                   {}, f"{type(exc).__name__}: {str(exc)[:200]}")
