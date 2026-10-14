"""Mock adapter base for OAuth-style providers (Entra, ServiceNow, Google).

mock mode   issues an opaque random token held only inside the handle and
            executes against in-memory fixtures. No network, no credentials.
live mode   reserved for workload identity federation / OAuth client
            credentials. It refuses (ProviderNotConfigured) until a deployment
            supplies its own federation settings; no credentials are ever
            hard-coded here.
"""

import os
import secrets
from typing import Any, Dict

from .base import (
    MODE_LIVE,
    MODE_MOCK,
    CredentialHandle,
    CredentialProvider,
    ExecutionResult,
    ProviderNotConfigured,
    bounded_expiry,
    new_credential_reference,
    utc_now,
)


class OAuthStyleAdapter(CredentialProvider):
    """Shared exchange logic; subclasses implement _execute_mock."""

    credential_type = "oauth_access_token"
    live_settings_env: tuple = ()

    def __init__(self, mode: str = MODE_MOCK, token_ttl_seconds: int = 300):
        if mode not in (MODE_MOCK, MODE_LIVE):
            raise ValueError(f"unknown provider mode {mode!r}")
        self.mode = mode
        self._ttl = int(token_ttl_seconds)

    def _live_settings(self) -> Dict[str, str]:
        settings = {k: os.environ.get(k, "") for k in self.live_settings_env}
        missing = [k for k, v in settings.items() if not v]
        if missing:
            raise ProviderNotConfigured(
                f"{self.name} live mode needs federation settings {missing}; "
                "the customer demo runs this provider in mock mode")
        return settings

    def exchange(self, verified, spec) -> CredentialHandle:
        grant = verified.grant
        if self.mode == MODE_LIVE:
            self._live_settings()
            raise ProviderNotConfigured(
                f"{self.name} live token exchange is an integration point for the customer's "
                "workload identity federation; it is intentionally not implemented in the demo")
        issued = utc_now()
        expires = bounded_expiry(grant, self._ttl)
        return CredentialHandle(
            provider=self.name, credential_type=self.credential_type,
            credential_reference=new_credential_reference(),
            issued_at=issued.isoformat(), expires_at=expires.isoformat(),
            effective_until=expires.isoformat(), scopes=list(spec.provider_scopes),
            grant_id=grant.grant_id, mode=self.mode,
            details={"token_audience": f"{self.name}-mock-tenant",
                     "subject": f"agent:{grant.agent_id}", "grant_bound": True},
            _secret=secrets.token_urlsafe(32),
        )

    def execute(self, handle: CredentialHandle, verified, spec) -> ExecutionResult:
        if handle._secret is None:
            return ExecutionResult(self.name, spec.operation_id, "failed", {}, "credential missing")
        request = verified.canonical_request
        summary = self._execute_mock(spec.operation_id, request["tool_parameters"],
                                     request["target_resource"], verified)
        return ExecutionResult(self.name, spec.operation_id, "success", summary)

    def _execute_mock(self, operation_id: str, params: Dict[str, Any], target: str,
                      verified) -> Dict[str, Any]:
        raise NotImplementedError


class MockProvider(OAuthStyleAdapter):
    """Generic in-memory provider for tests: records each executed request."""

    def __init__(self, name: str, mode: str = MODE_MOCK):
        super().__init__(mode)
        self.name = name
        self.executions = []

    def _execute_mock(self, operation_id, params, target, verified):
        self.executions.append({"operation_id": operation_id, "target": target, "params": dict(params)})
        return {"operation_id": operation_id, "target": target, "executed": True}
