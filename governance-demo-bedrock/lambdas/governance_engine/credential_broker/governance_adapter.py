"""Governance adapter: oversight operations executed inside the control plane.

Guardian agents use the same request -> decision -> grant -> credential path
as workers. Their operations only READ decisions and evidence or WRITE
recommendations and alerts for humans. None of them changes any agent's
authority; suspension, scope changes and policy changes stay human-only.

Recommendations and alerts are human-review records. They are written to a
durable oversight table and announced through notify (an alarm metric)
before the guardian is told they await review; a failed write is a failed
execution, never a silent drop. Inside a deployed function the adapter
refuses to run without the table (audit 2026-10-23, run-2:
memory-only-human-review-signal).

Oversight table keys: pk = "<kind>#<observed agent>", sk = the record id.
"""

import secrets
import uuid
from typing import Any, Callable, Dict, List, Optional

from durable_state import require_durable

from .base import (
    CredentialHandle,
    CredentialProvider,
    ExecutionResult,
    bounded_expiry,
    new_credential_reference,
    utc_now,
)


def oversight_table_definition(table_name: str) -> Dict[str, Any]:
    """create_table arguments matching the deployed oversight (recommendation) table."""
    return {
        "TableName": table_name,
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"},
                      {"AttributeName": "sk", "KeyType": "RANGE"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"},
                                 {"AttributeName": "sk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }


class GovernanceAdapter(CredentialProvider):
    name = "governance"
    mode = "internal"

    def __init__(self, decision_reader: Callable[[str, int], List[Dict[str, Any]]],
                 evidence_reader: Callable[[str], List[Dict[str, Any]]],
                 oversight_table: Any = None,
                 notify: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        # Human-review records are authoritative oversight state (V4 invariant 40, P0-12).
        require_durable("GovernanceAdapter", oversight_table)
        self._decisions = decision_reader
        self._evidence = evidence_reader
        self._table = oversight_table
        self._notify = notify or (lambda kind, item: None)
        # Local runs and tests only; with a table, the table is the record.
        self.recommendations: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []

    def _store(self, kind: str, item: Dict[str, Any]) -> None:
        if self._table is not None:
            self._table.put_item(
                Item={"pk": f"{kind}#{item['observed_agent']}", "sk": item[f"{kind}_id"],
                      "created_at": utc_now().isoformat(), **item},
                ConditionExpression="attribute_not_exists(pk)")
        (self.recommendations if kind == "recommendation" else self.alerts).append(item)
        self._notify(kind, item)

    def exchange(self, verified, spec) -> CredentialHandle:
        grant = verified.grant
        expires = bounded_expiry(grant, 120)
        return CredentialHandle(
            provider=self.name, credential_type="internal_scoped_token",
            credential_reference=new_credential_reference(), issued_at=utc_now().isoformat(),
            expires_at=expires.isoformat(), effective_until=expires.isoformat(),
            scopes=list(spec.provider_scopes), grant_id=grant.grant_id, mode=self.mode,
            details={"observer": grant.agent_id, "observed": grant.target_resource},
            _secret=secrets.token_urlsafe(24))

    def execute(self, handle, verified, spec) -> ExecutionResult:
        grant = verified.grant
        observed = grant.target_resource.split("/", 2)[1]
        params = verified.canonical_request["tool_parameters"]
        if spec.operation_id == "Governance.InspectDecisionHistory":
            limit = int(params.get("limit", 10))
            rows = self._decisions(observed, limit)
            return ExecutionResult(self.name, spec.operation_id, "success",
                                   {"observed_agent": observed, "decisions": rows, "count": len(rows)})
        if spec.operation_id == "Governance.InspectEvidence":
            rows = self._evidence(observed)
            return ExecutionResult(self.name, spec.operation_id, "success",
                                   {"observed_agent": observed, "evidence_records": len(rows),
                                    "event_types": sorted({r.get("event_type", "") for r in rows})})
        if spec.operation_id == "Governance.RecommendSuspension":
            rec = {"recommendation_id": "rec-" + uuid.uuid4().hex[:12], "observed_agent": observed,
                   "recommended_by": grant.agent_id, "reason": params["reason"],
                   "status": "awaiting_human_review", "effect_on_authority": "none"}
            try:
                self._store("recommendation", rec)
            except Exception as exc:
                return ExecutionResult(self.name, spec.operation_id, "failed", {},
                                       f"recommendation was not recorded for human review ({type(exc).__name__})")
            return ExecutionResult(self.name, spec.operation_id, "success", rec)
        if spec.operation_id == "Governance.CreateAlert":
            alert = {"alert_id": "alert-" + uuid.uuid4().hex[:12], "observed_agent": observed,
                     "raised_by": grant.agent_id, "severity": params["severity"], "summary": params["summary"]}
            try:
                self._store("alert", alert)
            except Exception as exc:
                return ExecutionResult(self.name, spec.operation_id, "failed", {},
                                       f"alert was not recorded for human review ({type(exc).__name__})")
            return ExecutionResult(self.name, spec.operation_id, "success", alert)
        return ExecutionResult(self.name, spec.operation_id, "failed", {},
                               f"governance adapter does not implement {spec.operation_id}")
