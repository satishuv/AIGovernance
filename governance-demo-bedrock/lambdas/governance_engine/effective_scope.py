"""Trusted effective scope (P0-02).

The scope a request runs at is the minimum of the trusted ceilings that apply
to it. A scope supplied by the caller can only lower that value, never raise
it:

  registered_max_scope       agent registry approved_scope (human-approved)
  operator_authorized_scope  Scope Table scope_level, set through the
                             human-authenticated admin plane; graduated scope
                             reduction and the kill switch also write here, so
                             this value carries the dynamic risk cap
  delegation_scope_cap       scope_cap of a verified delegation receipt
  authority_grant_scope_cap  scope ceiling of a verified authority grant, when
                             the caller acts under one

No trusted ceiling means no trusted authority: the effective scope is None and
the caller must deny.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


def _as_scope(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


@dataclass
class ScopeCeilings:
    registered_max_scope: Optional[int] = None
    operator_authorized_scope: Optional[int] = None
    delegation_scope_cap: Optional[int] = None
    authority_grant_scope_cap: Optional[int] = None
    requested_scope: Optional[int] = None

    def trusted(self) -> Dict[str, int]:
        values = {
            "registered_max_scope": self.registered_max_scope,
            "operator_authorized_scope": self.operator_authorized_scope,
            "delegation_scope_cap": self.delegation_scope_cap,
            "authority_grant_scope_cap": self.authority_grant_scope_cap,
        }
        return {name: value for name, value in values.items() if value is not None}

    def effective(self) -> Optional[int]:
        trusted = self.trusted()
        if not trusted:
            return None
        scope = min(trusted.values())
        if self.requested_scope is not None:
            scope = min(scope, self.requested_scope)
        return max(0, scope)

    def binding_ceiling(self) -> str:
        """Name of the ceiling that set the effective scope (for the trace)."""
        effective = self.effective()
        if effective is None:
            return ""
        if self.requested_scope is not None and self.requested_scope == effective:
            trusted_min = min(self.trusted().values())
            if self.requested_scope < trusted_min:
                return "requested_scope"
        for name, value in self.trusted().items():
            if value == effective:
                return name
        return "requested_scope"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registered_max_scope": self.registered_max_scope,
            "operator_authorized_scope": self.operator_authorized_scope,
            "delegation_scope_cap": self.delegation_scope_cap,
            "authority_grant_scope_cap": self.authority_grant_scope_cap,
            "requested_scope": self.requested_scope,
            "effective_scope": self.effective(),
            "binding_ceiling": self.binding_ceiling(),
        }


def ceilings_for(*, registry_entry: Any = None, operator_scope: Any = None,
                 delegation_cap: Any = None, grant_cap: Any = None,
                 requested_scope: Any = None) -> ScopeCeilings:
    """Assemble ceilings from trusted state; requested_scope comes from the caller."""
    registered = None
    if registry_entry is not None:
        registered = _as_scope(getattr(registry_entry, "approved_scope", None))
    return ScopeCeilings(
        registered_max_scope=registered,
        operator_authorized_scope=_as_scope(operator_scope),
        delegation_scope_cap=_as_scope(delegation_cap),
        authority_grant_scope_cap=_as_scope(grant_cap),
        requested_scope=_as_scope(requested_scope),
    )


def read_operator_scope(scope_table, agent_id: str) -> Optional[int]:
    """Scope Table scope_level for an agent: one GetItem. Errors propagate.

    None when no Scope Table is configured. 0 when the table is configured but
    holds no item for the agent: no operator ever authorized a scope, which the
    scope enforcer also treats as 0.
    """
    if scope_table is None or not agent_id:
        return None
    item = scope_table.get_item(Key={"agent_id": agent_id}).get("Item")
    if not item:
        return 0
    scope = _as_scope(item.get("scope_level"))
    return 0 if scope is None else scope
