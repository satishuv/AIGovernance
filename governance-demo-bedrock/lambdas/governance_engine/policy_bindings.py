"""Policy bindings by agent attribute (P0-17).

A policy applies to the agents its binding selects. Bindings select by
attribute, never by enumerating agents, because a policy engine must serve
2,000 or more agents and Policy in AgentCore holds at most 1,000 policies per
engine.

    "binding": {
        "policy_bundles": ["finance-procurement"],
        "risk_tiers": ["low", "medium"],
        "agent_types": ["worker"],
        "environments": ["prod"],
        "agent_ids": ["procurement-agent"]
    }

Every dimension present must match (AND); within a dimension any listed value
matches (OR). A policy without a binding is global and applies to every agent.

Agent attributes come from the trusted registry entry, never from the request.

A binding that cannot be read fails towards restriction: a deny policy with a
bad binding applies to every agent, and an allow or escalate policy with a
bad binding applies to none, so a malformed binding can tighten but never
widen authority.

The index keys rules by bundle, so selecting the rules for one decision reads
the global rules plus the agent's own bundle instead of every policy.
"""

from typing import Any, Dict, Iterable, List, Optional, Tuple

BINDING_DIMENSIONS = {
    "policy_bundles": "policy_bundle",
    "risk_tiers": "risk_tier",
    "agent_types": "agent_type",
    "environments": "environment",
    "agent_ids": "agent_id",
}
GLOBAL = "*"


class BindingError(ValueError):
    """A binding block that cannot be read."""


def parse_binding(raw: Any) -> Optional[Dict[str, frozenset]]:
    """None for a global policy; the selector otherwise. Raises BindingError."""
    if raw in (None, {}):
        return None
    if not isinstance(raw, dict):
        raise BindingError(f"binding must be an object, got {type(raw).__name__}")
    unknown = sorted(set(raw) - set(BINDING_DIMENSIONS))
    if unknown:
        raise BindingError(f"unknown binding dimensions {unknown}; allowed {sorted(BINDING_DIMENSIONS)}")
    selector: Dict[str, frozenset] = {}
    for dimension, values in raw.items():
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
            raise BindingError(f"binding.{dimension} must be a non-empty list of strings")
        selector[dimension] = frozenset(values)
    return selector


def resolve_binding(raw: Any, outcome: str) -> Tuple[Optional[Dict[str, frozenset]], bool, str]:
    """(selector, applies_to_none, error). A bad binding fails towards restriction."""
    try:
        return parse_binding(raw), False, ""
    except BindingError as exc:
        if str(outcome).lower() == "deny":
            return None, False, str(exc)  # deny everyone
        return None, True, str(exc)  # grant no one


def agent_attributes(registry_entry: Any = None, agent_id: str = "") -> Dict[str, str]:
    """The attributes bindings select on, from a trusted registry entry."""
    attrs = {"agent_id": agent_id or str(getattr(registry_entry, "agent_id", "") or "")}
    if registry_entry is not None:
        for attribute in ("policy_bundle", "risk_tier", "agent_type", "environment"):
            value = getattr(registry_entry, attribute, "") or ""
            if value:
                attrs[attribute] = str(value)
    return attrs


def selects(selector: Optional[Dict[str, frozenset]], attrs: Dict[str, str]) -> bool:
    if selector is None:
        return True
    for dimension, allowed in selector.items():
        if attrs.get(BINDING_DIMENSIONS[dimension], "") not in allowed:
            return False
    return True


def applies(rule: Any, attrs: Optional[Dict[str, str]]) -> bool:
    """Whether a loaded rule or policy applies to an agent with these attributes.

    With no attributes (a caller that did not identify the agent) only global
    rules apply, plus every deny rule whatever its binding, so missing
    attributes can only restrict.
    """
    if getattr(rule, "applies_to_none", False):
        return False
    selector = getattr(rule, "binding", None)
    if attrs is None:
        return selector is None or str(getattr(rule, "outcome", "")).lower() == "deny"
    return selects(selector, attrs)


def fingerprint_fields(rule: Any) -> Dict[str, Any]:
    """Binding fields for a policy fingerprint; empty for an unbound rule, so
    bundles without bindings keep the fingerprint they had before P0-17."""
    selector = getattr(rule, "binding", None)
    fields: Dict[str, Any] = {}
    if selector:
        fields["binding"] = {k: sorted(v) for k, v in sorted(selector.items())}
    if getattr(rule, "applies_to_none", False):
        fields["applies_to_none"] = True
    return fields


class BindingIndex:
    """Rules grouped by the bundle their binding names."""

    def __init__(self):
        self._by_bundle: Dict[str, List[Any]] = {}

    def add(self, rule: Any) -> None:
        if getattr(rule, "applies_to_none", False):
            return
        selector = getattr(rule, "binding", None)
        bundles: Iterable[str] = (selector or {}).get("policy_bundles") or [GLOBAL]
        for bundle in bundles:
            self._by_bundle.setdefault(bundle, []).append(rule)

    def candidates(self, attrs: Optional[Dict[str, str]]) -> List[Any]:
        """Rules that apply to an agent: global rules plus its bundle's, filtered."""
        attrs = attrs or {}
        rules = list(self._by_bundle.get(GLOBAL, []))
        bundle = attrs.get("policy_bundle", "")
        if bundle and bundle != GLOBAL:
            rules.extend(self._by_bundle.get(bundle, []))
        return [r for r in rules if selects(getattr(r, "binding", None), attrs)]

    def bundles(self) -> Dict[str, int]:
        return {bundle: len(rules) for bundle, rules in sorted(self._by_bundle.items())}
