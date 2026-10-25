"""OpenAPI operation registry: the authorization subject is the operationId.

Every executable operation is declared in an OpenAPI document with a stable
operationId and an x-governance block (provider, risk category, minimum scope,
resource patterns, data class, human-only flags, financial impact, provider
scopes, parameter schema). The governance control plane authorizes that
operationId; a model's natural-language description of an action is never the
authorization subject. An operationId that is not registered is denied.

The parameter validator implements the JSON Schema subset the catalog uses
(type, required, properties, additionalProperties, enum, pattern, minLength,
maxLength, minimum, maximum, items, maxItems) without third-party packages,
so it runs unchanged inside the Lambda runtime.
"""

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from request_canonicalization import canonical_json, sha256_hex

DEFAULT_CATALOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "operation_catalog", "public_sector_demo.openapi.json")

HTTP_METHODS = ("get", "put", "post", "patch", "delete")


@dataclass(frozen=True)
class OperationSpec:
    operation_id: str
    provider: str
    method: str
    path: str
    summary: str
    risk_category: str
    min_scope: int
    resource_type: str
    resource_patterns: Tuple[str, ...]
    data_class: str
    allowed_agent_types: Tuple[str, ...]
    parameter_schema: Dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    human_only: bool = False
    human_only_action: str = ""
    human_only_resource_patterns: Tuple[str, ...] = ()
    financial_impact: bool = False
    requires_approval: bool = False
    requires_assigned_guardian: bool = False
    allowed_environments: Tuple[str, ...] = ("dev", "staging", "prod")
    provider_scopes: Tuple[str, ...] = ()
    aws_actions: Tuple[str, ...] = ()
    credential_ttl_seconds: int = 300
    max_uses: int = 1
    amount_derivation: Dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    rate_limit_per_minute: int = 0

    def resource_allowed(self, target_resource: str) -> bool:
        return any(fnmatch.fnmatchcase(target_resource, p) for p in self.resource_patterns)

    def resource_is_human_only(self, target_resource: str) -> bool:
        return any(fnmatch.fnmatchcase(target_resource, p) for p in self.human_only_resource_patterns)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id, "provider": self.provider,
            "method": self.method.upper(), "path": self.path, "summary": self.summary,
            "risk_category": self.risk_category, "min_scope": self.min_scope,
            "resource_patterns": list(self.resource_patterns), "data_class": self.data_class,
            "human_only": self.human_only, "financial_impact": self.financial_impact,
            "requires_approval": self.requires_approval,
            "allowed_agent_types": list(self.allowed_agent_types),
            "provider_scopes": list(self.provider_scopes),
        }


class OperationCatalogError(ValueError):
    """The OpenAPI document is malformed or ambiguous."""


class OperationRegistry:
    """Registered operations keyed by operationId."""

    def __init__(self, operations: Dict[str, OperationSpec], fingerprint: str):
        self._operations = dict(operations)
        self._fingerprint = fingerprint

    @classmethod
    def from_openapi(cls, document: Dict[str, Any]) -> "OperationRegistry":
        operations: Dict[str, OperationSpec] = {}
        for path, item in (document.get("paths") or {}).items():
            for method in HTTP_METHODS:
                op = (item or {}).get(method)
                if not op:
                    continue
                op_id = op.get("operationId")
                gov = op.get("x-governance")
                if not op_id or not gov:
                    raise OperationCatalogError(
                        f"{method.upper()} {path} must declare operationId and x-governance")
                if op_id in operations:
                    raise OperationCatalogError(f"duplicate operationId {op_id}")
                if not gov.get("provider") or not gov.get("resource_patterns"):
                    raise OperationCatalogError(f"{op_id} needs provider and resource_patterns")
                operations[op_id] = OperationSpec(
                    operation_id=op_id,
                    provider=gov["provider"],
                    method=method,
                    path=path,
                    summary=op.get("summary", ""),
                    risk_category=gov.get("risk_category", "write"),
                    min_scope=int(gov.get("min_scope", 4)),
                    resource_type=gov.get("resource_type", ""),
                    resource_patterns=tuple(gov.get("resource_patterns", [])),
                    data_class=gov.get("data_class", "Internal"),
                    allowed_agent_types=tuple(gov.get("allowed_agent_types", [])),
                    parameter_schema=dict(gov.get("parameter_schema") or {"type": "object"}),
                    human_only=bool(gov.get("human_only", False)),
                    human_only_action=gov.get("human_only_action", ""),
                    human_only_resource_patterns=tuple(gov.get("human_only_resource_patterns", [])),
                    financial_impact=bool(gov.get("financial_impact", False)),
                    requires_approval=bool(gov.get("requires_approval", False)),
                    requires_assigned_guardian=bool(gov.get("requires_assigned_guardian", False)),
                    allowed_environments=tuple(gov.get("allowed_environments", ["dev", "staging", "prod"])),
                    provider_scopes=tuple(gov.get("provider_scopes", [])),
                    aws_actions=tuple(gov.get("aws_actions", [])),
                    credential_ttl_seconds=int(gov.get("credential_ttl_seconds", 300)),
                    max_uses=int(gov.get("max_uses", 1)),
                    amount_derivation=dict(gov.get("amount_derivation") or {}),
                    rate_limit_per_minute=int(gov.get("rate_limit_per_minute", 0)),
                )
        return cls(operations, sha256_hex(canonical_json(document)))

    @classmethod
    def load(cls, path: str = DEFAULT_CATALOG_PATH) -> "OperationRegistry":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_openapi(json.load(fh))

    def get(self, operation_id: str) -> Optional[OperationSpec]:
        return self._operations.get(operation_id or "")

    def all(self) -> List[OperationSpec]:
        return [self._operations[k] for k in sorted(self._operations)]

    def fingerprint(self) -> str:
        return self._fingerprint

    # Per-agent executions per minute when the operation declares no rate_limit_per_minute of its
    # own. Without a bound the engine's per-agent rate check was skipped for every generated rule, so
    # one agent's call volume could exhaust capacity every agent shares (audit 2026-10-23, run-2:
    # no-per-agent-admission-bound and per-returned-trace-kms-verify-fanout).
    DEFAULT_RATE_LIMITS_PER_MINUTE = {"read": 300, "oversight": 60, "write": 60, "financial": 30,
                                      "identity_admin": 30, "authority_change": 10}

    def tool_auth_rules(self, agents: List[Any]) -> List[Dict[str, Any]]:
        """ToolAuthTable items for every operation, allowing only agents whose
        registry entry lists the operation. Human-only operations get no agents."""
        rules = []
        for spec in self.all():
            allowed = sorted(a.agent_id for a in agents
                             if spec.operation_id in (a.allowed_operations or [])
                             and not spec.human_only)
            rules.append({
                "pk": f"RULE#{spec.operation_id}", "sk": "CONFIG",
                "tool_name": spec.operation_id, "allowed_agents": allowed,
                "min_scope": spec.min_scope, "status": "active",
                "reads_sensitive": spec.data_class.startswith("Protected"),
                "writes_external": False,
                "rate_limit_per_minute": spec.rate_limit_per_minute or self.DEFAULT_RATE_LIMITS_PER_MINUTE.get(
                    spec.risk_category, 30),
                "source": "openapi_operation_registry",
            })
        return rules


# ---------------------------------------------------------------------------
# Parameter validation (JSON Schema subset)
# ---------------------------------------------------------------------------

def _type_ok(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        try:
            from decimal import Decimal
            return isinstance(value, Decimal) and value == value.to_integral_value()
        except Exception:
            return False
    if expected == "number":
        if isinstance(value, bool):
            return False
        from decimal import Decimal
        return isinstance(value, (int, float, Decimal))
    return False


def _pattern_matches(pattern: str, value: str) -> bool:
    """JSON Schema pattern check without Python's trailing-newline '$' quirk.

    A pattern anchored as ^...$ must match the whole string exactly; in
    Python, re.search('^x$', 'x\\n') succeeds, which would let 'INC0012345\\n'
    pass an incident-id check. Fully anchored patterns use fullmatch on the
    inner expression; anything else keeps JSON Schema's unanchored search.
    """
    if pattern.startswith("^") and pattern.endswith("$") and not pattern.endswith("\\$"):
        return re.fullmatch(pattern[1:-1], value) is not None
    return re.search(pattern, value) is not None


def validate_against_schema(schema: Dict[str, Any], value: Any, path: str = "") -> List[str]:
    """Return a list of violations; an empty list means valid."""
    errors: List[str] = []
    label = path or "parameters"
    expected = schema.get("type")
    if expected and not _type_ok(expected, value):
        return [f"{label} must be of type {expected}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{label} must be one of {schema['enum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{label} is shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{label} is longer than {schema['maxLength']}")
        if "pattern" in schema and not _pattern_matches(schema["pattern"], value):
            errors.append(f"{label} does not match the required pattern")
    if _type_ok("number", value):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{label} is below the minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{label} is above the maximum {schema['maximum']}")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            errors.append(f"{label} has more than {schema['maxItems']} items")
        if "items" in schema:
            for idx, item in enumerate(value):
                errors.extend(validate_against_schema(schema["items"], item, f"{label}[{idx}]"))
    if isinstance(value, dict):
        props = schema.get("properties") or {}
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{label}.{req} is required")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{label}.{key} is not an allowed parameter")
        for key, sub in props.items():
            if key in value:
                errors.extend(validate_against_schema(sub, value[key], f"{label}.{key}"))
    return errors
