"""Canonical action requests and request digests.

One definition of "the exact request" is shared by governance decisions,
approvals, delegated authority grants and evidence records, so the four can
never disagree about what was authorized.

Design rules:
  * Only security-relevant fields enter the canonical request. Free text
    (input_text, stated intent, business reason) is retained elsewhere as
    context, never as the authorization subject.
  * Canonical JSON is deterministic: keys are sorted, numbers are rendered in
    normalized decimal form (4, 4.0 and Decimal("4.00") all render as 4), and
    strings stay quoted (so the string "4" and the number 4 stay distinct).
  * NaN and infinity are rejected rather than silently encoded.
  * Values survive a DynamoDB round trip (floats become Decimal, Decimal comes
    back) without changing the digest.
  * No credentials or secrets belong in a canonical request. Fields whose
    names look like secrets are rejected so a token can never be hashed into
    evidence by accident.
"""

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable

# Fields that define the authorization subject of a request.
SECURITY_RELEVANT_FIELDS = (
    "agent_id",
    "session_id",
    "provider",
    "operation_id",
    "target_resource",
    "environment",
    "tool_parameters",
    "data_class",
    "financial_context",
)

# Financial fields that are part of the authorization subject. Running session
# and daily totals are computed server-side from the spend ledger and change
# legitimately over time, so they are not part of the request digest.
FINANCIAL_SUBJECT_FIELDS = ("currency", "transaction_amount")

# Parameter names that must never appear in a canonical request.
_SECRET_NAME_MARKERS = (
    "password", "passwd", "secret", "access_token", "refresh_token", "id_token",
    "bearer", "session_token", "api_key", "apikey", "private_key", "access_key",
    "client_secret",
)

ENVIRONMENT_ALIASES = {"production": "prod", "development": "dev", "stage": "staging"}


class CanonicalizationError(ValueError):
    """Raised when a request cannot be canonicalized safely."""


def _number_text(value: Any) -> str:
    try:
        dec = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise CanonicalizationError(f"unrepresentable number: {value!r}") from exc
    if not dec.is_finite():
        raise CanonicalizationError(f"non-finite number is not allowed: {value!r}")
    text = format(dec.normalize(), "f")
    if text in ("-0", "-0.0"):
        text = "0"
    return text


def canonical_json(value: Any) -> str:
    """Deterministic JSON text for value (see module docstring)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, Decimal)):
        return _number_text(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys(), key=str):
            parts.append(json.dumps(str(key), ensure_ascii=False) + ":" + canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    raise CanonicalizationError(f"unsupported type in canonical request: {type(value).__name__}")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reject_secret_names(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_NAME_MARKERS):
                raise CanonicalizationError(
                    f"field '{path}{key}' looks like a credential; secrets must not "
                    "appear in an action request")
            _reject_secret_names(val, f"{path}{key}.")
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_secret_names(item, path)


def normalize_environment(env: Any) -> str:
    text = str(env or "").strip().lower()
    return ENVIRONMENT_ALIASES.get(text, text)


def _copy_plain(obj: Any) -> Any:
    """Deep copy using only JSON-like containers."""
    if isinstance(obj, dict):
        return {str(k): _copy_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_copy_plain(v) for v in obj]
    return obj


def canonicalize_financial_context(financial_context: Any) -> Dict[str, Any]:
    if not financial_context:
        return {}
    if not isinstance(financial_context, dict):
        raise CanonicalizationError("financial_context must be an object")
    out: Dict[str, Any] = {}
    currency = financial_context.get("currency")
    if currency not in (None, ""):
        out["currency"] = str(currency).strip().upper()
    amount = financial_context.get("transaction_amount")
    if amount not in (None, ""):
        if isinstance(amount, bool):
            raise CanonicalizationError("transaction_amount must be a number")
        out["transaction_amount"] = Decimal(_number_text(amount))
    return out


def canonicalize_action_request(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return the canonical, security-relevant view of an action request.

    Every security-relevant field is always present (empty defaults), so two
    requests that differ only by an omitted-versus-empty field still digest the
    same, and any populated difference changes the digest.
    """
    if not isinstance(raw, dict):
        raise CanonicalizationError("action request must be an object")
    params = raw.get("tool_parameters", raw.get("parameters", {})) or {}
    if not isinstance(params, dict):
        raise CanonicalizationError("tool_parameters must be an object")
    _reject_secret_names(params)

    canonical = {
        "agent_id": str(raw.get("agent_id", "") or "").strip(),
        "session_id": str(raw.get("session_id", "") or "").strip(),
        "provider": str(raw.get("provider", "") or "").strip(),
        "operation_id": str(raw.get("operation_id", "") or raw.get("action_group", "") or "").strip(),
        "target_resource": str(raw.get("target_resource", "") or "").strip(),
        "environment": normalize_environment(raw.get("environment", "")),
        "tool_parameters": _copy_plain(params),
        "data_class": str(raw.get("data_class", "") or "").strip(),
        "financial_context": canonicalize_financial_context(raw.get("financial_context")),
    }
    # Fail early if anything inside is not canonically representable.
    canonical_json(canonical)
    return canonical


def compute_action_request_digest(canonical_request: Dict[str, Any],
                                  policy_version_hash: str = "",
                                  expires_at: str = "") -> str:
    """SHA-256 over the canonical request, policy version and absolute expiry."""
    body = {
        "request": {k: canonical_request.get(k, "") for k in SECURITY_RELEVANT_FIELDS},
        "policy_version_hash": policy_version_hash or "",
        "expires_at": expires_at or "",
    }
    return sha256_hex(canonical_json(body))


def compute_policy_version_hash(components: Iterable[Any]) -> str:
    """Hash an ordered collection of policy inputs into one version identifier.

    Callers pass every input that can change an authorization outcome (the
    operation catalog, the policy bundle, the agent's policy-relevant registry
    fields, the approved catalog). If any of them changes after an approval,
    the approval no longer matches and must be re-requested.
    """
    return sha256_hex(canonical_json(list(components)))


def to_dynamodb_safe(obj: Any) -> Any:
    """Convert floats to Decimal recursively so DynamoDB accepts the value."""
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, float):
        return Decimal(_number_text(obj))
    if isinstance(obj, dict):
        return {str(k): to_dynamodb_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_dynamodb_safe(v) for v in obj]
    return obj


def to_json_safe(obj: Any) -> Any:
    """Convert Decimal to int/float recursively for JSON responses and UIs."""
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {str(k): to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_json_safe(v) for v in obj]
    return obj
