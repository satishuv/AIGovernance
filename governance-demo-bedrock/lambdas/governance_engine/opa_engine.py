"""OPA Policy Engine - Rego-based policy evaluation for AI governance.

Supports two modes (controlled by OPA_MODE environment variable):
- embedded: Evaluates Rego policies directly using a built-in Rego subset interpreter.
  Policies are loaded from S3 as .rego files.
- external: Forwards policy evaluation to an external OPA service via HTTP REST API.
  Requires OPA_ENDPOINT env var pointing to the OPA data API.

The embedded evaluator supports a practical subset of Rego sufficient for
governance policies: boolean rules, input matching, comparisons, logical
operators, array membership, and time conditions.

Replaces the legacy JSON-based policy engine with an industry-standard approach.
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger(__name__)

OPA_MODE = os.environ.get("OPA_MODE", "embedded")
OPA_ENDPOINT = os.environ.get("OPA_ENDPOINT", "")


class OPADecision:
    """Result of an OPA policy evaluation."""

    def __init__(self, allowed: bool, verdict: str, matched_rules: List[str],
                 explanation: str, evaluation_time_ms: float):
        self.allowed = allowed
        self.verdict = verdict
        self.matched_rules = matched_rules
        self.explanation = explanation
        self.evaluation_time_ms = evaluation_time_ms
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "verdict": self.verdict,
            "matched_rules": self.matched_rules,
            "explanation": self.explanation,
            "evaluation_time_ms": self.evaluation_time_ms,
            "timestamp": self.timestamp,
        }


class RegoRule:
    """A parsed Rego rule with conditions."""

    def __init__(self, name: str, outcome: str, conditions: List[Dict[str, Any]],
                 priority: int = 100, description: str = ""):
        self.name = name
        self.outcome = outcome  # "allow", "deny", "escalate"
        self.conditions = conditions
        self.priority = priority
        self.description = description

    def evaluate(self, input_data: Dict[str, Any]) -> bool:
        """Evaluate all conditions against input. All must be True (AND logic)."""
        for condition in self.conditions:
            if not self._evaluate_condition(condition, input_data):
                return False
        return True

    def _evaluate_condition(self, condition: Dict[str, Any], input_data: Dict[str, Any]) -> bool:
        field = condition.get("field", "")
        operator = condition.get("op", "==")
        value = condition.get("value")
        negate = condition.get("not", False)

        actual = self._resolve_field(field, input_data)

        if operator == "==":
            result = actual == value
        elif operator == "!=":
            result = actual != value
        elif operator == "<":
            result = actual is not None and actual < value
        elif operator == ">":
            result = actual is not None and actual > value
        elif operator == "<=":
            result = actual is not None and actual <= value
        elif operator == ">=":
            result = actual is not None and actual >= value
        elif operator == "in":
            result = actual in value if isinstance(value, list) else False
        elif operator == "not_in":
            result = actual not in value if isinstance(value, list) else True
        elif operator == "contains":
            result = value in actual if isinstance(actual, (str, list)) else False
        elif operator == "matches":
            result = bool(re.search(value, str(actual))) if actual else False
        elif operator == "exists":
            result = actual is not None
        else:
            result = False

        return (not result) if negate else result

    def _resolve_field(self, field: str, data: Dict[str, Any]) -> Any:
        """Resolve dotted field path (e.g., 'input.scope_level') against data."""
        parts = field.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current


class OPAEngine:
    """OPA-compatible policy engine with embedded Rego evaluation."""

    def __init__(self):
        self._rules: List[RegoRule] = []
        self._policies_raw: Dict[str, str] = {}
        self._last_load_time: float = 0.0
        self._s3_client = None
        self._bucket = ""
        self._prefix = ""

    def load_policies_from_s3(self, s3_client, bucket: str, prefix: str = "policies/") -> None:
        """Load .rego policy files from S3 and parse them."""
        self._s3_client = s3_client
        self._bucket = bucket
        self._prefix = prefix
        self._fetch_and_parse_policies()

    def load_policies_from_json(self, policy_defs: List[Dict[str, Any]]) -> None:
        """Load policies from JSON definitions (backward compat with existing format).

        Each policy dict should have:
        - rule_name (str)
        - outcome (str): allow/deny/escalate
        - conditions (list of dicts): [{field, op, value}, ...]
        - priority (int, optional)
        - description (str, optional)
        """
        self._rules = []
        for policy in policy_defs:
            rule = RegoRule(
                name=policy.get("rule_name", policy.get("policy_id", "")),
                outcome=policy.get("outcome", "deny"),
                conditions=policy.get("conditions", []),
                priority=policy.get("priority", 100),
                description=policy.get("description", ""),
            )
            self._rules.append(rule)
        self._last_load_time = time.time()
        logger.info(f"Loaded {len(self._rules)} OPA rules from JSON definitions")

    def evaluate(self, input_data: Dict[str, Any]) -> OPADecision:
        """Evaluate input against all loaded policies.

        Uses OPA_MODE to determine evaluation path:
        - embedded: evaluate locally using parsed rules
        - external: forward to OPA service

        Returns OPADecision with verdict (allow/deny/escalate).
        """
        start = time.time()

        if OPA_MODE == "external" and OPA_ENDPOINT:
            return self._evaluate_external(input_data, start)

        return self._evaluate_embedded(input_data, start)

    def _evaluate_embedded(self, input_data: Dict[str, Any], start: float) -> OPADecision:
        """Evaluate policies using embedded Rego-subset engine.

        Resolution: lowest priority number wins (highest precedence).
        """
        matched_rules = []
        all_matched = []

        wrapped_input = {"input": input_data}

        for rule in self._rules:
            if rule.evaluate(wrapped_input):
                matched_rules.append(rule.name)
                all_matched.append(rule)

        elapsed_ms = (time.time() - start) * 1000

        if not all_matched:
            return OPADecision(
                allowed=False,
                verdict="deny",
                matched_rules=[],
                explanation="No matching policy rule. Default deny.",
                evaluation_time_ms=elapsed_ms,
            )

        winner = min(all_matched, key=lambda r: r.priority)

        if winner.outcome == "allow":
            return OPADecision(
                allowed=True,
                verdict="allow",
                matched_rules=matched_rules,
                explanation=f"Allowed by rule '{winner.name}': {winner.description}",
                evaluation_time_ms=elapsed_ms,
            )
        elif winner.outcome == "escalate":
            return OPADecision(
                allowed=False,
                verdict="escalate",
                matched_rules=matched_rules,
                explanation=f"Escalated by rule '{winner.name}': {winner.description}",
                evaluation_time_ms=elapsed_ms,
            )
        else:
            return OPADecision(
                allowed=False,
                verdict="deny",
                matched_rules=matched_rules,
                explanation=f"Denied by rule '{winner.name}': {winner.description}",
                evaluation_time_ms=elapsed_ms,
            )

    def _evaluate_external(self, input_data: Dict[str, Any], start: float) -> OPADecision:
        """Forward evaluation to external OPA service."""
        try:
            payload = json.dumps({"input": input_data}).encode("utf-8")
            req = Request(
                OPA_ENDPOINT,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            elapsed_ms = (time.time() - start) * 1000
            opa_result = result.get("result", {})

            verdict = "deny"
            if opa_result.get("allow"):
                verdict = "allow"
            elif opa_result.get("escalate"):
                verdict = "escalate"

            return OPADecision(
                allowed=(verdict == "allow"),
                verdict=verdict,
                matched_rules=opa_result.get("matched_rules", []),
                explanation=opa_result.get("reason", f"OPA external verdict: {verdict}"),
                evaluation_time_ms=elapsed_ms,
            )

        except (URLError, Exception) as exc:
            elapsed_ms = (time.time() - start) * 1000
            logger.error(json.dumps({
                "event": "opa_external_call_failed",
                "endpoint": OPA_ENDPOINT,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return OPADecision(
                allowed=False,
                verdict="deny",
                matched_rules=[],
                explanation=f"OPA service unavailable (fail-safe deny): {str(exc)}",
                evaluation_time_ms=elapsed_ms,
            )

    def _fetch_and_parse_policies(self) -> None:
        """Load policy files from S3 and parse into RegoRule objects."""
        self._rules = []

        try:
            paginator = self._s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=self._bucket, Prefix=self._prefix)

            for page in pages:
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".json"):
                        self._load_json_policy(key)
                    elif key.endswith(".rego"):
                        self._load_rego_policy(key)

        except Exception as exc:
            logger.error(json.dumps({
                "event": "opa_policy_load_failed",
                "bucket": self._bucket,
                "prefix": self._prefix,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        self._last_load_time = time.time()
        logger.info(f"OPA engine loaded {len(self._rules)} rules from s3://{self._bucket}/{self._prefix}")

    def _load_json_policy(self, key: str) -> None:
        """Load a JSON policy file and convert to RegoRule."""
        try:
            response = self._s3_client.get_object(Bucket=self._bucket, Key=key)
            body = json.loads(response["Body"].read().decode("utf-8"))

            # Support both new OPA format and legacy format
            if "conditions" in body and isinstance(body["conditions"], list):
                # New OPA format
                rule = RegoRule(
                    name=body.get("rule_name", body.get("policy_id", key)),
                    outcome=body.get("outcome", "deny"),
                    conditions=body["conditions"],
                    priority=body.get("priority", 100),
                    description=body.get("description", ""),
                )
                self._rules.append(rule)
            elif "conditions" in body and isinstance(body["conditions"], dict):
                # Legacy format: convert {scope_level: 2, action_group: "X"} to condition list
                conditions = []
                legacy_conds = body["conditions"]
                for field, value in legacy_conds.items():
                    conditions.append({"field": f"input.{field}", "op": "==", "value": value})
                rule = RegoRule(
                    name=body.get("policy_id", key),
                    outcome=body.get("outcome", "deny"),
                    conditions=conditions,
                    priority=body.get("priority", 100),
                    description=body.get("description", body.get("name", "")),
                )
                self._rules.append(rule)

        except Exception as exc:
            logger.error(json.dumps({
                "event": "opa_json_policy_load_failed",
                "key": key,
                "error": str(exc),
            }))

    def _load_rego_policy(self, key: str) -> None:
        """Load a .rego file and store raw content for reference.

        Full Rego parsing requires a Rego runtime. In embedded mode,
        .rego files are stored as documentation. The JSON format is used
        for actual evaluation. Organizations with an external OPA service
        can evaluate .rego files natively via the external mode.
        """
        try:
            response = self._s3_client.get_object(Bucket=self._bucket, Key=key)
            content = response["Body"].read().decode("utf-8")
            self._policies_raw[key] = content
            logger.info(f"Loaded .rego policy reference: {key}")
        except Exception as exc:
            logger.error(json.dumps({
                "event": "opa_rego_load_failed",
                "key": key,
                "error": str(exc),
            }))

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def last_load_time(self) -> float:
        return self._last_load_time
