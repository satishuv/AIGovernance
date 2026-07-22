"""Policy Engine: loading, validation, and evaluation of governance policies.

Loads policy definitions from S3, validates them against a JSON Schema,
and stores them in-memory keyed by policy_id. Supports periodic reload
to pick up new policies within 60 seconds.
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

from models import PolicyConditions, PolicyDefinition, PolicyEvaluationResult

logger = logging.getLogger(__name__)

# Resolve the JSON Schema path relative to this package
_SCHEMA_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "schemas"
)
_SCHEMA_PATH = os.path.join(_SCHEMA_DIR, "policy_definition_schema.json")


def _load_schema() -> Dict[str, Any]:
    """Load the policy definition JSON Schema from disk."""
    try:
        with open(_SCHEMA_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("Policy schema not found at %s, schema validation disabled", _SCHEMA_PATH)
        return {}


class PolicyEngine:
    """Loads, validates, and stores governance policy definitions.

    Policies are loaded from S3 at initialization and cached in-memory.
    ``reload_policies()`` refreshes the cache from S3 to support the
    60-second refresh requirement.
    """

    def __init__(self) -> None:
        self._policies: Dict[str, PolicyDefinition] = {}
        self._schema: Dict[str, Any] = _load_schema()
        self._s3_client: Optional[Any] = None
        self._bucket: str = ""
        self._prefix: str = ""
        self._last_load_time: float = 0.0

    @property
    def policies(self) -> Dict[str, PolicyDefinition]:
        """Return the in-memory policy dict keyed by policy_id."""
        return self._policies

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_policies(
        self, s3_client: Any, bucket: str, prefix: str
    ) -> None:
        """Load policy JSON files from S3 and populate the in-memory cache.

        Args:
            s3_client: A boto3 S3 client instance.
            bucket: The S3 bucket name containing policy files.
            prefix: The S3 key prefix under which policy JSON files reside.
        """
        self._s3_client = s3_client
        self._bucket = bucket
        self._prefix = prefix
        self._fetch_and_cache_policies()

    def reload_policies(self) -> None:
        """Refresh policies from S3.

        Re-reads all policy files from the configured S3 bucket/prefix
        and replaces the in-memory cache.  Supports the 60-second
        refresh requirement; callers can invoke this on a timer.
        """
        if self._s3_client is None:
            logger.warning("reload_policies called before load_policies; skipping.")
            return
        self._fetch_and_cache_policies()

    def _fetch_and_cache_policies(self) -> None:
        """List objects under the prefix, download each, validate, and
        store valid policies in the cache."""
        new_policies: Dict[str, PolicyDefinition] = {}

        try:
            paginator = self._s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=self._bucket, Prefix=self._prefix)

            for page in pages:
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if not key.endswith(".json"):
                        continue
                    self._load_single_policy(key, new_policies)

        except Exception:
            logger.error(
                json.dumps(
                    {
                        "event": "policy_load_failure",
                        "bucket": self._bucket,
                        "prefix": self._prefix,
                        "error_type": "s3_list_error",
                        "timestamp": _iso_now(),
                    }
                )
            )
            raise

        self._policies = new_policies
        self._last_load_time = time.time()
        logger.info(
            "Loaded %d valid policies from s3://%s/%s",
            len(new_policies),
            self._bucket,
            self._prefix,
        )

    def _load_single_policy(
        self, key: str, target: Dict[str, PolicyDefinition]
    ) -> None:
        """Download one S3 object, validate, and add to *target* dict."""
        try:
            response = self._s3_client.get_object(
                Bucket=self._bucket, Key=key
            )
            body = response["Body"].read().decode("utf-8")
            policy_dict: Dict[str, Any] = json.loads(body)
        except Exception:
            logger.error(
                json.dumps(
                    {
                        "event": "policy_download_failure",
                        "bucket": self._bucket,
                        "key": key,
                        "timestamp": _iso_now(),
                    }
                )
            )
            return

        if not self.validate_policy(policy_dict):
            return

        try:
            policy = PolicyDefinition.from_dict(policy_dict)
            target[policy.policy_id] = policy
        except Exception:
            logger.error(
                json.dumps(
                    {
                        "event": "policy_parse_failure",
                        "policy_id": policy_dict.get("policy_id", "unknown"),
                        "key": key,
                        "timestamp": _iso_now(),
                    }
                )
            )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_policy(self, policy_dict: Dict[str, Any]) -> bool:
        """Validate a policy document against the JSON Schema.

        Args:
            policy_dict: A dict representing a policy definition.

        Returns:
            True if the policy is valid; False otherwise.
            Invalid policies are rejected with a structured error log
            containing the policy_id and validation failure details.
        """
        if not HAS_JSONSCHEMA:
            logger.warning("jsonschema not available, skipping schema validation")
            return True
        try:
            jsonschema.validate(instance=policy_dict, schema=self._schema)
            return True
        except jsonschema.ValidationError as exc:
            logger.error(
                json.dumps(
                    {
                        "event": "policy_validation_failure",
                        "policy_id": policy_dict.get("policy_id", "unknown"),
                        "validation_error": exc.message,
                        "schema_path": list(exc.absolute_schema_path),
                        "timestamp": _iso_now(),
                    }
                )
            )
            return False

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, action_request: Dict[str, Any]) -> PolicyEvaluationResult:
        """Evaluate an action request against all loaded policies.

        Matches the request attributes (scope_level, action_group,
        target_resource, time_of_day) against each policy's conditions.
        When multiple policies match, the one with the lowest priority
        value (highest priority) wins.  If no policy matches, a
        default-deny result is returned.

        Args:
            action_request: Dict with keys such as scope_level,
                action_group, target_resource, and time_of_day.

        Returns:
            A PolicyEvaluationResult with the winning policy's id,
            outcome, and the conditions that matched.
        """
        matched: list = []

        for policy in self._policies.values():
            matching_conditions = self._matches_policy(policy, action_request)
            if matching_conditions is not None:
                matched.append((policy, matching_conditions))

        if not matched:
            return PolicyEvaluationResult(
                policy_id="default-deny",
                outcome="deny",
                matching_conditions={},
                evaluation_timestamp=_iso_now(),
            )

        # Lower numeric priority value = higher priority
        matched.sort(key=lambda pair: pair[0].priority)
        winner, winning_conditions = matched[0]

        return PolicyEvaluationResult(
            policy_id=winner.policy_id,
            outcome=winner.outcome,
            matching_conditions=winning_conditions,
            evaluation_timestamp=_iso_now(),
        )

    @staticmethod
    def _matches_policy(
        policy: PolicyDefinition, action_request: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Check whether *action_request* satisfies *policy* conditions.

        Returns a dict of the conditions that matched, or ``None`` if the
        policy does not apply to this request.

        A condition field that is ``None`` (not set) in the policy is
        treated as a wildcard; it matches any value in the request.
        Only condition fields that are explicitly set must match.
        """
        conditions = policy.conditions
        if isinstance(conditions, dict):
            conditions = PolicyConditions.from_dict(conditions)

        matched: Dict[str, Any] = {}

        # scope_level: exact match
        if conditions.scope_level is not None:
            req_scope = action_request.get("scope_level")
            if req_scope is None or int(req_scope) != conditions.scope_level:
                return None
            matched["scope_level"] = conditions.scope_level

        # action_group: exact match
        if conditions.action_group is not None:
            req_ag = action_request.get("action_group")
            if req_ag is None or req_ag != conditions.action_group:
                return None
            matched["action_group"] = conditions.action_group

        # target_resource: exact match
        if conditions.target_resource is not None:
            req_tr = action_request.get("target_resource")
            if req_tr is None or req_tr != conditions.target_resource:
                return None
            matched["target_resource"] = conditions.target_resource

        # time_of_day: request time must fall within start/end window
        if conditions.time_of_day is not None:
            req_tod = action_request.get("time_of_day")
            if req_tod is None:
                return None
            start = conditions.time_of_day.get("start", "00:00")
            end = conditions.time_of_day.get("end", "23:59")
            if not (start <= req_tod <= end):
                return None
            matched["time_of_day"] = conditions.time_of_day

        return matched


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
