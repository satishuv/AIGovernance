"""Risk Scoring Engine, computes risk scores for agent actions.

Loads risk factor weights and escalation thresholds from a DynamoDB
configuration table and applies weighted factors (scope level, action
group, target resource, history) to produce a numeric risk score
between 0 and 100.  Each action is categorized into a risk category
with a base weight from the config table.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

from models import RiskAssessment

logger = logging.getLogger(__name__)

# Valid risk categories per Requirement 3.5
RISK_CATEGORIES = frozenset(
    {
        "data_access",
        "data_modification",
        "deployment",
        "configuration_change",
        "emergency_action",
    }
)

# Default mapping from action_group keywords to risk categories
_ACTION_CATEGORY_MAP: Dict[str, str] = {
    "read": "data_access",
    "get": "data_access",
    "list": "data_access",
    "describe": "data_access",
    "query": "data_access",
    "write": "data_modification",
    "put": "data_modification",
    "update": "data_modification",
    "delete": "data_modification",
    "create": "data_modification",
    "deploy": "deployment",
    "release": "deployment",
    "publish": "deployment",
    "config": "configuration_change",
    "configure": "configuration_change",
    "set": "configuration_change",
    "modify": "configuration_change",
    "emergency": "emergency_action",
    "kill": "emergency_action",
    "shutdown": "emergency_action",
    "revoke": "emergency_action",
}


# Fallback weights used when DynamoDB config is unavailable
_DEFAULT_CONFIG: Dict[str, Any] = {
    "escalation_threshold": {"N": "70"},
    "scope_level_weights": {
        "M": {
            "0": {"N": "0"},
            "1": {"N": "10"},
            "2": {"N": "25"},
            "3": {"N": "50"},
            "4": {"N": "75"},
        }
    },
    "action_group_weights": {
        "M": {
            "data_access": {"N": "10"},
            "data_modification": {"N": "30"},
            "deployment": {"N": "50"},
            "configuration_change": {"N": "40"},
            "emergency_action": {"N": "60"},
        }
    },
    "target_resource_weights": {
        "M": {
            "production": {"N": "30"},
            "staging": {"N": "15"},
            "development": {"N": "5"},
            "default": {"N": "10"},
        }
    },
    "category_base_weights": {
        "M": {
            "data_access": {"N": "5"},
            "data_modification": {"N": "15"},
            "deployment": {"N": "25"},
            "configuration_change": {"N": "20"},
            "emergency_action": {"N": "35"},
        }
    },
    "history_factor_weight": {"N": "5"},
}


def _iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_number_map(dynamo_map: Dict[str, Any]) -> Dict[str, float]:
    """Convert a DynamoDB map of ``{key: {N: value}}`` to ``{key: float}``."""
    result: Dict[str, float] = {}
    inner = dynamo_map.get("M", dynamo_map)
    for k, v in inner.items():
        if isinstance(v, dict) and "N" in v:
            result[k] = float(v["N"])
        else:
            result[k] = float(v)
    return result


def _parse_number(dynamo_val: Any) -> float:
    """Extract a numeric value from a DynamoDB attribute."""
    if isinstance(dynamo_val, dict) and "N" in dynamo_val:
        return float(dynamo_val["N"])
    return float(dynamo_val)


class RiskScoringEngine:
    """Computes risk scores for agent actions.

    Loads risk factor weights and the escalation threshold from a
    DynamoDB configuration table (table name from the
    ``RISK_CONFIG_TABLE_NAME`` environment variable).  Applies weighted
    factors, scope level, action group, target resource, and action
    history, to produce a ``RiskAssessment`` with a score clamped to
    0-100.

    Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
    """

    def __init__(self, dynamodb_resource: Optional[Any] = None) -> None:
        self._table_name: str = os.environ.get("RISK_CONFIG_TABLE_NAME", "")
        self._dynamodb = dynamodb_resource
        self._config_loaded: bool = False

        # Parsed config values
        self._escalation_threshold: float = 70.0
        self._scope_level_weights: Dict[str, float] = {}
        self._action_group_weights: Dict[str, float] = {}
        self._target_resource_weights: Dict[str, float] = {}
        self._category_base_weights: Dict[str, float] = {}
        self._history_factor_weight: float = 5.0

    # ------------------------------------------------------------------
    # Configuration loading
    # ------------------------------------------------------------------

    def load_config(self) -> None:
        """Load risk factor weights and escalation threshold from DynamoDB.

        Reads all items from the config table and parses them into
        in-memory dicts.  Falls back to built-in defaults if the table
        is unreachable.
        """
        try:
            if self._dynamodb is None:
                self._dynamodb = boto3.resource("dynamodb")

            table = self._dynamodb.Table(self._table_name)
            response = table.scan()
            items = {
                item["config_key"]: item for item in response.get("Items", [])
            }
            self._apply_config(items)
            self._config_loaded = True

            logger.info(
                json.dumps(
                    {
                        "event": "risk_config_loaded",
                        "table": self._table_name,
                        "keys_loaded": list(items.keys()),
                        "escalation_threshold": self._escalation_threshold,
                        "timestamp": _iso_now(),
                    }
                )
            )
        except Exception as exc:
            logger.error(
                json.dumps(
                    {
                        "event": "risk_config_load_failure",
                        "table": self._table_name,
                        "error": str(exc),
                        "timestamp": _iso_now(),
                    }
                )
            )
            self._apply_defaults()
            self._config_loaded = True

    def _apply_config(self, items: Dict[str, Any]) -> None:
        """Parse DynamoDB items into typed config values."""
        if "escalation_threshold" in items:
            self._escalation_threshold = float(
                items["escalation_threshold"].get("value", 70)
            )
        if "scope_level_weights" in items:
            self._scope_level_weights = {
                k: float(v)
                for k, v in items["scope_level_weights"]
                .get("weights", {})
                .items()
            }
        if "action_group_weights" in items:
            self._action_group_weights = {
                k: float(v)
                for k, v in items["action_group_weights"]
                .get("weights", {})
                .items()
            }
        if "target_resource_weights" in items:
            self._target_resource_weights = {
                k: float(v)
                for k, v in items["target_resource_weights"]
                .get("weights", {})
                .items()
            }
        if "category_base_weights" in items:
            self._category_base_weights = {
                k: float(v)
                for k, v in items["category_base_weights"]
                .get("weights", {})
                .items()
            }
        if "history_factor_weight" in items:
            self._history_factor_weight = float(
                items["history_factor_weight"].get("value", 5)
            )

        # Fill any missing values from defaults
        self._fill_defaults()

    def _apply_defaults(self) -> None:
        """Apply built-in default configuration values."""
        self._escalation_threshold = 70.0
        self._scope_level_weights = {"0": 0, "1": 10, "2": 25, "3": 50, "4": 75}
        self._action_group_weights = {
            "data_access": 10,
            "data_modification": 30,
            "deployment": 50,
            "configuration_change": 40,
            "emergency_action": 60,
        }
        self._target_resource_weights = {
            "production": 30,
            "staging": 15,
            "development": 5,
            "default": 10,
        }
        self._category_base_weights = {
            "data_access": 5,
            "data_modification": 15,
            "deployment": 25,
            "configuration_change": 20,
            "emergency_action": 35,
        }
        self._history_factor_weight = 5.0

    def _fill_defaults(self) -> None:
        """Ensure all config dicts have values, filling from defaults."""
        defaults = {
            "_scope_level_weights": {"0": 0, "1": 10, "2": 25, "3": 50, "4": 75},
            "_action_group_weights": {
                "data_access": 10,
                "data_modification": 30,
                "deployment": 50,
                "configuration_change": 40,
                "emergency_action": 60,
            },
            "_target_resource_weights": {
                "production": 30,
                "staging": 15,
                "development": 5,
                "default": 10,
            },
            "_category_base_weights": {
                "data_access": 5,
                "data_modification": 15,
                "deployment": 25,
                "configuration_change": 20,
                "emergency_action": 35,
            },
        }
        for attr, default_val in defaults.items():
            current = getattr(self, attr)
            if not current:
                setattr(self, attr, default_val)

    # ------------------------------------------------------------------
    # Risk computation
    # ------------------------------------------------------------------

    def compute_risk(
        self,
        action_request: Dict[str, Any],
        scope_level: int,
        action_history: Optional[List[Dict[str, Any]]] = None,
    ) -> RiskAssessment:
        """Compute a risk score for the given action request.

        Args:
            action_request: Dict with keys such as ``action_group``,
                ``target_resource``, and ``input_text``.
            scope_level: The agent's current scope level (0-4).
            action_history: Optional list of recent action dicts for
                history-based risk adjustment.

        Returns:
            A ``RiskAssessment`` with score clamped to 0-100, the
            assigned risk category, applied factor weights, and an
            escalation flag.
        """
        if not self._config_loaded:
            self.load_config()

        action_group = action_request.get("action_group", "")
        target_resource = action_request.get("target_resource", "")
        history = action_history or []

        # 1. Categorize the action (Req 3.5)
        risk_category = self._categorize_action(action_group)

        # 2. Compute weighted factors (Req 3.2)
        factors: Dict[str, float] = {}

        # Category base weight (Req 3.6)
        base_weight = self._category_base_weights.get(risk_category, 10.0)
        factors["category_base_weight"] = base_weight

        # Scope level weight
        scope_weight = self._scope_level_weights.get(str(scope_level), 10.0)
        factors["scope_level_weight"] = scope_weight

        # Action group weight
        ag_weight = self._action_group_weights.get(risk_category, 10.0)
        factors["action_group_weight"] = ag_weight

        # Target resource weight
        tr_weight = self._target_resource_weights.get(
            target_resource.lower() if target_resource else "default",
            self._target_resource_weights.get("default", 10.0),
        )
        factors["target_resource_weight"] = tr_weight

        # History factor, more recent actions increase risk
        history_count = min(len(history), 10)
        history_score = history_count * self._history_factor_weight
        factors["history_factor"] = history_score

        # 3. Sum all factors
        raw_score = (
            base_weight + scope_weight + ag_weight + tr_weight + history_score
        )

        # 4. Clamp to 0-100 (Req 3.1)
        risk_score = max(0.0, min(100.0, raw_score))

        # 5. Check escalation threshold (Req 3.4)
        escalation_flagged = risk_score >= self._escalation_threshold

        assessment = RiskAssessment(
            risk_score=risk_score,
            risk_category=risk_category,
            factors_applied=factors,
            escalation_flagged=escalation_flagged,
            assessment_timestamp=_iso_now(),
        )

        logger.info(
            json.dumps(
                {
                    "event": "risk_assessment_computed",
                    "risk_score": risk_score,
                    "risk_category": risk_category,
                    "scope_level": scope_level,
                    "action_group": action_group,
                    "target_resource": target_resource,
                    "escalation_flagged": escalation_flagged,
                    "factors": factors,
                    "timestamp": assessment.assessment_timestamp,
                }
            )
        )

        return assessment

    # ------------------------------------------------------------------
    # Action categorization
    # ------------------------------------------------------------------

    def _categorize_action(self, action_group: str) -> str:
        """Categorize an action into a risk category.

        Matches the action_group string against known keyword prefixes.
        Falls back to ``"data_access"`` (lowest risk) for unrecognized
        actions.

        Args:
            action_group: The action group name from the request.

        Returns:
            One of the valid risk categories.
        """
        if not action_group:
            return "data_access"

        lower = action_group.lower()

        # Check for exact match first
        if lower in _ACTION_CATEGORY_MAP:
            return _ACTION_CATEGORY_MAP[lower]

        # Check if any keyword is contained in the action group
        for keyword, category in _ACTION_CATEGORY_MAP.items():
            if keyword in lower:
                return category

        return "data_access"

    # ------------------------------------------------------------------
    # Properties for testing / inspection
    # ------------------------------------------------------------------

    @property
    def escalation_threshold(self) -> float:
        """Return the current escalation threshold."""
        return self._escalation_threshold

    @property
    def config_loaded(self) -> bool:
        """Return whether configuration has been loaded."""
        return self._config_loaded
