"""Input Validation Heuristics, Threat Detector module.

Applies defense-in-depth pattern-based checks to agent inputs. Patterns
are loaded from DynamoDB with a 60-second in-memory cache TTL. Matches
against "known_bad" patterns produce immediate deny; "suspicious" patterns
produce risk score adjustments. All evaluations are logged.

Requirements: 12.1, 12.2, 12.3, 12.5, 12.6
"""

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from models import ThreatPattern

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60


class ThreatDetector:
    """Evaluates input text against threat patterns with caching."""

    def __init__(self) -> None:
        self._patterns: List[ThreatPattern] = []
        self._cache_timestamp: float = 0.0

    def load_patterns(self, dynamodb_table) -> List[ThreatPattern]:
        """Load threat patterns from DynamoDB with 60s cache TTL.

        Args:
            dynamodb_table: boto3 DynamoDB Table for ThreatPatternsTable.

        Returns:
            List of loaded ThreatPattern objects.
        """
        now = time.time()
        if self._patterns and (now - self._cache_timestamp) < CACHE_TTL_SECONDS:
            return self._patterns

        response = dynamodb_table.scan()
        items = response.get("Items", [])
        while "LastEvaluatedKey" in response:
            response = dynamodb_table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        self._patterns = [ThreatPattern.from_dict(item) for item in items]
        self._cache_timestamp = now

        logger.info(
            json.dumps({
                "audit_event": "threat_patterns_loaded",
                "pattern_count": len(self._patterns),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        )
        return self._patterns

    def evaluate(
        self, input_text: str, agent_id: str
    ) -> Dict[str, Any]:
        """Evaluate input text against loaded threat patterns.

        Args:
            input_text: The input text to evaluate.
            agent_id: The agent's unique identifier.

        Returns:
            Dict with classification ("clean"/"denied"/"suspicious"),
            matched_patterns list, and risk_score_adjustment.
        """
        now = datetime.now(timezone.utc).isoformat()
        matched_patterns: List[Dict[str, Any]] = []
        classification = "clean"
        risk_score_adjustment = 0

        text_lower = input_text.lower()

        for pattern in self._patterns:
            matched = False
            try:
                matched = bool(re.search(pattern.pattern, text_lower, re.IGNORECASE))
            except re.error:
                matched = pattern.pattern.lower() in text_lower

            if matched:
                matched_patterns.append({
                    "pattern_id": pattern.pattern_id,
                    "category": pattern.category,
                    "description": pattern.description,
                    "risk_weight": pattern.risk_weight,
                })
                if pattern.category == "known_bad":
                    classification = "denied"
                elif pattern.category == "suspicious" and classification != "denied":
                    classification = "suspicious"
                risk_score_adjustment += pattern.risk_weight

        log_fn = logger.warning if classification != "clean" else logger.info
        log_fn(
            json.dumps({
                "audit_event": "threat_evaluation",
                "agent_id": agent_id,
                "classification": classification,
                "matched_pattern_count": len(matched_patterns),
                "risk_score_adjustment": risk_score_adjustment,
                "timestamp": now,
            })
        )

        return {
            "classification": classification,
            "matched_patterns": matched_patterns,
            "risk_score_adjustment": risk_score_adjustment,
        }

    @staticmethod
    def add_pattern(
        pattern: ThreatPattern, dynamodb_table
    ) -> ThreatPattern:
        """Add a new threat pattern to the ThreatPatternsTable.

        Available within 60 seconds via cache refresh.

        Args:
            pattern: The ThreatPattern to add.
            dynamodb_table: boto3 DynamoDB Table for ThreatPatternsTable.

        Returns:
            The added ThreatPattern.
        """
        dynamodb_table.put_item(Item=pattern.to_dict())

        logger.info(
            json.dumps({
                "audit_event": "threat_pattern_added",
                "pattern_id": pattern.pattern_id,
                "category": pattern.category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        )
        return pattern
