"""Input Defense Lambda - Layer 2 of the governance pipeline.

Performs input sanitization and threat detection:
- Unicode normalization and homoglyph detection
- Base64/hex/URL decoding of hidden payloads
- LLM delimiter injection detection
- Context stuffing detection
- Leet-speak instruction pattern detection
- Regex-based threat pattern matching (from DynamoDB)

Invoked by Step Functions. Returns sanitization result + threat assessment.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3

from input_sanitizer import InputSanitizer
from threat_detector import ThreatDetector

logger = logging.getLogger()
logger.setLevel(logging.INFO)

THREAT_PATTERNS_TABLE_NAME = os.environ.get("THREAT_PATTERNS_TABLE_NAME", "")

# In-Lambda cache for threat patterns (60s TTL)
_CACHE = {}
_CACHE_TTL = 60


def _cached_threat_detector():
    """Return a ThreatDetector with cached patterns."""
    now = time.time()
    cache_key = "threat_detector"
    if cache_key in _CACHE and (now - _CACHE[cache_key]["ts"]) < _CACHE_TTL:
        return _CACHE[cache_key]["data"]

    detector = ThreatDetector()
    if THREAT_PATTERNS_TABLE_NAME:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(THREAT_PATTERNS_TABLE_NAME)
        detector.load_patterns(table)

    _CACHE[cache_key] = {"data": detector, "ts": now}
    return detector


def handler(event, context):
    """Input Defense handler.

    Input event:
        agent_id (str): Agent identifier
        input_text (str): Raw user input
        action_group (str): Requested action group
        target_resource (str): Target resource
        scope_level (int): Current scope level

    Returns:
        {
            "passed": bool,
            "verdict": "allow" | "deny",
            "error_category": str (if denied),
            "explanation": str (if denied),
            "sanitized_text": str,
            "risk_score_adjustment": int,
            "agent_id": str,
            "timestamp": str
        }
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    agent_id = event.get("agent_id", "")
    input_text = event.get("input_text", "")

    result = {
        "passed": True,
        "verdict": "allow",
        "error_category": "",
        "explanation": "",
        "sanitized_text": input_text,
        "risk_score_adjustment": 0,
        "agent_id": agent_id,
        "timestamp": timestamp,
    }

    if not input_text:
        return result

    # Step 1: Advanced input sanitization
    sanitizer = InputSanitizer()
    sanitization = sanitizer.sanitize(input_text)

    if sanitization.blocked:
        result["passed"] = False
        result["verdict"] = "deny"
        result["error_category"] = "input_sanitization_blocked"
        result["explanation"] = f"Input blocked by advanced sanitization: {sanitization.block_reason}"
        logger.warning(json.dumps({
            "audit_event": "input_defense_denial",
            "layer": "sanitizer",
            "agent_id": agent_id,
            "block_reason": sanitization.block_reason,
            "timestamp": timestamp,
        }))
        return result

    result["sanitized_text"] = sanitization.sanitized_text

    # Step 2: Regex threat detection (using sanitized text)
    threat_detector = _cached_threat_detector()
    if threat_detector._patterns:
        threat_result = threat_detector.evaluate(sanitization.sanitized_text, agent_id)
        if threat_result["classification"] == "denied":
            matched_categories = list({
                p["category"] for p in threat_result["matched_patterns"]
            })
            result["passed"] = False
            result["verdict"] = "deny"
            result["error_category"] = "threat_detected"
            result["explanation"] = (
                f"Input denied by threat detection: matched "
                f"{', '.join(matched_categories)} pattern."
            )
            logger.warning(json.dumps({
                "audit_event": "input_defense_denial",
                "layer": "threat_detector",
                "agent_id": agent_id,
                "matched_categories": matched_categories,
                "timestamp": timestamp,
            }))
            return result
        elif threat_result["classification"] == "suspicious":
            result["risk_score_adjustment"] = threat_result.get("risk_score_adjustment", 0)

    return result
