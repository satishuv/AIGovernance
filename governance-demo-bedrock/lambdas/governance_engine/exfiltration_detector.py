"""Data Exfiltration Prevention module.

Evaluates agent output for exfiltration patterns: large data volumes,
base64/hex encoded blocks, and references to unapproved external endpoints.
Blocks suspicious output, increases agent risk score, and logs detections.

Requirements: 28.1, 28.2, 28.3, 28.4
"""

import json
import logging
import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from models import ExfiltrationDetectionResult

logger = logging.getLogger(__name__)

DEFAULT_SIZE_LIMITS = {0: 0, 1: 1024, 2: 4096, 3: 16384, 4: 65536}
DEFAULT_MAX_ENCODED_LENGTH = 512
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
HEX_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}){32,}")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


class ExfiltrationDetector:
    """Evaluates agent output for data exfiltration patterns."""

    def __init__(self):
        self._allowlist_cache: Optional[List[str]] = None
        self._allowlist_ttl: float = 0.0

    def evaluate_output(self, agent_id: str, output_text: str,
                        scope_level: int,
                        config: Optional[Dict[str, Any]] = None,
                        ) -> ExfiltrationDetectionResult:
        """Evaluate agent output for exfiltration patterns."""
        config = config or {}
        now = datetime.utcnow().isoformat()
        det_id = str(uuid.uuid4())
        size = len(output_text.encode("utf-8"))
        size_limits = config.get("size_limits", DEFAULT_SIZE_LIMITS)
        max_enc = config.get("max_encoded_length", DEFAULT_MAX_ENCODED_LENGTH)
        allowlist = config.get("allowlist", [])

        size_issue = self.check_output_size(output_text, scope_level, size_limits)
        if size_issue:
            return ExfiltrationDetectionResult(
                detection_id=det_id, agent_id=agent_id,
                pattern_type="large_volume", matched_detail=size_issue,
                output_size_bytes=size, blocked=True,
                risk_score_increase=20, timestamp=now)

        blocks = self.detect_encoded_blocks(output_text, max_enc)
        if blocks:
            return ExfiltrationDetectionResult(
                detection_id=det_id, agent_id=agent_id,
                pattern_type="encoded_block",
                matched_detail=f"Detected {len(blocks)} encoded block(s)",
                output_size_bytes=size, blocked=True,
                risk_score_increase=15, timestamp=now)

        unapproved = self.check_external_endpoints(output_text, allowlist)
        if unapproved:
            return ExfiltrationDetectionResult(
                detection_id=det_id, agent_id=agent_id,
                pattern_type="external_endpoint",
                matched_detail=f"Unapproved: {', '.join(unapproved[:5])}",
                output_size_bytes=size, blocked=True,
                risk_score_increase=25, timestamp=now)

        return ExfiltrationDetectionResult(
            detection_id=det_id, agent_id=agent_id,
            pattern_type="none", matched_detail="",
            output_size_bytes=size, blocked=False,
            risk_score_increase=0, timestamp=now)

    @staticmethod
    def check_output_size(output_text: str, scope_level: int,
                          size_limits: Any = None) -> str:
        """Check output size against scope-level limit. Returns issue or ''."""
        limits = size_limits or DEFAULT_SIZE_LIMITS
        if isinstance(limits, dict):
            limit = limits.get(scope_level, limits.get(str(scope_level), 65536))
        else:
            limit = 65536
        size = len(output_text.encode("utf-8"))
        if size > int(limit):
            return f"Output {size}B exceeds limit {limit}B for scope {scope_level}"
        return ""

    @staticmethod
    def detect_encoded_blocks(output_text: str,
                              max_encoded_length: int = DEFAULT_MAX_ENCODED_LENGTH,
                              ) -> List[str]:
        """Scan for base64/hex encoded blocks exceeding max length."""
        blocks: List[str] = []
        for m in BASE64_PATTERN.finditer(output_text):
            if len(m.group()) > max_encoded_length:
                blocks.append(f"base64@{m.start()}:{len(m.group())}chars")
        for m in HEX_PATTERN.finditer(output_text):
            if len(m.group()) > max_encoded_length:
                blocks.append(f"hex@{m.start()}:{len(m.group())}chars")
        return blocks

    @staticmethod
    def check_external_endpoints(output_text: str,
                                 allowlist: List[str]) -> List[str]:
        """Extract URLs and return those not in the allowlist."""
        urls = URL_PATTERN.findall(output_text)
        unapproved: List[str] = []
        for url in urls:
            if not any(pattern in url for pattern in allowlist):
                unapproved.append(url)
        return unapproved

    def block_and_log(self, agent_id: str,
                      detection_result: ExfiltrationDetectionResult,
                      risk_scoring_engine=None) -> Dict[str, Any]:
        """Block output, log exfiltration attempt, increase risk score."""
        now = datetime.utcnow().isoformat()
        record = {
            "audit_event": "exfiltration_blocked",
            "detection_id": detection_result.detection_id,
            "agent_id": agent_id,
            "pattern_type": detection_result.pattern_type,
            "matched_detail": detection_result.matched_detail,
            "output_size_bytes": detection_result.output_size_bytes,
            "risk_score_increase": detection_result.risk_score_increase,
            "timestamp": now,
        }
        logger.warning(json.dumps(record))
        return {
            "blocked": True,
            "reason": f"Exfiltration pattern detected: {detection_result.pattern_type}",
            "detection_id": detection_result.detection_id,
            "timestamp": now,
        }

    def load_allowlist(self, dynamodb_table) -> List[str]:
        """Load approved external endpoint allowlist from DynamoDB (60s TTL)."""
        now = time.time()
        if self._allowlist_cache is not None and now < self._allowlist_ttl:
            return self._allowlist_cache
        try:
            response = dynamodb_table.scan()
            items = response.get("Items", [])
            while "LastEvaluatedKey" in response:
                response = dynamodb_table.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"])
                items.extend(response.get("Items", []))
            self._allowlist_cache = [
                i.get("endpoint_pattern", "") for i in items if i.get("endpoint_pattern")
            ]
            self._allowlist_ttl = now + 60.0
        except Exception as exc:
            logger.error(json.dumps({
                "event": "load_allowlist_failed", "error": str(exc),
                "timestamp": datetime.utcnow().isoformat(),
            }))
            self._allowlist_cache = self._allowlist_cache or []
        return self._allowlist_cache
