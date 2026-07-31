"""Data Exfiltration Prevention module.

Evaluates agent output for exfiltration patterns: large data volumes,
base64/hex encoded blocks, and references to unapproved external endpoints.
Blocks suspicious output, increases agent risk score, and logs detections.

Requirements: 28.1, 28.2, 28.3, 28.4
"""

import json
import logging
import math
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import ExfiltrationDetectionResult

logger = logging.getLogger(__name__)

DEFAULT_SIZE_LIMITS = {0: 0, 1: 1024, 2: 4096, 3: 16384, 4: 65536}
DEFAULT_MAX_ENCODED_LENGTH = 512
# Minimum blob length (bytes) subject to entropy check; short strings are noisy
_ENTROPY_MIN_BLOB_LEN = 64
# Shannon entropy threshold above which a blob is flagged (7.2 bits/byte catches
# XOR+gzip+base64 chunked payloads; true random is ~8.0, English text is ~4.5)
_ENTROPY_THRESHOLD = 7.2
# Minimum number of high-entropy blobs before blocking (avoids false positives on
# single short tokens like JWTs in normal API responses)
_ENTROPY_MIN_BLOBS = 2
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
HEX_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}){32,}")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
# Chunked blob pattern: short base64 segments separated by delimiters (XOR+chunk scheme)
_CHUNKED_BLOB_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{8,}={0,2}[\s,;|]+){4,}")


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. Returns 0.0 for empty input."""
    if not data:
        return 0.0
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


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
        now = datetime.now(timezone.utc).isoformat()
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

        # Entropy-based detection: catches XOR+gzip+base64 chunked payloads that
        # evade regex pattern matching on chunk boundaries.
        high_entropy_blobs = self.detect_high_entropy_blobs(output_text)
        if high_entropy_blobs:
            return ExfiltrationDetectionResult(
                detection_id=det_id, agent_id=agent_id,
                pattern_type="high_entropy_blob",
                matched_detail=f"Detected {len(high_entropy_blobs)} high-entropy blob(s) "
                               f"(max entropy: {max(e for _, e in high_entropy_blobs):.2f} bits/byte)",
                output_size_bytes=size, blocked=True,
                risk_score_increase=25, timestamp=now)

        # Chunked blob pattern: multiple short base64 segments -- hallmark of
        # chunk+encode exfil schemes used in the HF incident.
        if _CHUNKED_BLOB_PATTERN.search(output_text):
            return ExfiltrationDetectionResult(
                detection_id=det_id, agent_id=agent_id,
                pattern_type="chunked_blob",
                matched_detail="Chunked base64 blob pattern detected (possible staged exfil payload)",
                output_size_bytes=size, blocked=True,
                risk_score_increase=25, timestamp=now)

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
    def detect_high_entropy_blobs(
        output_text: str,
        min_len: int = _ENTROPY_MIN_BLOB_LEN,
        threshold: float = _ENTROPY_THRESHOLD,
        min_blobs: int = _ENTROPY_MIN_BLOBS,
    ) -> List[tuple]:
        """Detect high-entropy blobs regardless of encoding scheme.

        Catches XOR+gzip+base64 chunked payloads that evade regex pattern
        matching by splitting the encoded payload across chunk boundaries.
        For base64-encoded tokens, measures entropy on the decoded bytes
        (base64 text is capped at ~6 bits/byte and would otherwise escape
        the threshold). Returns list of (blob_excerpt, entropy) tuples;
        empty list if count is below min_blobs.
        """
        import base64 as _b64
        _B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

        # Split on common delimiters to surface individual blobs
        candidates = re.split(r'[\s,;|"\'\n]+', output_text)
        high: List[tuple] = []
        for token in candidates:
            if len(token) < min_len:
                continue
            # Attempt base64 decode to measure entropy on raw bytes
            raw: bytes
            if _B64_RE.match(token):
                try:
                    raw = _b64.b64decode(token + "==")
                except Exception:
                    raw = token.encode("utf-8", errors="replace")
            else:
                raw = token.encode("utf-8", errors="replace")
            entropy = _shannon_entropy(raw)
            if entropy >= threshold:
                high.append((token[:32] + "...", entropy))
        if len(high) >= min_blobs:
            return high
        return []

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
        now = datetime.now(timezone.utc).isoformat()
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
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            self._allowlist_cache = self._allowlist_cache or []
        return self._allowlist_cache
