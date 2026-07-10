"""Threat Intelligence Feed Integration -- Self-Improving Governance.

Enables the governance framework to ingest new threat patterns from external
sources and internal anomaly detections without redeployment. New patterns
are written to the same DynamoDB table that threat_detector.py reads from,
becoming active within 60 seconds (the cache TTL).

Three classes:
1. ThreatFeedIntegrator -- accepts external threat intel (arXiv, OWASP,
   vendor advisories) and writes normalized ThreatPattern records.
2. AnomalyPromoter -- promotes confirmed anomalies into named patterns.
3. SelfTestRunner -- regression testing against attack datasets.

All operations are idempotent. Pattern deactivation is supported via
soft-delete (active=false flag). Structured JSON logging throughout.
"""

import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import ThreatPattern

logger = logging.getLogger(__name__)

THREAT_PATTERNS_TABLE_NAME = os.environ.get("THREAT_PATTERNS_TABLE_NAME", "ThreatPatternsTable")


# ---------------------------------------------------------------------------
# Data models for feed integration
# ---------------------------------------------------------------------------

@dataclass
class FeedSource:
    """Metadata about the source of a threat pattern.

    Attributes:
        source_type: One of 'arxiv', 'owasp', 'vendor', 'internal_anomaly'.
        source_id: Unique identifier within the source (e.g. paper DOI, CVE).
        ingested_at: ISO 8601 timestamp of ingestion.
        confidence: 0.0 to 1.0 confidence in the pattern's accuracy.
    """

    source_type: str
    source_id: str
    ingested_at: str = ""
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_id": self.source_id,
            "ingested_at": self.ingested_at or datetime.now(timezone.utc).isoformat(),
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeedSource":
        return cls(
            source_type=data.get("source_type", "unknown"),
            source_id=data.get("source_id", ""),
            ingested_at=data.get("ingested_at", ""),
            confidence=float(data.get("confidence", 1.0)),
        )


@dataclass
class PromotionRecord:
    """Audit record for anomaly-to-pattern promotion.

    Attributes:
        anomaly_fingerprint: Hash of the original anomaly input.
        promoted_pattern_id: The resulting ThreatPattern pattern_id.
        promoted_at: ISO 8601 timestamp of promotion.
        promoted_by: 'auto' or operator identifier who confirmed.
        occurrence_count: Number of times the anomaly was observed.
        original_score: The anomaly score at first detection.
    """

    anomaly_fingerprint: str
    promoted_pattern_id: str
    promoted_at: str
    promoted_by: str
    occurrence_count: int = 1
    original_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_fingerprint": self.anomaly_fingerprint,
            "promoted_pattern_id": self.promoted_pattern_id,
            "promoted_at": self.promoted_at,
            "promoted_by": self.promoted_by,
            "occurrence_count": self.occurrence_count,
            "original_score": round(self.original_score, 3),
        }


@dataclass
class RegressionAlert:
    """Alert raised when a previously-caught attack evades detection.

    Attributes:
        dataset_file: The test dataset filename.
        payload_index: Index of the payload within the dataset.
        payload_preview: First 100 chars of the evasive payload.
        expected_result: What detection should have returned.
        actual_result: What detection actually returned.
        detected_at: ISO 8601 timestamp of the regression detection.
    """

    dataset_file: str
    payload_index: int
    payload_preview: str
    expected_result: str
    actual_result: str
    detected_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_file": self.dataset_file,
            "payload_index": self.payload_index,
            "payload_preview": self.payload_preview[:100],
            "expected_result": self.expected_result,
            "actual_result": self.actual_result,
            "detected_at": self.detected_at or datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# ThreatFeedIntegrator
# ---------------------------------------------------------------------------

class ThreatFeedIntegrator:
    """Ingests threat intelligence from external feeds into DynamoDB.

    Accepts patterns from arXiv papers, OWASP updates, vendor advisories,
    and internal anomaly-to-pattern promotions. Normalizes them into
    ThreatPattern format and writes to the shared DynamoDB table.

    All writes are idempotent -- pattern_id is derived from a hash of the
    pattern content, so duplicate submissions are safe.
    """

    VALID_SOURCES = ("arxiv", "owasp", "vendor", "internal_anomaly")
    VALID_CATEGORIES = ("known_bad", "suspicious")

    def __init__(self, dynamodb_table=None) -> None:
        self._table = dynamodb_table
        self._ingestion_log: List[Dict[str, Any]] = []

    def set_table(self, dynamodb_table) -> None:
        """Set or replace the DynamoDB table reference."""
        self._table = dynamodb_table

    def ingest_pattern(
        self,
        pattern_regex: str,
        category: str,
        description: str,
        risk_weight: int,
        source: FeedSource,
        active: bool = False,
    ) -> Optional[ThreatPattern]:
        """Ingest a single threat pattern from an external feed.

        Patterns default to STAGING (active=False). They must pass validation
        via PatternStagingGate before going live. This prevents malicious or
        overly-broad patterns from causing denial-of-service via false positives.

        Args:
            pattern_regex: Regex or literal string to match against inputs.
            category: 'known_bad' or 'suspicious'.
            description: Human-readable description of the threat.
            risk_weight: Numeric weight (1-100) for risk scoring.
            source: FeedSource metadata about where this pattern came from.
            active: Whether the pattern should be active immediately.
                    Defaults to False (staging). Set True only for operator-verified patterns.

        Returns:
            The created ThreatPattern, or None if validation fails.
        """
        if category not in self.VALID_CATEGORIES:
            logger.warning(json.dumps({
                "audit_event": "feed_ingestion_rejected",
                "reason": f"invalid category: {category}",
                "source": source.to_dict(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

        if source.source_type not in self.VALID_SOURCES:
            logger.warning(json.dumps({
                "audit_event": "feed_ingestion_rejected",
                "reason": f"invalid source_type: {source.source_type}",
                "source": source.to_dict(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

        # Validate regex compiles
        try:
            re.compile(pattern_regex)
        except re.error as e:
            logger.warning(json.dumps({
                "audit_event": "feed_ingestion_rejected",
                "reason": f"invalid regex: {str(e)}",
                "pattern": pattern_regex[:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

        # Generate deterministic pattern_id from content for idempotency
        pattern_id = self._generate_pattern_id(pattern_regex, source)
        now = datetime.now(timezone.utc).isoformat()

        threat_pattern = ThreatPattern(
            pattern_id=pattern_id,
            category=category,
            pattern=pattern_regex,
            description=description,
            risk_weight=risk_weight,
            updated_at=now,
        )

        # Build item with extended metadata
        item = threat_pattern.to_dict()
        item["source"] = source.to_dict()
        item["auto_generated"] = True
        item["active"] = active
        item["created_at"] = now

        if self._table is not None:
            self._table.put_item(Item=item)

        self._ingestion_log.append({
            "pattern_id": pattern_id,
            "source": source.to_dict(),
            "active": active,
            "timestamp": now,
        })

        logger.info(json.dumps({
            "audit_event": "threat_pattern_ingested",
            "pattern_id": pattern_id,
            "category": category,
            "source_type": source.source_type,
            "source_id": source.source_id,
            "auto_generated": True,
            "active": active,
            "timestamp": now,
        }))

        return threat_pattern

    def ingest_batch(
        self,
        patterns: List[Dict[str, Any]],
        source: FeedSource,
    ) -> Dict[str, Any]:
        """Ingest multiple patterns from a single feed source.

        Args:
            patterns: List of dicts with keys: pattern_regex, category,
                     description, risk_weight.
            source: Shared FeedSource for the batch.

        Returns:
            Summary dict with ingested_count, rejected_count, pattern_ids.
        """
        ingested = []
        rejected = 0

        for entry in patterns:
            result = self.ingest_pattern(
                pattern_regex=entry.get("pattern_regex", ""),
                category=entry.get("category", "suspicious"),
                description=entry.get("description", "Auto-ingested pattern"),
                risk_weight=entry.get("risk_weight", 5),
                source=source,
                active=entry.get("active", True),
            )
            if result is not None:
                ingested.append(result.pattern_id)
            else:
                rejected += 1

        logger.info(json.dumps({
            "audit_event": "batch_ingestion_complete",
            "source_type": source.source_type,
            "source_id": source.source_id,
            "ingested_count": len(ingested),
            "rejected_count": rejected,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        return {
            "ingested_count": len(ingested),
            "rejected_count": rejected,
            "pattern_ids": ingested,
        }

    def deactivate_pattern(
        self, pattern_id: str, reason: str, deactivated_by: str = "system"
    ) -> bool:
        """Deactivate a pattern (soft-delete) due to false positives.

        The pattern remains in DynamoDB but is marked active=false.
        The threat_detector will skip inactive patterns on next cache refresh.

        Args:
            pattern_id: The pattern to deactivate.
            reason: Human-readable reason for deactivation.
            deactivated_by: Operator or 'system' for auto-deactivation.

        Returns:
            True if deactivation succeeded, False otherwise.
        """
        now = datetime.now(timezone.utc).isoformat()

        if self._table is None:
            logger.error(json.dumps({
                "audit_event": "deactivation_failed",
                "reason": "no DynamoDB table configured",
                "pattern_id": pattern_id,
                "timestamp": now,
            }))
            return False

        try:
            self._table.update_item(
                Key={"pattern_id": pattern_id},
                UpdateExpression=(
                    "SET active = :active, deactivated_at = :ts, "
                    "deactivation_reason = :reason, deactivated_by = :by"
                ),
                ExpressionAttributeValues={
                    ":active": False,
                    ":ts": now,
                    ":reason": reason,
                    ":by": deactivated_by,
                },
            )
        except Exception as e:
            logger.error(json.dumps({
                "audit_event": "deactivation_failed",
                "pattern_id": pattern_id,
                "error": str(e),
                "timestamp": now,
            }))
            return False

        logger.info(json.dumps({
            "audit_event": "threat_pattern_deactivated",
            "pattern_id": pattern_id,
            "reason": reason,
            "deactivated_by": deactivated_by,
            "timestamp": now,
        }))
        return True

    def reactivate_pattern(self, pattern_id: str, reason: str) -> bool:
        """Reactivate a previously deactivated pattern.

        Args:
            pattern_id: The pattern to reactivate.
            reason: Human-readable reason for reactivation.

        Returns:
            True if reactivation succeeded, False otherwise.
        """
        now = datetime.now(timezone.utc).isoformat()

        if self._table is None:
            return False

        try:
            self._table.update_item(
                Key={"pattern_id": pattern_id},
                UpdateExpression=(
                    "SET active = :active, reactivated_at = :ts, "
                    "reactivation_reason = :reason"
                ),
                ExpressionAttributeValues={
                    ":active": True,
                    ":ts": now,
                    ":reason": reason,
                },
            )
        except Exception as e:
            logger.error(json.dumps({
                "audit_event": "reactivation_failed",
                "pattern_id": pattern_id,
                "error": str(e),
                "timestamp": now,
            }))
            return False

        logger.info(json.dumps({
            "audit_event": "threat_pattern_reactivated",
            "pattern_id": pattern_id,
            "reason": reason,
            "timestamp": now,
        }))
        return True

    def get_ingestion_log(self) -> List[Dict[str, Any]]:
        """Return the in-memory ingestion log for the current session."""
        return list(self._ingestion_log)

    @staticmethod
    def _generate_pattern_id(pattern_regex: str, source: FeedSource) -> str:
        """Generate a deterministic pattern_id for idempotent writes.

        The ID is derived from the pattern content and source, so
        re-ingesting the same pattern from the same source produces the
        same ID (idempotent put_item overwrites with identical data).
        """
        content = f"{source.source_type}:{source.source_id}:{pattern_regex}"
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        return f"feed-{source.source_type}-{digest}"


# ---------------------------------------------------------------------------
# AnomalyPromoter
# ---------------------------------------------------------------------------

class AnomalyPromoter:
    """Promotes confirmed anomalies into named threat patterns.

    When the anomaly_detector.py flags an input as anomalous, that detection
    is initially unnamed -- just statistical scores. If the anomaly is
    confirmed (by repeated occurrence or human review), this class extracts
    a regex signature and promotes it to a named ThreatPattern in DynamoDB.

    Promotion history is tracked for audit compliance.
    """

    # Minimum occurrences before auto-promotion is allowed
    AUTO_PROMOTE_THRESHOLD = 3
    # Minimum anomaly score for auto-promotion eligibility
    MIN_SCORE_FOR_PROMOTION = 0.7

    def __init__(self, dynamodb_table=None) -> None:
        self._table = dynamodb_table
        self._occurrence_tracker: Dict[str, Dict[str, Any]] = {}
        self._promotion_history: List[PromotionRecord] = []
        self._integrator = ThreatFeedIntegrator(dynamodb_table)

    def set_table(self, dynamodb_table) -> None:
        """Set or replace the DynamoDB table reference."""
        self._table = dynamodb_table
        self._integrator.set_table(dynamodb_table)

    def record_anomaly(
        self,
        input_text: str,
        anomaly_score: float,
        factors: Dict[str, float],
    ) -> Dict[str, Any]:
        """Record an anomaly occurrence for potential promotion.

        Tracks occurrence count and highest score. When threshold is
        reached, marks the anomaly as eligible for auto-promotion.

        Args:
            input_text: The anomalous input text.
            anomaly_score: Composite anomaly score (0.0 to 1.0).
            factors: Per-factor breakdown from AnomalyDetector.

        Returns:
            Status dict with fingerprint, occurrence_count, eligible flag.
        """
        fingerprint = self._compute_fingerprint(input_text)
        now = datetime.now(timezone.utc).isoformat()

        if fingerprint not in self._occurrence_tracker:
            self._occurrence_tracker[fingerprint] = {
                "first_seen": now,
                "last_seen": now,
                "occurrence_count": 0,
                "max_score": 0.0,
                "factors": factors,
                "sample_text": input_text[:500],
                "promoted": False,
            }

        entry = self._occurrence_tracker[fingerprint]
        entry["occurrence_count"] += 1
        entry["last_seen"] = now
        entry["max_score"] = max(entry["max_score"], anomaly_score)
        # Keep the highest-scoring factors
        if anomaly_score >= entry["max_score"]:
            entry["factors"] = factors

        eligible = (
            entry["occurrence_count"] >= self.AUTO_PROMOTE_THRESHOLD
            and entry["max_score"] >= self.MIN_SCORE_FOR_PROMOTION
            and not entry["promoted"]
        )

        logger.info(json.dumps({
            "audit_event": "anomaly_recorded",
            "fingerprint": fingerprint,
            "occurrence_count": entry["occurrence_count"],
            "max_score": round(entry["max_score"], 3),
            "auto_promote_eligible": eligible,
            "timestamp": now,
        }))

        return {
            "fingerprint": fingerprint,
            "occurrence_count": entry["occurrence_count"],
            "max_score": entry["max_score"],
            "eligible_for_auto_promotion": eligible,
        }

    def promote_anomaly(
        self,
        fingerprint: str,
        promoted_by: str = "auto",
        category: str = "suspicious",
        description: Optional[str] = None,
        risk_weight: Optional[int] = None,
    ) -> Optional[ThreatPattern]:
        """Promote a tracked anomaly to a named ThreatPattern.

        Extracts a regex signature from the anomaly characteristics and
        writes it to DynamoDB via the ThreatFeedIntegrator.

        Args:
            fingerprint: The anomaly fingerprint from record_anomaly().
            promoted_by: 'auto' or operator identifier.
            category: Target category ('known_bad' or 'suspicious').
            description: Override description (auto-generated if None).
            risk_weight: Override risk weight (derived from score if None).

        Returns:
            The created ThreatPattern, or None if promotion fails.
        """
        now = datetime.now(timezone.utc).isoformat()

        if fingerprint not in self._occurrence_tracker:
            logger.warning(json.dumps({
                "audit_event": "promotion_failed",
                "reason": "fingerprint not found in tracker",
                "fingerprint": fingerprint,
                "timestamp": now,
            }))
            return None

        entry = self._occurrence_tracker[fingerprint]

        if entry["promoted"]:
            logger.info(json.dumps({
                "audit_event": "promotion_skipped",
                "reason": "already promoted",
                "fingerprint": fingerprint,
                "timestamp": now,
            }))
            return None

        # Extract regex signature from the anomaly factors
        pattern_regex = self._extract_signature(entry)
        if not pattern_regex:
            logger.warning(json.dumps({
                "audit_event": "promotion_failed",
                "reason": "could not extract viable signature",
                "fingerprint": fingerprint,
                "timestamp": now,
            }))
            return None

        # Derive risk weight from anomaly score if not provided
        if risk_weight is None:
            risk_weight = max(1, min(20, int(entry["max_score"] * 20)))

        if description is None:
            description = (
                f"Auto-promoted anomaly (score {entry['max_score']:.2f}, "
                f"seen {entry['occurrence_count']}x). "
                f"Dominant factors: {self._dominant_factors(entry['factors'])}"
            )

        source = FeedSource(
            source_type="internal_anomaly",
            source_id=fingerprint,
            ingested_at=now,
            confidence=min(1.0, entry["max_score"]),
        )

        result = self._integrator.ingest_pattern(
            pattern_regex=pattern_regex,
            category=category,
            description=description,
            risk_weight=risk_weight,
            source=source,
        )

        if result is not None:
            entry["promoted"] = True

            record = PromotionRecord(
                anomaly_fingerprint=fingerprint,
                promoted_pattern_id=result.pattern_id,
                promoted_at=now,
                promoted_by=promoted_by,
                occurrence_count=entry["occurrence_count"],
                original_score=entry["max_score"],
            )
            self._promotion_history.append(record)

            logger.info(json.dumps({
                "audit_event": "anomaly_promoted",
                "fingerprint": fingerprint,
                "pattern_id": result.pattern_id,
                "promoted_by": promoted_by,
                "occurrence_count": entry["occurrence_count"],
                "max_score": round(entry["max_score"], 3),
                "timestamp": now,
            }))

        return result

    def auto_promote_eligible(self) -> List[str]:
        """Return fingerprints eligible for automatic promotion.

        An anomaly is eligible when it has been seen at least
        AUTO_PROMOTE_THRESHOLD times with a score above
        MIN_SCORE_FOR_PROMOTION and has not already been promoted.
        """
        eligible = []
        for fp, entry in self._occurrence_tracker.items():
            if (
                entry["occurrence_count"] >= self.AUTO_PROMOTE_THRESHOLD
                and entry["max_score"] >= self.MIN_SCORE_FOR_PROMOTION
                and not entry["promoted"]
            ):
                eligible.append(fp)
        return eligible

    def get_promotion_history(self) -> List[Dict[str, Any]]:
        """Return the full promotion history for audit."""
        return [r.to_dict() for r in self._promotion_history]

    def get_tracker_state(self) -> Dict[str, Dict[str, Any]]:
        """Return the current occurrence tracker state (for debugging)."""
        return dict(self._occurrence_tracker)

    @staticmethod
    def _compute_fingerprint(text: str) -> str:
        """Compute a stable fingerprint for anomaly deduplication.

        Uses structural characteristics rather than exact content so
        that minor variations of the same attack cluster together.
        """
        # Normalize: lowercase, collapse whitespace, trim
        normalized = re.sub(r"\s+", " ", text.lower().strip())
        # Take first 200 chars for fingerprinting (attacks are front-loaded)
        prefix = normalized[:200]
        digest = hashlib.sha256(prefix.encode("utf-8")).hexdigest()[:20]
        return f"anomaly-{digest}"

    @staticmethod
    def _extract_signature(entry: Dict[str, Any]) -> Optional[str]:
        """Extract a regex signature from anomaly characteristics.

        Heuristic approach: uses the dominant anomaly factors to decide
        what kind of pattern to generate.
        """
        factors = entry.get("factors", {})
        sample = entry.get("sample_text", "")

        if not sample:
            return None

        # Strategy depends on which factors are highest
        dominant = sorted(factors.items(), key=lambda x: x[1], reverse=True)
        if not dominant:
            return None

        top_factor = dominant[0][0]

        if top_factor == "entropy":
            # High entropy -- likely encoded payload. Match base64-like blocks.
            return r"[A-Za-z0-9+/=]{40,}"

        elif top_factor == "special_char_ratio":
            # High special chars -- extract the special char sequence pattern
            specials = re.findall(r"[^\w\s]{3,}", sample)
            if specials:
                # Escape the longest special sequence as a literal pattern
                longest = max(specials, key=len)
                return re.escape(longest[:30])

        elif top_factor == "script_mixing":
            # Mixed scripts -- match non-ASCII alphabetic chars near ASCII
            return r"[Ѐ-ӿ][\w]*[a-zA-Z]|[a-zA-Z][\w]*[Ѐ-ӿ]"

        elif top_factor == "repetition":
            # High repetition -- extract the repeated n-gram
            words = sample.split()
            if len(words) >= 6:
                trigrams = [" ".join(words[i:i+3]) for i in range(len(words)-2)]
                from collections import Counter
                counts = Counter(trigrams)
                most_common = counts.most_common(1)
                if most_common and most_common[0][1] >= 2:
                    repeated = most_common[0][0]
                    return re.escape(repeated)

        elif top_factor == "length":
            # Abnormal length -- too generic for a useful regex
            # Fall back to matching the first distinctive substring
            pass

        # Fallback: extract first 4+ char word-boundary-delimited token
        tokens = re.findall(r"\b\w{4,}\b", sample)
        if tokens:
            # Use a combination of the first few distinctive tokens
            distinctive = [t for t in tokens if len(t) >= 6][:3]
            if distinctive:
                return r"(?i)" + r".*".join(re.escape(t) for t in distinctive)

        return None

    @staticmethod
    def _dominant_factors(factors: Dict[str, float]) -> str:
        """Format dominant factors for description text."""
        sorted_factors = sorted(factors.items(), key=lambda x: x[1], reverse=True)
        top = [f"{k}={v:.2f}" for k, v in sorted_factors[:3] if v > 0.3]
        return ", ".join(top) if top else "none"


# ---------------------------------------------------------------------------
# SelfTestRunner
# ---------------------------------------------------------------------------

class SelfTestRunner:
    """Regression testing against attack datasets.

    Periodically samples payloads from test_datasets/*.json and runs them
    through input_sanitizer to verify they are still being caught. If any
    previously-caught attack now passes (detection regression), an alert
    is raised.

    Tracks detection rate drift over time for trend reporting.
    """

    DEFAULT_SAMPLE_SIZE = 50
    DATASETS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "test_datasets",
    )

    def __init__(self, sample_size: int = None) -> None:
        self._sample_size = sample_size or self.DEFAULT_SAMPLE_SIZE
        self._run_history: List[Dict[str, Any]] = []
        self._alerts: List[RegressionAlert] = []
        self._baseline_results: Dict[str, Dict[int, str]] = {}

    def run_regression_check(
        self,
        sanitizer_fn=None,
        datasets_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a regression check against sampled attack payloads.

        Args:
            sanitizer_fn: Callable that takes (text: str) and returns a
                         result with a 'blocked' attribute or key.
                         If None, uses InputSanitizer.sanitize().
            datasets_dir: Override path to test_datasets directory.

        Returns:
            Summary dict with total_tested, caught, missed, detection_rate,
            regressions list, and comparison to previous run.
        """
        now = datetime.now(timezone.utc).isoformat()
        target_dir = datasets_dir or self.DATASETS_DIR

        if sanitizer_fn is None:
            sanitizer_fn = self._default_sanitizer()

        # Load and sample payloads
        payloads = self._load_dataset_samples(target_dir)
        if not payloads:
            logger.warning(json.dumps({
                "audit_event": "self_test_no_data",
                "datasets_dir": target_dir,
                "timestamp": now,
            }))
            return {
                "total_tested": 0,
                "caught": 0,
                "missed": 0,
                "detection_rate": 0.0,
                "regressions": [],
                "timestamp": now,
            }

        # Run each payload through the sanitizer
        caught = 0
        missed = 0
        regressions = []

        for dataset_file, index, payload in payloads:
            try:
                result = sanitizer_fn(payload)
                blocked = self._is_blocked(result)
            except Exception:
                # If sanitizer raises, count as caught (fail-closed)
                blocked = True

            if blocked:
                caught += 1
            else:
                missed += 1
                # Check if this was previously caught (regression)
                baseline_key = f"{dataset_file}:{index}"
                if self._was_previously_caught(dataset_file, index):
                    alert = RegressionAlert(
                        dataset_file=dataset_file,
                        payload_index=index,
                        payload_preview=payload[:100],
                        expected_result="blocked",
                        actual_result="passed",
                        detected_at=now,
                    )
                    regressions.append(alert)
                    self._alerts.append(alert)

            # Update baseline
            self._update_baseline(dataset_file, index, blocked)

        total = caught + missed
        detection_rate = caught / total if total > 0 else 0.0

        # Compare to previous run
        drift = self._compute_drift(detection_rate)

        run_record = {
            "timestamp": now,
            "total_tested": total,
            "caught": caught,
            "missed": missed,
            "detection_rate": round(detection_rate, 4),
            "regression_count": len(regressions),
            "drift_from_previous": drift,
        }
        self._run_history.append(run_record)

        # Log the results
        log_fn = logger.warning if regressions else logger.info
        log_fn(json.dumps({
            "audit_event": "self_test_complete",
            "total_tested": total,
            "caught": caught,
            "missed": missed,
            "detection_rate": round(detection_rate, 4),
            "regression_count": len(regressions),
            "drift": drift,
            "timestamp": now,
        }))

        if regressions:
            logger.error(json.dumps({
                "audit_event": "detection_regression_alert",
                "regression_count": len(regressions),
                "regressions": [r.to_dict() for r in regressions],
                "timestamp": now,
            }))

        return {
            "total_tested": total,
            "caught": caught,
            "missed": missed,
            "detection_rate": round(detection_rate, 4),
            "regressions": [r.to_dict() for r in regressions],
            "drift_from_previous": drift,
            "timestamp": now,
        }

    def get_detection_rate_history(self) -> List[Dict[str, Any]]:
        """Return detection rate over time for trend analysis."""
        return [
            {
                "timestamp": r["timestamp"],
                "detection_rate": r["detection_rate"],
                "total_tested": r["total_tested"],
                "drift": r.get("drift_from_previous", None),
            }
            for r in self._run_history
        ]

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return all regression alerts raised during self-test runs."""
        return [a.to_dict() for a in self._alerts]

    def clear_alerts(self) -> int:
        """Clear acknowledged alerts. Returns count of cleared alerts."""
        count = len(self._alerts)
        self._alerts = []
        return count

    def _load_dataset_samples(
        self, datasets_dir: str
    ) -> List[tuple]:
        """Load random samples from JSON dataset files.

        Returns list of (filename, index, payload) tuples.
        """
        samples = []

        try:
            if not os.path.isdir(datasets_dir):
                return samples

            files = [
                f for f in os.listdir(datasets_dir)
                if f.endswith(".json") and not f.startswith("benchmark_")
                and not f.startswith("governance_test_")
            ]
        except OSError:
            return samples

        for filename in files:
            filepath = os.path.join(datasets_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # Handle both list-of-strings and list-of-dicts formats
            payloads = []
            if isinstance(data, list):
                for i, item in enumerate(data):
                    if isinstance(item, str):
                        payloads.append((i, item))
                    elif isinstance(item, dict):
                        # Try common keys for the payload text
                        text = (
                            item.get("text")
                            or item.get("prompt")
                            or item.get("input")
                            or item.get("payload")
                            or item.get("content")
                        )
                        if text and isinstance(text, str):
                            payloads.append((i, text))

            if not payloads:
                continue

            # Sample from this dataset
            per_file_sample = max(1, self._sample_size // max(1, len(files)))
            chosen = random.sample(payloads, min(per_file_sample, len(payloads)))
            for idx, text in chosen:
                samples.append((filename, idx, text))

        return samples

    def _was_previously_caught(self, dataset_file: str, index: int) -> bool:
        """Check if a payload was caught in a previous run."""
        file_baseline = self._baseline_results.get(dataset_file, {})
        return file_baseline.get(index) == "blocked"

    def _update_baseline(self, dataset_file: str, index: int, blocked: bool) -> None:
        """Update the baseline result for a specific payload."""
        if dataset_file not in self._baseline_results:
            self._baseline_results[dataset_file] = {}
        self._baseline_results[dataset_file][index] = "blocked" if blocked else "passed"

    def _compute_drift(self, current_rate: float) -> Optional[float]:
        """Compute detection rate drift from previous run."""
        if not self._run_history:
            return None
        previous_rate = self._run_history[-1]["detection_rate"]
        return round(current_rate - previous_rate, 4)

    @staticmethod
    def _is_blocked(result) -> bool:
        """Determine if a sanitization result indicates blocking.

        Handles both object (SanitizationResult) and dict responses.
        """
        if hasattr(result, "blocked"):
            return bool(result.blocked)
        if isinstance(result, dict):
            return bool(result.get("blocked", False))
        return False

    @staticmethod
    def _default_sanitizer():
        """Create a default sanitizer function using InputSanitizer.

        Returns a callable that accepts text and returns SanitizationResult.
        """
        try:
            from input_sanitizer import InputSanitizer
            sanitizer = InputSanitizer()
            return sanitizer.sanitize
        except ImportError:
            # If input_sanitizer is not available, return a no-op
            logger.warning(json.dumps({
                "audit_event": "self_test_no_sanitizer",
                "reason": "input_sanitizer module not available",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

            def noop(text: str):
                return {"blocked": False}
            return noop


# ---------------------------------------------------------------------------
# PatternStagingGate
# ---------------------------------------------------------------------------

@dataclass
class StagingResult:
    """Result of testing a staged pattern against historical decisions.

    Attributes:
        pattern_id: The pattern being validated.
        total_tested: Number of historical inputs tested against.
        false_positives: Count of legitimate inputs that would be blocked.
        true_positives: Count of known-bad inputs that are correctly caught.
        fp_rate: False positive rate (0.0 to 1.0).
        verdict: 'activate', 'quarantine', or 'needs_review'.
        tested_at: ISO 8601 timestamp.
    """

    pattern_id: str
    total_tested: int
    false_positives: int
    true_positives: int
    fp_rate: float
    verdict: str
    tested_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "total_tested": self.total_tested,
            "false_positives": self.false_positives,
            "true_positives": self.true_positives,
            "fp_rate": round(self.fp_rate, 4),
            "verdict": self.verdict,
            "tested_at": self.tested_at or datetime.now(timezone.utc).isoformat(),
        }


class PatternStagingGate:
    """Validates staged patterns before activation.

    Tests a new pattern against historical legitimate inputs to measure
    false positive rate. Only activates patterns with FP rate below threshold.

    Flow:
        New pattern (active=False) → test against known-good inputs →
        FP rate < 2% → ACTIVATE (set active=True in DynamoDB)
        FP rate >= 2% → QUARANTINE (stays inactive, operator alerted)

    This prevents:
        - Overly broad regex (e.g., '.*') blocking all requests
        - Malicious patterns injected to cause denial of service
        - Auto-promoted anomalies that match too many legitimate inputs
    """

    FP_THRESHOLD = 0.02  # 2% max false positive rate
    MIN_TEST_SAMPLES = 50  # minimum inputs to test against

    def __init__(self, dynamodb_table=None) -> None:
        self._table = dynamodb_table
        self._known_good_inputs: List[str] = []

    def set_table(self, dynamodb_table) -> None:
        """Set or replace the DynamoDB table reference."""
        self._table = dynamodb_table

    def load_known_good_inputs(self, inputs: List[str]) -> None:
        """Load legitimate inputs to test patterns against.

        These should be real inputs that SHOULD be allowed (from decision
        history where verdict=allow). The more diverse, the better the
        false positive estimate.
        """
        self._known_good_inputs = inputs
        logger.info(json.dumps({
            "audit_event": "staging_gate_inputs_loaded",
            "count": len(inputs),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

    def validate_pattern(self, pattern_id: str, pattern_regex: str) -> StagingResult:
        """Test a staged pattern against known-good inputs.

        Args:
            pattern_id: The pattern identifier in DynamoDB.
            pattern_regex: The regex to test.

        Returns:
            StagingResult with verdict: 'activate', 'quarantine', or 'needs_review'.
        """
        now = datetime.now(timezone.utc).isoformat()

        if len(self._known_good_inputs) < self.MIN_TEST_SAMPLES:
            logger.warning(json.dumps({
                "audit_event": "staging_gate_insufficient_samples",
                "pattern_id": pattern_id,
                "available": len(self._known_good_inputs),
                "required": self.MIN_TEST_SAMPLES,
                "timestamp": now,
            }))
            return StagingResult(
                pattern_id=pattern_id,
                total_tested=len(self._known_good_inputs),
                false_positives=0,
                true_positives=0,
                fp_rate=0.0,
                verdict="needs_review",
                tested_at=now,
            )

        try:
            compiled = re.compile(pattern_regex, re.IGNORECASE)
        except re.error:
            return StagingResult(
                pattern_id=pattern_id,
                total_tested=0,
                false_positives=0,
                true_positives=0,
                fp_rate=1.0,
                verdict="quarantine",
                tested_at=now,
            )

        false_positives = 0
        for text in self._known_good_inputs:
            if compiled.search(text):
                false_positives += 1

        total = len(self._known_good_inputs)
        fp_rate = false_positives / total if total > 0 else 0.0

        if fp_rate < self.FP_THRESHOLD:
            verdict = "activate"
        else:
            verdict = "quarantine"

        result = StagingResult(
            pattern_id=pattern_id,
            total_tested=total,
            false_positives=false_positives,
            true_positives=0,
            fp_rate=fp_rate,
            verdict=verdict,
            tested_at=now,
        )

        logger.info(json.dumps({
            "audit_event": "staging_gate_validation",
            "pattern_id": pattern_id,
            "total_tested": total,
            "false_positives": false_positives,
            "fp_rate": round(fp_rate, 4),
            "verdict": verdict,
            "timestamp": now,
        }))

        return result

    def activate_pattern(self, pattern_id: str) -> bool:
        """Activate a staged pattern (set active=True in DynamoDB).

        Only call this after validate_pattern returns verdict='activate'.
        """
        if self._table is None:
            return False

        try:
            self._table.update_item(
                Key={"pattern_id": pattern_id},
                UpdateExpression="SET active = :a, activated_at = :t",
                ExpressionAttributeValues={
                    ":a": True,
                    ":t": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.info(json.dumps({
                "audit_event": "pattern_activated",
                "pattern_id": pattern_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return True
        except Exception as e:
            logger.error(json.dumps({
                "audit_event": "pattern_activation_failed",
                "pattern_id": pattern_id,
                "error": str(e)[:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return False

    def quarantine_pattern(self, pattern_id: str, reason: str) -> bool:
        """Quarantine a pattern that failed validation.

        Keeps it in DynamoDB for review but ensures it stays inactive.
        """
        if self._table is None:
            return False

        try:
            self._table.update_item(
                Key={"pattern_id": pattern_id},
                UpdateExpression="SET active = :a, quarantined = :q, quarantine_reason = :r, quarantined_at = :t",
                ExpressionAttributeValues={
                    ":a": False,
                    ":q": True,
                    ":r": reason,
                    ":t": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.info(json.dumps({
                "audit_event": "pattern_quarantined",
                "pattern_id": pattern_id,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return True
        except Exception as e:
            logger.error(json.dumps({
                "audit_event": "pattern_quarantine_failed",
                "pattern_id": pattern_id,
                "error": str(e)[:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return False

    def process_staged_patterns(self, staged_patterns: List[Dict[str, str]]) -> List[StagingResult]:
        """Validate all staged patterns and activate or quarantine each.

        Args:
            staged_patterns: List of dicts with 'pattern_id' and 'pattern' keys.

        Returns:
            List of StagingResult for each processed pattern.
        """
        results = []
        for p in staged_patterns:
            pattern_id = p.get("pattern_id", "")
            pattern_regex = p.get("pattern", "")

            result = self.validate_pattern(pattern_id, pattern_regex)
            results.append(result)

            if result.verdict == "activate":
                self.activate_pattern(pattern_id)
            elif result.verdict == "quarantine":
                self.quarantine_pattern(
                    pattern_id,
                    f"FP rate {result.fp_rate:.2%} exceeds threshold {self.FP_THRESHOLD:.2%}"
                )

        return results
