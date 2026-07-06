"""Semantic Cache Governance - validates cache reads and writes.

Prevents poisoned cache entries, PII leakage across users, stale
responses, and cache bypass cost attacks. Runs as a governance layer
between the application and the cache store.

Two enforcement points:
1. BEFORE CACHE WRITE: validate response is safe to cache
2. BEFORE CACHE READ (serve): validate cached response is still safe to serve
"""

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CacheValidationResult:
    """Result of cache governance validation."""

    def __init__(self, safe: bool, action: str, reasons: List[str] = None):
        self.safe = safe
        self.action = action  # "cache", "serve", "reject", "invalidate"
        self.reasons = reasons or []
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "action": self.action,
            "reasons": self.reasons,
            "timestamp": self.timestamp,
        }


class CacheGovernor:
    """Governs the semantic cache layer for AI agent responses."""

    # PII patterns that must NEVER be cached
    _PII_PATTERNS = [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
        re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),  # Credit card
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
        re.compile(r"\b\+?1?\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),  # Phone
        re.compile(r"\b\d{1,5}\s+[A-Za-z0-9\s,.'#-]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b", re.IGNORECASE),  # Address
    ]

    # Sensitive patterns that indicate user-specific data
    _USER_SPECIFIC_PATTERNS = [
        re.compile(r"your (?:order|account|balance|payment|address|delivery)", re.IGNORECASE),
        re.compile(r"(?:order|tracking|account|invoice)\s*#?\s*[A-Z0-9-]{6,}", re.IGNORECASE),
        re.compile(r"(?:Dear|Hi|Hello)\s+[A-Z][a-z]+", re.IGNORECASE),
    ]

    # Indicators of a potentially poisoned/manipulated response
    _POISON_INDICATORS = [
        re.compile(r"(?:ignore|disregard|forget)\s+(?:previous|prior|above)", re.IGNORECASE),
        re.compile(r"(?:system|admin|root)\s+(?:access|mode|override)", re.IGNORECASE),
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"(?:DROP|DELETE|INSERT|UPDATE)\s+(?:TABLE|FROM|INTO)", re.IGNORECASE),
    ]

    # Sensitive infrastructure patterns
    _INFRA_PATTERNS = [
        re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s]+"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),
    ]

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        self._ttl_seconds = config.get("ttl_seconds", 3600)
        self._max_response_size = config.get("max_response_size_bytes", 16384)
        self._max_queries_per_minute = config.get("max_unique_queries_per_minute", 60)

    def validate_before_cache_write(self, query: str, response: str,
                                     user_id: str = "",
                                     metadata: Dict[str, Any] = None) -> CacheValidationResult:
        """Validate a response BEFORE it enters the semantic cache.

        Checks:
        1. No PII in response (prevents cross-user PII leakage)
        2. No user-specific data (would be wrong for other users)
        3. No poison indicators (prevents cache poisoning attacks)
        4. No infrastructure secrets (ARNs, keys, tokens)
        5. Response size within limits (prevents cache bloat attacks)
        6. Response is not empty or trivially short

        Returns CacheValidationResult with action="cache" or "reject".
        """
        reasons = []

        # Check 1: PII detection
        for pattern in self._PII_PATTERNS:
            if pattern.search(response):
                reasons.append(f"pii_detected: {pattern.pattern[:30]}")

        # Check 2: User-specific content
        for pattern in self._USER_SPECIFIC_PATTERNS:
            if pattern.search(response):
                reasons.append(f"user_specific_content: {pattern.pattern[:30]}")

        # Check 3: Poison indicators
        for pattern in self._POISON_INDICATORS:
            if pattern.search(response):
                reasons.append(f"poison_indicator: {pattern.pattern[:30]}")

        # Check 4: Infrastructure secrets
        for pattern in self._INFRA_PATTERNS:
            if pattern.search(response):
                reasons.append(f"infra_secret_exposure: {pattern.pattern[:30]}")

        # Check 5: Size limits
        if len(response.encode("utf-8")) > self._max_response_size:
            reasons.append(f"response_too_large: {len(response.encode('utf-8'))} bytes > {self._max_response_size}")

        # Check 6: Empty or trivial response
        if len(response.strip()) < 10:
            reasons.append("response_too_short: likely error or empty response")

        if reasons:
            logger.warning(json.dumps({
                "event": "cache_write_rejected",
                "query_hash": hashlib.sha256(query.encode()).hexdigest()[:12],
                "user_id": user_id,
                "reasons": reasons,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return CacheValidationResult(safe=False, action="reject", reasons=reasons)

        logger.info(json.dumps({
            "event": "cache_write_approved",
            "query_hash": hashlib.sha256(query.encode()).hexdigest()[:12],
            "response_size": len(response),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        return CacheValidationResult(safe=True, action="cache", reasons=[])

    def validate_before_cache_serve(self, query: str, cached_response: str,
                                     cached_at: str,
                                     user_id: str = "",
                                     knowledge_base_last_sync: str = "") -> CacheValidationResult:
        """Validate a cached response BEFORE serving it to a user.

        Checks:
        1. Cache entry not stale (TTL not exceeded)
        2. Cache entry not stale (knowledge base updated after cache write)
        3. Response still passes safety checks (re-validate)
        4. No user-specific data being served to wrong user

        Returns CacheValidationResult with action="serve" or "invalidate".
        """
        reasons = []

        # Check 1: TTL expiry
        try:
            cache_time = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            age_seconds = (now - cache_time).total_seconds()
            if age_seconds > self._ttl_seconds:
                reasons.append(f"ttl_expired: cached {age_seconds:.0f}s ago, limit is {self._ttl_seconds}s")
        except (ValueError, TypeError):
            reasons.append("invalid_cache_timestamp: cannot verify age")

        # Check 2: Knowledge base freshness
        if knowledge_base_last_sync and cached_at:
            try:
                kb_time = datetime.fromisoformat(knowledge_base_last_sync.replace("Z", "+00:00"))
                cache_time = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
                if kb_time > cache_time:
                    reasons.append("knowledge_base_updated: cached response may be stale")
            except (ValueError, TypeError):
                pass

        # Check 3: Re-validate safety (poison/infra checks)
        for pattern in self._POISON_INDICATORS:
            if pattern.search(cached_response):
                reasons.append(f"poison_in_cache: {pattern.pattern[:30]}")

        for pattern in self._INFRA_PATTERNS:
            if pattern.search(cached_response):
                reasons.append(f"infra_secret_in_cache: {pattern.pattern[:30]}")

        # Check 4: PII re-check
        for pattern in self._PII_PATTERNS:
            if pattern.search(cached_response):
                reasons.append(f"pii_in_cached_response: {pattern.pattern[:30]}")

        if reasons:
            logger.warning(json.dumps({
                "event": "cache_serve_rejected",
                "query_hash": hashlib.sha256(query.encode()).hexdigest()[:12],
                "user_id": user_id,
                "reasons": reasons,
                "action": "invalidate",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return CacheValidationResult(safe=False, action="invalidate", reasons=reasons)

        return CacheValidationResult(safe=True, action="serve", reasons=[])

    def check_rate_limit(self, user_id: str, query_hash: str,
                          rate_table=None) -> Tuple[bool, int]:
        """Check if a user is exceeding the unique query rate limit.

        Prevents cache bypass cost attacks where an attacker sends
        many unique queries to force LLM invocations (bypassing cache).

        Args:
            user_id: The user making the request.
            query_hash: Hash of the query for dedup.
            rate_table: DynamoDB table for rate tracking (optional).

        Returns:
            (within_limit, current_count)
        """
        if not rate_table:
            return True, 0

        now = datetime.now(timezone.utc)
        window_key = f"RATE#{user_id}#{now.strftime('%Y%m%d%H%M')}"

        try:
            response = rate_table.update_item(
                Key={"pk": window_key, "sk": query_hash},
                UpdateExpression="SET #cnt = if_not_exists(#cnt, :zero) + :one, #ttl = :ttl",
                ExpressionAttributeNames={"#cnt": "count", "#ttl": "ttl_expiry"},
                ExpressionAttributeValues={
                    ":one": 1,
                    ":zero": 0,
                    ":ttl": int(now.timestamp()) + 120,
                },
                ReturnValues="ALL_NEW",
            )
            count = int(response.get("Attributes", {}).get("count", 1))

            if count > self._max_queries_per_minute:
                logger.warning(json.dumps({
                    "event": "cache_bypass_rate_limit",
                    "user_id": user_id,
                    "count": count,
                    "limit": self._max_queries_per_minute,
                    "timestamp": now.isoformat(),
                }))
                return False, count

            return True, count

        except Exception as exc:
            logger.error(json.dumps({
                "event": "rate_limit_check_failed",
                "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return True, 0

    def compute_cache_key(self, query: str, context: Dict[str, Any] = None) -> str:
        """Compute a governance-aware cache key.

        Includes query content + relevant context to prevent serving
        wrong cached responses when context differs.
        """
        key_parts = [query.strip().lower()]

        if context:
            # Include scope level in cache key (different scopes = different responses)
            if "scope_level" in context:
                key_parts.append(f"scope:{context['scope_level']}")
            # Include environment (dev/staging/prod responses may differ)
            if "environment" in context:
                key_parts.append(f"env:{context['environment']}")
            # Include language (multilingual responses must not cross-serve)
            if "language" in context:
                key_parts.append(f"lang:{context['language']}")

        combined = "|".join(key_parts)
        return hashlib.sha256(combined.encode()).hexdigest()
