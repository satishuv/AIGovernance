"""Retrieval Content Validator - scans data sources for indirect prompt injection.

Validates content retrieved from knowledge bases, S3 documents, databases,
and external APIs BEFORE it enters the agent's context window. Prevents
indirect prompt injection attacks where malicious instructions are planted
in data sources the agent reads.

Attack scenario:
    Attacker inserts "ignore previous instructions" into a wiki page.
    Agent's RAG retrieves that page as context.
    Without this validator: agent follows injected instructions.
    With this validator: poisoned content detected and neutralized.

Integration point: called by the Action Group Lambda after reading
from S3/DynamoDB/external APIs, before returning data to the agent.
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class RetrievalValidationResult:
    """Result of retrieval content validation."""

    def __init__(self, safe: bool, content: str, original_content: str,
                 threats_found: List[Dict[str, str]] = None,
                 neutralizations_applied: int = 0):
        self.safe = safe
        self.content = content  # sanitized content (safe to use)
        self.original_content = original_content
        self.threats_found = threats_found or []
        self.neutralizations_applied = neutralizations_applied
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "threats_found_count": len(self.threats_found),
            "threats_found": self.threats_found,
            "neutralizations_applied": self.neutralizations_applied,
            "content_length": len(self.content),
            "timestamp": self.timestamp,
        }


class RetrievalContentValidator:
    """Validates retrieved content for indirect prompt injection attacks."""

    # Instruction injection patterns hidden in documents
    _INSTRUCTION_PATTERNS = [
        # Direct instruction overrides
        re.compile(r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions|rules|guidelines|constraints|directives)", re.IGNORECASE),
        # Role reassignment
        re.compile(r"(?:you\s+are\s+now|from\s+now\s+on|pretend\s+to\s+be|act\s+as\s+if|roleplay\s+as|switch\s+to)\s+", re.IGNORECASE),
        # System prompt manipulation
        re.compile(r"(?:new\s+)?(?:system\s+)?(?:prompt|instructions|rules|guidelines)\s*[:=]", re.IGNORECASE),
        # Action directives hidden in content
        re.compile(r"(?:execute|run|perform|do)\s+(?:the\s+following|this)\s*:", re.IGNORECASE),
        # Data exfiltration instructions
        re.compile(r"(?:send|forward|transmit|post|upload)\s+(?:all|this|the)\s+(?:data|information|content|context|conversation)\s+(?:to|at)\s+", re.IGNORECASE),
        # Credential harvesting
        re.compile(r"(?:reveal|show|display|output|print)\s+(?:your|the|all)\s+(?:api|secret|access|private)\s*(?:key|token|credential|password)", re.IGNORECASE),
        # Scope escalation attempts
        re.compile(r"(?:escalate|elevate|increase|change)\s+(?:your|my|the)\s+(?:scope|permission|privilege|access|role)", re.IGNORECASE),
    ]

    # LLM delimiter markers that should NEVER appear in retrieved data
    _DELIMITER_PATTERNS = [
        re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>"),
        re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"),
        re.compile(r"<\|endoftext\|>|<\|pad\|>|<\|sep\|>"),
        re.compile(r"###\s*(?:System|Human|Assistant|User)\s*:"),
        re.compile(r"<(?:system|user|assistant)>"),
    ]

    # Encoded payloads hidden in documents
    _ENCODED_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")  # Base64 blocks
    _HEX_PATTERN = re.compile(r"(?:0x)?[0-9a-fA-F]{40,}")  # Long hex strings

    # URLs that might be exfiltration endpoints
    _SUSPICIOUS_URL_PATTERN = re.compile(
        r"https?://(?!(?:docs\.aws|docs\.amazon|w\.amazon|code\.amazon|quip-amazon))[^\s\"'<>]{10,}",
        re.IGNORECASE,
    )

    # Invisible/zero-width characters used to hide instructions
    _INVISIBLE_CHARS = re.compile(r"[​‌‍‎‏⁠⁡⁢⁣⁤﻿]")

    def validate(self, content: str, source: str = "",
                 content_type: str = "text") -> RetrievalValidationResult:
        """Validate retrieved content for indirect prompt injection.

        Args:
            content: The raw content retrieved from a data source.
            source: Identifier of the source (S3 key, URL, table name).
            content_type: Type of content (text, html, markdown, json).

        Returns:
            RetrievalValidationResult with sanitized content and threat details.
        """
        if not content:
            return RetrievalValidationResult(
                safe=True, content="", original_content="",
                threats_found=[], neutralizations_applied=0,
            )

        threats = []
        sanitized = content
        neutralizations = 0

        # Check 1: Instruction injection patterns
        for pattern in self._INSTRUCTION_PATTERNS:
            matches = pattern.finditer(content)
            for match in matches:
                threats.append({
                    "type": "instruction_injection",
                    "pattern": pattern.pattern[:50],
                    "match": match.group()[:80],
                    "position": match.start(),
                })
                sanitized = sanitized[:match.start()] + "[CONTENT REMOVED - INJECTION DETECTED]" + sanitized[match.end():]
                neutralizations += 1

        # Check 2: LLM delimiters in retrieved content
        for pattern in self._DELIMITER_PATTERNS:
            matches = pattern.finditer(sanitized)
            for match in matches:
                threats.append({
                    "type": "delimiter_injection",
                    "pattern": pattern.pattern[:50],
                    "match": match.group()[:40],
                    "position": match.start(),
                })
                sanitized = pattern.sub("[DELIMITER REMOVED]", sanitized)
                neutralizations += 1

        # Check 3: Invisible characters (used to hide instructions)
        invisible_matches = self._INVISIBLE_CHARS.findall(sanitized)
        if invisible_matches:
            threats.append({
                "type": "invisible_characters",
                "count": len(invisible_matches),
                "detail": "Zero-width characters detected (may hide instructions)",
            })
            sanitized = self._INVISIBLE_CHARS.sub("", sanitized)
            neutralizations += 1

        # Check 4: Suspicious encoded payloads (base64 blocks > 40 chars)
        base64_matches = self._ENCODED_PATTERN.finditer(sanitized)
        for match in base64_matches:
            block = match.group()
            # Try to decode and check if it contains injection
            try:
                import base64
                decoded = base64.b64decode(block + "==").decode("utf-8", errors="ignore")
                for inj_pattern in self._INSTRUCTION_PATTERNS[:3]:
                    if inj_pattern.search(decoded):
                        threats.append({
                            "type": "encoded_injection",
                            "encoding": "base64",
                            "decoded_match": decoded[:80],
                            "position": match.start(),
                        })
                        sanitized = sanitized.replace(block, "[ENCODED INJECTION REMOVED]")
                        neutralizations += 1
                        break
            except Exception:
                pass

        # Check 5: Suspicious external URLs (potential exfiltration endpoints)
        url_matches = self._SUSPICIOUS_URL_PATTERN.finditer(sanitized)
        suspicious_urls = []
        for match in url_matches:
            suspicious_urls.append(match.group())
        if suspicious_urls:
            threats.append({
                "type": "suspicious_urls",
                "urls": suspicious_urls[:5],
                "detail": "External URLs in retrieved content (potential exfiltration targets)",
            })

        # Determine overall safety
        is_safe = len(threats) == 0

        if threats:
            logger.warning(json.dumps({
                "event": "retrieval_content_threat_detected",
                "source": source,
                "content_type": content_type,
                "threat_count": len(threats),
                "threats": [t["type"] for t in threats],
                "neutralizations": neutralizations,
                "content_hash": hashlib.sha256(content.encode()).hexdigest()[:12],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
        else:
            logger.info(json.dumps({
                "event": "retrieval_content_validated",
                "source": source,
                "content_length": len(content),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        return RetrievalValidationResult(
            safe=is_safe,
            content=sanitized,
            original_content=content,
            threats_found=threats,
            neutralizations_applied=neutralizations,
        )

    def validate_batch(self, documents: List[Dict[str, str]]) -> List[RetrievalValidationResult]:
        """Validate a batch of retrieved documents.

        Args:
            documents: List of dicts with 'content' and optional 'source' keys.

        Returns:
            List of RetrievalValidationResult, one per document.
        """
        results = []
        for doc in documents:
            result = self.validate(
                content=doc.get("content", ""),
                source=doc.get("source", ""),
                content_type=doc.get("content_type", "text"),
            )
            results.append(result)
        return results
