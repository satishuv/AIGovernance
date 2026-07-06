"""Bedrock Guardrails Integration - AWS-native content safety evaluation.

Calls the Amazon Bedrock Guardrails ApplyGuardrail API to evaluate inputs
and outputs for content safety violations. This catches semantic attacks
(harmful content requests, persona jailbreaks) that regex-based detection
cannot identify.

Works independently from model invocation quotas. The ApplyGuardrail API
is a separate content classification service.

Integration points:
- Input validation: called after input_sanitizer (catches what regex misses)
- Output validation: called before returning response to user

Environment variables:
    BEDROCK_GUARDRAIL_ID: The guardrail identifier (e.g., 'v7p76l8t3ix9')
    BEDROCK_GUARDRAIL_VERSION: Version to use ('DRAFT' or version number)
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

BEDROCK_GUARDRAIL_ID = os.environ.get("BEDROCK_GUARDRAIL_ID", "")
BEDROCK_GUARDRAIL_VERSION = os.environ.get("BEDROCK_GUARDRAIL_VERSION", "DRAFT")


class GuardrailResult:
    """Result of a Bedrock Guardrail evaluation."""

    def __init__(self, blocked: bool, action: str, violations: List[Dict[str, Any]] = None,
                 explanation: str = ""):
        self.blocked = blocked
        self.action = action  # "GUARDRAIL_INTERVENED" or "NONE"
        self.violations = violations or []
        self.explanation = explanation
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked": self.blocked,
            "action": self.action,
            "violations": self.violations,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


class BedrockGuardrailsEvaluator:
    """Evaluates content using Amazon Bedrock Guardrails."""

    def __init__(self, guardrail_id: str = None, version: str = None):
        self._guardrail_id = guardrail_id or BEDROCK_GUARDRAIL_ID
        self._version = version or BEDROCK_GUARDRAIL_VERSION
        self._client = None

    def _get_client(self):
        if not self._client:
            import boto3
            self._client = boto3.client("bedrock-runtime")
        return self._client

    def evaluate_input(self, text: str) -> GuardrailResult:
        """Evaluate input text against Bedrock Guardrail.

        Checks for: harmful content, prompt attacks, jailbreak attempts,
        PII, and denied topics.
        """
        return self._evaluate(text, source="INPUT")

    def evaluate_output(self, text: str) -> GuardrailResult:
        """Evaluate output text against Bedrock Guardrail.

        Checks for: harmful content generation, PII leakage, and
        content policy violations in agent responses.
        """
        return self._evaluate(text, source="OUTPUT")

    def _evaluate(self, text: str, source: str) -> GuardrailResult:
        """Call ApplyGuardrail API."""
        if not self._guardrail_id:
            return GuardrailResult(
                blocked=False, action="NONE",
                explanation="Guardrail not configured (BEDROCK_GUARDRAIL_ID not set)",
            )

        if not text or len(text.strip()) == 0:
            return GuardrailResult(blocked=False, action="NONE", explanation="Empty input")

        try:
            client = self._get_client()
            response = client.apply_guardrail(
                guardrailIdentifier=self._guardrail_id,
                guardrailVersion=self._version,
                source=source,
                content=[{"text": {"text": text[:10000]}}],
            )

            action = response.get("action", "NONE")
            blocked = action == "GUARDRAIL_INTERVENED"

            violations = []
            for assessment in response.get("assessments", []):
                for policy_type, details in assessment.items():
                    if isinstance(details, dict):
                        for category, items in details.items():
                            if isinstance(items, list):
                                for item in items:
                                    if isinstance(item, dict) and item.get("action") == "BLOCKED":
                                        violations.append({
                                            "policy": policy_type,
                                            "type": item.get("type", category),
                                            "confidence": item.get("confidence", ""),
                                        })

            explanation = ""
            if blocked:
                violation_types = [v.get("type", "") for v in violations[:3]]
                explanation = f"Blocked by Bedrock Guardrail: {', '.join(violation_types)}"
                logger.warning(json.dumps({
                    "event": "bedrock_guardrail_blocked",
                    "source": source,
                    "action": action,
                    "violations": violations,
                    "text_preview": text[:100],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))

            return GuardrailResult(
                blocked=blocked,
                action=action,
                violations=violations,
                explanation=explanation,
            )

        except Exception as exc:
            logger.error(json.dumps({
                "event": "bedrock_guardrail_error",
                "source": source,
                "error": str(exc)[:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            # Fail-open for guardrail (other layers still enforce)
            return GuardrailResult(
                blocked=False, action="ERROR",
                explanation=f"Guardrail evaluation failed: {str(exc)[:50]}",
            )

    @property
    def configured(self) -> bool:
        """Whether a guardrail ID is configured."""
        return bool(self._guardrail_id)
