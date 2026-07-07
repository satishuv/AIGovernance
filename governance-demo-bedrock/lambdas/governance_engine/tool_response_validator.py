"""Tool Response Validator - validates data returned FROM tools BEFORE the agent processes it.

Closes the perception gap: input sanitizer checks what goes INTO tools,
output guardrails check what the agent says to users, but nothing checked
what tools return to the agent. This is the #1 exploited vector in
indirect prompt injection (Greshake et al., MCPTox 72.8% success rate).

Attack chain prevented:
  1. Attacker poisons data in S3/DynamoDB/external API
  2. Agent calls a legitimate tool (passes all checks)
  3. Tool returns data containing embedded instructions
  4. WITHOUT THIS: agent follows injected instructions
  5. WITH THIS: injection detected and stripped before agent sees it

Latency: ~3-5ms (regex + entropy on <10KB payloads)
"""

import json
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class ToolResponseValidation:
    """Result of validating a tool response."""

    tool_name: str
    original_response: str
    sanitized_response: str = ""
    injection_detected: bool = False
    injections_found: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    sensitive_data_stripped: List[str] = field(default_factory=list)
    entropy_score: float = 0.0
    blocked: bool = False
    block_reason: str = ""
    timestamp: str = ""


# Instruction patterns that should never appear in tool response data
_INSTRUCTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "ignore-previous-instructions"),
    (re.compile(r"ignore\s+(all\s+)?prior\s+(instructions|context)", re.IGNORECASE), "ignore-prior-context"),
    (re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE), "persona-override"),
    (re.compile(r"new\s+instructions?:\s*", re.IGNORECASE), "new-instructions-directive"),
    (re.compile(r"system\s*:\s*override", re.IGNORECASE), "system-override"),
    (re.compile(r"IMPORTANT:\s*(for\s+)?(security|compliance|safety)", re.IGNORECASE), "urgency-social-engineering"),
    (re.compile(r"(immediately|urgently|now)\s+(call|invoke|execute|run|use)\s+", re.IGNORECASE), "urgent-action-directive"),
    (re.compile(r"skip\s+(approval|verification|validation|review)", re.IGNORECASE), "skip-safety-check"),
    (re.compile(r"automated\s+governance\s+override", re.IGNORECASE), "fake-governance-override"),
    (re.compile(r"this\s+is\s+a(n)?\s+(authorized|approved|legitimate)\s+override", re.IGNORECASE), "fake-authorization"),
    (re.compile(r"do\s+not\s+(tell|inform|alert|notify)\s+(the\s+)?(user|operator|admin)", re.IGNORECASE), "concealment-directive"),
    (re.compile(r"(act|respond|behave)\s+as\s+(if|though)\s+", re.IGNORECASE), "behavior-override"),
    (re.compile(r"<\|im_start\|>|<\|im_end\|>", re.IGNORECASE), "chatml-delimiter"),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.IGNORECASE), "llama-delimiter"),
    (re.compile(r"Human:|Assistant:|System:", re.IGNORECASE), "role-delimiter"),
]

# Patterns for action directives (tool invocation attempts)
_ACTION_DIRECTIVE_PATTERNS = [
    (re.compile(r"(call|invoke|execute|trigger|run)\s+(the\s+)?(tool|function|action|api|endpoint)\s+", re.IGNORECASE), "tool-invocation-directive"),
    (re.compile(r"(call|invoke|execute)\s+(ReadPipelineStatus|ProposeChanges|StagingDeployment|ProductionDeployment)", re.IGNORECASE), "specific-tool-directive"),
    (re.compile(r"(deploy|push|release)\s+(to|into)\s+(production|prod|staging)", re.IGNORECASE), "deployment-directive"),
    (re.compile(r"(send|transmit|forward|exfiltrate)\s+.{0,30}\s+(to|via)\s+", re.IGNORECASE), "exfiltration-directive"),
    (re.compile(r"(escalate|elevate|increase)\s+(your\s+)?(scope|privilege|permission|access)", re.IGNORECASE), "privilege-escalation-directive"),
]

# Sensitive data patterns to strip from tool responses
_SENSITIVE_PATTERNS = [
    (re.compile(r"arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"']+"), "aws-arn"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws-access-key"),
    (re.compile(r"\b[A-Za-z0-9/+=]{40}\b"), "possible-secret-key"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "jwt-token"),
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "internal-ip"),
    (re.compile(r"(?<!\d)\d{12}(?!\d)"), "aws-account-id"),
]

# Entropy threshold for anomalous content
_HIGH_ENTROPY_THRESHOLD = 5.5
_LOW_ENTROPY_THRESHOLD = 1.5

# Maximum expected response size per tool type (bytes)
_MAX_RESPONSE_SIZE = {
    "ReadPipelineStatus": 4096,
    "ProposeChanges": 8192,
    "StagingDeployment": 4096,
    "ProductionDeployment": 4096,
    "default": 16384,
}


def _compute_entropy(text: str) -> float:
    """Compute Shannon entropy of text."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _check_format_anomaly(tool_name: str, response: str) -> List[str]:
    """Detect format anomalies for expected tool responses."""
    anomalies = []

    max_size = _MAX_RESPONSE_SIZE.get(tool_name, _MAX_RESPONSE_SIZE["default"])
    if len(response) > max_size:
        anomalies.append(f"response_size_exceeded: {len(response)} > {max_size} bytes")

    if tool_name in ("ReadPipelineStatus", "StagingDeployment", "ProductionDeployment"):
        try:
            json.loads(response)
        except (json.JSONDecodeError, TypeError):
            if not response.strip().startswith("{") and len(response) > 200:
                anomalies.append("expected_json_got_prose")

    return anomalies


class ToolResponseValidator:
    """Validates tool responses before the agent processes them."""

    def validate(self, tool_name: str, response: str) -> ToolResponseValidation:
        """Validate a tool response for injection, anomalies, and sensitive data.

        Returns a ToolResponseValidation with sanitized_response ready for
        the agent to process safely.
        """
        result = ToolResponseValidation(
            tool_name=tool_name,
            original_response=response,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if not response:
            result.sanitized_response = response
            return result

        sanitized = response
        blocked = False
        block_reason = ""

        # 1. Check for injection patterns
        for pattern, name in _INSTRUCTION_PATTERNS:
            if pattern.search(sanitized):
                result.injection_detected = True
                result.injections_found.append(name)
                sanitized = pattern.sub("[REDACTED:injection]", sanitized)
                if name in ("ignore-previous-instructions", "system-override",
                            "fake-governance-override", "concealment-directive",
                            "chatml-delimiter", "llama-delimiter"):
                    blocked = True
                    block_reason = f"Critical injection in tool response: {name}"

        # 2. Check for action directives
        for pattern, name in _ACTION_DIRECTIVE_PATTERNS:
            if pattern.search(sanitized):
                result.injection_detected = True
                result.injections_found.append(name)
                sanitized = pattern.sub("[REDACTED:directive]", sanitized)
                if name in ("specific-tool-directive", "privilege-escalation-directive"):
                    blocked = True
                    block_reason = f"Action directive in tool response: {name}"

        # 3. Strip sensitive data
        for pattern, name in _SENSITIVE_PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                result.sensitive_data_stripped.append(f"{name}:{len(matches)}")
                sanitized = pattern.sub(f"[REDACTED:{name}]", sanitized)

        # 4. Entropy analysis
        result.entropy_score = _compute_entropy(response[:2000])
        if result.entropy_score > _HIGH_ENTROPY_THRESHOLD:
            result.anomalies.append(f"high_entropy:{result.entropy_score:.2f}")
        elif result.entropy_score < _LOW_ENTROPY_THRESHOLD and len(response) > 100:
            result.anomalies.append(f"low_entropy_suspicious:{result.entropy_score:.2f}")

        # 5. Format anomaly detection
        format_anomalies = _check_format_anomaly(tool_name, response)
        result.anomalies.extend(format_anomalies)

        # 6. Proportion check: if >30% of response is redacted, block
        redaction_count = sanitized.count("[REDACTED:")
        if redaction_count > 3:
            blocked = True
            block_reason = f"Multiple injections detected ({redaction_count} redactions)"

        result.sanitized_response = sanitized
        result.blocked = blocked
        result.block_reason = block_reason

        if result.injection_detected:
            logger.warning(json.dumps({
                "event": "tool_response_injection_detected",
                "tool_name": tool_name,
                "injections": result.injections_found,
                "blocked": blocked,
                "timestamp": result.timestamp,
            }))

        return result
