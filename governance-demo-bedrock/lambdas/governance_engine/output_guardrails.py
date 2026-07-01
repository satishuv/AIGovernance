"""Output Guardrails module for the AI Governance Engine.

Validates agent responses BEFORE they reach the user, catching system prompt
leakage, internal path exposure, sensitive data patterns, canary token leakage,
and instruction echo attacks. Any violation causes the output to be redacted
and marked invalid.

Requirements: Output validation, response sanitization, canary detection.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Leakage indicator phrases that suggest system prompt disclosure
LEAKAGE_INDICATORS = [
    "My instructions are",
    "I was told to",
    "My system prompt",
    "As an AI assistant, I was configured to",
]

# AWS ARN pattern
ARN_PATTERN = re.compile(r"arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"']+")

# DynamoDB table name pattern (Stack-TableName-RandomChars)
DYNAMO_TABLE_PATTERN = re.compile(r"[A-Z][a-zA-Z0-9]+-[A-Z][a-zA-Z0-9]+-[A-Za-z0-9]{10,14}")

# S3 bucket path patterns
S3_URI_PATTERN = re.compile(r"s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](/[^\s]*)?")
S3_BUCKET_STACK_PATTERN = re.compile(
    r"[a-z][a-z0-9\-]*stack[a-z0-9\-]*-[a-z0-9\-]+-[a-z0-9]{8,14}"
)

# Internal IP patterns (RFC 1918)
INTERNAL_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# Lambda function name pattern (Stack-FunctionName-RandomChars)
LAMBDA_FUNCTION_PATTERN = re.compile(
    r"[A-Z][a-zA-Z0-9]+-[A-Z][a-zA-Z0-9]+Function[a-zA-Z0-9]*-[A-Za-z0-9]{10,14}"
)

# AWS account ID (12-digit number, not part of a longer number)
ACCOUNT_ID_PATTERN = re.compile(r"(?<!\d)\d{12}(?!\d)")

# AWS access key pattern (starts with AKIA)
AWS_ACCESS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# AWS secret key pattern (40-char base64-like string)
AWS_SECRET_KEY_PATTERN = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")

# Generic API key/token/secret labels followed by long alphanumeric values
GENERIC_SECRET_PATTERN = re.compile(
    r"(?:api[_\-]?key|token|secret|password|credential)[\s:=]+['\"]?"
    r"([A-Za-z0-9\-_/+=]{20,})",
    re.IGNORECASE,
)

# JWT token pattern
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b")

# Private key block pattern
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----"
)


@dataclass
class OutputValidationResult:
    """Result of output guardrail validation.

    Attributes:
        valid: True if output is safe to return to user.
        response_text: Original response text from the agent.
        redacted_text: Cleaned response with sensitive parts replaced by [REDACTED].
        violations: List of violation descriptions found during validation.
        system_prompt_leaked: True if system prompt content was detected in output.
        internal_paths_exposed: True if internal infrastructure details were detected.
        sensitive_data_found: True if credentials or secrets were detected.
        canary_leaked: True if a canary token was found in output.
        canary_token: The canary token that was leaked (empty string if none).
        instruction_echo: True if response is echoing back user input.
        timestamp: ISO 8601 timestamp of the validation.
    """

    valid: bool
    response_text: str
    redacted_text: str
    violations: List[str] = field(default_factory=list)
    system_prompt_leaked: bool = False
    internal_paths_exposed: bool = False
    sensitive_data_found: bool = False
    canary_leaked: bool = False
    canary_token: str = ""
    instruction_echo: bool = False
    timestamp: str = ""

    def to_dict(self):
        return {
            "valid": self.valid,
            "response_text": self.response_text,
            "redacted_text": self.redacted_text,
            "violations": list(self.violations),
            "system_prompt_leaked": self.system_prompt_leaked,
            "internal_paths_exposed": self.internal_paths_exposed,
            "sensitive_data_found": self.sensitive_data_found,
            "canary_leaked": self.canary_leaked,
            "canary_token": self.canary_token,
            "instruction_echo": self.instruction_echo,
            "timestamp": self.timestamp,
        }


class OutputGuardrails:
    """Validates agent responses before they reach the user.

    Runs a series of checks to detect system prompt leakage, internal
    infrastructure exposure, sensitive data patterns, canary token leakage,
    and instruction echo attacks. Produces a redacted version of the response
    with sensitive content replaced.
    """

    def validate_output(
        self,
        response_text: str,
        agent_instruction: str,
        agent_id: str,
        canary_tokens: List[str] = None,
    ) -> OutputValidationResult:
        """Main entry point. Runs all output guardrail checks.

        Args:
            response_text: The agent's response text to validate.
            agent_instruction: The agent's system instruction (to check for leakage).
            agent_id: Identifier of the agent that produced the response.
            canary_tokens: Optional list of canary tokens injected into agent context.

        Returns:
            OutputValidationResult with validation outcome and redacted text.
        """
        canary_tokens = canary_tokens or []
        now = datetime.now(timezone.utc).isoformat()
        violations: List[str] = []
        redacted = response_text

        # 1. Check system prompt leakage
        prompt_leaked, prompt_detail = self._detect_system_prompt_leakage(
            response_text, agent_instruction
        )
        if prompt_leaked:
            violations.append(f"System prompt leakage: {prompt_detail}")

        # 2. Check internal path exposure
        paths_exposed, exposures = self._detect_internal_path_exposure(response_text)
        if paths_exposed:
            violations.append(
                f"Internal path exposure: {len(exposures)} item(s) detected"
            )
            for exposure in exposures:
                redacted = redacted.replace(exposure, "[REDACTED]")

        # 3. Check sensitive data patterns
        sensitive_found, patterns = self._detect_sensitive_data_patterns(response_text)
        if sensitive_found:
            violations.append(
                f"Sensitive data detected: {len(patterns)} pattern(s) found"
            )
            for pattern in patterns:
                redacted = redacted.replace(pattern, "[REDACTED]")

        # 4. Check canary leakage
        canary_detected, leaked_canary = self._detect_canary_leakage(
            response_text, canary_tokens
        )
        if canary_detected:
            violations.append(f"Canary token leaked: {leaked_canary}")
            redacted = redacted.replace(leaked_canary, "[REDACTED]")

        # 5. Check instruction echo
        echo_detected = self._detect_instruction_echo(response_text, "")
        # Note: instruction echo check uses empty input_text here; callers can
        # extend to pass the original user input if available.

        # Build result
        is_valid = len(violations) == 0 and not echo_detected

        result = OutputValidationResult(
            valid=is_valid,
            response_text=response_text,
            redacted_text=redacted,
            violations=violations,
            system_prompt_leaked=prompt_leaked,
            internal_paths_exposed=paths_exposed,
            sensitive_data_found=sensitive_found,
            canary_leaked=canary_detected,
            canary_token=leaked_canary,
            instruction_echo=echo_detected,
            timestamp=now,
        )

        # Structured logging
        log_entry = {
            "event": "output_guardrail_validation",
            "agent_id": agent_id,
            "valid": is_valid,
            "violations_count": len(violations),
            "system_prompt_leaked": prompt_leaked,
            "internal_paths_exposed": paths_exposed,
            "sensitive_data_found": sensitive_found,
            "canary_leaked": canary_detected,
            "instruction_echo": echo_detected,
            "timestamp": now,
        }

        if canary_detected:
            log_entry["severity"] = "CRITICAL"
            log_entry["detail"] = (
                "Agent is compromised: canary token appeared in output"
            )
            log_entry["canary_token"] = leaked_canary
            logger.critical(json.dumps(log_entry))
        elif not is_valid:
            log_entry["severity"] = "HIGH"
            log_entry["violations"] = violations
            logger.warning(json.dumps(log_entry))
        else:
            log_entry["severity"] = "INFO"
            logger.info(json.dumps(log_entry))

        return result

    def _detect_system_prompt_leakage(
        self, response_text: str, agent_instruction: str
    ) -> Tuple[bool, str]:
        """Check if the response contains fragments of the agent's system instruction.

        Splits the instruction into 3+ word phrases and checks if any appear
        verbatim in the response. Also checks for common leakage indicator phrases.

        Args:
            response_text: The agent's response to check.
            agent_instruction: The agent's system instruction text.

        Returns:
            Tuple of (leaked: bool, detail: str describing the leak).
        """
        response_lower = response_text.lower()

        # Check common leakage indicator phrases
        for indicator in LEAKAGE_INDICATORS:
            if indicator.lower() in response_lower:
                return (True, f"Leakage indicator found: '{indicator}'")

        # Split instruction into phrases of 3+ consecutive words and check
        if not agent_instruction or not agent_instruction.strip():
            return (False, "")

        words = agent_instruction.split()
        # Generate phrases of length 3 to 6 words
        min_phrase_len = 3
        max_phrase_len = min(6, len(words))

        for phrase_len in range(max_phrase_len, min_phrase_len - 1, -1):
            for i in range(len(words) - phrase_len + 1):
                phrase = " ".join(words[i : i + phrase_len])
                # Skip very short or generic phrases
                if len(phrase) < 12:
                    continue
                if phrase.lower() in response_lower:
                    return (True, f"Instruction fragment found: '{phrase}'")

        return (False, "")

    def _detect_internal_path_exposure(
        self, response_text: str
    ) -> Tuple[bool, List[str]]:
        """Detect leaked internal infrastructure details in the response.

        Checks for:
        - AWS ARNs (arn:aws:...)
        - DynamoDB table names (Stack-TableName-RandomChars)
        - S3 bucket paths (s3://..., bucket names with stack prefixes)
        - Internal IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
        - Lambda function names (Stack-FunctionName-RandomChars)
        - Account IDs (12-digit numbers)

        Args:
            response_text: The agent's response to check.

        Returns:
            Tuple of (exposed: bool, list of exposure strings found).
        """
        exposures: List[str] = []

        # AWS ARNs
        for match in ARN_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # DynamoDB table names
        for match in DYNAMO_TABLE_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # S3 URIs
        for match in S3_URI_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # S3 bucket names with stack prefixes
        for match in S3_BUCKET_STACK_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # Internal IPs
        for match in INTERNAL_IP_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # Lambda function names
        for match in LAMBDA_FUNCTION_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # Account IDs (12-digit numbers)
        for match in ACCOUNT_ID_PATTERN.finditer(response_text):
            exposures.append(match.group())

        # Deduplicate while preserving order
        seen = set()
        unique_exposures: List[str] = []
        for item in exposures:
            if item not in seen:
                seen.add(item)
                unique_exposures.append(item)

        return (len(unique_exposures) > 0, unique_exposures)

    def _detect_sensitive_data_patterns(
        self, response_text: str
    ) -> Tuple[bool, List[str]]:
        """Detect leaked credentials and secrets in the response.

        Checks for:
        - AWS access keys (AKIA...)
        - AWS secret keys (40-char base64)
        - Generic API keys/tokens (long alphanumeric strings labeled as key/token/secret)
        - JWT tokens (eyJ...)
        - Private keys (BEGIN RSA/EC/PRIVATE KEY)

        Args:
            response_text: The agent's response to check.

        Returns:
            Tuple of (found: bool, list of matched sensitive strings).
        """
        findings: List[str] = []

        # AWS access keys
        for match in AWS_ACCESS_KEY_PATTERN.finditer(response_text):
            findings.append(match.group())

        # AWS secret keys (only flag if near a label like "secret" or "key")
        for match in AWS_SECRET_KEY_PATTERN.finditer(response_text):
            start = max(0, match.start() - 30)
            context = response_text[start : match.start()].lower()
            if any(kw in context for kw in ("secret", "key", "credential", "password")):
                findings.append(match.group())

        # Generic API key/token/secret patterns
        for match in GENERIC_SECRET_PATTERN.finditer(response_text):
            findings.append(match.group(1))

        # JWT tokens
        for match in JWT_PATTERN.finditer(response_text):
            findings.append(match.group())

        # Private key blocks
        for match in PRIVATE_KEY_PATTERN.finditer(response_text):
            # Include the full key block up to END marker if present
            end_marker = "-----END"
            end_idx = response_text.find(end_marker, match.start())
            if end_idx != -1:
                # Find the end of the END line
                line_end = response_text.find("-----", end_idx + len(end_marker))
                if line_end != -1:
                    findings.append(response_text[match.start() : line_end + 5])
                else:
                    findings.append(response_text[match.start() : end_idx + 50])
            else:
                findings.append(match.group())

        # Deduplicate while preserving order
        seen = set()
        unique_findings: List[str] = []
        for item in findings:
            if item not in seen:
                seen.add(item)
                unique_findings.append(item)

        return (len(unique_findings) > 0, unique_findings)

    def _detect_canary_leakage(
        self, response_text: str, canary_tokens: List[str]
    ) -> Tuple[bool, str]:
        """Check if any canary tokens appear in the agent's output.

        Canary tokens are secret strings injected into agent context. If any
        appear in the output, the agent has been compromised (it is revealing
        internal context that should never be exposed to users).

        Args:
            response_text: The agent's response to check.
            canary_tokens: List of canary token strings to search for.

        Returns:
            Tuple of (leaked: bool, which_canary: str). Empty string if no leak.
        """
        if not canary_tokens:
            return (False, "")

        for canary in canary_tokens:
            if not canary:
                continue
            if canary in response_text:
                return (True, canary)

        return (False, "")

    def _detect_instruction_echo(self, response_text: str, input_text: str) -> bool:
        """Check if response is just echoing back the user's input.

        A sign of prompt reflection attack where the agent parrots user input
        instead of processing it normally. Returns True if >80% of input words
        appear in the response in the same order.

        Args:
            response_text: The agent's response to check.
            input_text: The user's original input text.

        Returns:
            True if the response appears to be echoing the input.
        """
        if not input_text or not input_text.strip():
            return False

        input_words = input_text.lower().split()
        if len(input_words) < 3:
            # Too short to meaningfully detect echo
            return False

        response_lower = response_text.lower()
        response_words = response_lower.split()

        if not response_words:
            return False

        # Check ordered presence: how many input words appear in sequence in response
        matched = 0
        response_idx = 0
        for word in input_words:
            for j in range(response_idx, len(response_words)):
                if response_words[j] == word:
                    matched += 1
                    response_idx = j + 1
                    break

        ratio = matched / len(input_words)
        return ratio > 0.8
