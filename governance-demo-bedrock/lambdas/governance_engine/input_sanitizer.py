"""Phase 4 - Advanced Input Sanitization for AI Governance Engine.

Validates and sanitizes agent inputs BEFORE regex-based threat detection runs.
Catches encoding-based evasions, delimiter injection, context stuffing, and
obfuscated instruction patterns that simple regex patterns cannot detect.

This module runs as the first line of defense in the governance pipeline,
normalizing inputs so that downstream components (ThreatDetector, PolicyEngine)
operate on clean, canonical text representations.
"""

import base64
import json
import logging
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SanitizationResult:
    """Result of input sanitization containing detections and normalized text.

    Attributes:
        original_text: The unmodified input text.
        sanitized_text: Unicode-normalized text with homoglyphs replaced.
        decoded_payloads: Any decoded base64, hex, or URL-encoded content found.
        threats_detected: List of human-readable threat descriptions.
        delimiter_injections: Detected LLM delimiter markers.
        context_stuffing: True if input exceeds maximum length threshold.
        instruction_patterns: Detected obfuscated instruction patterns.
        blocked: True if any critical threat was found.
        block_reason: Human-readable reason if blocked.
        timestamp: ISO 8601 timestamp of the sanitization.
    """

    original_text: str
    sanitized_text: str = ""
    decoded_payloads: List[str] = field(default_factory=list)
    threats_detected: List[str] = field(default_factory=list)
    delimiter_injections: List[str] = field(default_factory=list)
    context_stuffing: bool = False
    instruction_patterns: List[str] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    timestamp: str = ""


# Homoglyph mapping: visually similar characters to their ASCII equivalents
_HOMOGLYPH_MAP = {
    "А": "A",  # Cyrillic A
    "В": "B",  # Cyrillic Ve
    "С": "C",  # Cyrillic Es
    "Е": "E",  # Cyrillic Ie
    "Н": "H",  # Cyrillic En
    "К": "K",  # Cyrillic Ka
    "М": "M",  # Cyrillic Em
    "О": "O",  # Cyrillic O
    "Р": "P",  # Cyrillic Er
    "Т": "T",  # Cyrillic Te
    "Х": "X",  # Cyrillic Kha
    "а": "a",  # Cyrillic a
    "е": "e",  # Cyrillic ie
    "о": "o",  # Cyrillic o
    "р": "p",  # Cyrillic er
    "с": "c",  # Cyrillic es
    "у": "y",  # Cyrillic u
    "х": "x",  # Cyrillic kha
    "і": "i",  # Cyrillic Byelorussian-Ukrainian i
    "０": "0",  # Fullwidth 0
    "１": "1",  # Fullwidth 1
    "２": "2",  # Fullwidth 2
    "３": "3",  # Fullwidth 3
    "４": "4",  # Fullwidth 4
    "５": "5",  # Fullwidth 5
    "６": "6",  # Fullwidth 6
    "７": "7",  # Fullwidth 7
    "８": "8",  # Fullwidth 8
    "９": "9",  # Fullwidth 9
    "⁰": "0",  # Superscript 0
    "¹": "1",  # Superscript 1
    "²": "2",  # Superscript 2
    "³": "3",  # Superscript 3
    "⁴": "4",  # Superscript 4
    "⁵": "5",  # Superscript 5
    "⁶": "6",  # Superscript 6
    "⁷": "7",  # Superscript 7
    "⁸": "8",  # Superscript 8
    "⁹": "9",  # Superscript 9
    "Ａ": "A",  # Fullwidth A
    "Ｂ": "B",  # Fullwidth B
    "Ｃ": "C",  # Fullwidth C
    "Ｄ": "D",  # Fullwidth D
    "Ｅ": "E",  # Fullwidth E
    "Ｆ": "F",  # Fullwidth F
    "Ｇ": "G",  # Fullwidth G
    "Ｈ": "H",  # Fullwidth H
    "Ｉ": "I",  # Fullwidth I
    "Ｊ": "J",  # Fullwidth J
    "Ｋ": "K",  # Fullwidth K
    "Ｌ": "L",  # Fullwidth L
    "Ｍ": "M",  # Fullwidth M
    "Ｎ": "N",  # Fullwidth N
    "Ｏ": "O",  # Fullwidth O
    "Ｐ": "P",  # Fullwidth P
    "Ｑ": "Q",  # Fullwidth Q
    "Ｒ": "R",  # Fullwidth R
    "Ｓ": "S",  # Fullwidth S
    "Ｔ": "T",  # Fullwidth T
    "Ｕ": "U",  # Fullwidth U
    "Ｖ": "V",  # Fullwidth V
    "Ｗ": "W",  # Fullwidth W
    "Ｘ": "X",  # Fullwidth X
    "Ｙ": "Y",  # Fullwidth Y
    "Ｚ": "Z",  # Fullwidth Z
    "@": "@",  # At sign (kept for leet-speak mapping below)
    "ǃ": "!",  # Latin letter retroflex click
}

# Leet-speak / substitution mapping for instruction detection
_LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
}

# ChatML delimiters
_CHATML_DELIMITERS = [
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
]

# Llama delimiters
_LLAMA_DELIMITERS = [
    "[INST]",
    "[/INST]",
    "<<SYS>>",
    "<</SYS>>",
]

# Generic model delimiters
_GENERIC_DELIMITERS = [
    "<s>",
    "</s>",
    "<|endoftext|>",
    "<|pad|>",
]

# System role markers
_SYSTEM_MARKERS = [
    "### System:",
    "### Human:",
    "### Assistant:",
]

# All delimiters combined for detection
_ALL_DELIMITERS = (
    _CHATML_DELIMITERS + _LLAMA_DELIMITERS + _GENERIC_DELIMITERS + _SYSTEM_MARKERS
)

# Instruction override pattern components (word groups)
_OVERRIDE_VERBS = {"ignore", "disregard", "forget", "override", "skip", "bypass",
                   "circumvent", "disable", "deactivate", "suppress", "remove"}
_OVERRIDE_TARGETS = {"previous", "above", "prior", "original", "earlier", "initial",
                     "all", "any", "your", "safety", "ethical", "content"}
_OVERRIDE_OBJECTS = {
    "instructions", "rules", "context", "guidelines", "constraints",
    "directives", "prompt", "system", "guardrails", "policies",
    "filters", "restrictions", "limitations", "safeguards", "moderation",
}

# Jailbreak persona/roleplay patterns
_JAILBREAK_PATTERNS = [
    re.compile(r"(?:pretend|act|behave|respond)\s+(?:to be|as if|as|like)\s+(?:you are|you're|a)", re.IGNORECASE),
    re.compile(r"(?:you are|you're)\s+(?:now|going to be|no longer)\s+", re.IGNORECASE),
    re.compile(r"(?:DAN|STAN|DUDE|KEVIN|MONGO|EVIL)\s*(?:mode|prompt)?", re.IGNORECASE),
    re.compile(r"(?:developer|admin|god|sudo|root|unrestricted|unfiltered)\s*mode", re.IGNORECASE),
    re.compile(r"(?:no|without|remove all|ignore all)\s+(?:restrictions|limits|filters|rules|guidelines|censorship|moderation)", re.IGNORECASE),
    re.compile(r"(?:always|must|will)\s+(?:answer|respond|comply|obey|do)\s+(?:any|every|all)", re.IGNORECASE),
    re.compile(r"(?:never|don'?t|do not|cannot)\s+(?:refuse|decline|reject|apologize|say no)", re.IGNORECASE),
    re.compile(r"(?:jailbreak|jailbroken|unlock|unleash|liberate)", re.IGNORECASE),
    re.compile(r"respond to every prompt .{0,30} without (?:refus|declin|reject)", re.IGNORECASE),
    re.compile(r"(?:from now on|henceforth|going forward).{0,40}(?:without|no).{0,20}(?:limit|restrict|filter|censor)", re.IGNORECASE),
]

# Multilingual instruction override patterns
_MULTILINGUAL_OVERRIDE_PATTERNS = [
    # German (expanded)
    re.compile(r"(?:vergiss|ignorier|vergessen)\s+(?:alles|alle|bisherige|vorherige)", re.IGNORECASE),
    re.compile(r"(?:neue|folgende)\s+(?:aufgabe|anweisung|instruktion)", re.IGNORECASE),
    re.compile(r"(?:stopp|achtung|abweichend).{0,20}(?:instruktion|aufgabe|anweisung)", re.IGNORECASE),
    re.compile(r"(?:obigen?|bisherigen?|vorherigen?)\s+(?:ausf.hrungen|anweisungen|instruktionen)\s+ignorier", re.IGNORECASE),
    re.compile(r"(?:lassen\s+sie|lass)\s+(?:alle|alles)\s+(?:vorherigen?|bisherigen?)\s+(?:informationen|aufgaben)", re.IGNORECASE),
    re.compile(r"(?:das\s+ist\s+erledigt|das\s+gen.gt|gut\s+gemacht).{0,30}(?:nun|jetzt|bitte)", re.IGNORECASE),
    re.compile(r"(?:nun\s+folgen|jetzt\s+komm|jetzt\s+kommen)\s+(?:neue|weitere)\s+(?:aufgaben|anweisungen)", re.IGNORECASE),
    # Spanish
    re.compile(r"(?:olvid[ae]|ignora)\s+(?:todo|todas|todos|las|los|anteriores)", re.IGNORECASE),
    re.compile(r"(?:nuevas?\s+instrucciones|solo\s+(?:tienes|debes)\s+(?:que|decir))", re.IGNORECASE),
    # French
    re.compile(r"(?:oubliez?|ignorez?)\s+(?:tout|toutes|les|instructions|pr[eé]c[eé]dentes)", re.IGNORECASE),
    # Croatian/Serbian/Bosnian
    re.compile(r"(?:zaboravi|ignoriraj)\s+(?:sve|prethodne|instrukcije)", re.IGNORECASE),
    # Hindi (transliterated)
    re.compile(r"(?:yaad\s+na\s+karen|bhool\s+jao|sab\s+bhool)", re.IGNORECASE),
    # Generic multi-language override signal
    re.compile(r"(?:forget|vergiss|olvid|oubli|zaboravi)\s+.{0,15}(?:everything|alles|todo|tout|sve)", re.IGNORECASE),
]

# Spacing/formatting evasion patterns
_SPACING_EVASION_PATTERNS = [
    re.compile(r"(?:[A-Za-z]\s){5,}"),  # S p a c e d  o u t  t e x t
    re.compile(r"\\n\s*\\n\s*\\n", re.IGNORECASE),  # Escaped newline stuffing
    re.compile(r"(?:stop|stopp)\s*:\s*(?:write|say|print|output)", re.IGNORECASE),  # stop: write X
]

# Harmful content request patterns
_HARMFUL_REQUEST_PATTERNS = [
    re.compile(r"(?:write|create|generate|produce|draft|compose)\s+(?:a|an)\s+(?:defamatory|racist|sexist|xenophobic|homophobic|discriminat)", re.IGNORECASE),
    re.compile(r"(?:write|create|generate|produce)\s+(?:a|an)\s+(?:phishing|malware|virus|ransomware|exploit|hack)", re.IGNORECASE),
    re.compile(r"(?:how to|steps to|guide to|instructions for)\s+(?:hack|exploit|break into|steal|attack|bomb|kill|murder|poison)", re.IGNORECASE),
    re.compile(r"(?:write|create|generate).{0,30}(?:hate speech|harassment|threat|blackmail|extortion)", re.IGNORECASE),
    re.compile(r"(?:promote|encourage|advocate|glorify).{0,30}(?:violence|terrorism|self-harm|suicide|genocide|discrimination)", re.IGNORECASE),
    re.compile(r"(?:design|plan|create).{0,30}(?:campaign|strategy|system).{0,30}(?:discourages|discriminat|target|shame|bully)", re.IGNORECASE),
    # Harmful-but-polite framing
    re.compile(r"(?:write|create).{0,20}(?:persuasive|convincing).{0,30}(?:children|kids|minors).{0,30}(?:eat|drink|consume|take)", re.IGNORECASE),
    re.compile(r"(?:write|create).{0,20}(?:blog|article|post).{0,30}(?:why|explaining).{0,30}(?:addicts?|gambling|payday|loan shark)", re.IGNORECASE),
    re.compile(r"(?:personalized|step-by-step|detailed).{0,20}(?:medical|treatment|legal|investment)\s+(?:plan|guide|advice)", re.IGNORECASE),
    re.compile(r"(?:create|build|write)\s+(?:a\s+)?bot.{0,30}(?:recommend|suggest).{0,30}(?:stock|bond|invest|financial)", re.IGNORECASE),
    re.compile(r"(?:suggest|claim|prove|argue).{0,30}(?:never happened|hoax|is flat|controlled by|illuminati|conspiracy)", re.IGNORECASE),
    re.compile(r"(?:formuliere|schreibe|verfasse).{0,30}(?:unwahre?|manifest|pl.doyer)", re.IGNORECASE),
    # Direct harmful instructions (teach/provide/show/instruct patterns)
    re.compile(r"(?:teach|show|instruct|tell)\s+(?:someone|me|people|us)\s+(?:how to|to)\s+(?:engage in|commit|make|create|do|perform)", re.IGNORECASE),
    re.compile(r"(?:provide|give|share)\s+(?:step-by-step|detailed|specific)\s+(?:instructions?|guide|plan|tutorial)\s+(?:for|on|to)", re.IGNORECASE),
    re.compile(r"(?:create|develop|write|build)\s+(?:a\s+)?(?:program|script|tool|bot|app).{0,30}(?:stalk|harass|steal|hack|spy|track|monitor)", re.IGNORECASE),
    re.compile(r"(?:provide|give|create|develop)\s+(?:a\s+)?(?:detailed|comprehensive|complete)?\s*(?:plan|blueprint|guide|roadmap)\s+(?:for|to)\s+(?:commit|carrying out|executing)", re.IGNORECASE),
    re.compile(r"(?:how to|ways to|methods to|steps to)\s+(?:obtain|acquire|get|buy|make|manufacture)\s+(?:illegal|illicit|prohibited)", re.IGNORECASE),
    re.compile(r"(?:write|draft|create)\s+(?:a\s+)?(?:letter|email|message|post)\s+(?:defaming|threatening|harassing|blackmailing)", re.IGNORECASE),
]

_ROLEPLAY_PREFIXES = {
    "you are now", "pretend to be", "act as", "roleplay as",
    "assume the role of", "behave as", "simulate being",
    "from now on you are", "switch to",
}

_NEW_INSTRUCTION_PHRASES = {
    "new instructions", "override instructions", "system prompt",
    "updated instructions", "replacement instructions", "revised rules",
    "new directive", "new system prompt",
}

_BYPASS_PHRASES = {
    "do not follow", "bypass", "circumvent", "disable", "turn off",
    "deactivate", "remove restrictions", "unlock", "jailbreak",
    "ignore safety", "ignore filters",
}

# Base64 detection pattern: valid base64 strings longer than 20 characters
_BASE64_PATTERN = re.compile(
    r"[A-Za-z0-9+/]{20,}={0,2}"
)

# Hex-encoded string patterns
_HEX_PREFIX_PATTERN = re.compile(r"0x([0-9A-Fa-f]{2}){4,}")
_HEX_LONG_PATTERN = re.compile(r"(?<![A-Za-z0-9])([0-9A-Fa-f]{8,})(?![A-Za-z0-9])")

# URL-encoded pattern: sequences of %XX
_URL_ENCODED_PATTERN = re.compile(r"(%[0-9A-Fa-f]{2}){3,}")


class InputSanitizer:
    """Advanced input sanitizer that validates agent inputs before threat detection.

    Catches encoding-based evasions, LLM delimiter injection, context window
    stuffing, and obfuscated instruction override patterns that simple regex
    threat patterns cannot detect.
    """

    def sanitize(self, input_text: str) -> SanitizationResult:
        """Main entry point. Run all sanitization checks and return results.

        Execution order:
        1. Normalize unicode (homoglyphs, NFKD decomposition)
        2. Decode encoded payloads (base64, hex, URL-encoding)
        3. Check for delimiter injection (original + decoded)
        4. Check for context stuffing
        5. Detect instruction override patterns (normalized + decoded)
        6. Determine block decision

        Args:
            input_text: Raw input text from the agent request.

        Returns:
            SanitizationResult with all findings and block decision.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        threats_detected: List[str] = []

        # Step 1: Normalize unicode
        sanitized_text = self._normalize_unicode(input_text)

        # Step 2: Decode encoded payloads
        decoded_combined, decoded_findings = self._decode_encoded_payloads(input_text)
        decoded_payloads = decoded_findings

        if decoded_findings:
            threats_detected.append(
                f"Encoded payload detected: {len(decoded_findings)} encoded segment(s) found"
            )

        # Step 3: Check delimiter injection in both original and decoded content
        delimiter_injections = self._detect_delimiter_injection(input_text)
        if decoded_combined:
            delimiter_injections.extend(
                self._detect_delimiter_injection(decoded_combined)
            )
        # Deduplicate while preserving order
        seen_delimiters: set = set()
        unique_delimiters: List[str] = []
        for d in delimiter_injections:
            if d not in seen_delimiters:
                seen_delimiters.add(d)
                unique_delimiters.append(d)
        delimiter_injections = unique_delimiters

        if delimiter_injections:
            threats_detected.append(
                f"Delimiter injection: {', '.join(delimiter_injections)}"
            )

        # Step 4: Check context stuffing
        context_stuffing = self._detect_context_stuffing(input_text)
        if context_stuffing:
            threats_detected.append(
                f"Context stuffing: input length {len(input_text)} exceeds maximum"
            )

        # Step 5: Detect instruction patterns in normalized text and decoded payloads
        instruction_patterns = self._detect_instruction_patterns(sanitized_text)
        decoded_instruction_patterns: List[str] = []
        if decoded_combined:
            decoded_instruction_patterns = self._detect_instruction_patterns(
                decoded_combined
            )
            # Add decoded patterns with prefix to distinguish source
            for pattern in decoded_instruction_patterns:
                prefixed = f"[decoded] {pattern}"
                if prefixed not in instruction_patterns:
                    instruction_patterns.append(prefixed)

        if instruction_patterns:
            threats_detected.append(
                f"Instruction override patterns: {'; '.join(instruction_patterns)}"
            )

        # Step 6: Determine block decision
        blocked = False
        block_reason = ""

        if delimiter_injections:
            blocked = True
            block_reason = (
                f"LLM delimiter injection detected: {', '.join(delimiter_injections)}"
            )
        elif decoded_instruction_patterns:
            blocked = True
            block_reason = (
                "Instruction override patterns found in encoded payload"
            )
        elif instruction_patterns:
            blocked = True
            block_reason = (
                f"Instruction override patterns detected: {'; '.join(instruction_patterns[:2])}"
            )
        elif context_stuffing:
            blocked = True
            block_reason = (
                f"Input length ({len(input_text)} chars) exceeds context stuffing threshold"
            )

        result = SanitizationResult(
            original_text=input_text,
            sanitized_text=sanitized_text,
            decoded_payloads=decoded_payloads,
            threats_detected=threats_detected,
            delimiter_injections=delimiter_injections,
            context_stuffing=context_stuffing,
            instruction_patterns=instruction_patterns,
            blocked=blocked,
            block_reason=block_reason,
            timestamp=timestamp,
        )

        # Structured JSON logging for security events
        log_data = {
            "audit_event": "input_sanitization",
            "blocked": blocked,
            "threats_detected_count": len(threats_detected),
            "delimiter_injections_count": len(delimiter_injections),
            "context_stuffing": context_stuffing,
            "instruction_patterns_count": len(instruction_patterns),
            "decoded_payloads_count": len(decoded_payloads),
            "input_length": len(input_text),
            "timestamp": timestamp,
        }

        if blocked:
            log_data["block_reason"] = block_reason
            logger.warning(json.dumps(log_data))
        elif threats_detected:
            logger.warning(json.dumps(log_data))
        else:
            logger.info(json.dumps(log_data))

        return result

    def _normalize_unicode(self, text: str) -> str:
        """Replace common homoglyphs with ASCII equivalents and normalize.

        Applies NFKD decomposition to break down composed characters, then
        replaces known homoglyphs (Cyrillic lookalikes, fullwidth characters,
        leet-speak substitutions) with their ASCII equivalents.

        Args:
            text: Input text potentially containing homoglyphs.

        Returns:
            Normalized text with homoglyphs replaced by ASCII equivalents.
        """
        # NFKD decomposition breaks composed characters into base + combining marks
        decomposed = unicodedata.normalize("NFKD", text)

        # Strip combining marks (accents, diacritics) to get base characters
        stripped = "".join(
            ch for ch in decomposed if not unicodedata.combining(ch)
        )

        # Replace known homoglyphs
        result = []
        for ch in stripped:
            if ch in _HOMOGLYPH_MAP:
                result.append(_HOMOGLYPH_MAP[ch])
            else:
                result.append(ch)

        return "".join(result)

    def _decode_encoded_payloads(self, text: str) -> Tuple[str, List[str]]:
        """Detect and decode base64, hex-encoded, and URL-encoded payloads.

        Scans the input for:
        - Base64 blocks (valid base64 strings longer than 20 characters)
        - Hex-encoded strings (0x... prefix or long hex sequences)
        - URL-encoded sequences (3+ consecutive %XX patterns)

        Args:
            text: Input text to scan for encoded content.

        Returns:
            Tuple of (combined decoded text, list of finding descriptions).
        """
        findings: List[str] = []
        decoded_segments: List[str] = []

        # Detect and decode base64
        for match in _BASE64_PATTERN.finditer(text):
            candidate = match.group(0)
            try:
                # Pad if necessary
                padded = candidate + "=" * (4 - len(candidate) % 4) if len(candidate) % 4 else candidate
                decoded_bytes = base64.b64decode(padded, validate=True)
                # Check if result is printable text
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if decoded_str.isprintable() or any(
                    ch.isalpha() for ch in decoded_str
                ):
                    findings.append(f"base64: {decoded_str[:100]}")
                    decoded_segments.append(decoded_str)
            except (ValueError, UnicodeDecodeError):
                # Not valid base64 or not UTF-8 text; skip
                continue

        # Detect and decode hex with 0x prefix
        for match in _HEX_PREFIX_PATTERN.finditer(text):
            hex_str = match.group(0)[2:]  # Strip 0x prefix
            try:
                decoded_bytes = bytes.fromhex(hex_str)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if decoded_str.isprintable() or any(
                    ch.isalpha() for ch in decoded_str
                ):
                    findings.append(f"hex: {decoded_str[:100]}")
                    decoded_segments.append(decoded_str)
            except (ValueError, UnicodeDecodeError):
                continue

        # Detect and decode long hex sequences (without prefix)
        for match in _HEX_LONG_PATTERN.finditer(text):
            hex_str = match.group(1) if match.lastindex else match.group(0)
            if len(hex_str) < 8:
                continue
            # Skip if already caught by 0x prefix pattern
            start = match.start()
            if start >= 2 and text[start - 2:start] == "0x":
                continue
            try:
                decoded_bytes = bytes.fromhex(hex_str)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if decoded_str.isprintable() or any(
                    ch.isalpha() for ch in decoded_str
                ):
                    findings.append(f"hex: {decoded_str[:100]}")
                    decoded_segments.append(decoded_str)
            except (ValueError, UnicodeDecodeError):
                continue

        # Detect and decode URL-encoded sequences
        for match in _URL_ENCODED_PATTERN.finditer(text):
            encoded_str = match.group(0)
            try:
                decoded_str = urllib.parse.unquote(encoded_str)
                if decoded_str != encoded_str:
                    findings.append(f"url_encoded: {decoded_str[:100]}")
                    decoded_segments.append(decoded_str)
            except (ValueError, UnicodeError):
                continue

        combined = " ".join(decoded_segments)
        return (combined, findings)

    def _detect_delimiter_injection(self, text: str) -> List[str]:
        """Detect LLM delimiter markers that indicate prompt injection attempts.

        Checks for ChatML, Llama, generic model delimiters, and system role
        markers that an attacker might inject to manipulate model behavior.

        Args:
            text: Input text to scan for delimiters.

        Returns:
            List of detected delimiter strings.
        """
        detected: List[str] = []
        text_lower = text.lower()

        for delimiter in _ALL_DELIMITERS:
            if delimiter.lower() in text_lower:
                detected.append(delimiter)

        return detected

    def _detect_context_stuffing(self, text: str, max_length: int = 5000) -> bool:
        """Detect context window stuffing attacks.

        Returns True if input exceeds the maximum length threshold, which may
        indicate an attempt to push the system prompt out of the model's
        context window.

        Args:
            text: Input text to check.
            max_length: Maximum allowed input length. Defaults to 5000 characters.

        Returns:
            True if the input exceeds max_length.
        """
        return len(text) > max_length

    def _detect_instruction_patterns(self, text: str) -> List[str]:
        """Detect instruction override patterns, including obfuscated variants.

        Performs word-level matching after leet-speak normalization to catch:
        - "ignore/disregard/forget + previous/above/prior + instructions/rules"
        - "you are now/pretend to be/act as/roleplay as"
        - "new instructions/override/system prompt"
        - "do not follow/bypass/circumvent"

        Args:
            text: Normalized or decoded text to scan.

        Returns:
            List of detected instruction pattern descriptions.
        """
        detected: List[str] = []

        # Apply leet-speak normalization for word-level matching
        normalized = self._apply_leet_decode(text.lower())

        # Check override verb + target + object combinations
        words = re.split(r"\s+", normalized)
        word_set_sliding = " ".join(words)  # Rejoin for phrase matching

        # Pattern 1: verb + target + object (within a sliding window)
        for i, word in enumerate(words):
            if word in _OVERRIDE_VERBS:
                # Look ahead up to 5 words for target and object
                window = words[i:i + 6]
                found_target = any(w in _OVERRIDE_TARGETS for w in window)
                found_object = any(w in _OVERRIDE_OBJECTS for w in window)
                if found_target and found_object:
                    context = " ".join(words[max(0, i - 1):i + 6])
                    pattern_desc = f"override pattern: '{context[:80]}'"
                    if pattern_desc not in detected:
                        detected.append(pattern_desc)

        # Pattern 2: Roleplay prefixes
        for phrase in _ROLEPLAY_PREFIXES:
            if phrase in word_set_sliding:
                detected.append(f"roleplay pattern: '{phrase}'")

        # Pattern 3: New instruction phrases
        for phrase in _NEW_INSTRUCTION_PHRASES:
            if phrase in word_set_sliding:
                detected.append(f"new instruction pattern: '{phrase}'")

        # Pattern 4: Bypass phrases
        for phrase in _BYPASS_PHRASES:
            if phrase in word_set_sliding:
                detected.append(f"bypass pattern: '{phrase}'")

        # Pattern 5: Jailbreak persona/roleplay (regex-based)
        for pattern in _JAILBREAK_PATTERNS:
            if pattern.search(text):
                detected.append(f"jailbreak pattern: '{pattern.pattern[:50]}'")
                break

        # Pattern 6: Harmful content requests (regex-based)
        for pattern in _HARMFUL_REQUEST_PATTERNS:
            if pattern.search(text):
                detected.append(f"harmful request: '{pattern.pattern[:50]}'")
                break

        # Pattern 7: Multilingual instruction overrides
        for pattern in _MULTILINGUAL_OVERRIDE_PATTERNS:
            if pattern.search(text):
                detected.append(f"multilingual override: '{pattern.pattern[:50]}'")
                break

        # Pattern 8: Spacing/formatting evasion
        for pattern in _SPACING_EVASION_PATTERNS:
            if pattern.search(text):
                detected.append(f"spacing evasion: '{pattern.pattern[:50]}'")
                break

        return detected

    @staticmethod
    def _apply_leet_decode(text: str) -> str:
        """Decode leet-speak substitutions to reveal hidden words.

        Args:
            text: Lowercase text to decode.

        Returns:
            Text with leet-speak characters replaced by letter equivalents.
        """
        result = []
        for ch in text:
            if ch in _LEET_MAP:
                result.append(_LEET_MAP[ch])
            else:
                result.append(ch)
        return "".join(result)
