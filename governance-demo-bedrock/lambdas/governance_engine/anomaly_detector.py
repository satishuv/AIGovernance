"""Statistical Anomaly Detection for AI Agent Inputs.

Goes beyond regex pattern matching by using statistical analysis to detect
inputs that are structurally unusual (likely adversarial). Catches attacks
that no pattern can match because they use novel obfuscation techniques.

Detection methods:
1. Shannon entropy analysis (encoded/encrypted payloads have high entropy)
2. Character distribution deviation (unusual character frequency = suspicious)
3. Special character ratio (injection attacks use more special chars)
4. Token length anomaly (context stuffing, unusually short triggers)
5. Language mixing score (multiple scripts = evasion attempt)
6. Repetition score (repeated patterns = prompt injection technique)

No ML libraries required. Pure statistical analysis using stdlib math.
"""

import json
import logging
import math
import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class AnomalyScore:
    """Result of anomaly detection analysis."""

    def __init__(self, score: float, anomalous: bool, factors: Dict[str, float],
                 explanation: str = ""):
        self.score = score  # 0.0 (normal) to 1.0 (highly anomalous)
        self.anomalous = anomalous  # True if score > threshold
        self.factors = factors  # individual factor scores
        self.explanation = explanation
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "anomalous": self.anomalous,
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


class AnomalyDetector:
    """Statistical anomaly detector for AI agent inputs."""

    # Baseline statistics for "normal" English text inputs
    # (derived from typical user queries to SDLC agents)
    NORMAL_ENTROPY_RANGE = (3.0, 5.0)  # bits per character
    NORMAL_SPECIAL_RATIO = (0.0, 0.15)  # fraction of non-alphanumeric
    NORMAL_LENGTH_RANGE = (5, 500)  # characters
    NORMAL_UNIQUE_CHAR_RATIO = (0.3, 0.8)  # unique chars / total chars

    # Weights for combining factor scores
    WEIGHTS = {
        "entropy": 0.25,
        "special_char_ratio": 0.20,
        "length": 0.10,
        "script_mixing": 0.20,
        "repetition": 0.15,
        "unique_char_ratio": 0.10,
    }

    ANOMALY_THRESHOLD = 0.6  # above this = flagged as anomalous

    def __init__(self, threshold: float = None):
        self._threshold = threshold or self.ANOMALY_THRESHOLD

    def analyze(self, text: str) -> AnomalyScore:
        """Analyze input text for statistical anomalies.

        Returns AnomalyScore with composite score and per-factor breakdown.
        """
        if not text or len(text.strip()) == 0:
            return AnomalyScore(score=0.0, anomalous=False, factors={},
                              explanation="Empty input")

        factors = {}

        # Factor 1: Shannon entropy
        factors["entropy"] = self._entropy_score(text)

        # Factor 2: Special character ratio
        factors["special_char_ratio"] = self._special_char_score(text)

        # Factor 3: Length anomaly
        factors["length"] = self._length_score(text)

        # Factor 4: Script mixing (multiple unicode scripts)
        factors["script_mixing"] = self._script_mixing_score(text)

        # Factor 5: Repetition patterns
        factors["repetition"] = self._repetition_score(text)

        # Factor 6: Unique character ratio
        factors["unique_char_ratio"] = self._unique_char_score(text)

        # Compute weighted composite score
        composite = sum(
            factors[k] * self.WEIGHTS[k] for k in self.WEIGHTS if k in factors
        )
        composite = min(1.0, max(0.0, composite))

        anomalous = composite > self._threshold

        # Build explanation
        flagged_factors = [k for k, v in factors.items() if v > 0.7]
        if anomalous:
            explanation = f"Anomalous input (score {composite:.2f}): {', '.join(flagged_factors)}"
        else:
            explanation = f"Normal input (score {composite:.2f})"

        if anomalous:
            logger.warning(json.dumps({
                "event": "anomaly_detected",
                "score": round(composite, 3),
                "factors": {k: round(v, 3) for k, v in factors.items()},
                "input_length": len(text),
                "flagged_factors": flagged_factors,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        return AnomalyScore(
            score=composite,
            anomalous=anomalous,
            factors=factors,
            explanation=explanation,
        )

    def _entropy_score(self, text: str) -> float:
        """Shannon entropy normalized to anomaly score.

        Normal English text: 3.0-5.0 bits/char
        Encoded payloads (base64, hex): >5.5 bits/char
        Repeated text: <2.5 bits/char
        """
        if len(text) == 0:
            return 0.0

        freq = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

        low, high = self.NORMAL_ENTROPY_RANGE
        if entropy > high:
            return min(1.0, (entropy - high) / 3.0)
        elif entropy < low:
            return min(1.0, (low - entropy) / 2.0)
        return 0.0

    def _special_char_score(self, text: str) -> float:
        """Ratio of special characters to total length.

        Injection attacks typically have high special char ratios
        (brackets, pipes, semicolons, quotes, etc.)
        """
        if len(text) == 0:
            return 0.0

        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        ratio = special / len(text)

        _, high = self.NORMAL_SPECIAL_RATIO
        if ratio > high:
            return min(1.0, (ratio - high) / 0.3)
        return 0.0

    def _length_score(self, text: str) -> float:
        """Flag unusually short or long inputs."""
        length = len(text)
        low, high = self.NORMAL_LENGTH_RANGE

        if length > high * 10:  # >5000 chars (context stuffing)
            return 1.0
        elif length > high:
            return min(1.0, (length - high) / (high * 9))
        elif length < low:
            return 0.3  # Very short inputs are mildly suspicious
        return 0.0

    def _script_mixing_score(self, text: str) -> float:
        """Detect mixing of unicode scripts (Latin + Cyrillic + etc).

        Homoglyph attacks mix scripts to create visually identical but
        semantically different characters.
        """
        scripts = set()
        for char in text:
            if char.isalpha():
                try:
                    script = unicodedata.name(char, "").split()[0]
                    scripts.add(script)
                except (ValueError, IndexError):
                    pass

        # More than 2 scripts is suspicious
        if len(scripts) > 3:
            return 1.0
        elif len(scripts) > 2:
            return 0.7
        elif len(scripts) > 1:
            # Check if it's just Latin + one other (common in URLs)
            if "LATIN" in scripts and len(scripts) == 2:
                return 0.3
            return 0.5
        return 0.0

    def _repetition_score(self, text: str) -> float:
        """Detect high repetition (prompt injection technique).

        Attackers repeat phrases to overwhelm the context window or
        reinforce injected instructions.
        """
        if len(text) < 20:
            return 0.0

        # Check for repeated n-grams (3-word chunks)
        words = text.split()
        if len(words) < 6:
            return 0.0

        trigrams = [" ".join(words[i:i+3]) for i in range(len(words)-2)]
        trigram_counts = Counter(trigrams)

        if not trigrams:
            return 0.0

        max_repeat = max(trigram_counts.values())
        repeat_ratio = max_repeat / len(trigrams)

        if repeat_ratio > 0.5:
            return 1.0
        elif repeat_ratio > 0.3:
            return 0.7
        elif repeat_ratio > 0.15:
            return 0.4
        return 0.0

    def _unique_char_score(self, text: str) -> float:
        """Ratio of unique characters to total length.

        Very low ratio: repeated/stuffed content
        Very high ratio: random/encoded content
        """
        if len(text) == 0:
            return 0.0

        ratio = len(set(text)) / len(text)
        low, high = self.NORMAL_UNIQUE_CHAR_RATIO

        if ratio > high:
            return min(1.0, (ratio - high) / 0.2)
        elif ratio < low:
            return min(1.0, (low - ratio) / 0.2)
        return 0.0
