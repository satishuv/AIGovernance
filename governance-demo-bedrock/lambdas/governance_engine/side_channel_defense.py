"""Side-channel leakage defense (AARM T9).

AARM T9: "Information is inferred from agent behavior, timing, or tool call
patterns rather than direct output."

Two side channels are addressed here; a third is documented as a residual
limitation rather than claimed as solved.

1. Timing oracle (addressed). Denials short-circuit early in the pipeline
   (kill switch < 5ms, input sanitizer, threat patterns, ...), while allows run
   the full evaluation. Response latency therefore leaks both the verdict and
   *which stage* blocked, letting an attacker map the defenses. `normalize_deny_timing`
   holds denials to a minimum floor so their timing no longer distinguishes
   stages (or allow-vs-deny for fast allows).

2. Oracle probing (addressed). Extracting information bit-by-bit via many
   near-identical requests that differ only slightly (a classic side-channel /
   blind-oracle technique). `ProbeDetector` fingerprints normalized requests per
   session and flags high-similarity, high-frequency probing.

Residual limitation (NOT solved here): fine-grained micro-timing and
infrastructure-level channels (cold starts, GC, network jitter, CPU cache) are
not defeated by application-level normalization. This module removes the coarse
verdict/stage timing oracle and detects probing; it does not claim constant-time
guarantees at the hardware level.
"""

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Minimum wall-clock floor (ms) for denial responses. All denials are held to
# at least this duration so stage-of-denial and allow-vs-fast-deny are not
# distinguishable by latency. Configurable; 0 disables (e.g. for tests).
DENY_TIMING_FLOOR_MS = int(os.environ.get("SIDE_CHANNEL_DENY_FLOOR_MS", "60"))

# Probe detection thresholds.
PROBE_WINDOW_SECONDS = int(os.environ.get("SIDE_CHANNEL_PROBE_WINDOW_S", "60"))
PROBE_MIN_COUNT = int(os.environ.get("SIDE_CHANNEL_PROBE_MIN_COUNT", "5"))
# Two requests are "near-identical" when their normalized token sets differ by
# at most this Jaccard distance (small edits = probing).
PROBE_SIMILARITY_MAX_DISTANCE = float(os.environ.get("SIDE_CHANNEL_PROBE_MAX_DIST", "0.25"))

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str):
    return set(_TOKEN_RE.findall((text or "").lower()))


def _jaccard_distance(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 0.0
    if not ta or not tb:
        return 1.0
    return 1.0 - (len(ta & tb) / len(ta | tb))


def normalize_deny_timing(start_monotonic: float, floor_ms: int = None,
                          sleep_fn=time.sleep) -> float:
    """Hold a denial response to a minimum time floor (timing-oracle defense).

    Given the monotonic start time of request handling, sleep until at least
    ``floor_ms`` has elapsed so that all denials take a similar minimum time,
    removing the stage-of-denial / allow-vs-deny latency signal.

    Args:
        start_monotonic: value of time.monotonic() captured at request start.
        floor_ms: minimum floor in ms (defaults to DENY_TIMING_FLOOR_MS).
        sleep_fn: injectable sleep (tests pass a no-op recorder).

    Returns:
        The number of milliseconds slept (0 if already past the floor).
    """
    floor = DENY_TIMING_FLOOR_MS if floor_ms is None else floor_ms
    if floor <= 0:
        return 0.0
    elapsed_ms = (time.monotonic() - start_monotonic) * 1000.0
    remaining_ms = floor - elapsed_ms
    if remaining_ms > 0:
        sleep_fn(remaining_ms / 1000.0)
        return remaining_ms
    return 0.0


@dataclass
class ProbeResult:
    """Outcome of an oracle-probing check.

    Attributes:
        is_probing: True when high-similarity, high-frequency probing is seen.
        similar_count: Number of near-identical recent requests in the window.
        reason: Human-readable explanation when probing is flagged.
    """
    is_probing: bool = False
    similar_count: int = 0
    reason: str = ""


class ProbeDetector:
    """Detects side-channel oracle probing via near-identical repeat requests.

    Persists per-session request fingerprints in the runtime drift table
    (record_type "probe#<session_id>"), reusing existing infrastructure. A
    burst of requests whose text is near-identical (small edits) within a short
    window is the signature of bit-by-bit oracle extraction.
    """

    def __init__(self, drift_table: Any = None) -> None:
        self._table = drift_table

    @staticmethod
    def _sk(session_id: str) -> str:
        return f"probe#{session_id}"

    @staticmethod
    def _fingerprint(text: str) -> str:
        # Order-independent token fingerprint so reordering does not evade.
        toks = sorted(_tokens(text))
        return hashlib.sha256(" ".join(toks).encode("utf-8")).hexdigest()[:16]

    def record_and_check(self, session_id: str, input_text: str,
                         now_epoch: Optional[float] = None) -> ProbeResult:
        """Record this request and report whether the session is probing.

        Args:
            session_id: The session to track (no-op if empty or no table).
            input_text: The current request text.
            now_epoch: Optional epoch seconds (injected in tests).

        Returns:
            A ProbeResult. Never raises; storage errors yield is_probing=False.
        """
        if self._table is None or not session_id or not input_text:
            return ProbeResult()

        now = now_epoch if now_epoch is not None else time.time()
        cutoff = now - PROBE_WINDOW_SECONDS
        sk = self._sk(session_id)

        try:
            resp = self._table.get_item(Key={"agent_id": sk, "record_type": "history"})
            item = resp.get("Item") or {}
            history: List[Dict[str, Any]] = item.get("recent", []) or []
        except Exception:
            history = []

        # Drop entries outside the window.
        history = [h for h in history if float(h.get("ts", 0)) >= cutoff]

        # Count near-identical prior requests (small-edit probing).
        similar = 0
        for h in history:
            if _jaccard_distance(h.get("text", ""), input_text) <= PROBE_SIMILARITY_MAX_DISTANCE:
                similar += 1

        # Append current request; cap stored history to bound item size.
        history.append({"ts": now, "text": input_text[:512]})
        history = history[-50:]

        try:
            self._table.put_item(Item={
                "agent_id": sk,
                "record_type": "history",
                "recent": history,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass

        # +1 to include the current request in the burst count.
        if similar + 1 >= PROBE_MIN_COUNT:
            return ProbeResult(
                is_probing=True,
                similar_count=similar + 1,
                reason=(
                    f"Oracle-probing pattern: {similar + 1} near-identical "
                    f"requests within {PROBE_WINDOW_SECONDS}s (side-channel "
                    f"extraction signature)."
                ),
            )
        return ProbeResult(is_probing=False, similar_count=similar + 1)
