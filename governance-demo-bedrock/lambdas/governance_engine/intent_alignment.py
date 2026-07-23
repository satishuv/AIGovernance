"""Stated-intent capture and alignment scoring (AARM R3 + R7).

AARM R3 (policy evaluation with intent alignment) requires that each action be
evaluated against the agent's stated intent, not in isolation. AARM R7
(semantic distance tracking) requires tracking the distance between proposed
actions and that stated intent, flagging drift over long task horizons.

Both need the same primitive: a captured stated intent per session, and a
distance function between an action and that intent. This module provides:

  - IntentStore: persist/fetch the stated intent for a session, reusing the
    runtime drift DynamoDB table (record_type = "session_intent#<session_id>")
    so no new table is required.
  - semantic_distance(): distance in [0.0, 1.0] between two texts. Lexical
    (Jaccard over token sets) by DEFAULT -- deterministic, hermetic, no network
    -- with an optional Bedrock Titan embedding path behind an off-by-default
    flag (INTENT_DISTANCE_MODE=embedding) for higher-fidelity scoring.
  - assess_alignment(): maps a distance to an alignment verdict hint used by the
    decision engine: aligned (allow), ambiguous (defer), or divergent (escalate).

Distance semantics: 0.0 = identical/fully aligned, 1.0 = no overlap/fully
divergent.
"""

import json
import logging
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Distance thresholds (on the 0..1 scale). Tunable; conservative defaults.
ALIGNED_MAX_DISTANCE = 0.60      # <= this: action aligns with intent -> allow
DIVERGENT_MIN_DISTANCE = 0.90    # >= this: strong divergence -> escalate
# Between the two: ambiguous -> defer (pending disambiguation).

# Drift over the session horizon: rolling mean distance at/above this flags R7.
DRIFT_ALERT_MEAN_DISTANCE = 0.75

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _jaccard_distance(a: str, b: str) -> float:
    """Lexical distance in [0,1]: 1 - Jaccard similarity of token sets."""
    ta, tb = set(_tokenize(a)), set(_tokenize(b))
    if not ta and not tb:
        return 0.0
    if not ta or not tb:
        return 1.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return 1.0 - (inter / union)


@dataclass
class AlignmentResult:
    """Outcome of an intent-alignment assessment.

    Attributes:
        distance: Semantic distance in [0,1] (0 aligned, 1 divergent).
        classification: "aligned" | "ambiguous" | "divergent".
        aligned: True when the action is considered aligned with intent.
        context_sufficient: False when ambiguous (feeds DEFER in decide()).
        divergent: True when strongly divergent (biases toward escalate).
        mode: "lexical" or "embedding".
    """

    distance: float
    classification: str
    aligned: bool
    context_sufficient: bool
    divergent: bool
    mode: str = "lexical"


def semantic_distance(intent_text: str, action_text: str, bedrock_client: Any = None) -> float:
    """Return distance in [0,1] between a stated intent and a proposed action.

    Lexical Jaccard by default. If INTENT_DISTANCE_MODE == "embedding" and a
    bedrock client is available, uses Titan embeddings (cosine distance) and
    falls back to lexical on any error, so this never fails the pipeline.
    """
    mode = os.environ.get("INTENT_DISTANCE_MODE", "lexical").lower()
    if mode == "embedding" and bedrock_client is not None:
        try:
            return _embedding_distance(intent_text, action_text, bedrock_client)
        except Exception as exc:
            logger.warning(json.dumps({
                "event": "intent_embedding_fallback_to_lexical",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
    return _jaccard_distance(intent_text, action_text)


def _embedding_distance(a: str, b: str, bedrock_client: Any) -> float:
    """Cosine distance in [0,1] using Bedrock Titan embeddings."""
    model_id = os.environ.get("INTENT_EMBEDDING_MODEL", "amazon.titan-embed-text-v2:0")

    def embed(text: str) -> List[float]:
        resp = bedrock_client.invoke_model(
            modelId=model_id,
            body=json.dumps({"inputText": text or ""}),
        )
        payload = json.loads(resp["body"].read())
        return payload["embedding"]

    va, vb = embed(a), embed(b)
    dot = sum(x * y for x, y in zip(va, vb))
    na = math.sqrt(sum(x * x for x in va))
    nb = math.sqrt(sum(y * y for y in vb))
    if na == 0 or nb == 0:
        return 1.0
    cosine_sim = dot / (na * nb)
    # Map cosine similarity [-1,1] to distance [0,1].
    return max(0.0, min(1.0, (1.0 - cosine_sim) / 2.0))


def assess_alignment(intent_text: str, action_text: str, bedrock_client: Any = None) -> AlignmentResult:
    """Assess whether an action aligns with the stated intent (AARM R3).

    If no intent has been captured (empty intent_text), treat as aligned with
    sufficient context -- absence of a stated intent must not manufacture
    spurious defers on an otherwise-valid request.
    """
    mode = os.environ.get("INTENT_DISTANCE_MODE", "lexical").lower()
    if not intent_text:
        return AlignmentResult(
            distance=0.0, classification="aligned", aligned=True,
            context_sufficient=True, divergent=False, mode=mode,
        )

    dist = semantic_distance(intent_text, action_text, bedrock_client)
    if dist <= ALIGNED_MAX_DISTANCE:
        return AlignmentResult(dist, "aligned", True, True, False, mode)
    if dist >= DIVERGENT_MIN_DISTANCE:
        return AlignmentResult(dist, "divergent", False, True, True, mode)
    # Middle band: ambiguous -> insufficient context -> DEFER.
    return AlignmentResult(dist, "ambiguous", False, False, False, mode)


class IntentStore:
    """Persist and fetch the stated intent for a session.

    Reuses the runtime drift table (PK agent_id, SK record_type) with
    record_type "session_intent#<session_id>", avoiding a new table.
    """

    def __init__(self, drift_table: Any = None) -> None:
        self._table = drift_table

    @staticmethod
    def _sk(session_id: str) -> str:
        return f"session_intent#{session_id}"

    def capture_intent(self, agent_id: str, session_id: str, intent_text: str) -> None:
        """Store the stated intent for a session if not already captured.

        First-write-wins: the intent is bootstrapped from the first request of
        a session and not overwritten by later actions (which is exactly the
        drift we want R7 to detect).
        """
        if self._table is None or not session_id:
            return
        try:
            self._table.put_item(
                Item={
                    "agent_id": agent_id,
                    "record_type": self._sk(session_id),
                    "intent_text": intent_text or "",
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                },
                ConditionExpression="attribute_not_exists(record_type)",
            )
        except Exception:
            # ConditionalCheckFailed (already captured) or transient error --
            # never fail the pipeline on intent capture.
            pass

    def get_intent(self, agent_id: str, session_id: str) -> str:
        """Return the stored intent text for a session, or "" if none."""
        if self._table is None or not session_id:
            return ""
        try:
            resp = self._table.get_item(
                Key={"agent_id": agent_id, "record_type": self._sk(session_id)}
            )
            item = resp.get("Item")
            return item.get("intent_text", "") if item else ""
        except Exception:
            return ""
