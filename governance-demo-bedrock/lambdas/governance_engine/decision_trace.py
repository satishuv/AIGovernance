"""Auditor decision-trace: build, sign, store, and verify the "why" of a verdict.

Consolidates the per-stage reasoning the governance pipeline already computes
into a single tamper-evident, KMS-signed record so an auditor can answer "why
did the engine decide this action?". Scope is the GOVERNANCE reasoning; the
agent's own chain-of-thought is deliberately excluded (it is not reliably
truthful and cannot be verified).

- DecisionTraceBuilder: accumulate stages during a pipeline run.
- DecisionTraceManager: sign (shared KMS signer) + store to DecisionTraceTable,
  fetch by decision_id, and verify a stored trace's signature offline.
"""

import json
import logging
from decimal import Decimal
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from crypto_signing import compute_hash, sign_digest
from models import DecisionTrace
from verdicts import to_aarm

logger = logging.getLogger(__name__)


def _canonical_body(trace_dict: Dict[str, Any]) -> str:
    """Canonical JSON of the trace content (excluding hash+signature fields).

    We store and hash this exact string. DynamoDB normalizes Decimals on the
    round-trip (10.0 -> 10), which would break a hash recomputed from parsed
    attributes; storing the canonical string sidesteps that entirely (this is
    how S3-stored evidence stays verifiable). Signature is computed over the
    SHA-256 of this string.
    """
    from crypto_signing import HASH_EXCLUDED_FIELDS
    filtered = {k: v for k, v in trace_dict.items() if k not in HASH_EXCLUDED_FIELDS}
    return json.dumps(filtered, sort_keys=True, default=str)

# Allowed per-stage results.
RESULT_PASS = "pass"     # stage ran, no issue
RESULT_BLOCK = "block"   # stage produced a deny/blocking outcome
RESULT_FLAG = "flag"     # stage raised a risk/suspicion signal (non-blocking)
RESULT_NA = "na"         # stage did not apply / was skipped


class DecisionTraceBuilder:
    """Accumulates ordered stage reasoning during one pipeline run.

    Lightweight and in-memory; one per request. Reuses reason strings the
    pipeline already computes -- it adds no new detection logic.
    """

    def __init__(self) -> None:
        self._stages: List[Dict[str, Any]] = []

    def add(self, stage: str, result: str, detail: str = "", decisive: bool = False,
            extra: Dict[str, Any] = None) -> None:
        """Record one stage outcome in order."""
        entry = {
            "stage": stage,
            "result": result,
            "detail": detail,
            "decisive": bool(decisive),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            entry.update(extra)
        self._stages.append(entry)

    @property
    def stages(self) -> List[Dict[str, Any]]:
        return list(self._stages)

    def build(self, *, decision_id: str, agent_id: str, action_requested: str,
              verdict: str, session_id: str = "", risk_factors: Dict[str, Any] = None,
              policy_id: str = "", decisive_stage: str = "") -> DecisionTrace:
        """Assemble a DecisionTrace from the accumulated stages.

        If decisive_stage is not given, the last stage flagged decisive (or the
        last block stage) is used.
        """
        if not decisive_stage:
            decisive = [s for s in self._stages if s.get("decisive")]
            if decisive:
                decisive_stage = decisive[-1]["stage"]
            else:
                blocks = [s for s in self._stages if s.get("result") == RESULT_BLOCK]
                decisive_stage = blocks[-1]["stage"] if blocks else ""
        return DecisionTrace(
            decision_id=decision_id,
            agent_id=agent_id,
            action_requested=action_requested,
            verdict=verdict,
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            aarm_decision=to_aarm(verdict),
            decisive_stage=decisive_stage,
            stages=self.stages,
            risk_factors=dict(risk_factors or {}),
            policy_id=policy_id,
        )


class DecisionTraceManager:
    """Signs, stores, fetches, and verifies decision traces."""

    @staticmethod
    def sign_and_store(trace: DecisionTrace, table, kms_client=None) -> Optional[DecisionTrace]:
        """Hash + KMS-sign the trace, then write it to DecisionTraceTable.

        Stores the canonical trace JSON as a string plus the hash/signature, so
        the signed bytes are preserved exactly (DynamoDB would otherwise
        normalize numbers and break verification). Returns the signed trace, or
        None on write failure. Never raises; best-effort so a trace outage cannot
        alter a verdict.
        """
        try:
            import hashlib
            canonical = _canonical_body(trace.to_dict())
            trace.trace_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            sig, kid, alg = sign_digest(trace.trace_hash, kms_client)
            trace.signature, trace.signing_key_id, trace.signing_algorithm = sig, kid, alg
            if table is not None:
                # Store the exact signed string + a few queryable attributes.
                table.put_item(Item={
                    "decision_id": trace.decision_id,
                    "agent_id": trace.agent_id,
                    "verdict": trace.verdict,
                    "timestamp": trace.timestamp,
                    "canonical_body": canonical,
                    "trace_hash": trace.trace_hash,
                    "signature": sig,
                    "signing_key_id": kid,
                    "signing_algorithm": alg,
                })
            logger.info(json.dumps({
                "audit_event": "decision_trace_stored",
                "decision_id": trace.decision_id,
                "decisive_stage": trace.decisive_stage,
                "signed": bool(sig),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return trace
        except Exception as exc:
            logger.error(json.dumps({
                "audit_event": "decision_trace_store_failed",
                "decision_id": getattr(trace, "decision_id", ""),
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

    @staticmethod
    def get_trace(decision_id: str, table) -> Optional[Dict[str, Any]]:
        """Fetch a stored trace by decision_id as a full dict, or None.

        Rehydrates the trace content from the stored canonical JSON string and
        attaches hash/signature so callers get one dict to render and verify.
        """
        try:
            resp = table.get_item(Key={"decision_id": decision_id})
            item = resp.get("Item")
            if not item:
                return None
            canonical = item.get("canonical_body")
            if canonical:
                body = json.loads(canonical)
                body["trace_hash"] = item.get("trace_hash", "")
                body["signature"] = item.get("signature", "")
                body["signing_key_id"] = item.get("signing_key_id", "")
                body["signing_algorithm"] = item.get("signing_algorithm", "")
                body["_canonical_body"] = canonical
                return body
            return item
        except Exception as exc:
            logger.error(json.dumps({
                "audit_event": "decision_trace_fetch_failed",
                "decision_id": decision_id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

    @staticmethod
    def verify_trace(trace_body: Dict[str, Any], public_key_pem: bytes = None, kms_client=None) -> bool:
        """Verify a stored trace's signature over its canonical body.

        Uses the preserved canonical JSON string (`_canonical_body`) when present
        so verification is over the exact signed bytes; otherwise recomputes from
        the dict. Returns False for an unsigned trace.
        """
        import base64
        import hashlib
        sig_b64 = trace_body.get("signature", "")
        if not sig_b64:
            return False
        canonical = trace_body.get("_canonical_body")
        if canonical is None:
            canonical = _canonical_body(trace_body)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if kms_client is not None:
            try:
                resp = kms_client.verify(
                    KeyId=trace_body.get("signing_key_id", ""),
                    Message=bytes.fromhex(digest), MessageType="DIGEST",
                    Signature=base64.b64decode(sig_b64),
                    SigningAlgorithm=trace_body.get("signing_algorithm", "ECDSA_SHA_256"),
                )
                return bool(resp.get("SignatureValid", False))
            except Exception:
                return False
        if public_key_pem is not None:
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
                from cryptography.hazmat.primitives.asymmetric import ec, utils as au
                from cryptography.hazmat.primitives import hashes
                from cryptography.exceptions import InvalidSignature
                try:
                    pub = load_pem_public_key(public_key_pem)
                except Exception:
                    pub = load_der_public_key(public_key_pem)
                try:
                    pub.verify(base64.b64decode(sig_b64), bytes.fromhex(digest),
                               ec.ECDSA(au.Prehashed(hashes.SHA256())))
                    return True
                except InvalidSignature:
                    return False
            except ImportError:
                return False
        return False
