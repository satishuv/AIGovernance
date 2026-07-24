"""Shared cryptographic signing for tamper-evident records (AARM R5/R6).

One signer, reused by the evidence pipeline and the decision-trace store, so the
two never diverge. Signs a SHA-256 digest with a KMS asymmetric key
(ECDSA_SHA_256, MessageType=DIGEST) producing an offline-verifiable,
non-repudiable signature bound to the signing key.

Signing is a no-op when no KMS client or signing key is configured (e.g. local
tests) -- the SHA-256 hash / hash chain still provides tamper-evidence in that
case, and callers must not treat "unsigned" as failure.
"""

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

# KMS key id shared with the evidence pipeline. Same key signs evidence and
# traces, so no new key/grant is needed for decision traces.
EVIDENCE_SIGNING_KEY_ID = os.environ.get("EVIDENCE_SIGNING_KEY_ID", "")
SIGNING_ALGORITHM = "ECDSA_SHA_256"

# Fields excluded from a record's SHA-256 hash: the hash cannot cover itself,
# and the signature is derived from the hash so it cannot be an input to it.
HASH_EXCLUDED_FIELDS = ("record_hash", "trace_hash", "signature", "signing_key_id", "signing_algorithm")


def compute_hash(record_dict: Dict[str, Any]) -> str:
    """SHA-256 (hex) over a canonical JSON record, excluding hash+signature fields."""
    filtered = {k: v for k, v in record_dict.items() if k not in HASH_EXCLUDED_FIELDS}
    canonical = json.dumps(filtered, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_digest(hex_digest: str, kms_client, key_id: str = None) -> Tuple[str, str, str]:
    """Sign a hex SHA-256 digest with a KMS asymmetric key.

    Returns (signature_b64, signing_key_id, signing_algorithm). Returns
    ("", "", "") when signing is not configured or fails -- never raises, so a
    signing outage cannot block the caller's write path.
    """
    kid = key_id or EVIDENCE_SIGNING_KEY_ID
    if kms_client is None or not kid or not hex_digest:
        return "", "", ""
    try:
        resp = kms_client.sign(
            KeyId=kid,
            Message=bytes.fromhex(hex_digest),
            MessageType="DIGEST",
            SigningAlgorithm=SIGNING_ALGORITHM,
        )
        return base64.b64encode(resp["Signature"]).decode("ascii"), kid, SIGNING_ALGORITHM
    except Exception as exc:
        logger.error(json.dumps({
            "audit_event": "record_signing_failed",
            "error": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        return "", "", ""
