"""Evidence for delegated authority: hash-chained, signed, secret-free.

Every authority lifecycle (one decision) produces an ordered chain:
  decision -> approval (if any) -> grant_minted -> grant_consumed ->
  credential_issued -> execution_completed (or denial / revocation)

Each record carries prev_hash and record_hash (SHA-256 over canonical JSON)
and an ECDSA signature over record_hash. Changing, removing or reordering a
record breaks verification. Records reference credentials only by
credential_reference; a guard refuses to write anything that looks like a
secret, so a token can never land in evidence.

Backends: S3 (the stack's evidence bucket) or in-memory (unit tests).
Layout: <prefix><agent_id>/<chain_id>/<seq>-<event_type>.json
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from request_canonicalization import canonical_json, to_json_safe

GENESIS = "GENESIS"
EXCLUDED = ("record_hash", "signature", "signing_key_id", "signature_algorithm")

_SECRET_KEYS = ("secret", "session_token", "access_token", "refresh_token", "password",
                "aws_access_key_id", "private_key", "_secret")
_SECRET_VALUES = (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
                  re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}"))


class EvidenceSecretLeak(ValueError):
    """A record looked like it contained a credential and was not written."""


def assert_no_secrets(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_KEYS) and lowered != "secret_preview":
                raise EvidenceSecretLeak(f"evidence field {path}{key} looks like a secret")
            assert_no_secrets(val, f"{path}{key}.")
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            assert_no_secrets(item, path)
    elif isinstance(obj, str):
        for pattern in _SECRET_VALUES:
            if pattern.search(obj):
                raise EvidenceSecretLeak(f"evidence value at {path} looks like a credential")


def record_hash(record: Dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in EXCLUDED}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class MemoryEvidenceBackend:
    def __init__(self):
        self._records: Dict[str, List[Dict[str, Any]]] = {}

    def append(self, agent_id: str, chain_id: str, record: Dict[str, Any]) -> str:
        self._records.setdefault(chain_id, []).append(json.loads(json.dumps(record)))
        return f"memory://{agent_id}/{chain_id}/{record['seq']:04d}"

    def chain(self, agent_id: str, chain_id: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._records.get(chain_id, [])]

    def for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return [dict(r) for rs in self._records.values() for r in rs if r.get("agent_id") == agent_id]


class S3EvidenceBackend:
    def __init__(self, s3_client, bucket: str, prefix: str = "evidence/delegated-authority/"):
        self._s3 = s3_client
        self._bucket = bucket
        self._prefix = prefix

    def _key(self, agent_id: str, chain_id: str, record: Dict[str, Any]) -> str:
        return f"{self._prefix}{agent_id}/{chain_id}/{record['seq']:04d}-{record['event_type']}.json"

    def append(self, agent_id: str, chain_id: str, record: Dict[str, Any]) -> str:
        key = self._key(agent_id, chain_id, record)
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=json.dumps(record, sort_keys=True).encode("utf-8"),
                            ContentType="application/json")
        return f"s3://{self._bucket}/{key}"

    def _list(self, prefix: str) -> List[str]:
        keys, token = [], None
        while True:
            kwargs = {"Bucket": self._bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kwargs)
            keys.extend(o["Key"] for o in resp.get("Contents", []))
            if not resp.get("IsTruncated"):
                return sorted(keys)
            token = resp.get("NextContinuationToken")

    def _load(self, keys: List[str]) -> List[Dict[str, Any]]:
        return [json.loads(self._s3.get_object(Bucket=self._bucket, Key=k)["Body"].read()) for k in keys]

    def chain(self, agent_id: str, chain_id: str) -> List[Dict[str, Any]]:
        return self._load(self._list(f"{self._prefix}{agent_id}/{chain_id}/"))

    def for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return self._load(self._list(f"{self._prefix}{agent_id}/"))


class EvidenceLedger:
    def __init__(self, signer, backend):
        self._signer = signer
        self._backend = backend

    @property
    def signer(self):
        return self._signer

    def record(self, *, agent_id: str, chain_id: str, event_type: str, **fields: Any) -> Dict[str, Any]:
        existing = self._backend.chain(agent_id, chain_id)
        prev = existing[-1] if existing else None
        record = to_json_safe({
            "evidence_id": "ev-" + uuid.uuid4().hex[:16],
            "chain_id": chain_id,
            "seq": (prev["seq"] + 1) if prev else 1,
            "event_type": event_type,
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": prev["record_hash"] if prev else GENESIS,
            **{k: v for k, v in fields.items() if v is not None},
        })
        assert_no_secrets(record)
        record["record_hash"] = record_hash(record)
        record["signature"] = self._signer.sign(record["record_hash"])
        record["signing_key_id"] = self._signer.key_id
        record["signature_algorithm"] = self._signer.algorithm
        record["location"] = None
        location = self._backend.append(agent_id, chain_id, {k: v for k, v in record.items() if k != "location"})
        record["location"] = location
        return record

    def chain(self, agent_id: str, chain_id: str) -> List[Dict[str, Any]]:
        return self._backend.chain(agent_id, chain_id)

    def for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return self._backend.for_agent(agent_id)

    def verify_chain(self, records: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Recompute hashes, links and signatures for an ordered chain."""
        if not records:
            return False, "no evidence records"
        prev: Optional[Dict[str, Any]] = None
        for rec in sorted(records, key=lambda r: r["seq"]):
            expected_prev = prev["record_hash"] if prev else GENESIS
            if rec.get("prev_hash") != expected_prev:
                return False, f"record {rec['seq']} is not linked to its predecessor"
            if record_hash({k: v for k, v in rec.items() if k != "location"}) != rec.get("record_hash"):
                return False, f"record {rec['seq']} was modified after it was written"
            if rec.get("signing_key_id") != self._signer.key_id or \
                    not self._signer.verify(rec["record_hash"], rec.get("signature", "")):
                return False, f"record {rec['seq']} signature does not verify"
            prev = rec
        return True, f"{len(records)} records: hashes linked, signatures verified"
