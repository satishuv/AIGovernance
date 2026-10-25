"""Evidence for delegated authority: hash-chained, signed, secret-free.

Every authority lifecycle (one decision) produces an ordered chain:
  decision -> approval (if any) -> grant_minted -> grant_consumed ->
  credential_issued -> execution_completed (or denial / revocation)

Each record carries prev_hash and record_hash (SHA-256 over canonical JSON)
and an ECDSA signature over record_hash. Changing, removing, reordering or
relocating a record breaks verification. Records reference credentials only
by credential_reference.

Secret-shaped values never reach evidence, and they never stop a record
from being written either: a field whose name marks a credential is
dropped, and a value that looks like a credential (an AWS access key id or a
JWT) is replaced by a fixed marker carrying its SHA-256 prefix. The record
lists what was masked. A caller cannot suppress its own audit record by
putting a secret-shaped string in an argument (audit 2026-10-23, run-2).

Append protocol (S3 backend):
  * one object per (agent, chain, seq): <prefix><agent_id>/<chain_id>/<seq:010d>.json,
    written with put_object IfNoneMatch='*', so S3 refuses the write when the key
    already exists. The write itself is the atomic claim on the sequence number: two
    concurrent appends can never both hold seq N, and no record is ever overwritten.
  * every fallible step (masking, hashing, signing) runs before that one write, so a
    refused or failed append leaves nothing behind and never strands a sequence number.
  * the next seq is found from the chain tail, not by reading the whole chain: a
    bounded per-process cache of each chain's tail, or a doubling-then-binary probe of
    key existence (O(log n) HEAD requests). An append reads one record, never n.
  * on contention the writer reads the record that won and chains onto it, with a
    bounded number of attempts.
Chains written with the earlier <seq:04d>-<event_type>.json layout keep being read
and verified (ordered numerically); new appends to such a chain go on reading the
listing, which is bounded by MAX_CHAIN_RECORDS.

Identifiers that shape a key (agent_id, chain_id) must match a fixed character
set with no '/', so one logical chain owns exactly one key prefix.

verify_chain checks contiguous sequence numbers from 1, links, record hashes,
signatures, and, when the caller says which chain it asked for, that every
record names that agent and chain. An authentic record copied to another
chain's location fails verification.

Backends: S3 (the stack's evidence bucket) or in-memory (unit tests).
"""

import hashlib
import json
import logging
import random
import re
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from request_canonicalization import canonical_json, to_json_safe

logger = logging.getLogger(__name__)

GENESIS = "GENESIS"
EXCLUDED = ("record_hash", "signature", "signing_key_id", "signature_algorithm")

# A chain id or agent id becomes an S3 key segment and a listing prefix: letters, digits and
# . _ : # @ = + - only, no '/', at most 160 characters.
_KEY_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:#@=+-]{0,159}")
# A chain may not grow past this many records. Appending to a full chain fails closed (the
# caller treats it as an evidence failure), so no chain can be grown without bound.
MAX_CHAIN_RECORDS = 1_000_000
# Strings longer than this are stored as a prefix plus the SHA-256 of the whole value, so a
# caller cannot make one record (or the scans over it) arbitrarily large.
MAX_FIELD_CHARS = 4096
_APPEND_ATTEMPTS = 8

_SECRET_KEYS = ("secret", "session_token", "access_token", "refresh_token", "password",
                "aws_access_key_id", "private_key", "_secret")
# Linear-time patterns. A match must start where no base64url character precedes it, so inside
# one dot-free run of base64url characters only the first position can start a match, and that
# attempt is bounded: a long eyJ...eyJ... run is scanned once, not once per start position. Once
# the header and the start of the payload match, the rest of the token (payload and signature) is
# included, so masking replaces the whole token.
_SECRET_VALUES = (re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
                  re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,}"
                             r"(?:\.[A-Za-z0-9_-]*)?"))
MASK = "[masked-credential sha256:{}]"


class EvidenceSecretLeak(ValueError):
    """A record looked like it contained a credential and was not written."""


class EvidenceSeqTaken(RuntimeError):
    """A concurrent append already holds this sequence number; nothing of ours was written."""


class EvidenceChainFull(RuntimeError):
    """The chain reached MAX_CHAIN_RECORDS; appending fails closed."""


class InvalidEvidenceKey(ValueError):
    """An agent id or chain id cannot be used as an evidence key segment."""


def validate_key_segment(value: str, what: str) -> str:
    if not isinstance(value, str) or not _KEY_SEGMENT.fullmatch(value):
        raise InvalidEvidenceKey(f"{what} {value!r} is not a valid evidence key segment "
                                 "(letters, digits and . _ : # @ = + - only, no '/', at most 160 characters)")
    return value


def safe_key_segment(value: str, prefix: str) -> str:
    """value if it is a valid key segment, else prefix + the SHA-256 of value (fixed shape)."""
    if isinstance(value, str) and _KEY_SEGMENT.fullmatch(value):
        return value
    digest = hashlib.sha256(str(value).encode("utf-8", "surrogatepass")).hexdigest()
    return f"{prefix}{digest}"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def assert_no_secrets(obj: Any, path: str = "") -> None:
    """Raise EvidenceSecretLeak if obj carries a credential-named field or a credential-shaped value."""
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


def scrub(obj: Any, path: str = "", masked: Optional[List[str]] = None) -> Tuple[Any, List[str]]:
    """A copy of obj with credentials removed, credential-shaped values masked and long strings capped.

    Returns (clean, masked_paths). Never raises on content: the record is always writable.
    """
    masked = [] if masked is None else masked
    if isinstance(obj, dict):
        out = {}
        for key, val in obj.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_KEYS) and lowered != "secret_preview":
                masked.append(f"{path}{key}")
                continue
            out[key] = scrub(val, f"{path}{key}.", masked)[0]
        return out, masked
    if isinstance(obj, (list, tuple)):
        return [scrub(v, path, masked)[0] for v in obj], masked
    if isinstance(obj, str):
        text = obj
        if len(text) > MAX_FIELD_CHARS:
            text = f"{text[:256]}...[truncated {len(obj)} chars sha256:{_digest(obj)}]"
            masked.append(f"{path.rstrip('.')} (truncated)")
        for pattern in _SECRET_VALUES:
            if pattern.search(text):
                text = pattern.sub(lambda m: MASK.format(_digest(m.group(0))[:16]), text)
                masked.append(path.rstrip("."))
        return text, masked
    return obj, masked


def record_hash(record: Dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in EXCLUDED}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _seq_of(record: Dict[str, Any]) -> int:
    try:
        return int(record.get("seq", 0))
    except (TypeError, ValueError):
        return 0


class MemoryEvidenceBackend:
    def __init__(self):
        self._records: Dict[Tuple[str, str], Dict[int, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def append(self, agent_id: str, chain_id: str, record: Dict[str, Any]) -> str:
        with self._lock:
            chain = self._records.setdefault((agent_id, chain_id), {})
            if record["seq"] in chain:
                raise EvidenceSeqTaken(f"{chain_id}/{record['seq']}")
            chain[record["seq"]] = json.loads(json.dumps(record))
        return f"memory://{agent_id}/{chain_id}/{record['seq']:010d}"

    def tail(self, agent_id: str, chain_id: str) -> Optional[Dict[str, Any]]:
        chain = self._records.get((agent_id, chain_id)) or {}
        return dict(chain[max(chain)]) if chain else None

    def chain(self, agent_id: str, chain_id: str) -> List[Dict[str, Any]]:
        chain = self._records.get((agent_id, chain_id)) or {}
        return [dict(chain[s]) for s in sorted(chain)]

    def for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return [dict(r) for (a, _), chain in self._records.items() if a == agent_id
                for r in (chain[s] for s in sorted(chain))]


class _TailCache:
    """Bounded, thread-safe LRU of (agent, chain) -> last record this process wrote or read."""

    def __init__(self, capacity: int = 4096):
        self._capacity = capacity
        self._items: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Tuple[str, str]) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._items.get(key)
            if item is not None:
                self._items.move_to_end(key)
            return item

    def put(self, key: Tuple[str, str], record: Dict[str, Any]) -> None:
        with self._lock:
            current = self._items.get(key)
            if current is None or _seq_of(record) >= _seq_of(current):
                self._items[key] = record
                self._items.move_to_end(key)
            while len(self._items) > self._capacity:
                self._items.popitem(last=False)


def _client_error(exc: Exception) -> Tuple[str, Optional[int]]:
    resp = getattr(exc, "response", None) or {}
    return str(resp.get("Error", {}).get("Code", "")), resp.get("ResponseMetadata", {}).get("HTTPStatusCode")


def _is_write_contention(exc: Exception) -> bool:
    """S3 refused a conditional put: the key exists (412) or a competing conditional put is in flight (409)."""
    code, status = _client_error(exc)
    return code in ("PreconditionFailed", "ConditionalRequestConflict") or status in (409, 412)


def _is_missing(exc: Exception) -> bool:
    code, status = _client_error(exc)
    return code in ("404", "NoSuchKey", "NotFound") or status == 404


class S3EvidenceBackend:
    """Evidence records in S3, one object per (agent, chain, seq).

    Retention comes from the bucket's default Object Lock rule. Writers deliberately hold no
    s3:PutObjectRetention: with it a writer could give a new record a shorter retention than the
    bucket default.
    """

    def __init__(self, s3_client, bucket: str, prefix: str = "evidence/delegated-authority/",
                 tail_cache: Optional[_TailCache] = None):
        self._s3 = s3_client
        self._bucket = bucket
        self._prefix = prefix
        self._tails = tail_cache or _TailCache()

    # ------------------------------------------------------------- keys
    def _chain_prefix(self, agent_id: str, chain_id: str) -> str:
        return f"{self._prefix}{agent_id}/{chain_id}/"

    def _key(self, agent_id: str, chain_id: str, record: Dict[str, Any]) -> str:
        return f"{self._chain_prefix(agent_id, chain_id)}{int(record['seq']):010d}.json"

    def _seq_key(self, agent_id: str, chain_id: str, seq: int) -> str:
        return f"{self._chain_prefix(agent_id, chain_id)}{seq:010d}.json"

    # ------------------------------------------------------------ writes
    def append(self, agent_id: str, chain_id: str, record: Dict[str, Any]) -> str:
        key = self._key(agent_id, chain_id, record)
        try:
            # IfNoneMatch='*': S3 refuses the put when the key already has a current version, so this
            # one write is the atomic claim on the seq and can never overwrite an earlier record.
            self._s3.put_object(Bucket=self._bucket, Key=key,
                                Body=json.dumps(record, sort_keys=True).encode("utf-8"),
                                ContentType="application/json", IfNoneMatch="*")
        except Exception as exc:
            if _is_write_contention(exc):
                raise EvidenceSeqTaken(key) from exc
            raise
        self._tails.put((agent_id, chain_id), dict(record))
        return f"s3://{self._bucket}/{key}"

    # ------------------------------------------------------------- reads
    def _exists(self, key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return True
        except Exception as exc:
            if _is_missing(exc):
                return False
            raise

    def _get(self, key: str) -> Dict[str, Any]:
        return json.loads(self._s3.get_object(Bucket=self._bucket, Key=key)["Body"].read())

    def _list(self, prefix: str) -> List[str]:
        keys, token = [], None
        while True:
            kwargs = {"Bucket": self._bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kwargs)
            keys.extend(o["Key"] for o in resp.get("Contents", []))
            if not resp.get("IsTruncated"):
                return keys
            token = resp.get("NextContinuationToken")

    def _load(self, keys: List[str]) -> List[Dict[str, Any]]:
        return [self._get(k) for k in keys]

    def _probe_tail_seq(self, agent_id: str, chain_id: str, start: int) -> int:
        """Highest seq with an existing new-layout key, found with O(log n) existence checks.

        Records are written contiguously from 1 (each seq is claimed only after its predecessor
        exists), so existence is monotone in seq and a doubling-then-binary search finds the end.
        """
        if not self._exists(self._seq_key(agent_id, chain_id, max(start, 1))):
            if start <= 1:
                return 0
            low, high = 0, start          # seq `start` absent: the end is below it
        else:
            low, step = max(start, 1), 1
            while True:
                probe = low + step
                if probe > MAX_CHAIN_RECORDS:
                    high = MAX_CHAIN_RECORDS + 1
                    break
                if self._exists(self._seq_key(agent_id, chain_id, probe)):
                    low, step = probe, step * 2
                else:
                    high = probe
                    break
        while high - low > 1:
            mid = (low + high) // 2
            if self._exists(self._seq_key(agent_id, chain_id, mid)):
                low = mid
            else:
                high = mid
        return low

    def tail(self, agent_id: str, chain_id: str) -> Optional[Dict[str, Any]]:
        """The chain's last record, reading one record (not the whole chain)."""
        cached = self._tails.get((agent_id, chain_id))
        start = _seq_of(cached) if cached else 1
        seq = self._probe_tail_seq(agent_id, chain_id, start)
        if seq == 0:
            # No new-layout record: a chain written before the layout change, or an empty chain.
            records = self.chain(agent_id, chain_id)
            last = max(records, key=_seq_of) if records else None
        elif cached is not None and _seq_of(cached) == seq:
            last = cached
        else:
            last = self._get(self._seq_key(agent_id, chain_id, seq))
        if last is not None:
            self._tails.put((agent_id, chain_id), last)
        return last

    def chain(self, agent_id: str, chain_id: str) -> List[Dict[str, Any]]:
        prefix = self._chain_prefix(agent_id, chain_id)
        # Only this chain's own objects: a key with a further '/' would belong to a nested prefix.
        keys = [k for k in self._list(prefix) if "/" not in k[len(prefix):]]
        return sorted(self._load(keys), key=_seq_of)

    def for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return self._load(sorted(self._list(f"{self._prefix}{agent_id}/")))

    def overwritten_keys(self, agent_id: str, chain_id: str) -> List[str]:
        """Auditor reconciliation for chains written before conditional puts: a key with more than one
        version was overwritten, and only its current version is listed. Needs s3:ListBucketVersions
        (AuditorReadOnlyRole); the writer roles do not hold it."""
        counts: Dict[str, int] = {}
        kwargs: Dict[str, Any] = {"Bucket": self._bucket, "Prefix": self._chain_prefix(agent_id, chain_id)}
        while True:
            resp = self._s3.list_object_versions(**kwargs)
            for version in resp.get("Versions", []):
                counts[version["Key"]] = counts.get(version["Key"], 0) + 1
            if not resp.get("IsTruncated"):
                return sorted(k for k, n in counts.items() if n > 1)
            kwargs.update(KeyMarker=resp["NextKeyMarker"], VersionIdMarker=resp["NextVersionIdMarker"])


class EvidenceLedger:
    def __init__(self, signer, backend):
        self._signer = signer
        self._backend = backend

    @property
    def signer(self):
        return self._signer

    def _tail(self, agent_id: str, chain_id: str) -> Optional[Dict[str, Any]]:
        tail = getattr(self._backend, "tail", None)
        if tail is not None:
            return tail(agent_id, chain_id)
        existing = self._backend.chain(agent_id, chain_id)
        return max(existing, key=_seq_of) if existing else None

    def record(self, *, agent_id: str, chain_id: str, event_type: str, **fields: Any) -> Dict[str, Any]:
        validate_key_segment(agent_id, "agent_id")
        validate_key_segment(chain_id, "chain_id")
        body, masked = scrub({k: v for k, v in fields.items() if v is not None})
        body = to_json_safe(body)
        for attempt in range(_APPEND_ATTEMPTS):
            prev = self._tail(agent_id, chain_id)
            seq = (_seq_of(prev) + 1) if prev else 1
            if seq > MAX_CHAIN_RECORDS:
                raise EvidenceChainFull(f"chain {chain_id} holds {MAX_CHAIN_RECORDS} records; failing closed")
            record = to_json_safe({
                "evidence_id": "ev-" + uuid.uuid4().hex[:16],
                "chain_id": chain_id,
                "seq": seq,
                "event_type": event_type,
                "agent_id": agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "prev_hash": prev["record_hash"] if prev else GENESIS,
                **body,
            })
            if masked:
                record["masked_fields"] = sorted(set(masked))
            # Defense in depth: scrub() removed everything this would refuse.
            assert_no_secrets(record)
            record["record_hash"] = record_hash(record)
            record["signature"] = self._signer.sign(record["record_hash"])
            record["signing_key_id"] = self._signer.key_id
            record["signature_algorithm"] = self._signer.algorithm
            try:
                location = self._backend.append(agent_id, chain_id, dict(record))
            except EvidenceSeqTaken:
                # A concurrent append took this seq first: read the new tail and chain onto it. If our own
                # put landed but its response was lost, the retry adds this event once more at the next
                # seq, linked and verifiable: a duplicate, never a loss.
                # Retry jitter only; nothing security-relevant depends on this value.
                time.sleep(random.uniform(0, 0.01 * (attempt + 1)))  # nosec B311
                continue
            record["location"] = location
            return record
        raise EvidenceSeqTaken(f"chain {chain_id}: no free evidence seq after {_APPEND_ATTEMPTS} attempts")

    def chain(self, agent_id: str, chain_id: str) -> List[Dict[str, Any]]:
        return self._backend.chain(agent_id, chain_id)

    def for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return self._backend.for_agent(agent_id)

    def verify_chain(self, records: List[Dict[str, Any]], *, agent_id: Optional[str] = None,
                     chain_id: Optional[str] = None) -> Tuple[bool, str]:
        """Recompute seqs, hashes, links and signatures for a chain.

        Sequence numbers must run 1..n with no gap or repeat. When agent_id or chain_id is given (the
        location the records were read from), every record must name it: a signature covers the body,
        and the body names its agent and chain, so a record copied to another location fails here.
        """
        if not records:
            return False, "no evidence records"
        prev: Optional[Dict[str, Any]] = None
        for rec in sorted(records, key=_seq_of):
            expected_seq = (_seq_of(prev) + 1) if prev else 1
            if _seq_of(rec) != expected_seq:
                if prev is not None and _seq_of(rec) == _seq_of(prev):
                    return False, f"two evidence records share seq {_seq_of(rec)} (concurrent append collision)"
                return False, f"evidence record {expected_seq} is missing"
            if agent_id is not None and rec.get("agent_id") != agent_id:
                return False, f"record {_seq_of(rec)} belongs to agent {rec.get('agent_id')!r}, not {agent_id!r}"
            if chain_id is not None and rec.get("chain_id") != chain_id:
                return False, f"record {_seq_of(rec)} belongs to chain {rec.get('chain_id')!r}, not {chain_id!r}"
            expected_prev = prev["record_hash"] if prev else GENESIS
            if rec.get("prev_hash") != expected_prev:
                return False, f"record {_seq_of(rec)} is not linked to its predecessor"
            if record_hash({k: v for k, v in rec.items() if k != "location"}) != rec.get("record_hash"):
                return False, f"record {_seq_of(rec)} was modified after it was written"
            if rec.get("signing_key_id") != self._signer.key_id:
                return False, f"record {_seq_of(rec)} was not signed by the configured evidence key"
            verdict = _signature_verdict(self._signer, rec["record_hash"], rec.get("signature", ""))
            if verdict is None:
                return False, (f"record {_seq_of(rec)} signature could not be checked (the signing key's "
                               "public key or KMS Verify is not available to this reader)")
            if not verdict:
                return False, f"record {_seq_of(rec)} signature does not verify"
            prev = rec
        return True, f"{len(records)} records: sequence contiguous, hashes linked, signatures verified"


def _signature_verdict(signer, hex_digest: str, signature: str) -> Optional[bool]:
    """True/False for a checked signature; None when the signer could not perform the check."""
    check = getattr(signer, "check", None)
    if check is not None:
        return check(hex_digest, signature)
    return bool(signer.verify(hex_digest, signature))
