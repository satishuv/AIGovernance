"""Evidence ledger and signer fixes from the 2026-10-23 audit (run-2).

Each test names the audit record it guards:
  evidence-record-append-nonatomic-seq-unconditional-put   concurrent appends never share a seq
  evidence-ledger-record-unbounded-per-append-chain-scan   an append reads one record, not the chain
  evidence-s3-seq-key-lexical-order-and-reuse              sequence numbers past 9999 stay unique
  evidence-s3-chain-id-nested-key-prefix-redirect           a chain id cannot nest under another chain
  evidence-secret-scan-agent-input-suppresses-denial-record secret-shaped input is masked, not fatal
  gateway.denial-reason.secret-shape-regex.superlinear      the credential patterns scan linearly
  signed-records-not-bound-to-requested-chain               a record copied elsewhere fails verify
  evidence-signatures-verifiable-only-by-writers            a refused check is not "invalid"
  per-returned-trace-kms-verify-fanout                      verified signatures are not re-checked
"""

import base64
import hashlib
import json
import os
import threading
import time
from unittest.mock import patch

import pytest

from tests.authority_test_support import FAKE_ENV, REGION, offline_demo

import authority_evidence as ae  # noqa: E402  (path set by authority_test_support)
from delegated_authority import KmsGrantSigner, LocalDemoSigner  # noqa: E402

BUCKET = "evidence-test"   # S3 bucket names are at least 3 characters (moto validates)


@pytest.fixture
def s3_ledger():
    import boto3
    from moto import mock_aws

    with patch.dict(os.environ, FAKE_ENV), mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        # S3 evaluates IfNoneMatch and applies the write as one step; moto does not serialize
        # concurrent calls, so a lock models the S3 guarantee (as serialize_conditional_writes does
        # for DynamoDB) and the concurrency test checks the ledger's logic, deterministically.
        lock = threading.Lock()
        original = s3.put_object

        def put_object(**kwargs):
            with lock:
                return original(**kwargs)

        s3.put_object = put_object
        yield s3, ae.EvidenceLedger(LocalDemoSigner(), ae.S3EvidenceBackend(s3, BUCKET))


class Counter:
    def __init__(self, s3):
        self.calls = []
        s3.meta.events.register("before-call.s3", lambda model, **_: self.calls.append(model.name))

    def count(self, name):
        return sum(1 for c in self.calls if c == name)


# ------------------------------------------------------------------ atomic appends
def test_concurrent_appends_take_distinct_sequence_numbers(s3_ledger):
    _, ledger = s3_ledger
    errors = []

    def append(i):
        try:
            # A fresh backend per writer: no shared tail cache, as with separate Lambda instances.
            writer = ae.EvidenceLedger(ledger.signer, ae.S3EvidenceBackend(ledger._backend._s3, BUCKET))
            writer.record(agent_id="agent-a", chain_id="gateway-x", event_type="gateway_deny", n=i)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=append, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    records = ledger.chain("agent-a", "gateway-x")
    assert [r["seq"] for r in records] == list(range(1, 13))
    ok, detail = ledger.verify_chain(records, agent_id="agent-a", chain_id="gateway-x")
    assert ok, detail


def test_a_taken_sequence_number_is_never_overwritten(s3_ledger):
    s3, ledger = s3_ledger
    first = ledger.record(agent_id="agent-a", chain_id="c", event_type="decision")
    stale = ae.S3EvidenceBackend(s3, BUCKET)
    with pytest.raises(ae.EvidenceSeqTaken):
        stale.append("agent-a", "c", {**first, "event_type": "forged"})
    stored = json.loads(s3.get_object(Bucket=BUCKET, Key=first["location"].split("/", 3)[3])["Body"].read())
    assert stored["event_type"] == "decision"


def test_verify_chain_rejects_a_gap_and_a_repeated_sequence_number(s3_ledger):
    _, ledger = s3_ledger
    for _ in range(3):
        ledger.record(agent_id="agent-a", chain_id="c", event_type="decision")
    records = ledger.chain("agent-a", "c")
    assert ledger.verify_chain(records[:1] + records[2:])[0] is False
    assert "share seq" in ledger.verify_chain(records + [dict(records[1])])[1]


# ------------------------------------------------------------------ bounded append cost
def test_an_append_does_not_read_the_whole_chain(s3_ledger):
    s3, ledger = s3_ledger
    for _ in range(40):
        ledger.record(agent_id="agent-a", chain_id="gateway-x", event_type="gateway_deny")
    counter = Counter(s3)
    ledger.record(agent_id="agent-a", chain_id="gateway-x", event_type="gateway_deny")
    assert counter.count("GetObject") == 0 and counter.count("ListObjectsV2") == 0
    assert counter.count("HeadObject") <= 2 and counter.count("PutObject") == 1


def test_a_cold_writer_finds_the_tail_with_logarithmic_reads(s3_ledger):
    s3, ledger = s3_ledger
    for _ in range(100):
        ledger.record(agent_id="agent-a", chain_id="gateway-x", event_type="gateway_deny")
    cold = ae.EvidenceLedger(ledger.signer, ae.S3EvidenceBackend(s3, BUCKET))
    counter = Counter(s3)
    rec = cold.record(agent_id="agent-a", chain_id="gateway-x", event_type="gateway_deny")
    assert rec["seq"] == 101
    assert counter.count("GetObject") == 1 and counter.count("ListObjectsV2") == 0
    assert counter.count("HeadObject") <= 16      # about 2 log2(100)


def test_sequence_numbers_past_9999_stay_unique():
    backend = ae.S3EvidenceBackend(None, BUCKET)
    keys = [backend._seq_key("a", "c", s) for s in (9_999, 10_000, 10_001)]
    assert keys == sorted(keys)                    # lexical order is numeric order
    assert len(set(keys)) == 3


def test_legacy_four_digit_chains_keep_verifying_and_appending():
    import boto3
    from moto import mock_aws

    with patch.dict(os.environ, FAKE_ENV), mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        signer = LocalDemoSigner()
        ledger = ae.EvidenceLedger(signer, ae.S3EvidenceBackend(s3, BUCKET))
        prev = ae.GENESIS
        for seq in (1, 2):   # the earlier <seq:04d>-<event_type>.json layout
            rec = {"evidence_id": f"ev-{seq}", "chain_id": "c", "seq": seq, "event_type": "decision",
                   "agent_id": "a", "timestamp": "2026-10-01T00:00:00+00:00", "prev_hash": prev}
            rec["record_hash"] = ae.record_hash(rec)
            rec.update(signature=signer.sign(rec["record_hash"]), signing_key_id=signer.key_id,
                       signature_algorithm=signer.algorithm)
            s3.put_object(Bucket=BUCKET, Key=f"evidence/delegated-authority/a/c/{seq:04d}-decision.json",
                          Body=json.dumps(rec).encode())
            prev = rec["record_hash"]
        third = ledger.record(agent_id="a", chain_id="c", event_type="grant_minted")
        assert third["seq"] == 3 and third["prev_hash"] == prev
        assert ledger.verify_chain(ledger.chain("a", "c"), agent_id="a", chain_id="c")[0]


# ------------------------------------------------------------------ key segments
@pytest.mark.parametrize("bad", ["gateway-x/nested", "../up", "", "a" * 161, "tab\there", "nul\x00"],
                         ids=["slash", "dot-dot", "empty", "too-long", "tab", "nul"])
def test_a_chain_id_cannot_shape_an_evidence_key(s3_ledger, bad):
    _, ledger = s3_ledger
    with pytest.raises(ae.InvalidEvidenceKey):
        ledger.record(agent_id="agent-a", chain_id=bad, event_type="x")


def test_safe_key_segment_hashes_anything_else():
    assert ae.safe_key_segment("gateway-ok", "h-") == "gateway-ok"
    hashed = ae.safe_key_segment("gateway-x/nested", "h-")
    assert hashed.startswith("h-") and "/" not in hashed and len(hashed) == 66


# ------------------------------------------------------------------ secret-shaped input
AKIA = "AKIA" + "ABCDEFGHIJKLMNOP"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4In0.c2lnbmF0dXJl"


@pytest.mark.parametrize("value", [AKIA, JWT, f"id {AKIA} and {JWT}"])
def test_secret_shaped_input_is_masked_and_the_record_is_still_written(s3_ledger, value):
    _, ledger = s3_ledger
    rec = ledger.record(agent_id="agent-a", chain_id="gateway-x", event_type="gateway_deny", reason=value)
    stored = ledger.chain("agent-a", "gateway-x")[-1]
    assert AKIA not in json.dumps(stored) and JWT not in json.dumps(stored)
    assert "masked-credential" in stored["reason"] and stored["masked_fields"] == ["reason"]
    assert ledger.verify_chain([stored], agent_id="agent-a", chain_id="gateway-x")[0]
    assert rec["seq"] == 1


def test_a_credential_named_field_is_dropped_not_fatal(s3_ledger):
    _, ledger = s3_ledger
    ledger.record(agent_id="agent-a", chain_id="c", event_type="x", client_secret="s3cr3t", note="kept")
    stored = ledger.chain("agent-a", "c")[-1]
    assert "client_secret" not in stored and stored["note"] == "kept"


def test_a_long_field_is_capped_with_its_digest(s3_ledger):
    _, ledger = s3_ledger
    ledger.record(agent_id="agent-a", chain_id="c", event_type="x", reason="r" * 50_000)
    stored = ledger.chain("agent-a", "c")[-1]
    assert len(stored["reason"]) < 1000 and hashlib.sha256(b"r" * 50_000).hexdigest() in stored["reason"]


@pytest.mark.parametrize("payload", [
    "eyJ" + "A" * 200_000,
    "eyJ" + "A" * 100_000 + ".eyJ" + "B" * 100_000,
    "eyJ" * 70_000,                    # every position starts with eyJ (the old engine pattern)
    "eyJ-" * 50_000,                   # a word boundary before every eyJ (the old platform pattern)
], ids=["one-long-run", "two-long-segments", "eyJ-repeated", "eyJ-dash-repeated"])
def test_the_credential_patterns_scan_linearly(payload):
    started = time.perf_counter()
    for pattern in ae._SECRET_VALUES:
        pattern.search(payload)
    assert time.perf_counter() - started < 0.5


# ------------------------------------------------------------------ location binding
def test_a_record_copied_to_another_chain_fails_verification(s3_ledger):
    s3, ledger = s3_ledger
    authentic = ledger.record(agent_id="agent-a", chain_id="dec-1", event_type="decision")
    body = {k: v for k, v in authentic.items() if k != "location"}
    s3.put_object(Bucket=BUCKET, Key="evidence/delegated-authority/agent-b/dec-2/0000000001.json",
                  Body=json.dumps(body).encode())
    moved = ledger.chain("agent-b", "dec-2")
    assert ledger.verify_chain(moved)[0] is True             # unbound: the old behaviour
    ok, detail = ledger.verify_chain(moved, agent_id="agent-b", chain_id="dec-2")
    assert ok is False and "belongs to agent" in detail


def test_decision_summaries_do_not_verify_a_relocated_trace():
    with offline_demo() as demo:
        from tests.authority_test_support import purchase
        cp = demo.control_plane
        out = cp.request_authority(purchase(), demo.agent("procurement-agent"))
        table = demo.tables["decisions"]
        item = table.get_item(Key={"decision_id": out["decision_id"]})["Item"]
        table.put_item(Item={**item, "decision_id": "dec-relocated", "trace_agent_id": "records-agent"})
        rows = cp.decision_summaries("records-agent", 10)
        assert rows and rows[0]["signature_verified"] is False
        assert cp.decision_summaries("procurement-agent", 10)[0]["signature_verified"] is True


# ------------------------------------------------------------------ signer
class FakeKms:
    """KMS stand-in: real ECDSA P-256 over the digest, as KMS signs a DIGEST message."""

    def __init__(self, deny_verify=False):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.public_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.deny_verify = deny_verify
        self.calls = []

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        self.calls.append("Sign")
        return {"Signature": self._key.sign(Message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))}

    def verify(self, **kwargs):
        self.calls.append("Verify")
        if self.deny_verify:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "Verify")
        return {"SignatureValid": True}

    def get_public_key(self, KeyId):
        self.calls.append("GetPublicKey")
        if self.deny_verify:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "GetPublicKey")
        return {"PublicKey": self.public_der}


def test_a_refused_check_is_not_reported_as_an_invalid_signature():
    writer = KmsGrantSigner(FakeKms(), "key-1")
    digest = hashlib.sha256(b"r").hexdigest()
    signature = writer.sign(digest)
    reader = KmsGrantSigner(FakeKms(deny_verify=True), "key-1")
    assert reader.check(digest, signature) is None and reader.verify(digest, signature) is False
    ledger = ae.EvidenceLedger(reader, ae.MemoryEvidenceBackend())
    rec = {"evidence_id": "e", "chain_id": "c", "seq": 1, "event_type": "x", "agent_id": "a",
           "timestamp": "t", "prev_hash": ae.GENESIS}
    rec["record_hash"] = ae.record_hash(rec)
    rec.update(signature=signature, signing_key_id="key-1", signature_algorithm="ECDSA_SHA_256")
    ok, detail = ledger.verify_chain([rec])
    assert ok is False and "could not be checked" in detail


def test_signatures_verify_locally_and_each_is_checked_once():
    kms = FakeKms()
    signer = KmsGrantSigner(kms, "key-1")
    digests = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(50)]
    signatures = [signer.sign(d) for d in digests]
    reader = KmsGrantSigner(kms, "key-1")
    kms.calls.clear()
    for _ in range(3):
        assert all(reader.verify(d, s) for d, s in zip(digests, signatures))
    assert kms.calls == ["GetPublicKey"]          # no remote Verify: local check, then remembered


def test_a_forged_signature_is_invalid():
    from botocore.exceptions import ClientError

    kms = FakeKms()
    signer = KmsGrantSigner(kms, "key-1")
    digest = hashlib.sha256(b"r").hexdigest()
    forged = base64.b64encode(b"\x30\x06\x02\x01\x01\x02\x01\x01").decode()   # DER (r=1, s=1)

    def invalid(**_):
        raise ClientError({"Error": {"Code": "KMSInvalidSignatureException", "Message": "invalid"}}, "Verify")

    kms.verify = invalid
    assert signer.check(digest, forged) is False
    assert signer.check(digest, "not base64!") is False
