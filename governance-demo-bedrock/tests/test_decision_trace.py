"""Tests for the auditor decision-trace (signed "why" of a verdict)."""
import os
import sys

import pytest

_LD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))
if _LD not in sys.path:
    sys.path.insert(0, _LD)
_SD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if _SD not in sys.path:
    sys.path.insert(0, _SD)


class _LocalKmsFake:
    """Fake KMS backed by a real local ECDSA P-256 key (sign + public key)."""
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.public_key_pem = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, KeyId=None, Message=None, MessageType=None, SigningAlgorithm=None):
        from cryptography.hazmat.primitives.asymmetric import ec, utils as au
        from cryptography.hazmat.primitives import hashes
        return {"Signature": self._priv.sign(Message, ec.ECDSA(au.Prehashed(hashes.SHA256())))}


class _MemTable:
    def __init__(self):
        self.items = {}
    def put_item(self, Item=None, **kw):
        self.items[Item["decision_id"]] = Item
    def get_item(self, Key=None):
        it = self.items.get(Key["decision_id"])
        return {"Item": it} if it else {}


class TestDecisionTraceBuilder:
    def test_stages_recorded_in_order(self):
        from decision_trace import DecisionTraceBuilder, RESULT_PASS, RESULT_BLOCK
        b = DecisionTraceBuilder()
        b.add("kill_switch", RESULT_PASS)
        b.add("input_sanitizer", RESULT_PASS)
        b.add("threat_detector", RESULT_BLOCK, "matched injection", decisive=True)
        assert [s["stage"] for s in b.stages] == ["kill_switch", "input_sanitizer", "threat_detector"]

    def test_build_infers_decisive_stage(self):
        from decision_trace import DecisionTraceBuilder, RESULT_PASS, RESULT_BLOCK
        b = DecisionTraceBuilder()
        b.add("input_sanitizer", RESULT_PASS)
        b.add("threat_detector", RESULT_BLOCK, "matched injection", decisive=True)
        t = b.build(decision_id="d1", agent_id="a1", action_requested="X", verdict="deny")
        assert t.decisive_stage == "threat_detector"
        assert t.aarm_decision == "DENY"

    def test_escalate_maps_to_step_up(self):
        from decision_trace import DecisionTraceBuilder
        b = DecisionTraceBuilder()
        b.add("decision_engine", "pass", "high risk", decisive=True)
        t = b.build(decision_id="d2", agent_id="a1", action_requested="X", verdict="escalate")
        assert t.aarm_decision == "STEP_UP"


class TestDecisionTraceSigning:
    def _signed(self, monkeypatch):
        import crypto_signing as cs
        monkeypatch.setattr(cs, "EVIDENCE_SIGNING_KEY_ID", "alias/test-key", raising=False)
        from decision_trace import DecisionTraceBuilder, DecisionTraceManager
        b = DecisionTraceBuilder()
        b.add("policy_evaluation", "pass", "allow")
        b.add("risk_scoring", "pass", "score 10")
        b.add("decision_engine", "pass", "allowed below threshold", decisive=True)
        # Use FLOAT risk factors (as the live pipeline does) to catch the
        # DynamoDB "float not supported" path and ensure hash/verify still match.
        trace = b.build(decision_id="dt1", agent_id="agent-x", action_requested="ReadPipelineStatus",
                        verdict="allow", session_id="sess-1",
                        risk_factors={"scope_weight": 12.5, "base": 30.0})
        kms = _LocalKmsFake()
        table = _MemTable()
        DecisionTraceManager.sign_and_store(trace, table, kms)
        # Read back through the real fetch path (rehydrates canonical body).
        body = DecisionTraceManager.get_trace("dt1", table)
        return body, table.items["dt1"], kms

    def test_trace_is_signed_and_stored(self, monkeypatch):
        body, raw, _ = self._signed(monkeypatch)
        assert raw["signature"] and raw["signing_algorithm"] == "ECDSA_SHA_256"
        assert body["decisive_stage"] == "decision_engine"
        assert body["risk_factors"]["scope_weight"] == 12.5

    def test_signature_verifies_offline(self, monkeypatch):
        from decision_trace import DecisionTraceManager
        body, _, kms = self._signed(monkeypatch)
        assert DecisionTraceManager.verify_trace(body, public_key_pem=kms.public_key_pem) is True

    def test_tampered_trace_fails_verification(self, monkeypatch):
        from decision_trace import DecisionTraceManager
        body, _, kms = self._signed(monkeypatch)
        # Tamper the preserved canonical body (what verification reads).
        body["_canonical_body"] = body["_canonical_body"].replace('"allow"', '"deny"')
        assert DecisionTraceManager.verify_trace(body, public_key_pem=kms.public_key_pem) is False

    def test_tampered_stage_detail_fails(self, monkeypatch):
        from decision_trace import DecisionTraceManager
        body, _, kms = self._signed(monkeypatch)
        body["_canonical_body"] = body["_canonical_body"].replace("allowed below threshold", "forged")
        assert DecisionTraceManager.verify_trace(body, public_key_pem=kms.public_key_pem) is False

    def test_get_trace_roundtrip(self, monkeypatch):
        from decision_trace import DecisionTraceManager
        _, _, _ = self._signed(monkeypatch)  # ensures no exception path
        # separate fetch check
        table = _MemTable()
        table.put_item(Item={"decision_id": "x", "verdict": "allow"})
        assert DecisionTraceManager.get_trace("x", table)["verdict"] == "allow"
        assert DecisionTraceManager.get_trace("missing", table) is None


class TestDecisionTraceReport:
    def _trace(self):
        return {
            "decision_id": "dr1", "agent_id": "agent-x", "session_id": "s1",
            "action_requested": "ProductionDeployment", "verdict": "deny",
            "aarm_decision": "DENY", "decisive_stage": "threat_detector",
            "timestamp": "2026-07-23T00:00:00+00:00", "policy_id": "pol-1",
            "risk_factors": {"scope": 20},
            "stages": [
                {"stage": "input_sanitizer", "result": "pass", "detail": "", "decisive": False},
                {"stage": "threat_detector", "result": "block", "detail": "matched injection", "decisive": True},
            ],
        }

    def test_report_has_core_sections(self):
        from decision_trace_report import render_report
        md = render_report(self._trace(), signature_status="VERIFIED (offline)")
        assert "# Decision Rationale: dr1" in md
        assert "## Why" in md
        assert "threat_detector" in md
        assert "DENY" in md
        assert "VERIFIED (offline)" in md
        # honesty footer: agent rationale not included
        assert "not verified" in md.lower()

    def test_report_why_names_decisive_stage(self):
        from decision_trace_report import render_report
        md = render_report(self._trace())
        assert "decisive check was **threat_detector**" in md
