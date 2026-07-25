"""Chaos / failure-injection tests (SAS review P2 #9).

The unit suite proves the decision LOGIC is fail-closed. These tests inject the
actual failure conditions a running deployment hits (DynamoDB throttling,
Bedrock 5xx, S3 write failure, OPA crash) and assert the framework degrades to a
SAFE state (DENY / worst-case escalate / evidence-does-not-block) rather than an
undefined or fail-open one. This is the review's "what happens when the
governance layer itself fails mid-decision" concern.

All faults are injected via boto3-style exceptions on mocked clients; no AWS.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

_LD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))
if _LD not in sys.path:
    sys.path.insert(0, _LD)


def _client_error(code, op):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


# =============================================================================
# DynamoDB throttling / unavailability -> fail closed
# =============================================================================

class TestDynamoDBFailure:
    def test_policy_engine_throttled_denies(self):
        from fail_safe import safe_evaluate_policy
        broken = MagicMock()
        broken.evaluate.side_effect = _client_error("ProvisionedThroughputExceededException", "GetItem")
        result = safe_evaluate_policy(broken, {"action_group": "Read"})
        assert result.outcome == "deny"
        assert result.policy_id == "fail-safe-deny"

    def test_risk_scoring_throttled_assumes_worst_case(self):
        from fail_safe import safe_compute_risk
        broken = MagicMock()
        broken.compute_risk.side_effect = _client_error("ProvisionedThroughputExceededException", "Query")
        result = safe_compute_risk(broken, {"action_group": "Deploy"}, 3)
        assert result.risk_score == 100.0
        assert result.escalation_flagged is True

    def test_identity_lookup_throttled_propagates_to_fail_closed_handler(self):
        # HONEST behavior (verified): AgentIdentityManager.get_agent does NOT
        # catch a throttled table; it raises. That is caught by the pipeline's
        # top-level except -> _deny_response (fail CLOSED, not open). This test
        # pins that contract: the exception propagates (so the outer fail-closed
        # handler denies) rather than being silently swallowed as "not suspended"
        # (which would be a subtle fail-OPEN). If a future change adds a local
        # try/except here that returns False, this test must be revisited.
        from agent_identity import AgentIdentityManager
        table = MagicMock()
        table.get_item.side_effect = _client_error("ThrottlingException", "GetItem")
        mgr = AgentIdentityManager(table)
        with pytest.raises(ClientError):
            mgr.is_suspended("agent-1")


# =============================================================================
# OPA / policy engine crash mid-evaluation -> fail closed
# =============================================================================

class TestOPAFailure:
    def test_opa_crash_denies(self):
        from fail_safe import safe_evaluate_opa
        broken = MagicMock()
        broken.evaluate.side_effect = RuntimeError("OPA interpreter crashed")
        decision = safe_evaluate_opa(broken, {"action_group": "Deploy"})
        assert decision.verdict == "deny"
        assert decision.allowed is False


# =============================================================================
# S3 evidence-write failure -> must NOT block/alter the decision
# =============================================================================

class TestEvidenceWriteFailure:
    def test_evidence_write_failure_does_not_raise(self):
        from fail_safe import safe_write_evidence
        def broken_writer(decision):
            raise _client_error("ServiceUnavailable", "PutObject")
        mock_decision = MagicMock(); mock_decision.decision_id = "d-chaos"
        # Returns False (failure recorded) but never raises: evidence is audit,
        # not authorization, so a write failure must not break the decision path.
        assert safe_write_evidence(broken_writer, mock_decision) is False

    def test_evidence_pipeline_retries_then_gives_up_cleanly(self):
        from evidence_pipeline import EvidencePipeline
        from models import GovernanceDecision
        s3 = MagicMock()
        s3.list_objects_v2.return_value = {"Contents": []}
        s3.put_object.side_effect = _client_error("ServiceUnavailable", "PutObject")
        dec = GovernanceDecision(
            decision_id="d1", agent_id="a1", action_requested="Read",
            risk_score=10.0, verdict="allow", timestamp="2026-07-25T00:00:00+00:00",
        )
        # All retries fail -> returns None, does not raise.
        result = EvidencePipeline().write_evidence(
            decision=dec, s3_client=s3, bucket="b", environment="dev", agent_id="a1")
        assert result is None


# =============================================================================
# Bedrock Guardrails 5xx -> defense-in-depth (other layers still run)
# =============================================================================

class TestBedrockGuardrailsFailure:
    def test_guardrail_error_does_not_crash_evaluator(self, monkeypatch):
        # Verified: evaluate_input wraps the call in try/except (bedrock_guardrails
        # line ~140), so a 5xx degrades gracefully rather than raising into the
        # pipeline (defense-in-depth: other layers still check). `configured` is a
        # read-only property, so we force it via the underlying guardrail id.
        import bedrock_guardrails as bg
        ev = bg.BedrockGuardrailsEvaluator()
        monkeypatch.setattr(ev, "_guardrail_id", "test-guardrail-id", raising=False)
        client = MagicMock()
        client.apply_guardrail.side_effect = _client_error("InternalServerException", "ApplyGuardrail")
        monkeypatch.setattr(ev, "_client", client, raising=False)
        # Must not raise a ClientError into the caller.
        try:
            res = ev.evaluate_input("some text")
        except ClientError:
            pytest.fail("guardrail evaluator leaked a ClientError on 5xx")
        assert res is not None


# =============================================================================
# KMS signing outage -> evidence/trace still stored, just unsigned (no crash)
# =============================================================================

class TestKmsSigningFailure:
    def test_signing_failure_returns_empty_not_raise(self):
        from crypto_signing import sign_digest
        kms = MagicMock()
        kms.sign.side_effect = _client_error("KMSInternalException", "Sign")
        sig, kid, alg = sign_digest("abc123", kms, key_id="alias/x")
        # Degrades to unsigned (hash chain still protects), never raises.
        assert sig == "" and kid == "" and alg == ""
