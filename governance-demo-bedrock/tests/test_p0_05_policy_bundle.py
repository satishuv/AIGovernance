"""P0-05: every decision names the policy bundle and version it ran under.

GovernanceDecision already carried the canonical request, the request digest
and the policy version hash. It now also carries policy_bundle_id (where the
bundle in force came from) and policy_version (each policy id with its
declared version), on both the governance pipeline and the authority plane.
"""

import os
import sys

import pytest

_GE = os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine")
sys.path.insert(0, os.path.abspath(_GE))
sys.path.insert(0, os.path.dirname(__file__))

from decision_engine import DecisionEngine  # noqa: E402
from models import GovernanceDecision, PolicyEvaluationResult, RiskAssessment  # noqa: E402
from opa_engine import OPAEngine  # noqa: E402


def _engine(policies):
    engine = OPAEngine()
    engine.load_policies_from_json(policies)
    return engine


def test_bundle_version_lists_each_policy_with_its_version():
    engine = _engine([
        {"rule_name": "allow_read", "outcome": "allow", "conditions": [], "version": "3"},
        {"rule_name": "default_deny", "outcome": "deny", "conditions": []},
    ])
    assert engine.bundle_id == "inline"
    assert engine.bundle_version() == "allow_read@3,default_deny@unversioned"


def test_large_bundles_report_a_count_and_fingerprint():
    engine = _engine([{"rule_name": f"r{i}", "outcome": "deny", "conditions": []} for i in range(60)])
    assert engine.bundle_version() == f"60 rules; fingerprint {engine.policy_fingerprint()[:16]}"


def test_s3_bundles_are_named_by_location():
    class EmptyS3:
        def list_objects_v2(self, **kwargs):
            return {"Contents": []}

        def get_paginator(self, name):
            class Pages:
                def paginate(self, **kwargs):
                    return [{"Contents": []}]
            return Pages()

    engine = OPAEngine()
    try:
        engine.load_policies_from_s3(EmptyS3(), "policy-bucket", "policies/")
    except Exception:
        pass  # loading an empty bucket may raise; the identity is set first
    assert engine.bundle_id == "s3://policy-bucket/policies/"


def test_decision_carries_bundle_identity_and_version():
    decision = DecisionEngine(70).decide(
        PolicyEvaluationResult(policy_id="allow_read", outcome="allow"),
        RiskAssessment(risk_score=10, risk_category="read"),
        {"agent_id": "a", "operation_id": "ReadPipelineStatus"}, "a",
        policy_version_hash="f" * 64, policy_bundle_id="s3://b/policies/", policy_version="allow_read@3")
    as_dict = decision.to_dict()
    assert (as_dict["policy_bundle_id"], as_dict["policy_version"]) == ("s3://b/policies/", "allow_read@3")
    again = GovernanceDecision.from_dict(as_dict)
    assert (again.policy_bundle_id, again.policy_version) == ("s3://b/policies/", "allow_read@3")


def test_authority_plane_decisions_name_the_bundle():
    from authority_test_support import offline_demo, purchase

    with offline_demo() as demo:
        out = demo.control_plane.request_authority(purchase(), demo.agent("procurement-agent"))
    assert out["policy_bundle_id"] == "public-sector-demo@file:delegated_authority_policy.json"
    assert out["policy_version"]
    assert len(out["policy_version_hash"]) == 64


@pytest.mark.parametrize("field", ["policy_bundle_id", "policy_version"])
def test_decision_fields_default_to_empty_for_old_records(field):
    old = {"decision_id": "d", "agent_id": "a", "action_requested": "x"}
    assert getattr(GovernanceDecision.from_dict(old), field) == ""
