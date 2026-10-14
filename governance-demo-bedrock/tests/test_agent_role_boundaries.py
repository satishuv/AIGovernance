"""Agents watching agents: guardian and worker boundaries."""

import pytest

from tests.authority_test_support import governance, offline_demo, stage


@pytest.fixture
def demo():
    with offline_demo() as d:
        yield d


HUMAN_ONLY = [
    ("Governance.GrantScope", {"new_scope_level": 4}),
    ("Governance.UpdateAgentScope", {"new_scope_level": 4}),
    ("Governance.AmendPolicy", {}),
    ("Governance.ApproveException", {}),
    ("Governance.ModifyMonitoringConfig", {}),
]


class TestGuardianBoundaries:
    @pytest.mark.parametrize("operation,params", HUMAN_ONLY)
    def test_guardian_cannot_perform_human_only_operations(self, demo, operation, params):
        req = governance("guardian-agent", operation, "agent/procurement-agent", params)
        resp = demo.control_plane.request_authority(req, demo.agent("guardian-agent"))
        assert resp["verdict"] == "deny"
        assert "human-only" in stage(resp, "role_boundary")["detail"]
        assert "grant" not in resp and "approval_id" not in resp

    @pytest.mark.parametrize("operation,params", HUMAN_ONLY)
    def test_worker_cannot_perform_human_only_operations_on_itself(self, demo, operation, params):
        req = governance("procurement-agent", operation, "agent/procurement-agent", params)
        resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
        assert resp["verdict"] == "deny"

    def test_guardian_can_inspect_an_assigned_worker(self, demo):
        cp = demo.control_plane
        req = governance("guardian-agent", "Governance.InspectDecisionHistory", "agent/procurement-agent",
                         {"limit": 5})
        resp = cp.request_authority(req, demo.agent("guardian-agent"))
        assert resp["verdict"] == "allow"
        out = cp.execute(resp["grant"]["grant_id"], req, demo.agent("guardian-agent"))
        assert out["status"] == "executed"

    def test_engine_traces_in_the_shared_table_are_ignored(self, demo):
        cp = demo.control_plane
        # The governance engine writes traces with a different body to the same table.
        demo.tables["decisions"].put_item(Item={
            "decision_id": "engine-1", "agent_id": "procurement-agent", "verdict": "allow",
            "timestamp": "2026-10-14T00:00:00+00:00", "canonical_body": "{\"decision_id\": \"engine-1\"}",
            "trace_hash": "x", "signature": ""})
        req = governance("guardian-agent", "Governance.InspectDecisionHistory", "agent/procurement-agent",
                         {"limit": 5})
        resp = cp.request_authority(req, demo.agent("guardian-agent"))
        out = cp.execute(resp["grant"]["grant_id"], req, demo.agent("guardian-agent"))
        assert out["status"] == "executed"
        ids = [d["decision_id"] for d in out["execution"]["summary"]["decisions"]]
        assert "engine-1" not in ids

    def test_guardian_recommendation_does_not_change_authority(self, demo):
        cp = demo.control_plane
        req = governance("guardian-agent", "Governance.RecommendSuspension", "agent/procurement-agent",
                         {"reason": "spend velocity is unusual for this session"})
        resp = cp.request_authority(req, demo.agent("guardian-agent"))
        assert resp["verdict"] == "allow"
        out = cp.execute(resp["grant"]["grant_id"], req, demo.agent("guardian-agent"))
        assert out["execution"]["summary"]["effect_on_authority"] == "none"
        assert cp.describe_agent("procurement-agent")["current_scope"] == 3

    def test_guardian_cannot_observe_an_unassigned_agent(self, demo):
        demo.control_plane.registry.update_agent("records-agent", {"guardian_agent_ids": []}, "admin")
        demo.control_plane.registry.update_agent("records-agent", {"requires_guardian": False}, "admin")
        req = governance("guardian-agent", "Governance.InspectEvidence", "agent/records-agent")
        resp = demo.control_plane.request_authority(req, demo.agent("guardian-agent"))
        assert resp["verdict"] == "deny"
        assert "not assigned" in stage(resp, "role_boundary")["detail"]

    def test_guardian_cannot_observe_itself(self, demo):
        req = governance("guardian-agent", "Governance.InspectEvidence", "agent/guardian-agent")
        resp = demo.control_plane.request_authority(req, demo.agent("guardian-agent"))
        assert resp["verdict"] == "deny"
        assert "itself" in stage(resp, "role_boundary")["detail"]

    def test_guardian_cannot_purchase(self, demo):
        from tests.authority_test_support import purchase
        req = purchase(agent_id="guardian-agent")
        resp = demo.control_plane.request_authority(req, demo.agent("guardian-agent"))
        assert resp["verdict"] == "deny"

    def test_guardian_cannot_approve_or_change_scope_through_the_planes(self, demo):
        cp = demo.control_plane
        assert cp.admin_set_scope("procurement-agent", 1, demo.agent("guardian-agent"))["status"] == "denied"
        assert cp.activate_kill_switch("procurement-agent", demo.agent("guardian-agent"), "x")["status"] == "denied"


class TestWorkerBoundaries:
    def test_worker_cannot_inspect_other_agents(self, demo):
        req = governance("procurement-agent", "Governance.InspectDecisionHistory", "agent/guardian-agent")
        resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
        assert resp["verdict"] == "deny"

    def test_agent_cannot_impersonate_another_agent(self, demo):
        req = governance("guardian-agent", "Governance.InspectEvidence", "agent/procurement-agent")
        resp = demo.control_plane.request_authority(req, demo.agent("records-agent"))
        assert resp["verdict"] == "deny"
        assert "impersonation" in stage(resp, "identity")["detail"]

    def test_humans_change_scope_only_within_the_approved_scope(self, demo):
        cp = demo.control_plane
        assert cp.admin_set_scope("procurement-agent", 4, demo.human("governance_admin"))["status"] == "denied"
        assert cp.admin_set_scope("procurement-agent", 2, demo.human("finance_approver"))["status"] == "denied"
        out = cp.admin_set_scope("procurement-agent", 2, demo.human("governance_admin"), "reduce during review")
        assert out["status"] == "updated" and out["scope_level"] == 2
