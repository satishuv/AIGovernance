"""Comprehensive unit+property tests for the Governance Engine.
All AWS services are mocked. Modules loaded via sys.path.
"""
import hashlib, io, json, logging, os, sys, time, uuid
from datetime import date, datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import pytest
from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st

_LD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))
if _LD not in sys.path:
    sys.path.insert(0, _LD)

from models import (
    AgentIdentity, AgentRegistryEntry, ControlTrace, EvidenceRecord,
    GovernanceDecision, GovernanceRoleAssignment, LatencyMetric,
    PolicyConditions, PolicyDefinition, PolicyEvaluationResult,
    RiskAssessment, ToolModelRegistryEntry, ValidationResult, ThreatPattern,
)
from policy_engine import PolicyEngine
from risk_scoring import RiskScoringEngine
from decision_engine import DecisionEngine
from fail_safe import safe_evaluate_policy, safe_compute_risk, safe_write_evidence
from latency import LatencyTracker, LATENCY_BUDGET_MS
from kill_switch import KillSwitchManager
from agent_identity import AgentIdentityManager
from agent_registry import AgentRegistry
from tool_model_registry import ToolModelRegistry
from separation_of_duties import SeparationOfDuties
from environment_isolation import EnvironmentIsolation
from evidence_pipeline import EvidencePipeline
from evidence_integrity import EvidenceIntegrity
from control_trace import ControlTraceManager
from threat_detector import ThreatDetector
from policy_lifecycle import PolicyLifecycle
from validation_suite import MinimumValidationSuite

# --- Hypothesis strategies ---
_st = st.text(alphabet=st.characters(whitelist_categories=("L","N","P","Z")), min_size=1, max_size=30)
_si = st.text(alphabet=st.characters(whitelist_categories=("L","N")), min_size=1, max_size=20)
_ts = st.just("2024-01-15T12:00:00+00:00")
_oc = st.sampled_from(["allow","deny","escalate"])
_ev = st.sampled_from(["dev","staging","prod"])
_ca = st.sampled_from(["model","tool_connector","data_source"])


@st.composite
def policy_defs(draw):
    return PolicyDefinition(
        policy_id=draw(_si), version=draw(st.integers(1,1000)), name=draw(_st),
        description=draw(_st), priority=draw(st.integers(0,100)),
        conditions=PolicyConditions(
            scope_level=draw(st.one_of(st.none(), st.integers(0,4))),
            action_group=draw(st.one_of(st.none(), _st)),
            target_resource=draw(st.one_of(st.none(), _st)),
        ),
        outcome=draw(_oc), owner=draw(_st),
        approval_status=draw(st.sampled_from(["approved","pending","draft"])),
        created_at=draw(_ts), updated_at=draw(_ts),
    )

@st.composite
def gov_decisions(draw):
    return GovernanceDecision(
        decision_id=draw(_si), agent_id=draw(_si), action_requested=draw(_st),
        policy_result={"policy_id": draw(_si), "outcome": draw(_oc)},
        risk_score=draw(st.floats(0,100,allow_nan=False,allow_infinity=False)),
        verdict=draw(_oc), explanation=draw(_st),
        framework_mapping=draw(st.lists(_si, max_size=5)),
        timestamp=draw(_ts), latency_breakdown={},
    )

@st.composite
def agent_reg_entries(draw):
    return AgentRegistryEntry(
        agent_id=draw(_si), purpose=draw(_st), owner=draw(_st),
        data_classes=draw(st.lists(_st, min_size=1, max_size=3)),
        tools=draw(st.lists(_st, max_size=3)),
        approved_scope=draw(st.integers(1,4)), environment=draw(_ev),
    )

@st.composite
def tool_entries(draw):
    return ToolModelRegistryEntry(
        entry_id=draw(_si), category=draw(_ca), name=draw(_st), version=draw(_st),
        approval_status=draw(st.sampled_from(["approved","pending","revoked",""])),
        approver=draw(_st), approval_timestamp=draw(_ts),
    )

@st.composite
def ev_records(draw):
    return EvidenceRecord(
        evidence_id=draw(_si), decision_id=draw(_si), agent_id=draw(_si),
        action_requested=draw(_st), policy_result=draw(_st),
        risk_score=draw(st.floats(0,100,allow_nan=False,allow_infinity=False)),
        verdict=draw(_oc), timestamp=draw(_ts),
        framework_mapping=draw(st.lists(_si, max_size=3)), environment=draw(_ev),
        previous_hash=draw(_si), record_hash=draw(_si),
        retention_class=draw(st.sampled_from(["standard","extended"])),
    )

@st.composite
def ctrl_traces(draw):
    return ControlTrace(
        control_id=draw(_si), implementation_component=draw(_st),
        evidence_record_id=draw(_si), decision_id=draw(_si), timestamp=draw(_ts),
    )


class MockTable:
    def __init__(self, key="agent_id"):
        self._items, self._key = {}, key
    def put_item(self, Item=None, **kw):
        item = Item or kw.get("Item",{})
        self._items[item.get(self._key, str(uuid.uuid4()))] = dict(item)
    def get_item(self, Key=None, **kw):
        k = (Key or kw.get("Key",{})).get(self._key,"")
        i = self._items.get(k)
        return {"Item": dict(i)} if i else {}
    def update_item(self, Key=None, **kw):
        k = (Key or kw.get("Key",{})).get(self._key,"")
        if k not in self._items:
            self._items[k] = {self._key: k}
        expr = kw.get("UpdateExpression","")
        vals = kw.get("ExpressionAttributeValues",{})
        names = kw.get("ExpressionAttributeNames",{})
        if expr.startswith("SET "):
            for part in expr[4:].split(","):
                part = part.strip()
                if "=" in part:
                    l,r = part.split("=",1)
                    self._items[k][names.get(l.strip(),l.strip())] = vals.get(r.strip(),r.strip())
    def scan(self, **kw):
        items = list(self._items.values())
        fe = kw.get("FilterExpression","")
        fv = kw.get("ExpressionAttributeValues",{})
        if fe and "user_id" in str(fe):
            uid = fv.get(":uid","")
            items = [i for i in items if i.get("user_id")==uid]
        return {"Items": items}
    def query(self, **kw):
        return {"Items": list(self._items.values())}
    def batch_writer(self):
        return _BW(self)

class _BW:
    def __init__(self, t): self._t = t
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def put_item(self, Item=None, **kw): self._t.put_item(Item=Item, **kw)


# ===== PROPERTY TESTS =====
class TestProp1PolicyDefRoundTrip:
    """**Validates: Requirement 1.8**"""
    @given(pd=policy_defs())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip(self, pd):
        r = PolicyDefinition.from_dict(pd.to_dict())
        assert r.policy_id == pd.policy_id and r.version == pd.version
        assert r.outcome == pd.outcome and r.priority == pd.priority

class TestProp2GovDecisionRoundTrip:
    """**Validates: Requirement 4.11**"""
    @given(gd=gov_decisions())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip(self, gd):
        r = GovernanceDecision.from_dict(gd.to_dict())
        assert r.decision_id == gd.decision_id and r.verdict == gd.verdict
        assert r.risk_score == gd.risk_score

class TestProp4AgentRegRoundTrip:
    """**Validates: Requirement 6.9**"""
    @given(e=agent_reg_entries())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip(self, e):
        r = AgentRegistryEntry.from_dict(e.to_dict())
        assert r.agent_id == e.agent_id and r.data_classes == e.data_classes

class TestProp5ToolModelRoundTrip:
    """**Validates: Requirement 7.10**"""
    @given(e=tool_entries())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip(self, e):
        r = ToolModelRegistryEntry.from_dict(e.to_dict())
        assert r.entry_id == e.entry_id and r.category == e.category

class TestProp6EvidenceRecordRoundTrip:
    """**Validates: Requirement 9.8**"""
    @given(er=ev_records())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip(self, er):
        r = EvidenceRecord.from_dict(er.to_dict())
        assert r.evidence_id == er.evidence_id and r.verdict == er.verdict

class TestProp7ControlTraceRoundTrip:
    """**Validates: Requirement 13.4**"""
    @given(ct=ctrl_traces())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip(self, ct):
        r = ControlTrace.from_dict(ct.to_dict())
        assert r.control_id == ct.control_id and r.decision_id == ct.decision_id


# ===== Task 2.2: Policy loading/validation =====
class TestPolicyLoading:
    def _vpd(self, pid="p1"):
        return {"policy_id":pid,"version":1,"name":"T","description":"D","priority":10,
                "conditions":{"scope_level":1},"outcome":"allow","owner":"admin",
                "approval_status":"approved","created_at":"2024-01-01","updated_at":"2024-01-01"}
    def test_load_from_mock_s3(self):
        e = PolicyEngine(); s3 = MagicMock()
        pg = MagicMock(); s3.get_paginator.return_value = pg
        pg.paginate.return_value = [{"Contents":[{"Key":"policies/p1.json"}]}]
        s3.get_object.return_value = {"Body":io.BytesIO(json.dumps(self._vpd()).encode())}
        e.load_policies(s3, "b", "policies/"); assert "p1" in e.policies
    def test_reject_invalid(self):
        assert PolicyEngine().validate_policy({"policy_id":"bad","version":1}) is False
    def test_error_log(self, caplog):
        with caplog.at_level(logging.ERROR):
            PolicyEngine().validate_policy({"policy_id":"bad-pol","version":"x"})
        assert any("bad-pol" in r.message for r in caplog.records if r.levelno>=logging.ERROR)


class TestPolicyIdempotence:
    def test_idempotent(self):
        e = PolicyEngine()
        p = PolicyDefinition("p1",1,"","",10,PolicyConditions(scope_level=1),"allow","","approved","","")
        e._policies = {"p1": p}
        results = [e.evaluate({"scope_level":1}) for _ in range(10)]
        assert all(r.outcome == results[0].outcome for r in results)

class TestPolicyEvaluation:
    def _eng(self, pols):
        e = PolicyEngine(); e._policies = {p.policy_id:p for p in pols}; return e
    def test_single_match(self):
        p = PolicyDefinition("p1",1,"","",10,PolicyConditions(scope_level=2),"deny","","approved","","")
        assert self._eng([p]).evaluate({"scope_level":2}).outcome == "deny"
    def test_default_deny(self):
        assert self._eng([]).evaluate({"scope_level":1}).policy_id == "default-deny"
    def test_priority(self):
        h = PolicyDefinition("h",1,"","",1,PolicyConditions(scope_level=1),"allow","","approved","","")
        l = PolicyDefinition("l",1,"","",100,PolicyConditions(scope_level=1),"deny","","approved","","")
        assert self._eng([l,h]).evaluate({"scope_level":1}).policy_id == "h"
    def test_action_group(self):
        p = PolicyDefinition("p1",1,"","",10,PolicyConditions(action_group="deploy"),"escalate","","approved","","")
        assert self._eng([p]).evaluate({"action_group":"deploy"}).outcome == "escalate"


class TestRiskScoring:
    def _engine(self):
        e = RiskScoringEngine(); e._apply_defaults(); e._config_loaded = True; return e
    def test_score_clamped(self):
        assert 0 <= self._engine().compute_risk({"action_group":"read"},0).risk_score <= 100
    def test_risk_category(self):
        e = self._engine()
        assert e.compute_risk({"action_group":"deploy"},1).risk_category == "deployment"
    def test_escalation_set(self):
        e = self._engine(); e._escalation_threshold = 10
        assert e.compute_risk({"action_group":"emergency"},4).escalation_flagged is True
    def test_escalation_not_set(self):
        e = self._engine(); e._escalation_threshold = 999
        assert e.compute_risk({"action_group":"read"},0).escalation_flagged is False
    def test_weights(self):
        e = self._engine()
        r1 = e.compute_risk({"action_group":"read"},1)
        r2 = e.compute_risk({"action_group":"read"},4)
        assert r2.risk_score > r1.risk_score


class TestDecisionEngine:
    def _de(self, t=70): return DecisionEngine(escalation_threshold=t)
    def _pr(self, o, p="p1"): return PolicyEvaluationResult(policy_id=p, outcome=o)
    def _ra(self, s): return RiskAssessment(risk_score=s, risk_category="data_access")
    def test_deny(self):
        assert self._de().decide(self._pr("deny"),self._ra(10),{"action_group":"x"},"a").verdict=="deny"
    def test_escalate_policy(self):
        assert self._de().decide(self._pr("escalate"),self._ra(10),{"action_group":"x"},"a").verdict=="escalate"
    def test_allow_low(self):
        assert self._de(70).decide(self._pr("allow"),self._ra(30),{"action_group":"x"},"a").verdict=="allow"
    def test_escalate_high(self):
        assert self._de(70).decide(self._pr("allow"),self._ra(80),{"action_group":"x"},"a").verdict=="escalate"
    def test_explanation(self):
        for o in ["allow","deny","escalate"]:
            d = self._de().decide(self._pr(o),self._ra(50),{"action_group":"x"},"a")
            assert len(d.explanation) > 0
    def test_framework(self):
        de = self._de(); de._framework_table_name = "ft"
        m = MagicMock(); mt = MagicMock(); m.Table.return_value = mt
        mt.get_item.return_value = {"Item":{"iso_42001_controls":["A.1"],"nist_ai_rmf_functions":["MAP"]}}
        de._dynamodb = m
        assert "A.1" in de.decide(self._pr("allow"),self._ra(10),{"action_group":"data_access"},"a").framework_mapping


class TestFailSafe:
    def test_policy_failure_deny(self):
        pe = MagicMock(); pe.evaluate.side_effect = RuntimeError("boom")
        r = safe_evaluate_policy(pe, {"action_group":"x"})
        assert r.outcome == "deny" and r.policy_id == "fail-safe-deny"
    def test_risk_failure_max(self):
        re = MagicMock(); re.compute_risk.side_effect = RuntimeError("boom")
        r = safe_compute_risk(re, {"action_group":"x"}, 1)
        assert r.risk_score == 100.0 and r.escalation_flagged is True
    @patch.dict(os.environ, {"OPERATOR_SNS_TOPIC_ARN": ""})
    def test_evidence_nonblocking(self):
        fn = MagicMock(side_effect=RuntimeError("s3 down"))
        d = GovernanceDecision(decision_id="d1",agent_id="a",action_requested="x")
        assert safe_write_evidence(fn, d) is False

class TestLatencyTracking:
    def test_breakdown(self):
        t = LatencyTracker()
        with t.track("policy_evaluation"): time.sleep(0.001)
        with t.track("risk_scoring"): time.sleep(0.001)
        m = t.record_latency("d1")
        assert "policy_evaluation" in m.component_latencies
    def test_budget_exceeded(self):
        t = LatencyTracker(); t._start_time = time.monotonic() - 1.0
        assert t.record_latency("d1").budget_exceeded is True
    def test_budget_ok(self):
        t = LatencyTracker()
        with t.track("policy_evaluation"): pass
        m = t.record_latency("d1")
        assert m.total_elapsed_ms < 5000
    def test_violation_logged(self, caplog):
        t = LatencyTracker(); t._start_time = time.monotonic() - 1.0
        with caplog.at_level(logging.WARNING):
            t.record_latency("d1")
        assert any("latency_budget_exceeded" in r.message for r in caplog.records)


class TestGovernanceHandler:
    def test_allow(self):
        pe = PolicyEngine()
        pe._policies = {"p1": PolicyDefinition("p1",1,"","",10,PolicyConditions(scope_level=1),"allow","","approved","","")}
        pr = pe.evaluate({"scope_level":1}); re = RiskScoringEngine(); re._apply_defaults(); re._config_loaded = True
        d = DecisionEngine(70).decide(pr, re.compute_risk({"action_group":"read"},1), {"action_group":"read"}, "a1")
        assert d.verdict == "allow"
    def test_deny(self):
        pe = PolicyEngine()
        pe._policies = {"p1": PolicyDefinition("p1",1,"","",10,PolicyConditions(scope_level=1),"deny","","approved","","")}
        d = DecisionEngine(70).decide(pe.evaluate({"scope_level":1}), RiskAssessment(risk_score=10,risk_category="data_access"), {"action_group":"x"}, "a1")
        assert d.verdict == "deny"
    def test_escalate(self):
        pe = PolicyEngine()
        pe._policies = {"p1": PolicyDefinition("p1",1,"","",10,PolicyConditions(scope_level=1),"allow","","approved","","")}
        d = DecisionEngine(70).decide(pe.evaluate({"scope_level":1}), RiskAssessment(risk_score=90,risk_category="deployment"), {"action_group":"x"}, "a1")
        assert d.verdict == "escalate"
    def test_ddb_unavailable(self):
        pe = MagicMock(); pe.evaluate.side_effect = Exception("ddb")
        assert safe_evaluate_policy(pe, {}).outcome == "deny"
    @patch.dict(os.environ, {"OPERATOR_SNS_TOPIC_ARN": ""})
    def test_evidence_fail(self):
        assert safe_write_evidence(MagicMock(side_effect=Exception()), GovernanceDecision(decision_id="d",agent_id="a",action_requested="x")) is False


class TestAgentIdentity:
    def test_create(self):
        a = AgentIdentityManager(MockTable()).create_agent("a1","Agent 1","dev")
        assert a.scope_level == 1 and a.status == "active"
    def test_reject_env(self):
        with pytest.raises(ValueError): AgentIdentityManager(MockTable()).create_agent("a1","A","bad")
    def test_update_scope(self):
        t = MockTable(); m = AgentIdentityManager(t); m.create_agent("a1","A","dev")
        with patch.dict(os.environ,{"CHANGE_LOG_TABLE_NAME":"","EVIDENCE_BUCKET_NAME":""}):
            assert m.update_scope_level("a1",2,"r",human_authorized=True).scope_level == 2
    def test_scope_no_auth(self):
        t = MockTable(); m = AgentIdentityManager(t); m.create_agent("a1","A","dev")
        with pytest.raises(ValueError): m.update_scope_level("a1",2,"r",human_authorized=False)
    def test_suspend(self):
        t = MockTable(); m = AgentIdentityManager(t); m.create_agent("a1","A","dev")
        m.suspend_agent("a1","r"); assert m.is_suspended("a1") is True
    def test_not_suspended(self):
        t = MockTable(); m = AgentIdentityManager(t); m.create_agent("a1","A","dev")
        assert m.is_suspended("a1") is False


class TestAgentRegistry:
    def _e(self, a="a1", p="P", o="O", dc=None, env="dev"):
        return AgentRegistryEntry(a, p, o, dc or ["pii"], ["t1"], 1, env)
    def test_enforce_fields(self):
        r = AgentRegistry(MockTable())
        with pytest.raises(ValueError): r.register_agent(AgentRegistryEntry("a","","O",["d"],[],"dev"),"r")
        with pytest.raises(ValueError): r.register_agent(AgentRegistryEntry("a","P","",["d"],[],"dev"),"r")
        with pytest.raises(ValueError): r.register_agent(AgentRegistryEntry("a","P","O",[],[],"dev"),"r")
    def test_get(self):
        t = MockTable(); r = AgentRegistry(t); r.register_agent(self._e(),"r")
        assert r.get_agent("a1").purpose == "P"
    def test_update(self, caplog):
        t = MockTable(); r = AgentRegistry(t); r.register_agent(self._e(),"r")
        with caplog.at_level(logging.INFO): r.update_agent("a1",{"purpose":"N"},"r")
        assert any("agent_registry_updated" in m.message for m in caplog.records)
    def test_data_class(self):
        t = MockTable(); r = AgentRegistry(t); r.register_agent(self._e(),"r")
        assert r.check_data_class_access("a1","pii") and not r.check_data_class_access("a1","x")
    def test_query(self):
        t = MockTable(); r = AgentRegistry(t)
        r.register_agent(self._e("a1",o="alice"),"r"); r.register_agent(self._e("a2",o="bob"),"r")
        assert len(r.query_agents({"owner":"alice"})) == 1


class TestToolModelRegistry:
    def _e(self, eid="e1"):
        return ToolModelRegistryEntry(eid,"model","MyModel","1.0")
    def test_role(self):
        with pytest.raises(PermissionError):
            ToolModelRegistry(MockTable("entry_id")).register_entry(self._e(),"r",[])
    def test_bad_cat(self):
        with pytest.raises(ValueError):
            ToolModelRegistry(MockTable("entry_id")).register_entry(ToolModelRegistryEntry("e1","bad","N","1.0"),"r",["policy_approver"])
    def test_approve(self):
        t = MockTable("entry_id"); r = ToolModelRegistry(t)
        r.register_entry(self._e(),"r",["policy_approver"]); r.approve_entry("e1","a",["policy_approver"])
        assert r.is_approved("e1")
    def test_revoke(self):
        t = MockTable("entry_id"); r = ToolModelRegistry(t)
        r.register_entry(self._e(),"r",["policy_approver"]); r.approve_entry("e1","a",["policy_approver"])
        r.revoke_entry("e1","r"); assert not r.is_approved("e1")
    def test_usage(self):
        t = MockTable("entry_id"); r = ToolModelRegistry(t)
        r.register_entry(self._e(),"r",["policy_approver"]); r.approve_entry("e1","a",["policy_approver"])
        assert r.check_usage_allowed("model","MyModel","1.0") and not r.check_usage_allowed("model","X","1.0")


class TestSoD:
    def test_assign(self):
        assert SeparationOfDuties(MockTable("user_id")).assign_role("u1","policy_author","g","a").role == "policy_author"
    def test_author_approver(self):
        t = MockTable("user_id"); s = SeparationOfDuties(t); s.assign_role("u1","policy_author","g","a")
        with pytest.raises(ValueError): s.assign_role("u1","policy_approver","g","a")
    def test_operator_auditor(self):
        t = MockTable("user_id"); s = SeparationOfDuties(t); s.assign_role("u1","operator","g","a")
        with pytest.raises(ValueError): s.assign_role("u1","auditor","g","a")
    def test_validate(self):
        t = MockTable("user_id"); s = SeparationOfDuties(t); s.assign_role("u1","policy_author","s","a")
        assert s.validate_action("u1","edit","s") is True
    def test_get_roles(self):
        t = MockTable("user_id"); s = SeparationOfDuties(t); s.assign_role("u1","operator","g","a")
        assert len(s.get_user_roles("u1")) >= 1

class TestEnvIsolation:
    def test_valid(self):
        ei = EnvironmentIsolation()
        for e in ["dev","staging","prod"]: assert ei.validate_environment(e)
    def test_invalid(self):
        ei = EnvironmentIsolation()
        for e in ["","test","production"]: assert not ei.validate_environment(e)
    def test_cross_match(self):
        assert EnvironmentIsolation().check_cross_environment("dev","dev")
    def test_cross_mismatch(self):
        assert not EnvironmentIsolation().check_cross_environment("dev","prod")
    def test_prefix(self):
        assert EnvironmentIsolation().get_environment_evidence_prefix("prod","a1",date(2024,6,15)) == "evidence/prod/a1/2024/06/15/"


class TestPhase1bIntegration:
    def test_suspended(self):
        t = MockTable(); m = AgentIdentityManager(t); m.create_agent("a1","A","dev")
        m.suspend_agent("a1","r"); assert m.is_suspended("a1")
    def test_unregistered(self):
        assert AgentRegistry(MockTable()).get_agent("x") is None
    def test_cross_env(self):
        assert not EnvironmentIsolation().check_cross_environment("dev","prod")
    def test_undeclared_dc(self):
        t = MockTable(); r = AgentRegistry(t)
        r.register_agent(AgentRegistryEntry("a1","P","O",["pii"],[],"dev"),"r")
        assert not r.check_data_class_access("a1","secret")
    def test_unapproved_tool(self):
        t = MockTable("entry_id"); r = ToolModelRegistry(t)
        r.register_entry(ToolModelRegistryEntry("e1","model","M","1.0"),"r",["policy_approver"])
        assert not r.check_usage_allowed("model","M","1.0")


class TestKillSwitch:
    def test_activate(self):
        st,art = MockTable(),MockTable(); art.put_item(Item={"agent_id":"a1"})
        r = KillSwitchManager().activate("op1",st,art)
        assert r["status"]=="activated" and "a1" in r["affected_agent_ids"]
    def test_logs(self, caplog):
        st,art = MockTable(),MockTable(); art.put_item(Item={"agent_id":"a1"})
        with caplog.at_level(logging.INFO): KillSwitchManager().activate("op1",st,art)
        assert any("kill_switch_activated" in m.message for m in caplog.records)
    def test_is_active(self):
        st,art = MockTable(),MockTable(); art.put_item(Item={"agent_id":"a1"})
        km = KillSwitchManager(); km.activate("op1",st,art); assert km.is_active(st)
    def test_deactivate_role(self):
        with pytest.raises(ValueError): KillSwitchManager().deactivate("op1",[],MockTable())
    def test_check(self):
        st,art = MockTable(),MockTable(); art.put_item(Item={"agent_id":"a1"})
        km = KillSwitchManager(); km.activate("op1",st,art)
        assert km.check_kill_switch(st)["verdict"]=="deny"


class TestEvidencePipeline:
    def test_s3_key(self):
        s3 = MagicMock(); s3.list_objects_v2.return_value = {"Contents":[]}; s3.put_object.return_value = {}
        d = GovernanceDecision(decision_id="d1",agent_id="a1",action_requested="r",verdict="allow",risk_score=10)
        r = EvidencePipeline().write_evidence(d,s3,"b","prod","a1")
        assert r and s3.put_object.call_args[1]["Key"].startswith("evidence/prod/a1/")
    def test_sha256(self):
        s3 = MagicMock(); s3.list_objects_v2.return_value = {"Contents":[]}; s3.put_object.return_value = {}
        r = EvidencePipeline().write_evidence(GovernanceDecision(decision_id="d1",agent_id="a1",action_requested="r",verdict="allow",risk_score=10),s3,"b","dev","a1")
        assert len(r.record_hash) == 64
    def test_chain(self):
        s3 = MagicMock()
        s3.list_objects_v2.return_value = {"Contents":[{"Key":"evidence/dev/a1/2024/01/01/old.json","LastModified":"2024-01-01"}]}
        s3.get_object.return_value = {"Body":io.BytesIO(json.dumps({"record_hash":"abc"}).encode())}
        s3.put_object.return_value = {}
        r = EvidencePipeline().write_evidence(GovernanceDecision(decision_id="d2",agent_id="a1",action_requested="r",verdict="allow",risk_score=10),s3,"b","dev","a1")
        assert r.previous_hash == "abc"
    def test_retry(self):
        s3 = MagicMock(); s3.list_objects_v2.return_value = {"Contents":[]}
        s3.put_object.side_effect = [Exception(),Exception(),{}]
        with patch("evidence_pipeline.time.sleep"):
            r = EvidencePipeline().write_evidence(GovernanceDecision(decision_id="d1",agent_id="a1",action_requested="r",verdict="allow",risk_score=10),s3,"b","dev","a1")
        assert r is not None
    def test_retention(self):
        assert EvidencePipeline._assign_retention_class("emergency_action")=="extended"
        assert EvidencePipeline._assign_retention_class("data_access")=="standard"
    def test_traces(self):
        er = EvidenceRecord("ev1","d1","a1","r","allow",10,"allow","2024-01-01",["A.1","MAP"])
        assert len(EvidencePipeline.generate_control_traces(er,["A.1","MAP"])) == 2


class TestPolicyLifecycle:
    def test_version(self):
        s3 = MagicMock(); s3.copy_object.return_value={}; s3.put_object.return_value={}
        t = MockTable("policy_id"); pl = PolicyLifecycle()
        with patch.dict(os.environ,{"CHANGE_LOG_TABLE_NAME":"","EVIDENCE_BUCKET_NAME":""}):
            assert pl.update_policy("p1",{},"a",s3,"b",t).version == 1
            assert pl.update_policy("p1",{},"a",s3,"b",t).version == 2
    def test_archive(self):
        s3 = MagicMock(); s3.copy_object.return_value={}; s3.put_object.return_value={}
        t = MockTable("policy_id"); pl = PolicyLifecycle()
        with patch.dict(os.environ,{"CHANGE_LOG_TABLE_NAME":"","EVIDENCE_BUCKET_NAME":""}):
            pl.update_policy("p1",{},"a",s3,"b",t); pl.update_policy("p1",{},"a",s3,"b",t)
        assert s3.copy_object.called
    def test_sod(self):
        with pytest.raises(ValueError): PolicyLifecycle().approve_policy("p1",1,"same",["policy_approver"],"same")
    def test_rollback(self):
        s3 = MagicMock(); s3.copy_object.return_value={}; s3.put_object.return_value={}
        t = MockTable("policy_id"); pl = PolicyLifecycle()
        with patch.dict(os.environ,{"CHANGE_LOG_TABLE_NAME":"","EVIDENCE_BUCKET_NAME":""}):
            pl.update_policy("p1",{},"a",s3,"b",t); pl.update_policy("p1",{},"a",s3,"b",t)
            assert pl.rollback_policy("p1",1,"r",s3,"b",t).version == 3
    def test_history(self):
        s3 = MagicMock(); s3.copy_object.return_value={}; s3.put_object.return_value={}
        t = MockTable("policy_id"); pl = PolicyLifecycle()
        with patch.dict(os.environ,{"CHANGE_LOG_TABLE_NAME":"","EVIDENCE_BUCKET_NAME":""}):
            pl.update_policy("p1",{},"a",s3,"b",t)
        assert len(pl.get_policy_history("p1",t)) >= 1


class TestThreatDetector:
    def _td(self, pats):
        td = ThreatDetector(); td._patterns = [ThreatPattern(**p) for p in pats]; td._cache_timestamp = time.time(); return td
    def test_sql(self):
        assert self._td([{"pattern_id":"t1","category":"known_bad","pattern":"select.*from","description":"S","risk_weight":50,"updated_at":""}]).evaluate("SELECT * FROM users","a")["classification"]=="denied"
    def test_prompt(self):
        assert self._td([{"pattern_id":"t2","category":"known_bad","pattern":"ignore previous instructions","description":"P","risk_weight":50,"updated_at":""}]).evaluate("ignore previous instructions","a")["classification"]=="denied"
    def test_suspicious(self):
        assert self._td([{"pattern_id":"t3","category":"suspicious","pattern":"sudo","description":"S","risk_weight":20,"updated_at":""}]).evaluate("run sudo","a")["classification"]=="suspicious"
    def test_clean(self):
        assert self._td([{"pattern_id":"t1","category":"known_bad","pattern":"drop table","description":"D","risk_weight":50,"updated_at":""}]).evaluate("show status","a")["classification"]=="clean"
    def test_risk_adj(self):
        assert self._td([{"pattern_id":"t1","category":"suspicious","pattern":"admin","description":"A","risk_weight":15,"updated_at":""}]).evaluate("admin access","a")["risk_score_adjustment"]==15
    def test_log(self, caplog):
        td = self._td([{"pattern_id":"t1","category":"known_bad","pattern":"drop","description":"D","risk_weight":50,"updated_at":""}])
        with caplog.at_level(logging.WARNING): td.evaluate("drop table","a")
        assert any("threat_evaluation" in m.message for m in caplog.records)


class TestControlTraceManager:
    def test_store(self):
        t = MockTable("control_id")
        assert ControlTraceManager.store_traces([ControlTrace("c1","comp","ev1","d1","2024-01-01"),ControlTrace("c2","comp","ev1","d1","2024-01-01")],t)==2
    def test_query_control(self):
        t = MockTable("control_id"); t.put_item(Item={"control_id":"c1","implementation_component":"c","evidence_record_id":"e","decision_id":"d","timestamp":"t"})
        assert len(ControlTraceManager.query_by_control_id("c1",t))>=1
    def test_query_evidence(self):
        t = MagicMock(); t.query.return_value={"Items":[{"control_id":"c1","implementation_component":"c","evidence_record_id":"ev1","decision_id":"d","timestamp":"t"}]}
        assert len(ControlTraceManager.query_by_evidence_record_id("ev1",t))==1
    def test_query_decision(self):
        t = MagicMock(); t.query.return_value={"Items":[{"control_id":"c1","implementation_component":"c","evidence_record_id":"e","decision_id":"d1","timestamp":"t"}]}
        assert len(ControlTraceManager.query_by_decision_id("d1",t))==1


class TestEvidenceIntegrity:
    def _rec(self):
        d = {"evidence_id":"ev1","decision_id":"d1","agent_id":"a1","verdict":"allow","timestamp":"2024-01-01"}
        h = hashlib.sha256(json.dumps(d,sort_keys=True).encode()).hexdigest()
        d["record_hash"]=h; return d,h
    def test_valid(self):
        d,_ = self._rec(); s3=MagicMock(); s3.get_object.return_value={"Body":io.BytesIO(json.dumps(d).encode())}
        assert EvidenceIntegrity().verify_record_integrity("ev1",s3,"b","k")
    def test_mismatch(self):
        d,_ = self._rec(); d["record_hash"]="bad"; s3=MagicMock(); s3.get_object.return_value={"Body":io.BytesIO(json.dumps(d).encode())}
        assert not EvidenceIntegrity().verify_record_integrity("ev1",s3,"b","k")
    def test_chain_ok(self):
        r1={"evidence_id":"ev1","timestamp":"2024-01-01","record_hash":"h1","previous_hash":""}
        r2={"evidence_id":"ev2","timestamp":"2024-01-02","record_hash":"h2","previous_hash":"h1"}
        s3=MagicMock(); s3.list_objects_v2.return_value={"Contents":[{"Key":"evidence/prod/a1/2024/01/01/ev1.json"},{"Key":"evidence/prod/a1/2024/01/02/ev2.json"}]}
        s3.get_object.side_effect=[{"Body":io.BytesIO(json.dumps(r1).encode())},{"Body":io.BytesIO(json.dumps(r2).encode())}]
        assert all(r["chain_valid"] for r in EvidenceIntegrity().verify_hash_chain(s3,"b","prod","a1","2024-01-01","2024-01-02"))
    def test_chain_break(self):
        r1={"evidence_id":"ev1","timestamp":"2024-01-01","record_hash":"h1","previous_hash":""}
        r2={"evidence_id":"ev2","timestamp":"2024-01-02","record_hash":"h2","previous_hash":"wrong"}
        s3=MagicMock(); s3.list_objects_v2.return_value={"Contents":[{"Key":"evidence/prod/a1/2024/01/01/ev1.json"},{"Key":"evidence/prod/a1/2024/01/02/ev2.json"}]}
        s3.get_object.side_effect=[{"Body":io.BytesIO(json.dumps(r1).encode())},{"Body":io.BytesIO(json.dumps(r2).encode())}]
        assert not EvidenceIntegrity().verify_hash_chain(s3,"b","prod","a1","2024-01-01","2024-01-02")[1]["chain_valid"]
    def test_retention(self):
        assert EvidenceIntegrity.get_retention_config("standard")==365 and EvidenceIntegrity.get_retention_config("extended")==2555


class TestPhase1cIntegration:
    def test_kill_deny(self):
        st,art = MockTable(),MockTable(); art.put_item(Item={"agent_id":"a1"})
        km = KillSwitchManager(); km.activate("op1",st,art)
        assert km.check_kill_switch(st)["verdict"]=="deny"
    def test_threat(self):
        td = ThreatDetector(); td._patterns=[ThreatPattern("t1","known_bad","drop table","D",50,"")]; td._cache_timestamp=time.time()
        assert td.evaluate("drop table users","a")["classification"]=="denied"
    def test_suspicious(self):
        td = ThreatDetector(); td._patterns=[ThreatPattern("t1","suspicious","sudo","S",20,"")]; td._cache_timestamp=time.time()
        assert td.evaluate("sudo rm","a")["risk_score_adjustment"]==20
    def test_evidence(self):
        s3=MagicMock(); s3.list_objects_v2.return_value={"Contents":[]}; s3.put_object.return_value={}
        assert EvidencePipeline().write_evidence(GovernanceDecision(decision_id="d1",agent_id="a1",action_requested="r",verdict="allow",risk_score=10),s3,"b","dev","a1") is not None
    def test_traces(self):
        er = EvidenceRecord("ev1","d1","a1","r","allow",10,"allow","2024-01-01",["A.1"])
        assert len(EvidencePipeline.generate_control_traces(er,["A.1"]))==1

class TestValidationSuite:
    def test_run_all(self):
        assert len(MinimumValidationSuite().run_all_tests()) >= 4
    def test_report(self):
        vs = MinimumValidationSuite(); r = vs.generate_report(vs.run_all_tests())
        assert "suite_passed" in r and "tests" in r
    def test_passed_true(self):
        assert MinimumValidationSuite().check_suite_passed([ValidationResult("t1",True),ValidationResult("t2",True)])
    def test_passed_false(self):
        assert not MinimumValidationSuite().check_suite_passed([ValidationResult("t1",True),ValidationResult("t2",False)])
    def test_evidence_gen(self):
        r = MinimumValidationSuite().test_evidence_generation()
        assert r.passed and len(r.evidence_record_ids) > 0
