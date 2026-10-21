"""P0-17: real policy bindings, selected by trusted agent attributes."""

import json
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "lambdas" / "governance_engine"))

from models import AgentRegistryEntry  # noqa: E402
from opa_engine import OPAEngine  # noqa: E402
from policy_bindings import BindingError, agent_attributes, parse_binding  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402

READ = [{"field": "input.action_group", "op": "==", "value": "ReadPipelineStatus"}]


def _agent(agent_id, bundle="", tier="medium", env="prod"):
    return AgentRegistryEntry(agent_id=agent_id, purpose="p", owner="o", data_classes=["x"], environment=env,
                              policy_bundle=bundle, risk_tier=tier)


def _engine(*policies):
    engine = OPAEngine()
    engine.load_policies_from_json(list(policies))
    return engine


def _rule(name, outcome, priority, binding=None):
    rule = {"rule_name": name, "outcome": outcome, "priority": priority, "conditions": READ}
    if binding is not None:
        rule["binding"] = binding
    return rule


def _verdict(engine, agent):
    return engine.evaluate({"action_group": "ReadPipelineStatus"}, agent_attrs=agent_attributes(agent)).verdict


def test_bound_policies_apply_only_to_selected_agents():
    engine = _engine(
        _rule("finance_read", "allow", 50, {"policy_bundles": ["finance"]}),
        _rule("default_deny", "deny", 999),
    )
    assert _verdict(engine, _agent("payments", bundle="finance")) == "allow"
    # Before P0-17 every policy applied to every agent, so this agent was allowed too.
    assert _verdict(engine, _agent("hr-bot", bundle="hr")) == "deny"


def test_every_dimension_must_match():
    engine = _engine(
        _rule("low_risk_prod", "allow", 50, {"risk_tiers": ["low"], "environments": ["prod"]}),
        _rule("default_deny", "deny", 999),
    )
    assert _verdict(engine, _agent("a", tier="low", env="prod")) == "allow"
    assert _verdict(engine, _agent("b", tier="high", env="prod")) == "deny"
    assert _verdict(engine, _agent("c", tier="low", env="dev")) == "deny"


def test_without_attributes_only_global_and_deny_rules_apply():
    engine = _engine(
        _rule("finance_read", "allow", 50, {"policy_bundles": ["finance"]}),
        _rule("finance_freeze", "deny", 10, {"policy_bundles": ["finance"]}),
        _rule("global_read", "allow", 60),
    )
    decision = engine.evaluate({"action_group": "ReadPipelineStatus"})
    assert decision.verdict == "deny" and decision.matched_rules[0] == "finance_freeze"


@pytest.mark.parametrize("raw", ["finance", {"bundles": ["x"]}, {"risk_tiers": []}, {"agent_ids": [3]}])
def test_malformed_bindings_are_rejected(raw):
    with pytest.raises(BindingError):
        parse_binding(raw)


def test_a_bad_binding_can_restrict_but_never_widen():
    engine = _engine(
        _rule("broken_allow", "allow", 10, {"bundles": ["finance"]}),
        _rule("broken_deny", "deny", 5, {"bundles": ["hr"]}),
        _rule("global_read", "allow", 60),
    )
    # The broken allow applies to no one; the broken deny applies to everyone.
    decision = engine.evaluate({"action_group": "ReadPipelineStatus"}, agent_attrs=agent_attributes(_agent("x")))
    assert decision.verdict == "deny" and decision.matched_rules[0] == "broken_deny"
    assert "broken_allow" not in decision.matched_rules


def test_index_reads_global_rules_plus_the_agents_bundle_only():
    policies = [_rule(f"bundle_{i}_read", "allow", 50, {"policy_bundles": [f"bundle-{i}"]}) for i in range(500)]
    engine = _engine(*policies, _rule("default_deny", "deny", 999))
    names = {r.name for r in engine.rules_for(agent_attributes(_agent("a", bundle="bundle-7")))}
    assert names == {"bundle_7_read", "default_deny"}
    assert engine.binding_summary()["*"] == 1 and len(engine.binding_summary()) == 501


def test_binding_changes_change_the_policy_fingerprint():
    unbound = _engine(_rule("r", "allow", 50))
    bound = _engine(_rule("r", "allow", 50, {"policy_bundles": ["finance"]}))
    rebound = _engine(_rule("r", "allow", 50, {"policy_bundles": ["hr"]}))
    assert len({unbound.policy_fingerprint(), bound.policy_fingerprint(), rebound.policy_fingerprint()}) == 3


def test_json_engine_honours_bindings_and_the_schema_accepts_them(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="binding-policies")
        base = {"version": 1, "priority": 50, "conditions": {"action_group": "ReadPipelineStatus"},
                "outcome": "allow", "name": "finance read", "description": "binding test", "owner": "o",
                "approval_status": "approved", "created_at": "2026-10-21T00:00:00+00:00",
                "updated_at": "2026-10-21T00:00:00+00:00"}
        s3.put_object(Bucket="binding-policies", Key="policies/finance.json", Body=json.dumps(
            {**base, "policy_id": "finance_read", "binding": {"policy_bundles": ["finance"]}}))
        engine = PolicyEngine()
        engine.load_policies(s3, "binding-policies", "policies/")
        assert "finance_read" in engine.policies  # schema accepted the binding
        request = {"action_group": "ReadPipelineStatus"}
        assert engine.evaluate(request, agent_attrs=agent_attributes(_agent("p", bundle="finance"))).outcome == "allow"
        assert engine.evaluate(request, agent_attrs=agent_attributes(_agent("h", bundle="hr"))).outcome == "deny"


def test_pipeline_applies_bindings_from_the_registry_not_the_request(monkeypatch):
    import importlib.util

    with mock_aws():
        for key, value in {"AWS_DEFAULT_REGION": "ca-central-1", "AWS_ACCESS_KEY_ID": "t",
                           "AWS_SECRET_ACCESS_KEY": "t"}.items():
            monkeypatch.setenv(key, value)
        from agent_registry import AgentRegistry, registry_table_definition
        ddb = boto3.resource("dynamodb", region_name="ca-central-1")
        s3 = boto3.client("s3", region_name="ca-central-1")
        registry = AgentRegistry(ddb.create_table(**registry_table_definition("registry")))
        scope = ddb.create_table(TableName="scope", KeySchema=[{"AttributeName": "agent_id", "KeyType": "HASH"}],
                                 AttributeDefinitions=[{"AttributeName": "agent_id", "AttributeType": "S"}],
                                 BillingMode="PAY_PER_REQUEST")
        s3.create_bucket(Bucket="policies", CreateBucketConfiguration={"LocationConstraint": "ca-central-1"})
        s3.put_object(Bucket="policies", Key="policies/finance-read.json", Body=json.dumps(
            _rule("finance_read", "allow", 50, {"policy_bundles": ["finance"]})))
        s3.put_object(Bucket="policies", Key="policies/default-deny.json",
                      Body=json.dumps({"rule_name": "default_deny", "outcome": "deny", "priority": 999,
                                       "conditions": []}))
        for agent, bundle in (("payments", "finance"), ("hr-bot", "hr")):
            entry = _agent(agent, bundle=bundle, env="dev")
            entry.data_classes = ["pipeline_status"]
            registry.register_agent(entry, requester_id="admin")
            scope.put_item(Item={"agent_id": agent, "scope_level": 1})

        import pipeline_orchestrator as po
        spec = importlib.util.spec_from_file_location("index", _ROOT / "lambdas" / "governance_engine" / "index.py")
        engine_index = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine_index)
        monkeypatch.setitem(sys.modules, "index", engine_index)
        for name, value in (("AGENT_REGISTRY_TABLE_NAME", "registry"), ("SCOPE_TABLE_NAME", "scope"),
                            ("POLICY_BUCKET_NAME", "policies")):
            monkeypatch.setattr(po, name, value)
        po.reset_request_path_caches()
        try:
            def run(agent_id, **extra):
                return po.run_pipeline({"agent_id": agent_id, "action_group": "ReadPipelineStatus",
                                        "input_text": "show build status", **extra}, None)["verdict"]
            assert run("payments") == "allow"
            assert run("hr-bot") == "deny"
            # A bundle named in the request is not an attribute.
            assert run("hr-bot", policy_bundle="finance") == "deny"
        finally:
            po.reset_request_path_caches()
