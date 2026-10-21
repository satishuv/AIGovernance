"""P0-18: no DynamoDB scans on the authorization request path.

Every request-path lookup changed by P0-18 runs here against a table wrapper
whose scan() raises, so a regression back to a scan fails loudly instead of
silently getting slower as the registry grows towards 2,000 agents.
"""

import os
import sys
import types

import boto3
import pytest
from moto import mock_aws

_GE = os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine")
sys.path.insert(0, os.path.abspath(_GE))

from agent_registry import AgentRegistry, registry_table_definition  # noqa: E402
from authority_identity import (  # noqa: E402
    AmbiguousAgentPrincipal, RoleDirectory, resolve_caller)
from models import AgentRegistryEntry, ToolModelRegistryEntry  # noqa: E402
from tool_execution_auth import (  # noqa: E402
    ToolExecutionAuthManager, tool_auth_table_definition)
from tool_model_registry import ToolModelRegistry  # noqa: E402

REGION = "ca-central-1"
WORKER_ROLE = "arn:aws:iam::111122223333:role/worker-runtime"
WORKER_SESSION = "arn:aws:sts::111122223333:assumed-role/worker-runtime/session-7"
APPROVER = "arn:aws:iam::111122223333:role/Approver"


class NoScanTable:
    """Forwards every call to a real table except scan(), which fails the test."""

    def __init__(self, table):
        self._table = table

    def scan(self, **kwargs):
        raise AssertionError(f"request path scanned the table {self._table.name}")

    def __getattr__(self, name):
        return getattr(self._table, name)


@pytest.fixture
def ddb():
    with mock_aws():
        os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
        yield boto3.resource("dynamodb", region_name=REGION)


def _agent(agent_id, principal=""):
    return AgentRegistryEntry(agent_id=agent_id, purpose="test agent", owner="owner-team",
                              data_classes=["Internal"], environment="prod",
                              runtime_principal=principal)


def _registry(ddb):
    return ddb.create_table(**registry_table_definition("registry"))


def test_runtime_principal_lookup_is_an_index_query(ddb):
    table = _registry(ddb)
    real = AgentRegistry(table)
    real.register_agent(_agent("worker-agent", WORKER_ROLE), requester_id="admin")
    # An agent with no runtime principal registers (no empty index key) and
    # is simply absent from the index.
    real.register_agent(_agent("batch-agent"), requester_id="admin")

    registry = AgentRegistry(NoScanTable(table))
    assert registry.agent_id_for_principal(WORKER_ROLE) == "worker-agent"
    # An STS session of the role resolves through the role ARN.
    assert registry.agent_id_for_principal(WORKER_SESSION) == "worker-agent"
    assert registry.agent_id_for_principal("arn:aws:iam::111122223333:role/someone-else") == ""
    assert "runtime_principal" not in table.get_item(Key={"agent_id": "batch-agent"})["Item"]


def test_clearing_a_runtime_principal_removes_it_from_the_index(ddb):
    table = _registry(ddb)
    registry = AgentRegistry(table)
    registry.register_agent(_agent("worker-agent", WORKER_ROLE), requester_id="admin")
    registry.update_agent("worker-agent", {"runtime_principal": ""}, requester_id="admin")
    assert registry.agent_id_for_principal(WORKER_ROLE) == ""
    assert registry.get_agent("worker-agent").runtime_principal == ""


def test_a_principal_claimed_by_two_agents_is_denied_everywhere(ddb):
    table = _registry(ddb)
    registry = AgentRegistry(table)
    registry.register_agent(_agent("worker-agent", WORKER_ROLE), requester_id="admin")
    registry.register_agent(_agent("impostor-agent", WORKER_ROLE), requester_id="admin")
    with pytest.raises(AmbiguousAgentPrincipal):
        registry.find_by_runtime_principal(WORKER_SESSION)
    caller = resolve_caller(WORKER_SESSION, "iam", RoleDirectory({WORKER_ROLE: {"governance_admin"}}),
                            registry.agent_id_for_principal)
    # Neither an agent nor a human: no plane accepts an unknown principal, and
    # the governance_admin role recorded for the principal is not applied.
    assert caller.principal_type == "unknown"
    assert caller.roles == set()


def test_roles_are_read_with_key_queries(ddb):
    roles = ddb.create_table(
        TableName="roles",
        KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"},
                   {"AttributeName": "role", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"},
                              {"AttributeName": "role", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    roles.put_item(Item={"user_id": APPROVER, "role": "policy_approver"})
    roles.put_item(Item={"user_id": APPROVER, "role": "operator", "status": "revoked"})
    roles.put_item(Item={"user_id": "arn:aws:iam::111122223333:role/Other", "role": "governance_admin"})

    session = "arn:aws:sts::111122223333:assumed-role/Approver/alice"
    directory = RoleDirectory.for_principal(NoScanTable(roles), session)
    assert directory.roles_for(session) == {"policy_approver"}


def test_role_query_failure_grants_no_roles():
    class Broken:
        def query(self, **kwargs):
            raise RuntimeError("throttled")
    assert RoleDirectory.for_principal(Broken(), APPROVER).roles_for(APPROVER) == set()


def test_api_caller_resolution_never_scans(ddb):
    from authority_factory import caller_from_api_event

    registry_table = _registry(ddb)
    AgentRegistry(registry_table).register_agent(_agent("worker-agent", WORKER_ROLE), requester_id="admin")
    roles = ddb.create_table(
        TableName="roles2",
        KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"},
                   {"AttributeName": "role", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"},
                              {"AttributeName": "role", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    roles.put_item(Item={"user_id": APPROVER, "role": "policy_approver"})
    control_plane = types.SimpleNamespace(registry=AgentRegistry(NoScanTable(registry_table)))

    def event(principal):
        return {"requestContext": {"identity": {"userArn": principal}}}

    agent = caller_from_api_event(event(WORKER_SESSION), control_plane, NoScanTable(roles))
    assert (agent.principal_type, agent.agent_id) == ("agent", "worker-agent")
    human = caller_from_api_event(event(APPROVER), control_plane, NoScanTable(roles))
    assert (human.principal_type, human.roles) == ("human", {"policy_approver"})


def test_tool_model_usage_check_is_an_index_query(ddb):
    table = ddb.create_table(
        TableName="tool-models",
        KeySchema=[{"AttributeName": "entry_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "entry_id", "AttributeType": "S"},
                              {"AttributeName": "identity_key", "AttributeType": "S"}],
        GlobalSecondaryIndexes=[{"IndexName": "ByIdentity",
                                 "KeySchema": [{"AttributeName": "identity_key", "KeyType": "HASH"}],
                                 "Projection": {"ProjectionType": "ALL"}}],
        BillingMode="PAY_PER_REQUEST")
    admin = ToolModelRegistry(table)
    admin.register_entry(ToolModelRegistryEntry("e1", "model", "nova-micro", "1.0"), "r", ["policy_approver"])
    admin.register_entry(ToolModelRegistryEntry("e2", "model", "nova-micro", "2.0"), "r", ["policy_approver"])
    admin.approve_entry("e1", "approver", ["policy_approver"])

    registry = ToolModelRegistry(NoScanTable(table))
    assert registry.check_usage_allowed("model", "nova-micro", "1.0") is True
    assert registry.check_usage_allowed("model", "nova-micro", "2.0") is False  # pending
    assert registry.check_usage_allowed("model", "unknown-model", "1.0") is False

    # An entry written before the index existed is invisible until backfilled.
    table.put_item(Item={"entry_id": "legacy", "category": "tool_connector", "name": "jira",
                         "version": "3", "approval_status": "approved"})
    assert registry.check_usage_allowed("tool_connector", "jira", "3") is False
    assert admin.backfill_identity_keys() == 1
    assert registry.check_usage_allowed("tool_connector", "jira", "3") is True


def test_tool_model_query_failure_denies():
    class Broken:
        def query(self, **kwargs):
            raise RuntimeError("index missing")
    assert ToolModelRegistry(Broken()).check_usage_allowed("model", "m", "1") is False


def test_chain_detection_reads_the_lookup_index_only(ddb):
    table = ddb.create_table(**tool_auth_table_definition("tool-auth"))
    # The record shape seed_data.py writes: "sequence" and "chain_name".
    table.put_item(Item={"pk": "CHAIN#exfiltration_pattern", "sk": "DEFINITION",
                         "lookup_pk": "CHAIN", "lookup_sk": "CHAIN#exfiltration_pattern",
                         "chain_name": "exfiltration_pattern",
                         "description": "Detects potential data exfiltration via tool chaining",
                         "sequence": ["ReadPipelineStatus", "SensitiveDataExport"]})
    manager = ToolExecutionAuthManager()
    manager.record_tool_call("worker-agent", "ReadPipelineStatus", table)
    manager.record_tool_call("other-agent", "ReadPipelineStatus", table)

    guarded = NoScanTable(table)
    assert manager._get_recent_tool_history("worker-agent", guarded) == ["ReadPipelineStatus"]
    safe, description = manager._check_chain("worker-agent", "SensitiveDataExport", guarded)
    assert safe is False and "exfiltration" in description.lower()
    # A fresh agent with no history does not complete the chain.
    assert manager._check_chain("new-agent", "SensitiveDataExport", guarded) == (True, "")


def test_pipeline_reuses_configuration_between_requests(monkeypatch):
    import pipeline_orchestrator as po

    loads = []

    class FakeRiskEngine:
        def __init__(self):
            self.last_load_ok = False
            self.escalation_threshold = 70.0

        def load_config(self):
            loads.append(1)
            self.last_load_ok = len(loads) > 1  # the first load fails

    monkeypatch.setattr(po, "RiskScoringEngine", FakeRiskEngine)
    po.reset_request_path_caches()
    try:
        first = po._get_cached_risk_engine()
        second = po._get_cached_risk_engine()  # failed load was not cached
        third = po._get_cached_risk_engine()   # served from the cache
        assert len(loads) == 2 and first is not second and second is third
        assert po._get_threat_detector() is po._get_threat_detector()
        assert po._get_exfiltration_detector() is po._get_exfiltration_detector()
    finally:
        po.reset_request_path_caches()
