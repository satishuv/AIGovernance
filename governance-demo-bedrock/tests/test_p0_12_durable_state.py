"""P0-12: no authoritative security state only in process memory.

Each authoritative class keeps working in memory for tests, refuses to start
memory-only inside a deployed Lambda function, and with a table behaves as
one shared store: a second instance (a second Lambda container) sees what
the first wrote, and concurrent status changes cannot both win.
"""

import os
import subprocess
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "lambdas" / "governance_engine"))

from agent_lifecycle_states import AgentLifecycleManager  # noqa: E402
from agent_memory import AgentMemoryManager  # noqa: E402
from agent_token_exchange import AgentTokenExchange  # noqa: E402
from ai_asset_registry import AIAsset, AIAssetRegistry  # noqa: E402
from cost_governance import AgentBudget, CostGovernance, cost_table_definition  # noqa: E402
from durable_state import MemoryOnlyStateError, key_table_definition  # noqa: E402
from governance_change_management import GovernanceChangeManagement  # noqa: E402
from governance_rollback import GovernanceRollbackManager  # noqa: E402

REGION = "ca-central-1"


@pytest.fixture
def ddb():
    with mock_aws():
        os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
        yield boto3.resource("dynamodb", region_name=REGION)


@pytest.mark.parametrize("factory", [
    AIAssetRegistry, CostGovernance, GovernanceChangeManagement, AgentLifecycleManager,
    AgentMemoryManager, AgentTokenExchange, GovernanceRollbackManager,
], ids=lambda f: f.__name__)
def test_memory_only_state_is_refused_in_a_deployed_function(monkeypatch, factory):
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "governance-engine")
    with pytest.raises(MemoryOnlyStateError):
        factory()


def test_memory_only_state_still_works_outside_lambda(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    for factory in (AIAssetRegistry, CostGovernance, GovernanceChangeManagement, AgentLifecycleManager):
        factory()


def test_asset_revocation_is_seen_by_another_instance(ddb):
    table = ddb.create_table(**key_table_definition("assets", "asset_id"))
    first, second = AIAssetRegistry(table), AIAssetRegistry(table)
    first.register(AIAsset(asset_id="model-1", asset_type="model", name="nova", owner="ml-team"))
    first.update("model-1", {"approval_status": "approved"})
    assert second.check_access("model-1", "any-agent") is True
    first.revoke("model-1", revoked_by="security", reason="vulnerability")
    # Before P0-12 the second container kept its own copy and still allowed it.
    assert second.check_access("model-1", "any-agent") is False
    assert second.get_inventory_summary()["by_status"] == {"revoked": 1}


def test_asset_read_error_denies(ddb):
    class Broken:
        def get_item(self, **kwargs):
            raise RuntimeError("throttled")
    assert AIAssetRegistry(Broken()).check_access("model-1", "agent") is False


def test_spend_is_shared_and_atomic_across_instances(ddb):
    table = ddb.create_table(**cost_table_definition("cost"))
    first, second = CostGovernance(table), CostGovernance(table)
    first.set_budget(AgentBudget(agent_id="agent-1", daily_limit_usd=0.0025, alert_threshold_pct=90))
    # One governance decision costs 0.001.
    assert first.record_spend("agent-1", "governance_decision") is None  # 0.001 of 0.0025
    assert second.record_spend("agent-1", "governance_decision") is None  # 0.002: 80 %, under the alert
    alert = first.record_spend("agent-1", "governance_decision")  # 0.003: over
    assert alert and alert.startswith("BUDGET_EXCEEDED")
    report = second.get_cost_report("agent-1")
    assert report.total_decisions == 3 and report.throttled is True
    assert second.check_budget("agent-1")["throttled"] is True


def test_change_request_cannot_be_approved_twice_by_two_instances(ddb):
    table = ddb.create_table(**key_table_definition("changes", "request_id"))
    first, second = GovernanceChangeManagement(table), GovernanceChangeManagement(table)
    applied = []
    for manager in (first, second):
        manager.register_apply_callback("modify_agent", lambda target, changes: applied.append(target))
    request = first.create_request("modify_agent", "agent-1", "agent", "alice", "raise limit", {"x": 1})
    # The second instance read the request while it was still pending.
    stale = second._get(request.request_id)
    first.approve(request.request_id, reviewer="bob")
    second._get = lambda request_id: stale
    with pytest.raises(ValueError, match="changed concurrently"):
        second.approve(request.request_id, reviewer="carol")
    assert applied == ["agent-1"]
    assert GovernanceChangeManagement(table).get_summary()["applied"] == 1


def test_lifecycle_suspension_is_not_overwritten_by_a_stale_instance(ddb):
    table = ddb.create_table(**key_table_definition("lifecycle", "agent_id"))
    first, second = AgentLifecycleManager(table), AgentLifecycleManager(table)
    first.initialize_agent("agent-1", created_by="admin")
    for target in ("registered", "risk_reviewed", "approved", "deployed"):
        assert first.transition("agent-1", target, "admin").success, target
    assert second.check_operational("agent-1") is True
    stale = second._load("agent-1")
    suspended = first.transition("agent-1", "suspended", "security", "incident")
    assert (suspended.from_state, suspended.to_state) == ("deployed", "suspended")
    # A transition decided on the stale "deployed" state must not win.
    second._load = lambda agent_id: stale
    result = second.transition("agent-1", "monitored", "automation")
    assert result.success is False and "concurrently" in result.reason
    assert AgentLifecycleManager(table).check_operational("agent-1") is False


def test_memory_recall_failure_does_not_serve_a_partial_history(ddb):
    class FlakyTable:
        def put_item(self, **kwargs):
            pass

        def query(self, **kwargs):
            raise RuntimeError("throttled")

    memory = AgentMemoryManager(FlakyTable())
    memory.store_memory("agent-1", "governance", "denied production deploy")
    with pytest.raises(RuntimeError):
        memory.recall_memories("agent-1")


def test_inventory_has_no_unreviewed_in_memory_state():
    result = subprocess.run([sys.executable, str(_ROOT / "scripts" / "inventory_in_memory_state.py")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
