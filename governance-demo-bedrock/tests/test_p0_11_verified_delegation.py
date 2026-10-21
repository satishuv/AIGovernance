"""P0-11 verified delegation and P0-02 trusted effective scope.

The store and scope tests are unit tests. The pipeline tests run the real
governance pipeline (run_pipeline) on moto with the sample policy bundle, so
they exercise the same code the Lambda runs.
"""

import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "lambdas" / "governance_engine"))

from agent_registry import AgentRegistry, registry_table_definition  # noqa: E402
from delegation_receipts import (  # noqa: E402
    DelegationError, DelegationReceiptStore, receipt_table_definition)
from effective_scope import ceilings_for, read_operator_scope  # noqa: E402
from models import AgentRegistryEntry  # noqa: E402

REGION = "ca-central-1"


class Clock:
    def __init__(self, now=1_800_000_000):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def ddb():
    with mock_aws():
        os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
        yield boto3.resource("dynamodb", region_name=REGION)


@pytest.fixture
def store(ddb):
    clock = Clock()
    return DelegationReceiptStore(ddb.create_table(**receipt_table_definition("receipts")), clock=clock), clock


# --- receipt store -----------------------------------------------------------

def test_receipt_is_single_use_and_bound_to_its_child(store):
    receipts, _ = store
    issued = receipts.issue(parent_agent_id="orchestrator", child_agent_id="worker", parent_scope=2)
    assert (issued.chain, issued.scope_cap, issued.max_uses) == (["orchestrator"], 2, 1)

    assert receipts.consume(issued.receipt_id, "intruder")[1] == "delegation receipt was issued to a different agent"
    used, reason = receipts.consume(issued.receipt_id, "worker")
    assert reason == "" and used.uses == 1
    assert receipts.consume(issued.receipt_id, "worker") == (None, "delegation receipt has already been used")


def test_expired_revoked_and_unknown_receipts_are_refused(store):
    receipts, clock = store
    expiring = receipts.issue(parent_agent_id="p", child_agent_id="c", parent_scope=1, ttl_seconds=60)
    revoked = receipts.issue(parent_agent_id="p", child_agent_id="c", parent_scope=1)
    assert receipts.revoke(revoked.receipt_id, revoked_by="operator")
    clock.now += 61
    assert receipts.consume(expiring.receipt_id, "c")[1] == "delegation receipt has expired"
    assert receipts.consume(revoked.receipt_id, "c")[1] == "delegation receipt is revoked"
    assert receipts.consume("dlg-missing", "c")[1] == "delegation receipt not found"
    assert receipts.consume("", "c")[1] == "no delegation receipt presented"
    assert receipts.revoke("dlg-missing", revoked_by="operator") is False


def test_delegated_operations_bind_the_receipt(store):
    receipts, _ = store
    issued = receipts.issue(parent_agent_id="p", child_agent_id="c", parent_scope=3,
                            allowed_operations=["ReadPipelineStatus"], max_uses=2)
    assert receipts.consume(issued.receipt_id, "c", "ProductionDeployment")[0] is None
    assert receipts.consume(issued.receipt_id, "c", "ReadPipelineStatus")[0] is not None


def test_verify_never_uses_a_receipt(store):
    receipts, _ = store
    issued = receipts.issue(parent_agent_id="p", child_agent_id="c", parent_scope=1)
    for _ in range(3):
        assert receipts.verify(issued.receipt_id, "c")[0] is not None
    assert receipts.consume(issued.receipt_id, "c")[0] is not None


def test_a_concurrent_use_cannot_exceed_max_uses(store):
    receipts, _ = store
    issued = receipts.issue(parent_agent_id="p", child_agent_id="c", parent_scope=1)
    # Simulate the race: both requests pass the read, then the second write
    # finds the receipt already used. Only the conditional write decides.
    stale = receipts._checked(issued.receipt_id, "c", "")[0]
    assert receipts.consume(issued.receipt_id, "c")[0] is not None
    receipts._checked = lambda *args: (stale, "")
    assert receipts.consume(issued.receipt_id, "c") == (
        None, "delegation receipt was used, revoked or expired concurrently")


@pytest.mark.parametrize("kwargs, message", [
    ({"parent_agent_id": "a", "child_agent_id": "a"}, "cannot delegate to itself"),
    ({"parent_agent_id": "b", "child_agent_id": "a", "parent_chain": ["a"]}, "cycle"),
    ({"parent_agent_id": "d", "child_agent_id": "e", "parent_chain": ["a", "b", "c"]}, "depth"),
    ({"parent_agent_id": "a", "child_agent_id": "b", "ttl_seconds": 7200}, "ttl_seconds"),
    ({"parent_agent_id": "a", "child_agent_id": "b", "max_uses": 0}, "max_uses"),
])
def test_issue_refuses_unsafe_delegations(store, kwargs, message):
    receipts, _ = store
    with pytest.raises(DelegationError, match=message):
        receipts.issue(parent_scope=1, **kwargs)


# --- effective scope ---------------------------------------------------------

def test_effective_scope_is_the_minimum_trusted_ceiling():
    entry = AgentRegistryEntry(agent_id="a", purpose="p", owner="o", data_classes=["x"],
                               environment="dev", approved_scope=3)
    ceilings = ceilings_for(registry_entry=entry, operator_scope=2, delegation_cap=4, requested_scope=4)
    assert ceilings.effective() == 2 and ceilings.binding_ceiling() == "operator_authorized_scope"
    # A caller can lower its scope, never raise it.
    assert ceilings_for(registry_entry=entry, operator_scope=2, requested_scope=1).effective() == 1
    assert ceilings_for(registry_entry=entry, operator_scope=2, requested_scope=1).binding_ceiling() == \
        "requested_scope"
    # A requested scope alone is not authority.
    assert ceilings_for(requested_scope=4).effective() is None


def test_missing_scope_table_item_means_no_operator_scope(ddb):
    table = ddb.create_table(TableName="scope", KeySchema=[{"AttributeName": "agent_id", "KeyType": "HASH"}],
                             AttributeDefinitions=[{"AttributeName": "agent_id", "AttributeType": "S"}],
                             BillingMode="PAY_PER_REQUEST")
    table.put_item(Item={"agent_id": "a", "scope_level": 3})
    assert read_operator_scope(table, "a") == 3
    assert read_operator_scope(table, "unknown") == 0
    assert read_operator_scope(None, "a") is None


# --- the real pipeline -------------------------------------------------------

@pytest.fixture
def pipeline(monkeypatch):
    with mock_aws():
        for key, value in {"AWS_DEFAULT_REGION": REGION, "AWS_ACCESS_KEY_ID": "testing",
                           "AWS_SECRET_ACCESS_KEY": "testing"}.items():
            monkeypatch.setenv(key, value)
        ddb = boto3.resource("dynamodb", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        registry = AgentRegistry(ddb.create_table(**registry_table_definition("registry")))
        scope = ddb.create_table(TableName="scope", KeySchema=[{"AttributeName": "agent_id", "KeyType": "HASH"}],
                                 AttributeDefinitions=[{"AttributeName": "agent_id", "AttributeType": "S"}],
                                 BillingMode="PAY_PER_REQUEST")
        ddb.create_table(**receipt_table_definition("receipts"))
        s3.create_bucket(Bucket="policies", CreateBucketConfiguration={"LocationConstraint": REGION})
        policy_dir = _ROOT / "sample_data" / "policies"
        for path in policy_dir.rglob("*"):
            if path.is_file():
                s3.put_object(Bucket="policies", Key="policies/" + path.relative_to(policy_dir).as_posix(),
                              Body=path.read_bytes())
        # approved_scope (registry), scope_level (Scope Table)
        for agent, approved, operator in (("orchestrator", 2, 1), ("worker", 4, 4), ("unscoped", 3, None)):
            registry.register_agent(AgentRegistryEntry(
                agent_id=agent, purpose="p", owner="o", data_classes=["pipeline_status"],
                environment="dev", approved_scope=approved), requester_id="admin")
            if operator is not None:
                scope.put_item(Item={"agent_id": agent, "scope_level": operator, "status": "active"})

        import importlib.util
        import pipeline_orchestrator as po
        # The pipeline imports DecimalEncoder from "index". Other test files
        # load another Lambda's index.py under that name, so pin the
        # governance engine's own module for these tests.
        spec = importlib.util.spec_from_file_location(
            "index", _ROOT / "lambdas" / "governance_engine" / "index.py")
        engine_index = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine_index)
        monkeypatch.setitem(sys.modules, "index", engine_index)
        monkeypatch.setattr(po, "AGENT_REGISTRY_TABLE_NAME", "registry")
        monkeypatch.setattr(po, "SCOPE_TABLE_NAME", "scope")
        monkeypatch.setattr(po, "DELEGATION_RECEIPT_TABLE_NAME", "receipts")
        monkeypatch.setattr(po, "POLICY_BUCKET_NAME", "policies")
        po.reset_request_path_caches()

        def run(agent_id, **fields):
            event = {"agent_id": agent_id, "action_group": "ReadPipelineStatus",
                     "input_text": "show build status", **fields}
            return po.run_pipeline(event, None)

        yield run
        po.reset_request_path_caches()


def test_caller_scope_cannot_raise_the_trusted_scope(pipeline):
    out = pipeline("orchestrator", scope_level=4)
    assert out["verdict"] == "allow"
    assert out["effective_scope"]["effective_scope"] == 1
    assert out["effective_scope"]["binding_ceiling"] == "operator_authorized_scope"


def test_agent_without_operator_scope_is_denied(pipeline):
    out = pipeline("unscoped", scope_level=3)
    assert (out["verdict"], out["error_category"]) == ("deny", "no_authorized_scope")


def test_no_trusted_scope_source_denies(pipeline, monkeypatch):
    import pipeline_orchestrator as po
    monkeypatch.setattr(po, "AGENT_REGISTRY_TABLE_NAME", "")
    monkeypatch.setattr(po, "SCOPE_TABLE_NAME", "")
    out = pipeline("orchestrator", scope_level=4)
    assert (out["verdict"], out["error_category"]) == ("deny", "no_trusted_scope")


def test_verified_delegation_caps_the_child_and_works_once(pipeline):
    parent = pipeline("orchestrator", delegate_to_agent_id="worker")
    receipt = parent["delegation"]
    assert parent["verdict"] == "allow"
    assert (receipt["child_agent_id"], receipt["scope_cap"], receipt["chain"]) == ("worker", 1, ["orchestrator"])

    child = pipeline("worker", scope_level=4, delegation_receipt_id=receipt["delegation_receipt_id"])
    assert child["verdict"] == "allow"
    # The worker's own ceilings are 4; the parent's verified cap binds.
    assert child["effective_scope"]["effective_scope"] == 1
    assert child["effective_scope"]["binding_ceiling"] == "delegation_scope_cap"

    replay = pipeline("worker", delegation_receipt_id=receipt["delegation_receipt_id"])
    assert (replay["verdict"], replay["error_category"]) == ("deny", "trust_chain_unverified_delegation")


def test_forged_delegation_claims_are_denied(pipeline):
    # Before P0-11 the claimed calling_agent_scope was trusted; here it would
    # also have been dropped, so the parent's cap was never applied at all.
    forged = pipeline("worker", calling_agent_id="orchestrator", calling_agent_scope=4,
                      delegation_chain=["orchestrator"])
    assert (forged["verdict"], forged["error_category"]) == ("deny", "trust_chain_unverified_delegation")


def test_a_claim_that_disagrees_with_the_receipt_is_denied(pipeline):
    receipt = pipeline("orchestrator", delegate_to_agent_id="worker")["delegation"]
    out = pipeline("worker", delegation_receipt_id=receipt["delegation_receipt_id"], calling_agent_scope=4)
    assert (out["verdict"], out["error_category"]) == ("deny", "trust_chain_delegation_mismatch")


def test_receipt_for_another_agent_is_denied(pipeline):
    receipt = pipeline("orchestrator", delegate_to_agent_id="worker")["delegation"]
    out = pipeline("unscoped", delegation_receipt_id=receipt["delegation_receipt_id"])
    assert (out["verdict"], out["error_category"]) == ("deny", "trust_chain_unverified_delegation")


def test_simulation_does_not_use_the_receipt(pipeline):
    receipt = pipeline("orchestrator", delegate_to_agent_id="worker")["delegation"]
    simulated = pipeline("worker", delegation_receipt_id=receipt["delegation_receipt_id"], simulation_mode=True)
    assert simulated["verdict"] == "allow"
    real = pipeline("worker", delegation_receipt_id=receipt["delegation_receipt_id"])
    assert real["verdict"] == "allow"


def test_delegation_to_an_unregistered_agent_issues_nothing(pipeline):
    out = pipeline("orchestrator", delegate_to_agent_id="ghost-agent")
    assert out["verdict"] == "allow" and "delegation" not in out
    assert out["delegation_error"] == "delegate 'ghost-agent' is not registered"
