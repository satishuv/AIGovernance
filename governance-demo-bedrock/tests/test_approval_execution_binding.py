"""Approval -> execution binding tests (ApprovalWorkflow.verify_and_consume).

An approval authorizes exactly one request, once, before its absolute expiry,
under the policy version in force when it was approved.
"""

import os
import sys
import threading
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))

from approval_workflow import ApprovalWorkflow  # noqa: E402
from decision_engine import DecisionEngine  # noqa: E402
from models import PolicyEvaluationResult, RiskAssessment  # noqa: E402

REGION = "ca-central-1"
POLICY = "policy-hash-v1"


def _request(**overrides):
    base = {
        "agent_id": "procurement-agent", "session_id": "session-7",
        "provider": "servicenow", "operation_id": "Subscription.Purchase",
        "target_resource": "catalog/software/approved/analytics-suite",
        "environment": "prod", "data_class": "Internal",
        "tool_parameters": {"catalog_item_id": "analytics-suite", "quantity": 4},
        "financial_context": {"currency": "CAD", "transaction_amount": 1800},
    }
    base.update(overrides)
    return base


@pytest.fixture
def workflow():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        table = ddb.create_table(
            TableName="pending-approvals",
            KeySchema=[{"AttributeName": "approval_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "approval_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield ApprovalWorkflow(table), table


def _escalated_decision(req=None, policy=POLICY):
    req = req or _request()
    pr = PolicyEvaluationResult(policy_id="budget-step-up", outcome="escalate")
    ra = RiskAssessment(risk_score=72, risk_category="financial")
    return DecisionEngine(70).decide(pr, ra, req, req["agent_id"], policy_version_hash=policy)


def _approved(workflow, req=None, timeout=3600):
    wf, _ = workflow
    approval_id = wf.create_pending_approval(_escalated_decision(req), timeout_seconds=timeout)
    wf.approve(approval_id, "arn:aws:sts::111122223333:assumed-role/Approver/finance-lead",
               "digital-services-owner")
    return approval_id


class TestApprovalRecordBinding:
    def test_record_stores_canonical_request_digest_and_absolute_expiry(self, workflow):
        wf, table = workflow
        approval_id = wf.create_pending_approval(_escalated_decision(), timeout_seconds=600)
        item = table.get_item(Key={"approval_id": approval_id})["Item"]
        assert item["digest_version"] == 2
        assert item["action_request"]["operation_id"] == "Subscription.Purchase"
        assert item["policy_version_hash"] == POLICY
        assert item["expires_at"].endswith("+00:00")
        assert int(item["expires_at_epoch"]) > int(datetime.now(timezone.utc).timestamp())
        assert item["consumed"] is False and item["status"] == "pending"


class TestVerifyAndConsume:
    def test_valid_approval_executes_once(self, workflow):
        wf, _ = workflow
        approval_id = _approved(workflow)
        ok, reason, item = wf.verify_and_consume(approval_id, _request(), POLICY)
        assert ok is True, reason
        assert item["consumed"] is True

    def test_pending_approval_cannot_execute(self, workflow):
        wf, _ = workflow
        approval_id = wf.create_pending_approval(_escalated_decision())
        ok, reason, _ = wf.verify_and_consume(approval_id, _request(), POLICY)
        assert ok is False and "pending" in reason

    def test_denied_approval_cannot_execute(self, workflow):
        wf, _ = workflow
        approval_id = wf.create_pending_approval(_escalated_decision())
        wf.deny(approval_id, "arn:aws:sts::111122223333:assumed-role/Approver/finance-lead", "no budget")
        ok, reason, _ = wf.verify_and_consume(approval_id, _request(), POLICY)
        assert ok is False and "denied" in reason

    def test_expired_approval_cannot_execute(self, workflow):
        wf, table = workflow
        approval_id = _approved(workflow)
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        table.update_item(Key={"approval_id": approval_id},
                          UpdateExpression="SET expires_at_epoch = :e",
                          ExpressionAttributeValues={":e": int(past.timestamp())})
        ok, reason, _ = wf.verify_and_consume(approval_id, _request(), POLICY)
        assert ok is False and "expired" in reason

    @pytest.mark.parametrize("change,field", [
        ({"tool_parameters": {"catalog_item_id": "analytics-suite", "quantity": 40}}, "tool_parameters"),
        ({"financial_context": {"currency": "CAD", "transaction_amount": 18000}}, "financial_context"),
        ({"target_resource": "catalog/software/unapproved/crypto-miner"}, "target_resource"),
        ({"operation_id": "Subscription.PurchaseEnterprise"}, "operation_id"),
        ({"agent_id": "other-agent"}, "agent_id"),
        ({"environment": "dev"}, "environment"),
    ])
    def test_changed_request_after_approval_fails(self, workflow, change, field):
        wf, table = workflow
        approval_id = _approved(workflow)
        ok, reason, _ = wf.verify_and_consume(approval_id, _request(**change), POLICY)
        assert ok is False
        assert "does not match" in reason and field in reason
        # The failed attempt must not consume the approval.
        assert table.get_item(Key={"approval_id": approval_id})["Item"]["consumed"] is False

    def test_policy_change_after_approval_fails(self, workflow):
        wf, _ = workflow
        approval_id = _approved(workflow)
        ok, reason, _ = wf.verify_and_consume(approval_id, _request(), "policy-hash-v2")
        assert ok is False and "policy_version_hash" in reason

    def test_replay_fails(self, workflow):
        wf, _ = workflow
        approval_id = _approved(workflow)
        assert wf.verify_and_consume(approval_id, _request(), POLICY)[0] is True
        ok, reason, _ = wf.verify_and_consume(approval_id, _request(), POLICY)
        assert ok is False and "consumed" in reason

    def test_concurrent_double_use_permits_only_one(self, workflow):
        wf, _ = workflow
        approval_id = _approved(workflow)
        results = []
        barrier = threading.Barrier(8)

        def attempt():
            barrier.wait()
            results.append(wf.verify_and_consume(approval_id, _request(), POLICY)[0])

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(True) == 1
        assert results.count(False) == 7

    def test_unknown_approval_fails_closed(self, workflow):
        wf, _ = workflow
        ok, reason, _ = wf.verify_and_consume("does-not-exist", _request(), POLICY)
        assert ok is False and "not found" in reason


class TestApprovalStateTransitions:
    def test_cannot_approve_unknown_id(self, workflow):
        wf, table = workflow
        with pytest.raises(ValueError):
            wf.approve("ghost", "arn:aws:sts::111122223333:assumed-role/Approver/a", "owner")
        assert "Item" not in table.get_item(Key={"approval_id": "ghost"})

    def test_cannot_reapprove_denied(self, workflow):
        wf, _ = workflow
        approval_id = wf.create_pending_approval(_escalated_decision())
        wf.deny(approval_id, "arn:aws:sts::111122223333:assumed-role/Approver/a", "no")
        with pytest.raises(ValueError):
            wf.approve(approval_id, "arn:aws:sts::111122223333:assumed-role/Approver/b", "owner")

    def test_anonymous_approval_rejected(self, workflow):
        wf, _ = workflow
        approval_id = wf.create_pending_approval(_escalated_decision())
        with pytest.raises(ValueError):
            wf.approve(approval_id, "", "owner")

    def test_owner_cannot_approve(self, workflow):
        wf, _ = workflow
        approval_id = wf.create_pending_approval(_escalated_decision())
        with pytest.raises(ValueError):
            wf.approve(approval_id, "digital-services-owner", "digital-services-owner")
