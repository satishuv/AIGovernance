"""Assemble the delegated authority control plane.

from_environment()   Lambda: real DynamoDB, KMS, S3 and STS from env vars.
build_offline()      Demo/tests: the caller supplies boto3 resources (normally
                     moto-backed). Same control-plane code, generic demo data.

Demo identities use the AWS documentation example account 111122223333 and
generic names (procurement-agent, guardian-agent, records-agent). No customer
data, names or architecture details belong here.
"""

import os
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Optional

from agent_registry import AgentRegistry, registry_table_definition
from approval_workflow import ApprovalWorkflow
from tool_execution_auth import tool_auth_table_definition
from authority_control_plane import ControlPlaneConfig, DelegatedAuthorityControlPlane, decision_trace_index_definition
from authority_evidence import EvidenceLedger, S3EvidenceBackend
from authority_identity import AuthenticatedCaller, RoleDirectory, resolve_caller
from budget_governance import ApprovedCatalog, SpendLedger
from credential_broker import (
    AwsStsAdapter,
    CredentialBroker,
    EntraAdapter,
    GoogleAdapter,
    GovernanceAdapter,
    ServiceNowAdapter,
    oversight_table_definition,
)
from delegated_authority import GrantStore, KmsGrantSigner
from models import AgentRegistryEntry
from opa_engine import OPAEngine
from operation_registry import OperationRegistry

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_BUNDLE_PATH = os.path.join(HERE, "operation_catalog", "delegated_authority_policy.json")

ACCOUNT = "111122223333"
HUMAN = {
    "finance_approver": f"arn:aws:sts::{ACCOUNT}:assumed-role/GovApprover/finance-approver",
    "service_owner": f"arn:aws:sts::{ACCOUNT}:assumed-role/ServiceOwner/digital-services-owner",
    "governance_admin": f"arn:aws:sts::{ACCOUNT}:assumed-role/GovAdmin/governance-admin",
    "security_operator": f"arn:aws:sts::{ACCOUNT}:assumed-role/SecurityOps/security-operator",
}
AGENT_ROLE = {
    "procurement-agent": f"arn:aws:iam::{ACCOUNT}:role/procurement-agent-runtime",
    "guardian-agent": f"arn:aws:iam::{ACCOUNT}:role/guardian-agent-runtime",
    "records-agent": f"arn:aws:iam::{ACCOUNT}:role/records-agent-runtime",
}
# Teams own agents as IAM roles: every session of the role is an owner, so separation of duties
# can compare an approver against it (a bare team name names no principal).
TEAM_ROLE = {
    "digital-services-platform-team": f"arn:aws:iam::{ACCOUNT}:role/digital-services-platform-team",
    "security-operations-team": f"arn:aws:iam::{ACCOUNT}:role/security-operations-team",
}
DEMO_ROLES = {
    HUMAN["finance_approver"]: {"policy_approver"},
    HUMAN["service_owner"]: {"policy_approver"},  # holds the role, but owns the agent (SoD)
    HUMAN["governance_admin"]: {"governance_admin"},
    HUMAN["security_operator"]: {"operator"},
}

DEMO_CATALOG = {
    "productivity-suite": {"name": "Approved Productivity Suite (per seat, monthly)",
                           "unit_price": Decimal("42.00"), "currency": "CAD", "approved": True},
    "analytics-suite": {"name": "Approved Analytics Suite (per seat, annual)",
                        "unit_price": Decimal("450.00"), "currency": "CAD", "approved": True},
    "unvetted-ai-plugin": {"name": "Unvetted AI Browser Plugin", "unit_price": Decimal("15.00"),
                           "currency": "CAD", "approved": False},
}

DEMO_SCOPES = {"procurement-agent": 3, "guardian-agent": 1, "records-agent": 1}


def demo_agents(now_iso: str = "2026-10-01T00:00:00+00:00") -> List[AgentRegistryEntry]:
    return [
        AgentRegistryEntry(
            agent_id="procurement-agent", purpose="Buys approved software subscriptions for teams",
            owner=HUMAN["service_owner"], data_classes=["Public", "Internal"], tools=[],
            approved_scope=3, environment="prod", agent_type="worker",
            business_owner=HUMAN["service_owner"], technical_owner=TEAM_ROLE["digital-services-platform-team"],
            runtime_provider="aws-lambda", model_provider="amazon-bedrock",
            runtime_principal=AGENT_ROLE["procurement-agent"],
            allowed_providers=["servicenow", "aws"],
            allowed_operations=["Subscription.ListCatalog", "Subscription.Purchase",
                                "ServiceNow.GetIncident", "AWS.ReadObject"],
            allowed_resource_patterns=["catalog/software", "catalog/software/approved/*",
                                       "servicenow/incident/*", "aws/s3/*/reports/approved/*"],
            spend_policy={"currency": "CAD", "per_transaction_max": Decimal("500"),
                          "per_session_max": Decimal("1000"), "daily_max": Decimal("2000"),
                          "hard_transaction_max": Decimal("5000")},
            credential_ttl_seconds=300, guardian_agent_ids=["guardian-agent"], requires_guardian=True,
            requires_human_for=[], risk_tier="medium", policy_bundle="public-sector-demo",
            status="active", created_at=now_iso, last_attested_at=now_iso),
        AgentRegistryEntry(
            agent_id="guardian-agent", purpose="Observes worker agents and recommends action to humans",
            owner=HUMAN["security_operator"], data_classes=["Public", "Internal"], tools=[],
            approved_scope=1, environment="prod", agent_type="guardian",
            business_owner=HUMAN["security_operator"], technical_owner=TEAM_ROLE["security-operations-team"],
            runtime_provider="aws-lambda", model_provider="amazon-bedrock",
            runtime_principal=AGENT_ROLE["guardian-agent"], allowed_providers=["governance"],
            allowed_operations=["Governance.InspectDecisionHistory", "Governance.InspectEvidence",
                                "Governance.RecommendSuspension", "Governance.CreateAlert"],
            allowed_resource_patterns=["agent/*"], spend_policy={}, credential_ttl_seconds=120,
            risk_tier="low", policy_bundle="public-sector-demo", status="active",
            created_at=now_iso, last_attested_at=now_iso),
        AgentRegistryEntry(
            agent_id="records-agent", purpose="Looks up directory and document metadata for case workers",
            owner=HUMAN["service_owner"], data_classes=["Public", "Internal", "Protected-A"], tools=[],
            approved_scope=1, environment="prod", agent_type="worker",
            business_owner=HUMAN["service_owner"], technical_owner=TEAM_ROLE["digital-services-platform-team"],
            runtime_provider="external-agent-runtime", model_provider="any",
            runtime_principal=AGENT_ROLE["records-agent"], allowed_providers=["entra", "google"],
            allowed_operations=["Entra.GetUser", "Google.ReadDriveFile"],
            allowed_resource_patterns=["entra/user/*", "google/drive/file/*"], spend_policy={},
            credential_ttl_seconds=300, guardian_agent_ids=["guardian-agent"], requires_guardian=True,
            risk_tier="medium", policy_bundle="public-sector-demo", status="active",
            created_at=now_iso, last_attested_at=now_iso),
    ]


TABLES = {
    "scope": ("agent_id", None), "registry": ("agent_id", None), "approvals": ("approval_id", None),
    "tool_auth": ("pk", "sk"), "grants": ("grant_id", None), "ledger": ("ledger_key", None),
    "decisions": ("decision_id", None),
}


def create_demo_tables(dynamodb, prefix: str = "dag-demo-") -> Dict[str, Any]:
    """Create the control-plane tables (for a moto backend or a sandbox account)."""
    tables = {}
    for name, (pk, sk) in TABLES.items():
        keys = [{"AttributeName": pk, "KeyType": "HASH"}]
        attrs = [{"AttributeName": pk, "AttributeType": "S"}]
        if sk:
            keys.append({"AttributeName": sk, "KeyType": "RANGE"})
            attrs.append({"AttributeName": sk, "AttributeType": "S"})
        kwargs = {"TableName": prefix + name, "KeySchema": keys, "AttributeDefinitions": attrs,
                  "BillingMode": "PAY_PER_REQUEST"}
        if name == "grants":
            kwargs["AttributeDefinitions"] = attrs + [{"AttributeName": "agent_id", "AttributeType": "S"}]
            kwargs["GlobalSecondaryIndexes"] = [{
                "IndexName": "ByAgentId", "KeySchema": [{"AttributeName": "agent_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"}}]
        if name == "registry":
            kwargs = registry_table_definition(prefix + name)
        if name == "tool_auth":
            kwargs = tool_auth_table_definition(prefix + name)
        if name == "decisions":
            index = decision_trace_index_definition()
            kwargs["AttributeDefinitions"] = attrs + index["AttributeDefinitions"]
            kwargs["GlobalSecondaryIndexes"] = index["GlobalSecondaryIndexes"]
        tables[name] = dynamodb.create_table(**kwargs)
    return tables


def seed_demo(tables: Dict[str, Any], operations: OperationRegistry) -> List[AgentRegistryEntry]:
    agents = demo_agents()
    registry = AgentRegistry(tables["registry"])
    for agent in agents:
        errors = agent.validate_governance_fields()
        if errors:
            raise ValueError(f"demo registry entry {agent.agent_id} is invalid: {errors}")
        registry.register_agent(agent, requester_id=HUMAN["governance_admin"])
        tables["scope"].put_item(Item={"agent_id": agent.agent_id, "scope_level": DEMO_SCOPES[agent.agent_id],
                                       "updated_by": HUMAN["governance_admin"]})
    for rule in operations.tool_auth_rules(agents):
        tables["tool_auth"].put_item(Item=rule)
    return agents


def load_policy_engine(path: str = POLICY_BUNDLE_PATH) -> OPAEngine:
    import json
    engine = OPAEngine()
    engine.bundle_id = "file:" + os.path.basename(path)
    with open(path, "r", encoding="utf-8") as fh:
        engine.load_policies_from_json(json.load(fh))
    return engine


@dataclass
class OfflineDemo:
    control_plane: DelegatedAuthorityControlPlane
    tables: Dict[str, Any]
    operations: OperationRegistry
    adapters: Dict[str, Any]
    bucket: str
    roles: RoleDirectory

    def _resolve(self, principal: str) -> AuthenticatedCaller:
        return resolve_caller(principal, "demo", self.roles, self.control_plane.registry.agent_id_for_principal)

    def agent(self, agent_id: str) -> AuthenticatedCaller:
        """Authenticated agent session: the runtime role's STS session ARN."""
        session = (AGENT_ROLE[agent_id].replace(":iam::", ":sts::").replace(":role/", ":assumed-role/")
                   + "/session-1")
        return self._resolve(session)

    def human(self, key: str) -> AuthenticatedCaller:
        return self._resolve(HUMAN[key])


def build_offline(*, dynamodb, s3, kms, sts=None, region: str = "ca-central-1",
                  aws_mode: str = "mock", grant_signer=None, evidence_signer=None,
                  bucket: str = "dag-demo-evidence", prefix: str = "dag-demo-") -> OfflineDemo:
    operations = OperationRegistry.load()
    tables = create_demo_tables(dynamodb, prefix)
    seed_demo(tables, operations)
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    report_key = "reports/approved/price-benchmark-2026.csv"
    s3.put_object(Bucket=bucket, Key=report_key, Body=b"item,list_price\nproductivity-suite,42.00\n")
    s3.put_object(Bucket=bucket, Key="reports/restricted/salary-bands.csv", Body=b"restricted\n")

    if grant_signer is None:
        key = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256",
                             Description="delegated authority grant signing (demo)")["KeyMetadata"]["KeyId"]
        grant_signer = KmsGrantSigner(kms, key)
    if evidence_signer is None:
        key = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256",
                             Description="delegated authority evidence signing (demo)")["KeyMetadata"]["KeyId"]
        evidence_signer = KmsGrantSigner(kms, key)

    grants = GrantStore(tables["grants"], grant_signer)
    evidence = EvidenceLedger(evidence_signer, S3EvidenceBackend(s3, bucket))
    oversight = dynamodb.create_table(**oversight_table_definition(prefix + "oversight"))
    tables["oversight"] = oversight
    holder: Dict[str, Any] = {}
    adapters = {
        "servicenow": ServiceNowAdapter("mock", catalog=DEMO_CATALOG),
        "entra": EntraAdapter("mock"),
        "google": GoogleAdapter("mock"),
        "aws": AwsStsAdapter(aws_mode, sts_client=sts, role_arn=f"arn:aws:iam::{ACCOUNT}:role/delegated-execution",
                             region=region, account=ACCOUNT,
                             client_factory=(lambda svc, secret: s3) if aws_mode == "live" else None,
                             mock_objects={f"{bucket}/{report_key}": b"item,list_price\nproductivity-suite,42.00\n"}),
        "governance": GovernanceAdapter(lambda agent_id, limit: holder["cp"].decision_summaries(agent_id, limit),
                                        lambda agent_id: holder["cp"].evidence.for_agent(agent_id),
                                        oversight_table=oversight),
    }
    control_plane = DelegatedAuthorityControlPlane(
        registry=AgentRegistry(tables["registry"]), scope_table=tables["scope"],
        approvals=ApprovalWorkflow(tables["approvals"]), tool_auth_table=tables["tool_auth"],
        grants=grants, ledger=SpendLedger(tables["ledger"]), operations=operations,
        catalog=ApprovedCatalog(DEMO_CATALOG), broker=CredentialBroker(adapters, grants),
        evidence=evidence, opa=load_policy_engine(), decision_table=tables["decisions"],
        config=ControlPlaneConfig())
    holder["cp"] = control_plane
    return OfflineDemo(control_plane, tables, operations, adapters, bucket, RoleDirectory(DEMO_ROLES))


def from_environment(boto3_module=None) -> DelegatedAuthorityControlPlane:
    """Lambda wiring. Fails closed if a required setting is missing."""
    import boto3 as _boto3
    boto = boto3_module or _boto3
    env = os.environ
    required = ("SCOPE_TABLE_NAME", "AGENT_REGISTRY_TABLE_NAME", "PENDING_APPROVAL_TABLE_NAME",
                "TOOL_AUTH_TABLE_NAME", "AUTHORITY_GRANT_TABLE_NAME", "SPEND_LEDGER_TABLE_NAME",
                "GRANT_SIGNING_KEY_ID", "EVIDENCE_SIGNING_KEY_ID", "EVIDENCE_BUCKET_NAME",
                "DECISION_TRACE_TABLE_NAME", "GOVERNANCE_RECOMMENDATION_TABLE_NAME")
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise RuntimeError(f"delegated authority is not configured: missing {missing}")
    ddb, kms, s3 = boto.resource("dynamodb"), boto.client("kms"), boto.client("s3")
    t = ddb.Table
    grants = GrantStore(t(env["AUTHORITY_GRANT_TABLE_NAME"]), KmsGrantSigner(kms, env["GRANT_SIGNING_KEY_ID"]))
    evidence = EvidenceLedger(KmsGrantSigner(kms, env["EVIDENCE_SIGNING_KEY_ID"]),
                              S3EvidenceBackend(s3, env["EVIDENCE_BUCKET_NAME"]))
    provider_mode = env.get("PROVIDER_MODE", "mock")
    aws_mode = env.get("AWS_PROVIDER_MODE", "live" if env.get("DELEGATED_EXECUTION_ROLE_ARN") else "mock")
    holder: Dict[str, Any] = {}
    adapters = {
        "servicenow": ServiceNowAdapter(provider_mode, catalog=DEMO_CATALOG),
        "entra": EntraAdapter(provider_mode),
        "google": GoogleAdapter(provider_mode),
        "aws": AwsStsAdapter(aws_mode, sts_client=boto.client("sts") if aws_mode == "live" else None,
                             role_arn=env.get("DELEGATED_EXECUTION_ROLE_ARN", ""),
                             region=env.get("AWS_REGION", ""), account=env.get("AWS_ACCOUNT_ID", "")),
        "governance": GovernanceAdapter(lambda a, n: holder["cp"].decision_summaries(a, n),
                                        lambda a: holder["cp"].evidence.for_agent(a),
                                        oversight_table=t(env["GOVERNANCE_RECOMMENDATION_TABLE_NAME"])),
    }
    cp = DelegatedAuthorityControlPlane(
        registry=AgentRegistry(t(env["AGENT_REGISTRY_TABLE_NAME"])), scope_table=t(env["SCOPE_TABLE_NAME"]),
        approvals=ApprovalWorkflow(t(env["PENDING_APPROVAL_TABLE_NAME"])),
        tool_auth_table=t(env["TOOL_AUTH_TABLE_NAME"]), grants=grants,
        ledger=SpendLedger(t(env["SPEND_LEDGER_TABLE_NAME"])), operations=OperationRegistry.load(),
        catalog=ApprovedCatalog(DEMO_CATALOG), broker=CredentialBroker(adapters, grants), evidence=evidence,
        opa=load_policy_engine(), decision_table=t(env["DECISION_TRACE_TABLE_NAME"]))
    holder["cp"] = cp
    return cp


def caller_from_api_event(event: Dict[str, Any], control_plane: DelegatedAuthorityControlPlane,
                          roles_table=None) -> Optional[AuthenticatedCaller]:
    """Classify the API caller with key reads: one registry index query for the
    principal and one roles query, never a scan of either table (P0-18)."""
    from authority_identity import principal_from_api_event, resolve_caller
    principal, source = principal_from_api_event(event)
    if not principal:
        return None
    return resolve_caller(principal, source, RoleDirectory.for_principal(roles_table, principal),
                          control_plane.registry.agent_id_for_principal)
