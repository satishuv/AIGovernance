"""Live delegated-authority demo against a deployed stack (real AWS).

Deploy first (demo account, Canada Central), passing your own principal so you
can act as both the agent runtime (by assuming the demo role) and the human
approver/administrator:

    npx cdk deploy -c profile=public-sector-canada \
        -c delegated_demo_operator=<your IAM role ARN> --require-approval never

Then, with the same credentials in your terminal:

    python demo/public_sector_hallpass/live_aws_demo.py --region ca-central-1 --seed

What runs for real: API Gateway IAM (SigV4) authentication, the authority
Lambda, DynamoDB conditional writes, KMS grant and evidence signatures, S3
evidence, STS AssumeRole with a grant-derived session policy, and an IAM
probe proving the grant's credential cannot read a second object.
ServiceNow, Entra and Google remain mock adapters.

--seed writes demo registry entries, scopes, tool rules and YOUR principal's
governance roles into the stack's own tables and uploads two generic report
objects. Use a demo account, never a production one.
"""

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GE = os.path.normpath(os.path.join(HERE, "..", "..", "lambdas", "governance_engine"))
sys.path[:0] = [HERE, GE]

import boto3  # noqa: E402

from api_client import LiveApiClient  # noqa: E402

RESULTS = []


def check(label, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))


def stack_info(cfn, stack):
    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    tables = {}
    for res in cfn.describe_stack_resources(StackName=stack)["StackResources"]:
        if res["ResourceType"] == "AWS::DynamoDB::Table":
            for key in ("AgentRegistryTable", "ScopeTable", "ToolAuthTable", "GovernanceRolesTable"):
                if key in res["LogicalResourceId"]:
                    tables[key] = res["PhysicalResourceId"]
    needed = ("ApprovalApiUrl", "DemoAgentRuntimeRoleArn", "DataBucketName")
    missing = [k for k in needed if k not in outputs]
    if missing:
        sys.exit(f"stack outputs {missing} are missing; deploy with -c delegated_demo_operator=<your ARN>")
    return outputs, tables


def seed(session, outputs, tables, operator_arn):
    from authority_factory import DEMO_SCOPES, demo_agents
    from agent_registry import AgentRegistry
    from operation_registry import OperationRegistry
    ddb, s3 = session.resource("dynamodb"), session.client("s3")
    agents = demo_agents()
    for agent in agents:
        if agent.agent_id == "procurement-agent":
            agent.runtime_principal = outputs["DemoAgentRuntimeRoleArn"]
        AgentRegistry(ddb.Table(tables["AgentRegistryTable"])).register_agent(agent, operator_arn)
        ddb.Table(tables["ScopeTable"]).put_item(Item={"agent_id": agent.agent_id,
                                                       "scope_level": DEMO_SCOPES[agent.agent_id]})
    for rule in OperationRegistry.load().tool_auth_rules(agents):
        ddb.Table(tables["ToolAuthTable"]).put_item(Item=rule)
    # Store the IAM role ARN, not the session ARN, so the roles survive new sessions.
    from authority_identity import normalize_principal_arn
    for role in ("policy_approver", "operator", "governance_admin"):
        ddb.Table(tables["GovernanceRolesTable"]).put_item(
            Item={"user_id": normalize_principal_arn(operator_arn), "role": role})
    bucket = outputs["DataBucketName"]
    s3.put_object(Bucket=bucket, Key="reports/approved/price-benchmark-2026.csv",
                  Body=b"item,list_price\nproductivity-suite,42.00\n")
    # Readable by the execution role, NOT named by the grant: the IAM probe target.
    s3.put_object(Bucket=bucket, Key="reports/approved/vendor-contacts-2026.csv",
                  Body=b"vendor,contact\nvendor-a,generic-contact\n")
    s3.put_object(Bucket=bucket, Key="reports/restricted/salary-bands.csv", Body=b"restricted demo object\n")
    print("Seeded demo registry, scopes, tool rules, operator roles and report objects.")


def purchase(item, qty, amount, session_id):
    return {"agent_id": "procurement-agent", "session_id": session_id, "provider": "servicenow",
            "operation_id": "Subscription.Purchase", "target_resource": f"catalog/software/approved/{item}",
            "environment": "prod",
            "tool_parameters": {"catalog_item_id": item, "quantity": qty, "cost_centre": "CC-1234"},
            "financial_context": {"currency": "CAD", "transaction_amount": amount}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="ca-central-1")
    parser.add_argument("--stack", default="GovernanceBedrockStack")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()

    operator = boto3.Session(region_name=args.region)
    operator_arn = operator.client("sts").get_caller_identity()["Arn"]
    outputs, tables = stack_info(operator.client("cloudformation"), args.stack)
    if args.seed:
        seed(operator, outputs, tables, operator_arn)

    creds = operator.client("sts").assume_role(RoleArn=outputs["DemoAgentRuntimeRoleArn"],
                                               RoleSessionName="procurement-agent-demo")["Credentials"]
    agent_session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                                  aws_session_token=creds["SessionToken"], region_name=args.region)
    agent = LiveApiClient(outputs["ApprovalApiUrl"], args.region, agent_session)
    human = LiveApiClient(outputs["ApprovalApiUrl"], args.region, operator)
    run = f"live-{int(time.time())}"
    bucket = outputs["DataBucketName"]

    print(f"Operator (human approver/admin): {operator_arn}")
    print("Agent runtime: assumed DemoAgentRuntimeRole")
    read = {"agent_id": "procurement-agent", "session_id": run + "-aws", "provider": "aws",
            "operation_id": "AWS.ReadObject", "target_resource": f"aws/s3/{bucket}/reports/approved/price-benchmark-2026.csv",
            "environment": "prod", "tool_parameters": {}}
    r = agent.request_authority(read)
    check("AWS.ReadObject approved object is allowed", r.get("verdict") == "allow", r.get("explanation", r))
    if r.get("grant"):
        out = agent.execute(r["grant"]["grant_id"], read)
        summary = (out.get("execution") or {}).get("summary", {})
        check("Read with the grant's STS session", out.get("status") == "executed",
              json.dumps((out.get("credential") or {}).get("details", {}))[:240])
        probe = summary.get("iam_probe", {})
        check("Same credential cannot read a second object the role CAN read (session policy)",
              probe.get("probe") == "denied", json.dumps(probe))
    restricted = dict(read, target_resource=f"aws/s3/{bucket}/reports/restricted/salary-bands.csv")
    r = agent.request_authority(restricted)
    check("Restricted object is denied before any credential", r.get("verdict") == "deny" and "grant" not in r)

    small = purchase("productivity-suite", 4, 168, run + "-p1")
    r = agent.request_authority(small)
    out = agent.execute(r["grant"]["grant_id"], small) if r.get("grant") else {}
    check("CAD 168 autonomous purchase executes", out.get("status") == "executed")
    replay = agent.execute(r["grant"]["grant_id"], small) if r.get("grant") else {}
    check("Replay of the used hall pass is denied", replay.get("status") == "denied", replay.get("reason", ""))

    big = purchase("analytics-suite", 4, 1800, run + "-p2")
    r = agent.request_authority(big)
    check("CAD 1,800 steps up to a human", r.get("verdict") == "escalate", r.get("approval_id", ""))
    if r.get("approval_id"):
        approval = human.approve(r["approval_id"])
        check("Operator approves (authenticated by SigV4, not by body)", approval.get("status") == "approved",
              approval.get("approver_id", approval))
        tampered = purchase("analytics-suite", 40, 18000, run + "-p2")
        t = agent.mint_after_approval(r["approval_id"], tampered)
        check("CAD 18,000 presented against the approval is denied", t.get("verdict") == "deny", t.get("reason", ""))
        m = agent.mint_after_approval(r["approval_id"], big)
        out = agent.execute(m["grant"]["grant_id"], big) if m.get("grant") else {}
        check("Exact approved request executes once", out.get("status") == "executed")

    ks = human.kill_switch("procurement-agent", "live drill")
    after = agent.request_authority(purchase("productivity-suite", 1, 42, run + "-p3"))
    check("Kill switch stops new requests", ks.get("status") == "kill_switch_active" and after.get("verdict") == "deny")
    restored = human.set_scope("procurement-agent", 3, "drill complete")
    check("Human admin restores scope", restored.get("status") == "updated")

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} live checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
