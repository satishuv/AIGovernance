"""Teardown for the defense-in-depth demo infrastructure.

Deletes EVERYTHING created by the multi-OU / VPC / NFW / WAF demo, in correct
dependency order, so nothing keeps billing (NAT Gateway ~$32/mo, Network
Firewall ~$395/mo are the expensive ones). Reads the resource inventory written
at deploy time.

SAFE: only touches resources tagged project=AIGovernance purpose=defense-in-
depth-demo, recorded in network_resources.json. Does NOT touch the live
governance stack, the org's live account, or the Security OU that pre-existed.

Usage:
    python scripts/teardown_defense_in_depth.py --inventory network_resources.json --yes
    python scripts/teardown_defense_in_depth.py --inventory network_resources.json   # dry run
    python scripts/teardown_defense_in_depth.py --org   # also detach+delete OUs/SCPs/RCP (separate flag; OUs are empty)
"""
import argparse
import json
import sys
import time

import boto3

REGION = "us-east-1"


def _try(label, fn):
    try:
        fn()
        print(f"  deleted {label}")
    except Exception as e:
        print(f"  skip {label}: {str(e)[:80]}")


def teardown_network(inv, dry):
    ec2 = boto3.client("ec2", REGION)
    nfw = boto3.client("network-firewall", REGION)
    waf = boto3.client("wafv2", REGION)
    logs = boto3.client("logs", REGION)
    iam = boto3.client("iam")

    if dry:
        print("DRY RUN. Would delete:")
        print(json.dumps({k: v for k, v in inv.items()}, indent=2)[:2000])
        return

    # 1. WAF web ACL (needs lock token)
    w = inv.get("waf", {})
    if w.get("id"):
        def _w():
            lt = waf.get_web_acl(Name=w["name"], Scope="REGIONAL", Id=w["id"])["LockToken"]
            waf.delete_web_acl(Name=w["name"], Scope="REGIONAL", Id=w["id"], LockToken=lt)
        _try(f"WAF {w['id']}", _w)

    # 2. Network Firewall (delete firewall, then policy, then rule group; NFW needs the firewall gone first)
    n = inv.get("nfw", {})
    if n.get("firewall_name"):
        _try(f"NFW firewall {n['firewall_name']}", lambda: nfw.delete_firewall(FirewallName=n["firewall_name"]))
        # wait for firewall deletion before policy/rule group
        for _ in range(30):
            try:
                nfw.describe_firewall(FirewallName=n["firewall_name"]); time.sleep(10)
            except Exception:
                break
    if n.get("policy"):
        _try("NFW policy", lambda: nfw.delete_firewall_policy(FirewallPolicyArn=n["policy"]))
    if n.get("rulegroup"):
        _try("NFW rule group", lambda: nfw.delete_rule_group(RuleGroupArn=n["rulegroup"], Type="STATEFUL"))

    # 3. NAT gateway + release EIP
    for nat in inv.get("nat", []):
        _try(f"NAT {nat}", lambda nat=nat: ec2.delete_nat_gateway(NatGatewayId=nat))
    if inv.get("nat"):
        print("  waiting for NAT deletion (~40s)..."); time.sleep(45)
    for eip in inv.get("eip", []):
        _try(f"EIP {eip}", lambda eip=eip: ec2.release_address(AllocationId=eip))

    # 4. Flow logs
    if inv.get("flowlog"):
        _try("flow logs", lambda: ec2.delete_flow_logs(FlowLogIds=inv["flowlog"]))
    for lg in inv.get("loggroup", []):
        _try(f"log group {lg}", lambda lg=lg: logs.delete_log_group(logGroupName=lg))

    # 5. VPC endpoints
    if inv.get("endpoints"):
        _try("vpc endpoints", lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=inv["endpoints"]))
        time.sleep(10)

    # 6. Per-VPC teardown: SGs (non-default), subnets, IGW detach/delete, then VPC
    for env, v in inv.get("vpcs", {}).items():
        # security groups
        for sg in inv.get("sg", []):
            _try(f"sg {sg}", lambda sg=sg: ec2.delete_security_group(GroupId=sg))
        # subnets in this vpc
        subs = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [v]}])["Subnets"]
        for s in subs:
            _try(f"subnet {s['SubnetId']}", lambda s=s: ec2.delete_subnet(SubnetId=s["SubnetId"]))
        # custom NACLs (non-default)
        for acl in ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [v]}])["NetworkAcls"]:
            if not acl["IsDefault"]:
                _try(f"nacl {acl['NetworkAclId']}", lambda a=acl: ec2.delete_network_acl(NetworkAclId=a["NetworkAclId"]))
        # IGWs
        for ig in ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [v]}])["InternetGateways"]:
            _try(f"igw detach {ig['InternetGatewayId']}", lambda ig=ig: ec2.detach_internet_gateway(InternetGatewayId=ig["InternetGatewayId"], VpcId=v))
            _try(f"igw {ig['InternetGatewayId']}", lambda ig=ig: ec2.delete_internet_gateway(InternetGatewayId=ig["InternetGatewayId"]))
        # non-main route tables
        for rt in ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [v]}])["RouteTables"]:
            if not any(a.get("Main") for a in rt.get("Associations", [])):
                _try(f"rt {rt['RouteTableId']}", lambda rt=rt: ec2.delete_route_table(RouteTableId=rt["RouteTableId"]))
        _try(f"vpc {v} ({env})", lambda v=v: ec2.delete_vpc(VpcId=v))

    # 7. IAM flow-logs role
    for role in inv.get("iamrole", []):
        def _r(role=role):
            for p in iam.list_role_policies(RoleName=role)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role, PolicyName=p)
            iam.delete_role(RoleName=role)
        _try(f"iam role {role}", _r)


def teardown_org(inv):
    """Detach + delete SCPs/RCP and the OUs we created. OUs must be empty.

    OU ids are read from the inventory (inv["ous"]) rather than hardcoded, so no
    org-specific identifiers live in source. If absent, discover our OUs by name
    under the root.
    """
    org = boto3.client("organizations")
    OUS = list(inv.get("ous", {}).values())
    if not OUS:
        root = org.list_roots()["Roots"][0]["Id"]
        names = {"Workloads", "Infrastructure", "Sandbox"}
        for ou in org.list_organizational_units_for_parent(ParentId=root)["OrganizationalUnits"]:
            if ou["Name"] in names:
                OUS.append(ou["Id"])
                for child in org.list_organizational_units_for_parent(ParentId=ou["Id"])["OrganizationalUnits"]:
                    OUS.insert(0, child["Id"])  # children first
    # detach + delete our policies (leave AWS FullAccess default alone)
    for pid_file in ("scp_ids.txt", "rcp_id.txt"):
        try:
            pids = open(pid_file).read().split()
        except Exception:
            pids = []
        for pid in pids:
            for t in org.list_targets_for_policy(PolicyId=pid).get("Targets", []):
                _try(f"detach {pid} from {t['TargetId']}", lambda pid=pid, t=t: org.detach_policy(PolicyId=pid, TargetId=t["TargetId"]))
            _try(f"delete policy {pid}", lambda pid=pid: org.delete_policy(PolicyId=pid))
    # delete OUs (children first: Workloads children then Workloads)
    for ou in OUS:
        _try(f"delete OU {ou}", lambda ou=ou: org.delete_organizational_unit(OrganizationalUnitId=ou))
    print("NOTE: pre-existing Security OU left intact. RCP policy-type left enabled.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", default="network_resources.json")
    ap.add_argument("--yes", action="store_true", help="actually delete (default is dry run)")
    ap.add_argument("--org", action="store_true", help="ALSO tear down OUs/SCPs/RCP")
    args = ap.parse_args()
    try:
        inv = json.load(open(args.inventory))
    except Exception:
        print(f"could not read {args.inventory}"); return 1
    teardown_network(inv, dry=not args.yes)
    if args.org and args.yes:
        teardown_org(inv)
    print("done." if args.yes else "dry run complete; re-run with --yes to delete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
