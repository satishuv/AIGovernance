# Multi-Account & Defense-in-Depth Architecture

Addresses SAS review Concern #3 (single-account/single-region design) and the
enterprise-scale question: real organizations run AI workloads across many
accounts organized into OUs (Prod / Staging / Test / Dev separated), with
layered guardrails. This documents the target architecture AND what is actually
deployed as a live reference in the demo Organization.

## Deployment status (honest)

Deployed live in a demo AWS Organization (management account, us-east-1,
2026-07-24). Org/account/OU identifiers are intentionally omitted from this
public doc; they live only in the local (gitignored) deploy inventory:

| Layer | Status | Notes |
|-------|--------|-------|
| OU tree (Prod/Staging/Test/Dev/Infra/Sandbox/Security) | **Deployed** | OUs are intentionally EMPTY; the live account stays at Root, never moved under a restrictive OU |
| SCPs (3) attached to OUs | **Deployed** | Enforce on nothing yet (empty OUs) by design; real, inspectable policy docs |
| RCP (resource/identity perimeter) on Workloads | **Deployed** | RESOURCE_CONTROL_POLICY type enabled in the org |
| 3 per-env VPCs + tiered subnets + NACLs + SGs | **Deployed** | dev/staging/prod, isolated from the live governance stack |
| Gateway endpoints (S3/DynamoDB), NAT (Prod), VPC Flow Logs | **Deployed** | NAT in Prod only to bound cost |
| Network Firewall (Prod) + WAF web ACL | **Deployed** | Suricata egress rule + AWS managed baseline rules |

**Cost note:** NAT Gateway (~$32/mo) and Network Firewall (~$395/mo) bill while
running. `scripts/teardown_defense_in_depth.py --inventory network_resources.json --yes`
deletes everything created here. Tear down after the demo.

**Safety note:** the pre-existing `Security` OU was left as-is; the live account
was never moved into an SCP-governed OU (a wrong SCP on the Org management
account can lock out the account and the running demo). All guardrails were
attached to empty OUs.

## The OU structure

```
Root
│  [management account — live governance stack, STAYS at root]
├─ Security OU        SCP: deny leave-org, deny disabling CloudTrail/GuardDuty/Config, deny root user
├─ Infrastructure OU  (shared services)
├─ Sandbox OU         (experimentation)
└─ Workloads OU       RCP: identity perimeter (only org principals touch S3/STS)
   ├─ Prod OU         SCP (strict): region lock (us-east-1), deny disabling security, deny unencrypted S3, deny root
   ├─ Staging OU      SCP (strict, same as Prod)
   ├─ Test OU         SCP (permissive, same as Dev)
   └─ Dev OU          SCP (permissive): region lock only (us-east-1/us-west-2)
```

Escalating strictness is the point: Dev optimizes for developer freedom inside a
region boundary; Prod/Staging add encryption enforcement, security-control
protection, and root denial.

## Defense-in-depth: six layers

Each layer is independent; a bypass at one is caught by the next. Layers 1-5 are
AWS-native guardrails; layer 6 is this framework.

| # | Layer | Control | Scope | Deployed |
|---|-------|---------|-------|----------|
| 1 | Org perimeter | **SCP** | Max permissions for principals in an account | Yes (empty OUs) |
| 2 | Resource perimeter | **RCP** | Who may access resources (identity perimeter) | Yes (Workloads OU) |
| 3 | Network subnet | **NACL** (stateless) | Allow/deny per subnet; isolated tier denies internet | Yes (3 VPCs) |
| 4 | Network instance | **Security Group** (stateful) | Per-ENI; governance SG allows only 443 from within VPC | Yes (3 VPCs) |
| 5 | Egress / L7 | **NAT + Network Firewall + WAF** | Controlled egress, SNI/domain blocking, web L7 rules | Yes (Prod) |
| 6 | Runtime action | **AIGovernance engine** | What the agent may do per action (allow/deny/escalate/modify/defer), signed evidence | Yes (live stack) |

### How layer 6 maps onto the account structure

The framework's `environment_isolation` module and scope levels already model
the dev/staging/prod boundary *logically* (an agent in `dev` cannot act on
`prod`). This OU/account structure is the *infrastructure* enforcement of that
same boundary: what the framework asserts in a DynamoDB field, the OU + SCP +
account boundary enforces at the AWS control-plane level. The two reinforce each
other: even if an agent's logical scope check were bypassed, the SCP on the
account it runs in still denies the cross-environment action.

## Network segmentation (per environment)

Each VPC has three subnet tiers:
- **public** — internet-facing (ALB, NAT); reachable from the internet via IGW.
- **private** — application/agent compute; outbound only via NAT (Prod) or
  Gateway endpoints (all).
- **isolated** — data tier; NACL denies all internet, only intra-VPC 443.

S3 and DynamoDB are reached through **Gateway VPC endpoints** (free, no NAT
needed) so data-plane traffic never leaves the AWS network.

## Reference (not deployed here): full multi-account

In a real enterprise this Organization would hold many accounts:
- The governance engine runs in a dedicated **Security/Audit account** (hub);
  agents run in **workload accounts** across the OUs (spokes).
- Evidence centralizes to a **Log Archive account** (write-once, cross-account).
- The kill switch propagates cross-account via a central control-plane API or
  per-account deployment with a shared signal.
- Cost scales with account count; the engine is deployed once per
  environment-account (or centrally), not per agent.

This demo runs the structure in a single account (empty OUs + isolated VPCs) to
demonstrate the design without provisioning many accounts. Moving real accounts
into the OUs activates the guardrails unchanged.
