# Tenant Isolation Model

Answers the SAS review's P3 #14 question: can this govern multiple agents /
multiple tenants in one deployment, or is it one-stack-per-agent? Written to be
honest about what is enforced today vs. what a multi-tenant production deployment
would require.

## What the deployment unit is

**One stack governs many agents, not one-stack-per-agent.** A single deployed
governance stack (one governance engine, one set of tables/buckets) evaluates
actions for all registered agents. Agents are distinguished by `agent_id`
throughout: the agent registry, scope table, decision history, evidence, and
decision traces are all keyed or partitioned by `agent_id`.

## Isolation that IS enforced today (within one stack)

| Boundary | Mechanism |
|----------|-----------|
| Per-agent identity | Every action carries `agent_id`; unregistered agents are denied (`agent_not_registered`) |
| Per-agent scope | Scope level (0-4) per agent in the scope table; caps what each agent may do |
| Per-agent data classes | Registry declares allowed data classes; undeclared access denied |
| Environment (dev/staging/prod) | `environment_isolation`: an agent bound to one environment cannot act on another |
| Cross-agent rules | `multi_agent` enforces which agents may act on/through which others (blocks cross-agent propagation) |
| Per-agent evidence partition | `MultiAgentConfig.evidence_partition` gives each agent an S3 key prefix for its evidence records |
| Per-agent drift/health | Runtime drift and health tracked per `agent_id` |

This is **logical, same-account, same-stack** isolation. It is real and
enforced, and it is sufficient for governing many agents belonging to one
organization.

## What this is NOT (honest limits)

This is **not** hard multi-tenant isolation between mutually-distrusting
tenants. Specifically, today:

- All agents share the same DynamoDB tables, S3 buckets, and KMS signing key.
  Isolation is by key/prefix and IAM at the item/object level, not by separate
  infrastructure per tenant. A flaw in the governance engine's own IAM or a
  logic bug could, in principle, cross the logical boundary; there is no
  physical blast-radius separation between tenants in a single stack.
- There is no per-tenant encryption key, per-tenant table, or per-tenant network
  boundary in the single-stack model.
- Do not represent this as "hard multi-tenancy" or "tenant-isolated by design"
  to a customer. It is multi-agent governance within a trust boundary.

## The production multi-tenant path

For mutually-distrusting tenants (e.g. a SaaS offering, or separate business
units with compliance separation), the correct model is **one stack per tenant
boundary**, aligned to the account structure in
[MULTI_ACCOUNT_ARCHITECTURE.md](MULTI_ACCOUNT_ARCHITECTURE.md):

- Deploy the governance stack per tenant account (or per environment-account),
  so tenants get separate tables, buckets, keys, and IAM, physical isolation.
- The OU/SCP/RCP structure enforces the tenant boundary at the AWS control plane.
- Evidence can still centralize to a shared Log Archive account for org-wide
  audit, while each tenant's runtime governance stays isolated.

## Summary

- **Today:** one stack, many agents, logical per-agent isolation (identity,
  scope, environment, data class, evidence partition). Suitable for one
  organization's fleet.
- **For distrusting tenants:** deploy per-tenant/per-account. The framework
  supports this by redeployment; it does not provide hard in-stack tenant
  isolation, and we do not claim it does.
