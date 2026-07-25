# Cost Model

Estimated monthly cost of running the governance framework at three scales (SAS
review P3 #15). For the stated public-sector / regulated audience, budget
predictability matters.

**These are ESTIMATES from AWS public on-demand pricing (us-east-1, 2026), not
billed measurements.** Actual cost varies with payload size, region, evidence
retention, and traffic shape. Use them for planning, not procurement.

## Assumptions

- Single-Lambda mode, single account/region (the deployed demo config).
- 1 decision = 1 governance-engine invocation (~3.5s ALLOW measured, 256 MB) +
  ~5 DynamoDB reads + 1 S3 policy read (cached per warm container) + 1 evidence
  write to S3 + 1 KMS Sign + a few CloudWatch metrics.
- Evidence: ~4 KB/record to S3 (immutable bucket).
- Bedrock Guardrails applied on input (priced per text unit).
- Prices rounded; small line items (<$1/mo) grouped as "misc".

## Per-scale estimate

| Service | 100 decisions/day | 10K/day | 100K/day |
|---------|------------------:|--------:|---------:|
| Lambda (256 MB, ~3.5s ea) | <$1 | ~$15 | ~$150 |
| DynamoDB (on-demand, ~5 reads + writes/decision, 23 tables) | <$1 | ~$8 | ~$80 |
| S3 evidence (PUT + storage, WORM) | <$1 | ~$3 | ~$30 |
| KMS Sign (1/decision) | <$1 | ~$1 | ~$9 |
| Bedrock Guardrails (per text unit) | <$1 | ~$15 | ~$150 |
| CloudWatch (metrics + logs) | ~$2 | ~$10 | ~$60 |
| **Approx total** | **~$5/mo** | **~$50/mo** | **~$480/mo** |

## What dominates, and how to reduce it

- At scale, **Lambda duration** and **Bedrock Guardrails** dominate. The ~3.5s
  ALLOW latency (evidence write + policy load) directly drives Lambda cost, so
  the latency fixes in [runtime-flow.md](architecture/runtime-flow.md#latency-and-performance)
  (async evidence, policy cache, Step Functions mode) are also **cost** fixes:
  cutting ALLOW to ~2s cuts Lambda cost proportionally.
- **DynamoDB on-demand** is convenient but not cheapest at steady high volume;
  provisioned capacity or fewer tables (the review's single-table suggestion)
  would reduce it. We do not recommend the refactor without a measured need
  (see review disposition), but the cost lever exists.
- **Evidence storage** grows with retention. WORM retention is 365 days
  (standard) / 2555 days (extended, ~7 yr). Long retention on high volume is the
  quiet long-term cost; size it against the compliance requirement.

## Costs NOT in the per-decision model

- **Step Functions Express** (if using that mode): priced per request + duration;
  roughly comparable to Lambda mode at these volumes.
- **Defense-in-depth demo infra** (separate, see MULTI_ACCOUNT_ARCHITECTURE.md):
  NAT Gateway ~$32/mo, Network Firewall ~$395/mo. These are the enterprise
  network layer, NOT per-decision governance cost, and the demo teardown script
  removes them.
- **Multi-account:** cost scales roughly linearly with the number of
  environment-accounts the engine is deployed into.

## Honest caveat

No sustained load test has been run to validate these at 100K/day; they are
bottom-up estimates from unit prices and the measured per-decision resource
profile. A load test would tighten them and is a reasonable pre-production step.
