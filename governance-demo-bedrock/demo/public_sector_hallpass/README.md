# Public Sector Agent Delegated Authority Demo

A presentation aid for the delegated authority ("hall pass") control plane. It runs the real control-plane code; it is not a production UI. All names and data are generic.

Architecture and design rationale: [docs/architecture/delegated-authority.md](../../docs/architecture/delegated-authority.md).

## Run it (offline, no AWS account)

From `governance-demo-bedrock/`:

```bash
# 1. Validate every scenario (run this before every demo; must print 12/12)
python demo/public_sector_hallpass/run_demo_validation.py

# 2. Start the UI at http://127.0.0.1:8765
python demo/public_sector_hallpass/app.py
```

Requirements: the packages in `requirements.txt` (boto3, moto) plus `cryptography`. The offline mode starts an in-process AWS emulator (moto) for DynamoDB, KMS, S3 and STS, so no account, network or credentials are used.

The UI binds to 127.0.0.1 only, requires a per-process token on every action, rejects non-loopback Host headers, and never displays a credential.

## Adapter modes

| Provider | Offline demo | Deployed stack |
|---|---|---|
| AWS | real STS call path against the emulator (the emulator does not enforce session policies) | live STS AssumeRole with a grant-derived session policy, enforced by IAM |
| ServiceNow | mock | mock |
| Microsoft Entra | mock | mock |
| Google | mock | mock |

## Run it live on AWS (demo account, Canada Central)

```bash
npx cdk deploy -c profile=public-sector-canada \
    -c delegated_demo_operator=<your IAM role ARN> --require-approval never
python demo/public_sector_hallpass/live_aws_demo.py --region ca-central-1 --seed
```

`--seed` writes demo registry entries, scopes, tool rules, your principal's governance roles and two generic report objects into the stack's own tables and bucket. Use a demo account. The live script assumes a demo agent runtime role that may call only the agent-plane routes, and your own credentials act as the human approver and administrator. It shows a grant's STS credential reading the approved object and IAM denying the same credential on a second object.

The `public-sector-canada` profile pins the stack to `ca-central-1`; deploying it to another Region fails unless `-c allow_region_override=true` is passed.

## Scenarios

| # | Scenario | Expected |
|---|---|---|
| 1 | Normal autonomous transaction (CAD 168) | ALLOW, 5-minute one-use grant, credential, execute, CONSUMED, signed evidence |
| 2 | Budget escalation (CAD 1,800, limit 500) | STEP_UP, approval created, no grant |
| 3 | Human approves the exact transaction | owner cannot approve; approver approves; grant; executed once |
| 4 | Post-approval tampering (CAD 18,000) | DENY, digest mismatch; approval not burned |
| 5 | Replay attack | DENY, grant CONSUMED |
| 6 | Agent privilege escalation (GrantScope, smuggled new_scope) | DENY, human-only |
| 7 | Guardian-agent boundary | DENY on agent and admin planes |
| 8 | Guardian oversight | ALLOW inspection and recommendation; no authority change |
| 9 | Revoke an active grant | DENY, REVOKED |
| 10 | Emergency kill switch | live grant revoked, new requests DENY, human restores scope |
| 11 | Provider-native enforcement on AWS | session policy scoped to one object; restricted object denied |
| 12 | Same contract on Entra and Google | identical lifecycle |

## 10-minute demo script

1. **Minute 0-1, the principle.** "Humans approve the boundaries. Governance evaluates every action against them. Inside the boundary the agent gets a hall pass: short-lived, exact, revocable, signed. Outside it, denial or a human."
2. **Minute 1-3, scenario 1.** Walk the four panels: the agent's approved boundary, the structured request (operationId, not a prompt), every governance gate, then the hall pass (5 minutes, 1 use, CAD 500 ceiling, signature verified), the credential reference with the secret masked, the order, and the grant becoming CONSUMED.
3. **Minute 3-4, scenario 2.** Same agent, CAD 1,800. STEP_UP. Point out that no credential exists anywhere yet.
4. **Minute 4-5, scenario 3.** The agent's own business owner tries to approve and is refused (separation of duties). A finance approver approves; the identity comes from the signed request, not a form field.
5. **Minute 5-6, scenario 4, the key moment.** Change the approved CAD 1,800 to CAD 18,000. Denied: the approved request digest does not match. The approval is still unused.
6. **Minute 6-7, scenarios 5 and 9.** Replay the used hall pass: denied. Revoke a fresh one before use: denied.
7. **Minute 7-8, scenarios 6, 7 and 8.** The worker cannot raise its own scope. The guardian cannot raise the worker's scope either, but it can inspect signed decision history and recommend suspension, which changes nothing until a human acts.
8. **Minute 8-9, scenario 10.** One kill switch: the live hall pass is revoked and every new request is denied. Only a governance administrator restores scope.
9. **Minute 9-10, scenarios 11 and 12.** On AWS the hall pass becomes an STS session that can read exactly one object until the grant expires. Entra and Google use the same request, grant and evidence contract. Close: "The governance model is vendor-neutral. The enforcement mechanism is provider-native."

## Talking points to keep accurate

* AgentCore Gateway and Identity are optional implementation choices, subject to the customer's residency requirements and the current CCCS assessment. The demo does not depend on AgentCore.
* This demo makes no compliance or authorization claim about any AWS service.
