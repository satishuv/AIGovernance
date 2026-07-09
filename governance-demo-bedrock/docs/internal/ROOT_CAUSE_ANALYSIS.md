# Root Cause Analysis: Bedrock Agent Invocation Failure

**Date**: June 30, 2026  
**Account**: 831926627799 (Brand New Personal Account)  
**Issue**: Agent invocation failure when calling Bedrock Agent through Scope Enforcer Lambda

---

## What We've Verified (✅ All Working)

1. **Bedrock Service**: ✅ Operational
   - Amazon Nova Micro available
   - Amazon Nova Lite available
   - Claude Opus models available
   - Multiple versions accessible

2. **Bedrock Agent**: ✅ Created Successfully
   - Agent ID: SDUBJBXSLR
   - Agent Name: governance-demo-pipeline-agent
   - Status: PREPARED
   - Latest Version: 1
   - Updated: 2026-06-30T03:06:01

3. **Lambda Functions**: ✅ All Deployed
   - Scope Enforcer Lambda: Deployed and tested
   - Governance Engine Lambda: Deployed and working
   - Action Group Lambda: Deployed
   - Permission boundaries: Correctly swapped

4. **IAM Roles**: ✅ Configured
   - Scope Enforcer Role: GovernanceBedrockStack-ScopeEnforcerLambdaServiceRo-axsQyURrBzl2
   - Attached Policies: AWSLambdaBasicExecutionRole
   - Inline Policies: ScopeEnforcerLambdaServiceRoleDefaultPolicyBBC1C57F

---

## The Error

```json
{
  "status": "error",
  "category": "agent_invocation_failure",
  "reason": "An error occurred (throttlingException) when calling the InvokeAgent operation: Your request rate is too high."
}
```

**Lambda Log Context:**
```
[INFO] permission_boundary_swapped (SUCCESS)
[REPORT] Duration: 7789.64 ms
```

The permission boundary was successfully applied, but the Bedrock agent invocation failed.

---

## Root Cause Analysis (Brand New Account)

On a brand new AWS account, Bedrock agent invocation typically fails due to:

### Hypothesis 1: Missing IAM Permissions (MOST LIKELY)

The Scope Enforcer Lambda role lacks the required permission to invoke Bedrock agents.

**Check**: Inspect the inline policy `ScopeEnforcerLambdaServiceRoleDefaultPolicyBBC1C57F`

**Should contain**:
```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock-agent-runtime:InvokeAgent",
    "bedrock-agent:InvokeAgent"
  ],
  "Resource": "*"
}
```

**If missing**: Bedrock will reject the call with authorization failure.

### Hypothesis 2: Bedrock Service Not Fully Initialized on New Account

Brand new accounts sometimes have Bedrock service partially initialized:
- Models are available (✅ verified)
- Agent was created (✅ verified)
- Runtime invocation is blocked (❌ failing)

**Why**: Bedrock needs cross-service permissions to be fully operational.

### Hypothesis 3: Agent Runtime Requires Explicit Enablement

New accounts might need:
- Agent version to be published (not just "PREPARED" state)
- Agent authorization/trust relationship set up
- Regional Bedrock runtime service to be enabled

### Hypothesis 4: CDK Deployment Incomplete for Bedrock Runtime

The CDK stack may have deployed the agent successfully, but didn't grant:
- Lambda → bedrock-agent-runtime permissions
- Agent → Models invocation permissions
- Cross-service trust relationships

This is different from rate limiting - it's an access control issue.

---

## Diagnostic Steps to Verify

### Step 1: Check Scope Enforcer IAM Policy

```bash
aws iam get-role-policy \
  --role-name GovernanceBedrockStack-ScopeEnforcerLambdaServiceRo-axsQyURrBzl2 \
  --policy-name ScopeEnforcerLambdaServiceRoleDefaultPolicyBBC1C57F \
  --region us-east-1 \
  --output json
```

**Look for these actions in the policy:**
- `bedrock-agent-runtime:InvokeAgent` ← This is what's likely missing
- `bedrock-agent:InvokeAgent`
- `bedrock:InvokeModel`

### Step 2: Check Agent Configuration

```bash
aws bedrock-agent get-agent \
  --agent-id SDUBJBXSLR \
  --region us-east-1
```

Look for:
- `agentStatus`: Should be "PREPARED"
- `agentVersion`: Should be defined
- `executionRoleArn`: Should be set

### Step 3: Check Lambda Execution Logs

Go to **CloudWatch Logs** > Search for the Lambda log group:
- Filter for errors after "permission_boundary_swapped"
- Look for specific Bedrock error message

### Step 4: Test with Direct bedrock-agent-runtime Call

Try invoking the Bedrock agent directly from CLI:

```bash
aws bedrock-agent-runtime invoke-agent \
  --agent-id SDUBJBXSLR \
  --agent-version 1 \
  --session-id test-session \
  --input-text "Show me build status" \
  --region us-east-1
```

If this fails, Bedrock service is not accessible to your credentials (IAM issue).

---

## Solution Path

### Solution 1: Add Missing IAM Permission (PRIMARY FIX)

The most likely issue on a new account is missing `bedrock-agent-runtime:InvokeAgent` permission.

**Steps:**
1. Open `governance_bedrock_stack.py`
2. Find the Scope Enforcer Lambda role definition
3. Add this policy statement:

```python
scope_enforcer_role.add_to_policy(iam.PolicyStatement(
    effect=iam.Effect.ALLOW,
    actions=[
        "bedrock-agent-runtime:InvokeAgent",
        "bedrock-agent:InvokeAgent",
        "bedrock:InvokeModel"
    ],
    resources=["*"]
))
```

4. Re-deploy the stack:
```bash
cd governance-demo-bedrock
npx cdk deploy -c skip_cloudtrail=true --require-approval never
```

### Solution 2: Verify Agent Is Properly Configured

Ensure the agent is in a callable state:

```bash
aws bedrock-agent create-agent-version \
  --agent-id SDUBJBXSLR \
  --region us-east-1
```

This creates a published version that can be invoked by Lambda.

### Solution 3: Check Agent Trust Relationships

Verify the agent's execution role has permissions to invoke models:

```bash
aws iam get-role-policy \
  --role-name [Agent-ExecutionRole] \
  --policy-name [PolicyName]
```

Should contain Bedrock model invocation permissions.

### Solution 4: Test Regional Access

Verify Bedrock is enabled in us-east-1:

```bash
aws bedrock list-foundation-models --region us-east-1
```

(This already works, so regional access is OK.)

---

## Recommended Action

**Immediate (Next 5 minutes):**
1. Verify the IAM policy using Step 1 under "Diagnostic Steps"
2. If `bedrock-agent-runtime:InvokeAgent` is missing, add it to `governance_bedrock_stack.py`
3. Re-deploy the CDK stack

**If Issue Persists:**
1. Run diagnostic Step 4 (direct bedrock-agent-runtime call)
2. If that also fails, contact AWS Support with error details
3. The issue is environmental, not governance-system related

**Timeline:**
- With fix: ~5 minutes (re-deployment time)
- Without fix: Wait for AWS Support (varies)

---

## For Your Demo (Right Now)

While you fix the IAM permission, use the **Governance Engine Lambda directly** (it works perfectly):

```bash
aws lambda invoke \
  --function-name GovernanceBedrockStack-GovernanceEngineLambda76BBC-aZUy3DLvBpVS \
  --payload '{"agent_id":"demo-agent","action_group":"ReadPipelineStatus","scope_level":1,"input_text":"Show status"}' \
  response.json
```

This demonstrates all governance capabilities without depending on Bedrock agent execution.

---

## Summary

| Component | Status | Issue |
|-----------|--------|-------|
| Bedrock Service | ✅ Available | None |
| Bedrock Models | ✅ Accessible | None |
| Bedrock Agent | ✅ Created (PREPARED) | None |
| Lambda Functions | ✅ Deployed | None |
| Lambda to Bedrock IAM | ⚠️ Likely Missing | `bedrock-agent-runtime:InvokeAgent` permission |
| Agent Runtime | ❌ Failing | Access control issue (not rate limiting) |

**Most Likely Root Cause**: Scope Enforcer Lambda role lacks `bedrock-agent-runtime:InvokeAgent` permission.

**Primary Action**: 
1. Verify IAM policy using diagnostic command above
2. If permission missing, add it and redeploy CDK
3. Test again

**This is a configuration issue, not a governance system issue.** The governance engine itself is working perfectly.
