# Deploy to Your Personal AWS Account - Step by Step

This guide will help you deploy the governance-demo-bedrock stack to your personal AWS account using temporary credentials.

## Step 1: Generate Temporary Credentials from AWS Console

1. **Login to your personal AWS Account** at https://console.aws.amazon.com
2. **Click your account name** (top-right corner)
3. **Select "Security Credentials"**
4. **Click "Create access key"** or look for "Temporary security credentials"
5. **You'll see:**
   - Access Key ID
   - Secret Access Key
   - Session Token (if using temporary credentials)
6. **Copy all three** and save them somewhere temporarily

## Step 2: Configure AWS Credentials Locally

Open PowerShell and run:

```powershell
# Set the temporary credentials (replace with your values)
$env:AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
$env:AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
$env:AWS_SESSION_TOKEN="YOUR_SESSION_TOKEN"  # If you have one

# Verify the credentials work
aws sts get-caller-identity
```

You should see output like:
```json
{
    "UserId": "...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-name"
}
```

## Step 3: Check Bedrock Availability in Your Region

Run this to see if Bedrock is available in your account:

```powershell
# List available Bedrock models
aws bedrock list-foundation-models --region us-east-1
```

If you see Claude models listed, you're good to go!

## Step 4: Deploy the Stack

```powershell
cd "c:\Users\satishuv\AI Blog Setup\governance-demo-bedrock"

# Activate venv (if not already)
.\.venv\Scripts\Activate.ps1

# Deploy with temporary credentials (they're already set in env vars above)
npx cdk deploy -c skip_cloudtrail=true --require-approval never --region us-east-1
```

The stack will deploy in ~2 minutes.

## Step 5: After Deployment

Once deployed, you'll have:
- ✅ 8 Lambda functions
- ✅ 21 DynamoDB tables  
- ✅ 5 S3 buckets
- ✅ 2 API Gateway endpoints
- ✅ Bedrock Agent (with actual model access!)

## Step 6: Run Full End-to-End Tests

```powershell
# Test 1: Read request (low risk) - should ALLOW
$payload = @{agent_id='demo-agent'; input_text='Show me the build status for build-47'} | ConvertTo-Json
aws lambda invoke --function-name GovernanceBedrockStack-GovernanceEngineLambda* `
  --payload $payload --region us-east-1 --cli-binary-format raw-in-base64-out response.json
Get-Content response.json
```

## Troubleshooting

**Error: "UnrecognizedClientException" or "InvalidClientTokenId"**
- Your credentials expired or are invalid
- Generate new temporary credentials and try again

**Error: "Bedrock model not found"**
- Bedrock Amazon Nova Micro not available in that region
- Try us-west-2 or eu-west-1 instead

**Error: "Access Denied"**
- Your account doesn't have IAM permissions to deploy CDK stacks
- Ask your AWS admin for IAM access

## What's Different from Isengard?

| Feature | Isengard (Current) | Your Personal Account |
|---------|-------------------|----------------------|
| Governance Engine | ✅ Works | ✅ Works |
| Lambda Functions | ✅ Deployed | ✅ Deployed |
| DynamoDB Tables | ✅ Seeded | ✅ Seeded |
| Bedrock Agent | ❌ SCP blocks it | ✅ Should work! |
| **FULL END-TO-END DEMO** | ❌ No | ✅ YES! |

## Clean Up (Optional)

When you're done testing:

```powershell
cd "c:\Users\satishuv\AI Blog Setup\governance-demo-bedrock"
.\.venv\Scripts\Activate.ps1
npx cdk destroy -c skip_cloudtrail=true
```

---

**Once you have credentials ready, provide them and I'll help you deploy!**
