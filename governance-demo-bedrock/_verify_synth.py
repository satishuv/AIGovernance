#!/usr/bin/env python3
"""Checkpoint script: verify CDK stack synthesizes cleanly."""
import sys
import os

# Ensure we're in the right directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

try:
    import aws_cdk as cdk
    version = getattr(cdk, '__version__', 'unknown')
    print(f"[OK] aws_cdk imported (version: {version})")
except ImportError as e:
    print(f"[FAIL] Cannot import aws_cdk: {e}")
    sys.exit(1)

try:
    from governance_bedrock_stack import GovernanceBedrockStack
    print("[OK] GovernanceBedrockStack imported successfully")
except Exception as e:
    print(f"[FAIL] Cannot import GovernanceBedrockStack: {e}")
    sys.exit(1)

# Synthesize the stack
try:
    app = cdk.App(context={"skip_cloudtrail": False})
    stack = GovernanceBedrockStack(app, "VerifyStack",
        env=cdk.Environment(region="us-east-1"),
    )
    assembly = app.synth()
    print("[OK] CDK synth completed successfully")
    
    # Check the template was generated
    template = assembly.get_stack_by_name("VerifyStack").template
    resources = template.get("Resources", {})
    print(f"[OK] Template has {len(resources)} resources")
    
    # Verify key Phase 1a resources exist
    resource_types = {}
    for logical_id, res in resources.items():
        rtype = res.get("Type", "Unknown")
        resource_types.setdefault(rtype, []).append(logical_id)
    
    # Print resource summary
    for rtype, ids in sorted(resource_types.items()):
        print(f"  {rtype}: {len(ids)} resource(s)")
    
    # Check for Phase 1a specific resources
    dynamo_tables = resource_types.get("AWS::DynamoDB::Table", [])
    s3_buckets = resource_types.get("AWS::S3::Bucket", [])
    lambdas = resource_types.get("AWS::Lambda::Function", [])
    sns_topics = resource_types.get("AWS::SNS::Topic", [])
    
    print(f"\n--- Phase 1a Resource Verification ---")
    print(f"DynamoDB Tables: {len(dynamo_tables)} (expect >= 5)")
    print(f"S3 Buckets: {len(s3_buckets)} (expect >= 3)")
    print(f"Lambda Functions: {len(lambdas)} (expect >= 4)")
    print(f"SNS Topics: {len(sns_topics)} (expect >= 1)")
    
    errors = []
    if len(dynamo_tables) < 5:
        errors.append(f"Expected >= 5 DynamoDB tables, got {len(dynamo_tables)}")
    if len(s3_buckets) < 3:
        errors.append(f"Expected >= 3 S3 buckets, got {len(s3_buckets)}")
    if len(lambdas) < 4:
        errors.append(f"Expected >= 4 Lambda functions, got {len(lambdas)}")
    if len(sns_topics) < 1:
        errors.append(f"Expected >= 1 SNS topic, got {len(sns_topics)}")
    
    if errors:
        print("\n[FAIL] Resource count validation errors:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\n[OK] All Phase 1a resources present")
        print("\n=== CDK SYNTH CHECKPOINT PASSED ===")

except Exception as e:
    print(f"[FAIL] CDK synth failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
