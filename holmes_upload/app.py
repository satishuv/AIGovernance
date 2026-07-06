#!/usr/bin/env python
import aws_cdk as cdk
from governance_bedrock_stack import GovernanceBedrockStack

app = cdk.App()
GovernanceBedrockStack(app, "GovernanceBedrockStack",
    env=cdk.Environment(region="us-east-1"),
)
app.synth()
