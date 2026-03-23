#!/usr/bin/env python3
import aws_cdk as cdk

from governance_stack import AgenticGovernanceDemoStack

app = cdk.App()
AgenticGovernanceDemoStack(
    app,
    "AgenticGovernanceDemo",
    env=cdk.Environment(region="us-east-1"),
)
app.synth()
