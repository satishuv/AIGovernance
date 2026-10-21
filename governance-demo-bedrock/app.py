#!/usr/bin/env python
import aws_cdk as cdk

from deployment_profile import load_profile, resolve_region
from governance_bedrock_stack import GovernanceBedrockStack

app = cdk.App()

# Without -c profile=..., behaviour is unchanged (us-east-1). With
# -c profile=public-sector-canada the stack is pinned to ca-central-1 and the
# region guard refuses any other region unless -c allow_region_override=true.
profile = load_profile(app.node.try_get_context("profile"))
region = resolve_region(
    profile,
    requested=app.node.try_get_context("region"),
    allow_override=str(app.node.try_get_context("allow_region_override")).lower() == "true",
)

GovernanceBedrockStack(app, "GovernanceBedrockStack",
    env=cdk.Environment(region=region),
)
app.synth()
