package governance

# AI Agent Governance Policies (OPA Rego)
# Used when OPA_MODE=external with a standalone OPA service.
# The embedded mode uses the JSON equivalents in the parent directory.

default allow = false
default escalate = false

# ---------------------------------------------------------------
# PREVENTIVE: Block before execution
# ---------------------------------------------------------------

# Allow read-only pipeline queries at any scope
allow {
    input.action_group == "ReadPipelineStatus"
}

# Allow production deployment at scope 3+
allow {
    input.action_group == "ProductionDeployment"
    input.scope_level >= 3
    within_business_hours
}

# Allow propose changes at scope 2+
allow {
    input.action_group == "ProposeChanges"
    input.scope_level >= 2
}

# Deny production deployment below scope 3
deny {
    input.action_group == "ProductionDeployment"
    input.scope_level < 3
}

# Deny production deployment outside business hours
deny {
    input.action_group == "ProductionDeployment"
    not within_business_hours
}

# ---------------------------------------------------------------
# DETECTIVE: Escalate for human review
# ---------------------------------------------------------------

# Staging deployments need human confirmation
escalate {
    input.action_group == "StagingDeployment"
    input.scope_level < 4
}

# ---------------------------------------------------------------
# HELPER RULES
# ---------------------------------------------------------------

within_business_hours {
    input.hour >= 6
    input.hour <= 22
}

# Result aggregation
reason = msg {
    deny
    msg := "Action denied by policy"
}

reason = msg {
    escalate
    not deny
    msg := "Action escalated for human approval"
}

reason = msg {
    allow
    not deny
    not escalate
    msg := "Action allowed by policy"
}

matched_rules[rule] {
    deny
    rule := "deny"
}

matched_rules[rule] {
    escalate
    rule := "escalate"
}

matched_rules[rule] {
    allow
    rule := "allow"
}
