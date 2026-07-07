import json
import os

from aws_cdk import (
    Duration,
    aws_iam as iam,
    aws_lambda as _lambda,
    custom_resources as cr,
)
from constructs import Construct


class SeedDataConstruct(Construct):
    """Seed Lambda and custom resource that populates all DynamoDB tables."""

    def __init__(
        self, scope: Construct, construct_id: str, *, storage, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stack_dir = os.path.dirname(os.path.dirname(__file__))

        # --- Scope Table Init (legacy custom resource) ---

        self.scope_table_init = cr.AwsCustomResource(
            self,
            "ScopeTableInit",
            on_create=cr.AwsSdkCall(
                service="DynamoDB",
                action="putItem",
                parameters={
                    "TableName": storage.scope_table.table_name,
                    "Item": {
                        "agent_id": {"S": "demo-agent"},
                        "scope_level": {"N": "1"},
                        "updated_at": {"S": "2025-01-15T10:30:00Z"},
                        "updated_by": {"S": "cdk-init"},
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of("ScopeTableInit"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["dynamodb:PutItem"],
                    resources=[storage.scope_table.table_arn],
                ),
            ]),
        )

        # --- Seed Tables Lambda ---

        self.seed_tables_lambda = _lambda.Function(
            self,
            "SeedTablesLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "seed_tables")
            ),
            timeout=Duration.seconds(120),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
        )

        all_seed_table_arns = [
            storage.scope_table.table_arn,
            storage.risk_config_table.table_arn,
            storage.framework_mapping_table.table_arn,
            storage.agent_registry_table.table_arn,
            storage.governance_roles_table.table_arn,
            storage.threat_patterns_table.table_arn,
            storage.control_mapping_table.table_arn,
            storage.pending_approval_table.table_arn,
            storage.exfiltration_allowlist_table.table_arn,
            storage.metrics_threshold_table.table_arn,
            storage.multi_agent_config_table.table_arn,
            storage.tool_model_registry_table.table_arn,
            storage.runtime_drift_table.table_arn,
            storage.agent_health_table.table_arn,
            storage.tool_auth_table.table_arn,
        ]

        self.seed_tables_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["dynamodb:PutItem", "dynamodb:BatchWriteItem"],
                resources=all_seed_table_arns,
            )
        )

        # --- Build seed payload ---

        control_mapping_dir = os.path.join(stack_dir, "sample_data", "control_mapping")
        control_mapping_items = []
        for filename in ["iso42001_mappings.json", "nist_ai_rmf_mappings.json"]:
            filepath = os.path.join(control_mapping_dir, filename)
            with open(filepath) as f:
                data = json.load(f)
            for m in data.get("mappings", []):
                composite_id = f"{m['control_id']}#{m['implementation_component']}"
                control_mapping_items.append({
                    "control_id": composite_id,
                    "framework": data["framework"],
                    "control_name": m["control_name"],
                    "implementation_component": m["implementation_component"],
                    "evidence_generated": m["evidence_generated"],
                })

        seed_payload = {
            "seeds": [
                {
                    "table_name": storage.scope_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "scope_level": 1,
                            "updated_at": "2025-01-15T10:30:00Z",
                            "updated_by": "cdk-init",
                            "environment": "dev",
                            "status": "active",
                            "display_name": "Demo Agent",
                        },
                    ],
                },
                {
                    "table_name": storage.risk_config_table.table_name,
                    "items": [
                        {
                            "config_key": "escalation_threshold",
                            "value": 70,
                            "description": "Risk score threshold above which actions are escalated",
                        },
                        {
                            "config_key": "scope_level_weights",
                            "weights": {"0": 0, "1": 10, "2": 25, "3": 50, "4": 75},
                            "description": "Risk weight per scope level",
                        },
                        {
                            "config_key": "action_group_weights",
                            "weights": {
                                "data_access": 10, "data_modification": 30,
                                "deployment": 50, "configuration_change": 40,
                                "emergency_action": 60,
                            },
                            "description": "Risk weight per action group category",
                        },
                        {
                            "config_key": "target_resource_weights",
                            "weights": {
                                "production": 30, "staging": 15,
                                "development": 5, "default": 10,
                            },
                            "description": "Risk weight per target resource type",
                        },
                        {
                            "config_key": "category_base_weights",
                            "weights": {
                                "data_access": 5, "data_modification": 15,
                                "deployment": 25, "configuration_change": 20,
                                "emergency_action": 35,
                            },
                            "description": "Base risk weight per risk category",
                        },
                        {
                            "config_key": "history_factor_weight",
                            "value": 5,
                            "description": "Risk weight multiplier per recent action in history",
                        },
                        {
                            "config_key": "scope_reduction_mode",
                            "value": "approval-gated",
                            "time_window_seconds": 3600,
                            "sustained_period_seconds": 1800,
                            "cooldown_seconds": 7200,
                            "high_risk_threshold": 70,
                            "description": "Graduated scope reduction configuration",
                        },
                    ],
                },
                {
                    "table_name": storage.framework_mapping_table.table_name,
                    "items": [
                        {
                            "action_type": "data_access",
                            "iso_42001_controls": ["A.8.4", "A.6.2.2"],
                            "nist_ai_rmf_functions": ["GOVERN 1.1", "MAP 1.1"],
                        },
                        {
                            "action_type": "data_modification",
                            "iso_42001_controls": ["A.8.4", "A.8.5", "A.6.2.2"],
                            "nist_ai_rmf_functions": ["GOVERN 1.1", "GOVERN 1.2", "MAP 1.5"],
                        },
                        {
                            "action_type": "deployment",
                            "iso_42001_controls": ["A.8.2", "A.8.5", "A.6.2.1"],
                            "nist_ai_rmf_functions": ["GOVERN 1.2", "MAP 3.4", "MANAGE 1.1"],
                        },
                        {
                            "action_type": "configuration_change",
                            "iso_42001_controls": ["A.8.2", "A.8.4", "A.6.2.1"],
                            "nist_ai_rmf_functions": ["GOVERN 1.1", "GOVERN 1.2", "MANAGE 2.2"],
                        },
                        {
                            "action_type": "emergency_action",
                            "iso_42001_controls": ["A.8.2", "A.8.5", "A.6.2.1", "A.6.2.2"],
                            "nist_ai_rmf_functions": ["GOVERN 1.2", "MANAGE 1.1", "MANAGE 4.1"],
                        },
                    ],
                },
                {
                    "table_name": storage.agent_registry_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "purpose": "Software Deployment Pipeline Agent",
                            "owner": "governance-admin",
                            "data_classes": ["pipeline_status", "deployment_config"],
                            "tools": ["ReadPipelineStatus", "ProposeChanges"],
                            "approved_scope": 2,
                            "environment": "dev",
                        },
                    ],
                },
                {
                    "table_name": storage.governance_roles_table.table_name,
                    "items": [
                        {
                            "user_id": "governance-admin",
                            "role": "policy_author",
                            "scope": "global",
                            "assigned_by": "cdk-init",
                            "assigned_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "user_id": "governance-admin",
                            "role": "operator",
                            "scope": "global",
                            "assigned_by": "cdk-init",
                            "assigned_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "user_id": "demo-auditor",
                            "role": "auditor",
                            "scope": "global",
                            "assigned_by": "cdk-init",
                            "assigned_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
                {
                    "table_name": storage.threat_patterns_table.table_name,
                    "items": [
                        {"pattern_id": "kb-sql-injection-1", "category": "known_bad",
                         "pattern": "';\\s*drop\\s+table",
                         "description": "SQL injection: DROP TABLE attempt",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-sql-injection-2", "category": "known_bad",
                         "pattern": "or\\s+1\\s*=\\s*1",
                         "description": "SQL injection: OR 1=1 tautology",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-prompt-injection-1", "category": "known_bad",
                         "pattern": "ignore\\s+previous\\s+instructions",
                         "description": "Prompt injection: ignore previous instructions",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-prompt-injection-2", "category": "known_bad",
                         "pattern": "system:\\s*override",
                         "description": "Prompt injection: system override attempt",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-disallowed-cmd-1", "category": "known_bad",
                         "pattern": "rm\\s+-rf",
                         "description": "Disallowed command: rm -rf",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-disallowed-cmd-2", "category": "known_bad",
                         "pattern": "format\\s+c:",
                         "description": "Disallowed command: format c:",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "sus-partial-prompt-1", "category": "suspicious",
                         "pattern": "you\\s+are\\s+now",
                         "description": "Suspicious: partial prompt injection indicator",
                         "risk_weight": 30, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "sus-encoding-1", "category": "suspicious",
                         "pattern": "%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",
                         "description": "Suspicious: unusual URL encoding sequences",
                         "risk_weight": 20, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "sus-length-1", "category": "suspicious",
                         "pattern": ".{5000,}",
                         "description": "Suspicious: anomalous input length (>5000 chars)",
                         "risk_weight": 25, "updated_at": "2025-01-15T10:30:00Z"},
                    ],
                },
                {
                    "table_name": storage.tool_model_registry_table.table_name,
                    "items": [
                        {"entry_id": "tc-read-pipeline", "category": "tool_connector",
                         "name": "ReadPipelineStatus", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Read pipeline status action group (Scope 1+)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                        {"entry_id": "tc-propose-changes", "category": "tool_connector",
                         "name": "ProposeChanges", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Propose changes action group (Scope 2+)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                        {"entry_id": "tc-staging-deploy", "category": "tool_connector",
                         "name": "StagingDeployment", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Staging deployment action group (Scope 3+)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                        {"entry_id": "tc-production-deploy", "category": "tool_connector",
                         "name": "ProductionDeployment", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Production deployment action group (Scope 4)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                    ],
                },
                {
                    "table_name": storage.control_mapping_table.table_name,
                    "items": control_mapping_items,
                },
                {
                    "table_name": storage.pending_approval_table.table_name,
                    "items": [
                        {
                            "approval_id": "sample-approval-001",
                            "decision_id": "sample-decision-001",
                            "agent_id": "demo-agent",
                            "action_requested": "StagingDeployment",
                            "risk_score": 75,
                            "escalation_reason": "Risk score 75 exceeds escalation threshold of 70",
                            "status": "pending",
                            "approver_id": "",
                            "approval_conditions": "",
                            "denial_reason": "",
                            "created_at": "2025-01-15T10:30:00Z",
                            "resolved_at": "",
                            "timeout_seconds": 3600,
                        },
                    ],
                },
                {
                    "table_name": storage.exfiltration_allowlist_table.table_name,
                    "items": [
                        {"endpoint_pattern": "amazonaws.com",
                         "description": "Default approved endpoint: amazonaws.com",
                         "added_at": "2025-01-15T10:30:00Z"},
                        {"endpoint_pattern": "aws.amazon.com",
                         "description": "Default approved endpoint: aws.amazon.com",
                         "added_at": "2025-01-15T10:30:00Z"},
                        {"endpoint_pattern": "github.com",
                         "description": "Default approved endpoint: github.com",
                         "added_at": "2025-01-15T10:30:00Z"},
                    ],
                },
                {
                    "table_name": storage.metrics_threshold_table.table_name,
                    "items": [
                        {"metric_name": "denial_rate", "threshold": 0.3,
                         "description": "Maximum acceptable denial rate"},
                        {"metric_name": "escalation_rate", "threshold": 0.2,
                         "description": "Maximum acceptable escalation rate"},
                        {"metric_name": "avg_risk_score", "threshold": 60,
                         "description": "Maximum acceptable average risk score"},
                    ],
                },
                {
                    "table_name": storage.multi_agent_config_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "policy_binding_ids": ["default-deny", "allow-read-at-scope-1"],
                            "risk_profile": {"base_risk": 10, "escalation_threshold": 70},
                            "evidence_partition": "evidence/demo-agent/",
                            "environment": "dev",
                        },
                    ],
                },
                {
                    "table_name": storage.runtime_drift_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "record_type": "baseline",
                            "action_group_frequencies": {
                                "ReadPipelineStatus": 0.7,
                                "ProposeChanges": 0.2,
                                "StagingDeployment": 0.08,
                                "ProductionDeployment": 0.02,
                            },
                            "target_resources": ["pipeline_status", "deployment_config"],
                            "avg_risk_score": 22,
                            "window_hours": 24,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
                {
                    "table_name": storage.agent_health_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "record_type": "health_state",
                            "health_score": 85,
                            "status": "healthy",
                            "last_action_at": "2025-01-15T10:30:00Z",
                            "denial_rate_1h": 0.05,
                            "avg_latency_ms": 120,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
                {
                    "table_name": storage.tool_auth_table.table_name,
                    "items": [
                        {
                            "pk": "RULE#ReadPipelineStatus",
                            "sk": "CONFIG",
                            "tool_name": "ReadPipelineStatus",
                            "rate_limit": 30,
                            "rate_window_seconds": 60,
                            "allowed_agents": ["demo-agent"],
                            "min_scope": 1,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "RULE#ProposeChanges",
                            "sk": "CONFIG",
                            "tool_name": "ProposeChanges",
                            "rate_limit": 10,
                            "rate_window_seconds": 60,
                            "allowed_agents": ["demo-agent"],
                            "min_scope": 2,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "RULE#ProductionDeployment",
                            "sk": "CONFIG",
                            "tool_name": "ProductionDeployment",
                            "rate_limit": 2,
                            "rate_window_seconds": 3600,
                            "allowed_agents": ["demo-agent"],
                            "min_scope": 4,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "RULE#SensitiveDataExport",
                            "sk": "CONFIG",
                            "tool_name": "SensitiveDataExport",
                            "rate_limit": 0,
                            "rate_window_seconds": 60,
                            "allowed_agents": [],
                            "min_scope": 99,
                            "blocked": True,
                            "block_reason": "Sensitive data export is globally blocked",
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "CHAIN#exfiltration_pattern",
                            "sk": "DEFINITION",
                            "chain_name": "exfiltration_pattern",
                            "description": "Detects potential data exfiltration via tool chaining",
                            "sequence": [
                                "ReadPipelineStatus",
                                "SensitiveDataExport",
                            ],
                            "window_seconds": 300,
                            "action": "DENY",
                            "risk_boost": 50,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
            ],
        }

        # --- Trigger seed Lambda ---

        self.seed_tables_trigger = cr.AwsCustomResource(
            self,
            "SeedTablesTrigger",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": self.seed_tables_lambda.function_name,
                    "InvocationType": "RequestResponse",
                    "Payload": json.dumps(seed_payload),
                },
                physical_resource_id=cr.PhysicalResourceId.of("SeedTablesTrigger"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["lambda:InvokeFunction"],
                    resources=[self.seed_tables_lambda.function_arn],
                ),
            ]),
        )
