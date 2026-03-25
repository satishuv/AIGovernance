#!/usr/bin/env python3
"""CLI entry point for executing the Minimum Validation Suite.

Usage:
    python run_validation.py          # Local execution mode
    python run_validation.py --api    # API invocation mode

Exits with code 0 if all tests pass, code 1 if any test fails.

Requirements: 16.6
"""

import argparse
import json
import logging
import os
import sys

# Ensure the lambdas package is importable when running from the project root.
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lambdas")
)

from governance_engine.validation_suite import MinimumValidationSuite  # noqa: E402


def _build_config_from_env() -> dict:
    """Build configuration dict from environment variables."""
    return {
        "scope_table_name": os.environ.get("SCOPE_TABLE_NAME", ""),
        "agent_registry_table_name": os.environ.get(
            "AGENT_REGISTRY_TABLE_NAME", ""
        ),
        "policy_bucket_name": os.environ.get("POLICY_BUCKET_NAME", ""),
        "evidence_bucket_name": os.environ.get("EVIDENCE_BUCKET_NAME", ""),
        "control_trace_table_name": os.environ.get(
            "CONTROL_TRACE_TABLE_NAME", ""
        ),
        "governance_roles_table_name": os.environ.get(
            "GOVERNANCE_ROLES_TABLE_NAME", ""
        ),
        "risk_config_table_name": os.environ.get(
            "RISK_CONFIG_TABLE_NAME", ""
        ),
        "framework_mapping_table_name": os.environ.get(
            "FRAMEWORK_MAPPING_TABLE_NAME", ""
        ),
        "immutable_evidence_bucket_name": os.environ.get(
            "IMMUTABLE_EVIDENCE_BUCKET_NAME", ""
        ),
        "operator_sns_topic_arn": os.environ.get(
            "OPERATOR_SNS_TOPIC_ARN", ""
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Minimum Validation Suite for governance controls."
    )
    parser.add_argument(
        "--api",
        action="store_true",
        default=False,
        help="Use API invocation mode instead of local execution.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = _build_config_from_env()
    if args.api:
        config["mode"] = "api"

    suite = MinimumValidationSuite(config=config)
    results = suite.run_all_tests()
    report = suite.generate_report(results)

    print(json.dumps(report, indent=2))

    if report["suite_passed"]:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
