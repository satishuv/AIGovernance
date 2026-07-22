"""
Preservation Property Tests, Property 2: Preservation

Validates that the three working action group schemas, Lambda routing,
and parameter extraction remain unchanged. These tests MUST PASS on both
unfixed and fixed code.
"""

import json
import os
import sys

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Schema preservation: other three schemas use POST+requestBody
# ---------------------------------------------------------------------------
SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), "..", "schemas")

WORKING_SCHEMAS = [
    "production_deployment.json",
    "propose_changes.json",
    "staging_deployment.json",
]


def _load_schema(filename):
    with open(os.path.join(SCHEMAS_DIR, filename)) as f:
        return json.load(f)


# Collect all (schema_name, path_key, path_obj) tuples from working schemas
WORKING_SCHEMA_PATHS = []
for schema_file in WORKING_SCHEMAS:
    schema = _load_schema(schema_file)
    for path_key, path_obj in schema["paths"].items():
        WORKING_SCHEMA_PATHS.append((schema_file, path_key, path_obj))


@given(entry=st.sampled_from(WORKING_SCHEMA_PATHS))
@settings(max_examples=len(WORKING_SCHEMA_PATHS))
def test_working_schemas_use_post_with_request_body(entry):
    """All paths in the three working schemas must use POST+requestBody."""
    schema_file, path_key, path_obj = entry

    assert "post" in path_obj, (
        f"{schema_file}: {path_key} missing 'post' method"
    )
    post_op = path_obj["post"]
    assert "requestBody" in post_op, (
        f"{schema_file}: {path_key} POST missing 'requestBody'"
    )
    content = post_op["requestBody"].get("content", {})
    assert "application/json" in content, (
        f"{schema_file}: {path_key} requestBody missing 'application/json'"
    )


# ---------------------------------------------------------------------------
# Lambda routing preservation: ROUTE_TABLE maps 8 routes across 4 groups
# ---------------------------------------------------------------------------
# Add the lambdas directory to sys.path so we can import the handler
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "action_group")
)

# Mock boto3 before importing the handler (it creates clients at import time)
from unittest.mock import MagicMock
import unittest.mock

with unittest.mock.patch.dict("os.environ", {
    "DATA_BUCKET_NAME": "test-bucket",
    "PENDING_TABLE_NAME": "test-table",
    "LOG_GROUP_NAME": "test-log-group",
}):
    with unittest.mock.patch("boto3.client", return_value=MagicMock()):
        with unittest.mock.patch("boto3.resource", return_value=MagicMock()):
            import index as action_group_index


EXPECTED_ROUTES = [
    ("ReadPipelineStatus", "/getBuildStatus"),
    ("ReadPipelineStatus", "/getTestResults"),
    ("ProposeChanges", "/draftDeploymentPlan"),
    ("ProposeChanges", "/draftRollbackStrategy"),
    ("StagingDeployment", "/deployToStaging"),
    ("StagingDeployment", "/triggerTests"),
    ("ProductionDeployment", "/deployToProduction"),
    ("ProductionDeployment", "/rollbackDeployment"),
]


@given(route=st.sampled_from(EXPECTED_ROUTES))
@settings(max_examples=len(EXPECTED_ROUTES))
def test_route_table_resolves_all_expected_routes(route):
    """Every expected (actionGroup, apiPath) resolves to a handler."""
    action_group, api_path = route
    handler_fn = action_group_index._resolve_route(action_group, api_path)
    assert handler_fn is not None, (
        f"Route ({action_group}, {api_path}) did not resolve to a handler"
    )


def test_route_table_has_eight_entries():
    """ROUTE_TABLE must have exactly 8 entries."""
    assert len(action_group_index.ROUTE_TABLE) == 8


# ---------------------------------------------------------------------------
# Lambda parameter extraction preservation: _get_param is format-agnostic
# ---------------------------------------------------------------------------
@given(build_id=st.text(min_size=1, max_size=100))
@settings(max_examples=50)
def test_get_param_extracts_build_id(build_id):
    """_get_param extracts buildId from parameters list regardless of format."""
    params = [{"name": "buildId", "value": build_id}]
    result = action_group_index._get_param(params, "buildId")
    assert result == build_id


def test_get_param_returns_none_for_missing():
    """_get_param returns None when parameter is not found."""
    params = [{"name": "other", "value": "val"}]
    assert action_group_index._get_param(params, "buildId") is None


def test_get_param_returns_none_for_empty():
    """_get_param returns None for empty/None parameters."""
    assert action_group_index._get_param(None, "buildId") is None
    assert action_group_index._get_param([], "buildId") is None
