"""
Bug Condition Exploration Test, Property 1: Fault Condition

Validates that all ReadPipelineStatus schema paths use POST method with
requestBody (not GET with path parameters). This test is EXPECTED TO FAIL
on unfixed code, confirming the bug exists.
"""

import json
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "schemas", "read_pipeline_status.json"
)

with open(SCHEMA_PATH) as f:
    SCHEMA = json.load(f)

PATHS = list(SCHEMA["paths"].items())


@given(path_entry=st.sampled_from(PATHS))
@settings(max_examples=len(PATHS))
def test_all_paths_use_post_with_request_body(path_entry):
    """Every path in ReadPipelineStatus schema must use POST with requestBody."""
    path_key, path_obj = path_entry

    # Must have "post" method, not "get"
    assert "post" in path_obj, (
        f"Path {path_key} uses '{list(path_obj.keys())}' instead of 'post'"
    )
    assert "get" not in path_obj, (
        f"Path {path_key} still has a 'get' method, Bedrock doesn't support GET"
    )

    post_op = path_obj["post"]

    # Must have requestBody with application/json content
    assert "requestBody" in post_op, (
        f"Path {path_key} POST operation missing 'requestBody'"
    )
    content = post_op["requestBody"].get("content", {})
    assert "application/json" in content, (
        f"Path {path_key} requestBody missing 'application/json' content"
    )

    # Must have buildId in the schema properties
    schema_props = content["application/json"]["schema"].get("properties", {})
    assert "buildId" in schema_props, (
        f"Path {path_key} requestBody schema missing 'buildId' property"
    )

    # Must NOT have path parameters
    assert "parameters" not in post_op, (
        f"Path {path_key} POST operation should not have 'parameters' array"
    )
