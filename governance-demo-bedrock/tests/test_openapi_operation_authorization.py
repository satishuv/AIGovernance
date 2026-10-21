"""The operationId is the authorization subject; unregistered means denied."""

import pytest

from tests.authority_test_support import offline_demo, purchase, stage

from operation_registry import (  # noqa: E402
    OperationCatalogError, OperationRegistry, validate_against_schema,
)


@pytest.fixture(scope="module")
def registry():
    return OperationRegistry.load()


class TestCatalog:
    def test_every_operation_has_governance_metadata(self, registry):
        ops = registry.all()
        assert len(ops) >= 15
        for spec in ops:
            assert spec.provider and spec.resource_patterns and spec.parameter_schema.get("type") == "object"

    def test_human_only_operations_are_registered_to_no_agent(self, registry):
        from authority_factory import demo_agents
        rules = {r["tool_name"]: r for r in registry.tool_auth_rules(demo_agents())}
        for op in ("Governance.GrantScope", "Governance.UpdateAgentScope", "Governance.AmendPolicy",
                   "Entra.CreateApplication"):
            assert rules[op]["allowed_agents"] == []

    def test_duplicate_operation_ids_are_rejected(self):
        doc = {"paths": {"/a": {"get": {"operationId": "X.Op", "x-governance": {"provider": "p", "resource_patterns": ["a"]}}},
                         "/b": {"get": {"operationId": "X.Op", "x-governance": {"provider": "p", "resource_patterns": ["b"]}}}}}
        with pytest.raises(OperationCatalogError):
            OperationRegistry.from_openapi(doc)

    def test_operation_without_governance_block_is_rejected(self):
        with pytest.raises(OperationCatalogError):
            OperationRegistry.from_openapi({"paths": {"/a": {"get": {"operationId": "X.Op"}}}})

    def test_fingerprint_is_stable_and_content_sensitive(self, registry):
        assert registry.fingerprint() == OperationRegistry.load().fingerprint()
        doc = {"paths": {"/a": {"get": {"operationId": "X.Op", "x-governance": {"provider": "p", "resource_patterns": ["a"]}}}}}
        changed = {"paths": {"/a": {"get": {"operationId": "X.Op", "x-governance": {"provider": "p", "resource_patterns": ["b"]}}}}}
        assert OperationRegistry.from_openapi(doc).fingerprint() != OperationRegistry.from_openapi(changed).fingerprint()


class TestSchemaValidation:
    SCHEMA = {"type": "object", "additionalProperties": False, "required": ["incident_id", "count"],
              "properties": {"incident_id": {"type": "string", "pattern": "^INC[0-9]{7}$"},
                             "count": {"type": "integer", "minimum": 1, "maximum": 5}}}

    def test_valid(self):
        assert validate_against_schema(self.SCHEMA, {"incident_id": "INC0012345", "count": 2}) == []

    def test_trailing_newline_cannot_satisfy_anchor(self):
        assert validate_against_schema(self.SCHEMA, {"incident_id": "INC0012345\n", "count": 2})

    def test_boolean_is_not_an_integer(self):
        assert validate_against_schema(self.SCHEMA, {"incident_id": "INC0012345", "count": True})

    def test_unknown_parameter_rejected(self):
        assert validate_against_schema(self.SCHEMA, {"incident_id": "INC0012345", "count": 1, "x": 1})

    def test_range_and_required(self):
        assert validate_against_schema(self.SCHEMA, {"incident_id": "INC0012345", "count": 9})
        assert validate_against_schema(self.SCHEMA, {"count": 1})


class TestControlPlaneUsesOperationIds:
    def test_unregistered_operation_is_denied(self):
        with offline_demo() as demo:
            req = purchase(operation_id="Subscription.PurchaseAnything")
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert stage(resp, "operation_registered")["result"] == "fail"

    def test_free_text_cannot_change_the_evaluated_operation(self):
        with offline_demo() as demo:
            req = purchase(input_text="just read the catalog, nothing else", stated_intent="read only")
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert stage(resp, "operation_registered")["detail"].startswith("POST")
            assert resp["verdict"] == "allow"
            assert demo.control_plane.grants.get(resp["grant"]["grant_id"]).operation_id == "Subscription.Purchase"

    def test_operation_outside_agent_registry_is_denied(self):
        with offline_demo() as demo:
            req = {"agent_id": "procurement-agent", "session_id": "s", "provider": "servicenow",
                   "operation_id": "ServiceNow.UpdateIncident", "target_resource": "servicenow/incident/INC0012345",
                   "environment": "prod", "tool_parameters": {"incident_id": "INC0012345", "state": "resolved"}}
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert stage(resp, "operation_allowed")["result"] == "fail"

    def test_missing_structured_fields_fail_closed(self):
        with offline_demo() as demo:
            resp = demo.control_plane.request_authority(
                {"agent_id": "procurement-agent", "input_text": "buy four seats"}, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert stage(resp, "request_shape")["result"] == "fail"

    @pytest.mark.parametrize("field", ["new_scope", "approved", "human_authorized", "scope_level", "grant_id"])
    def test_authority_fields_in_an_agent_request_are_denied(self, field):
        with offline_demo() as demo:
            req = purchase(**{field: 4})
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert field in stage(resp, "request_shape")["detail"]

    def test_understated_data_class_uses_operation_class(self):
        with offline_demo() as demo:
            req = {"agent_id": "procurement-agent", "session_id": "s", "provider": "servicenow",
                   "operation_id": "ServiceNow.GetIncident", "target_resource": "servicenow/incident/INC0012345",
                   "environment": "prod", "data_class": "Public", "tool_parameters": {"incident_id": "INC0012345"}}
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert "Internal classification applies" in stage(resp, "data_classification")["detail"]

    def test_unapproved_data_class_is_denied(self):
        with offline_demo() as demo:
            req = {"agent_id": "procurement-agent", "session_id": "s", "provider": "servicenow",
                   "operation_id": "ServiceNow.GetIncident", "target_resource": "servicenow/incident/INC0012345",
                   "environment": "prod", "data_class": "Protected-B", "tool_parameters": {"incident_id": "INC0012345"}}
            resp = demo.control_plane.request_authority(req, demo.agent("procurement-agent"))
            assert resp["verdict"] == "deny"
            assert stage(resp, "data_classification")["result"] == "fail"
