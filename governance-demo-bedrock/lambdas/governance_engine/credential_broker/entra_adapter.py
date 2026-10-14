"""Microsoft Entra adapter (mock by default).

Live mode is the integration point for workload identity federation (the
agent's AWS identity exchanged for an Entra token via a federated credential).
It refuses until a deployment supplies its own tenant and client settings.
"""

from .mock_adapter import OAuthStyleAdapter


class EntraAdapter(OAuthStyleAdapter):
    name = "entra"
    live_settings_env = ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_FEDERATED_TOKEN_FILE")

    def __init__(self, mode: str = "mock"):
        super().__init__(mode)
        self.users = {"j.doe": {"department": "Digital Services", "enabled": True},
                      "a.analyst": {"department": "Finance", "enabled": True}}
        self.groups = {"ProcurementReaders": {"a.analyst"}, "GlobalAdministrators": set()}

    def _execute_mock(self, operation_id, params, target, verified):
        if operation_id == "Entra.GetUser":
            user = self.users.get(params["user_id"])
            # Return only non-sensitive attributes; the demo never surfaces PII.
            return {"user_id": params["user_id"], "found": user is not None,
                    "department": (user or {}).get("department", "")}
        if operation_id == "Entra.AddGroupMember":
            members = self.groups.setdefault(params["group_id"], set())
            members.add(params["user_id"])
            return {"group_id": params["group_id"], "user_id": params["user_id"], "member_count": len(members)}
        raise ValueError(f"Entra adapter does not implement {operation_id}")
