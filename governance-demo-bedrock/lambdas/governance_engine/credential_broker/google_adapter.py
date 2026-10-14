"""Google Workspace adapter (mock by default; live uses workload identity federation)."""

import hashlib

from .mock_adapter import OAuthStyleAdapter


class GoogleAdapter(OAuthStyleAdapter):
    name = "google"
    live_settings_env = ("GOOGLE_WORKLOAD_IDENTITY_PROVIDER", "GOOGLE_SERVICE_ACCOUNT_EMAIL")

    def __init__(self, mode: str = "mock"):
        super().__init__(mode)
        self.files = {"doc-000123": {"title": "Approved vendor list", "content": b"vendor-a,vendor-b"}}

    def _execute_mock(self, operation_id, params, target, verified):
        if operation_id == "Google.ReadDriveFile":
            doc = self.files.get(params["file_id"])
            if doc is None:
                return {"file_id": params["file_id"], "found": False}
            return {"file_id": params["file_id"], "found": True, "title": doc["title"],
                    "bytes": len(doc["content"]), "sha256": hashlib.sha256(doc["content"]).hexdigest()}
        raise ValueError(f"Google adapter does not implement {operation_id}")
