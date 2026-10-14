"""ServiceNow adapter (mock by default; live is a federation integration point)."""

import secrets
from decimal import Decimal
from typing import Any, Dict

from .mock_adapter import OAuthStyleAdapter


class ServiceNowAdapter(OAuthStyleAdapter):
    name = "servicenow"
    live_settings_env = ("SERVICENOW_INSTANCE_URL", "SERVICENOW_OAUTH_CLIENT_ID", "SERVICENOW_TOKEN_SOURCE")

    def __init__(self, mode: str = "mock", catalog: Dict[str, Dict[str, Any]] = None):
        super().__init__(mode)
        self.catalog = {k: dict(v) for k, v in (catalog or {}).items()}
        self.incidents = {
            "INC0012345": {"short_description": "VPN outage at a regional office", "state": "new", "urgency": 2},
            "INC0012346": {"short_description": "Shared drive quota alert", "state": "in_progress", "urgency": 3},
        }
        self.orders = {}

    def _execute_mock(self, operation_id, params, target, verified):
        if operation_id == "ServiceNow.GetIncident":
            inc = self.incidents.get(params["incident_id"])
            if inc is None:
                return {"found": False, "incident_id": params["incident_id"]}
            return {"found": True, "incident_id": params["incident_id"], **inc}
        if operation_id == "ServiceNow.UpdateIncident":
            inc = self.incidents.setdefault(params["incident_id"], {"short_description": "", "urgency": 3})
            inc["state"] = params["state"]
            return {"incident_id": params["incident_id"], "state": inc["state"], "work_note_added": "work_note" in params}
        if operation_id == "ServiceNow.CreateIncident":
            incident_id = "INC" + str(secrets.randbelow(9_000_000) + 1_000_000)
            self.incidents[incident_id] = {"short_description": params["short_description"],
                                           "urgency": params["urgency"], "state": "new"}
            return {"incident_id": incident_id, "state": "new"}
        if operation_id == "Subscription.ListCatalog":
            return {"items": [{"catalog_item_id": k, "name": v["name"], "unit_price": str(v["unit_price"]),
                               "currency": v["currency"]} for k, v in sorted(self.catalog.items()) if v.get("approved")]}
        if operation_id == "Subscription.Purchase":
            item = self.catalog[params["catalog_item_id"]]
            total = (Decimal(str(item["unit_price"])) * Decimal(params["quantity"])).quantize(Decimal("0.01"))
            order_id = "REQ" + str(secrets.randbelow(9_000_000) + 1_000_000)
            self.orders[order_id] = {"catalog_item_id": params["catalog_item_id"], "quantity": params["quantity"],
                                     "total": total, "grant_id": verified.grant.grant_id}
            return {"order_id": order_id, "catalog_item_id": params["catalog_item_id"],
                    "item_name": item["name"], "quantity": params["quantity"],
                    "unit_price": str(item["unit_price"]), "total": str(total), "currency": item["currency"],
                    "cost_centre": params["cost_centre"]}
        raise ValueError(f"ServiceNow adapter does not implement {operation_id}")
