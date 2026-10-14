"""Clients for the delegated authority demo.

OfflineSession   starts an in-process AWS emulator (moto), builds the control
                 plane with generic demo data, and keeps both alive. No network,
                 no AWS account, no credentials. This is the default customer
                 demo mode.
LiveApiClient    calls the deployed, IAM-authorized API with SigV4 signatures
                 using the caller's own AWS credentials. Identity comes from the
                 signature, never from the request body.
"""

import json
import os
import sys
import urllib.request
from typing import Any, Dict, Optional
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
GE = os.path.normpath(os.path.join(HERE, "..", "..", "lambdas", "governance_engine"))
if GE not in sys.path:
    sys.path.insert(0, GE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

DEMO_REGION = "ca-central-1"


class OfflineSession:
    """moto-backed control plane with the demo registry, catalog and policies."""

    def __init__(self, aws_mode: str = "live"):
        # aws_mode="live" runs the real STS AssumeRole call path against the
        # emulator; the emulator does not enforce session policies, which is why
        # the UI labels it "STS (emulated)".
        self.aws_mode = aws_mode
        self._env = None
        self._mock = None
        self.demo = None
        self.runner = None
        self.start()

    def start(self) -> None:
        import boto3
        from moto import mock_aws

        from authority_factory import build_offline
        from scenarios import ScenarioRunner

        self._env = patch.dict(os.environ, {"AWS_DEFAULT_REGION": DEMO_REGION,
                                            "AWS_ACCESS_KEY_ID": "demo", "AWS_SECRET_ACCESS_KEY": "demo"})
        self._env.start()
        self._mock = mock_aws()
        self._mock.start()
        self.demo = build_offline(
            dynamodb=boto3.resource("dynamodb", region_name=DEMO_REGION),
            s3=boto3.client("s3", region_name=DEMO_REGION),
            kms=boto3.client("kms", region_name=DEMO_REGION),
            sts=boto3.client("sts", region_name=DEMO_REGION),
            region=DEMO_REGION, aws_mode=self.aws_mode)
        self.runner = ScenarioRunner(self.demo)

    def close(self) -> None:
        if self._mock is not None:
            self._mock.stop()
            self._mock = None
        if self._env is not None:
            self._env.stop()
            self._env = None

    def reset(self) -> None:
        self.close()
        self.start()

    def provider_modes(self) -> Dict[str, str]:
        modes = self.demo.control_plane.broker.adapter_modes()
        if modes.get("aws") == "live":
            modes["aws"] = "live STS call path (emulated)"
        return modes


class LiveApiClient:
    """SigV4 client for the deployed delegated-authority API (execute-api)."""

    def __init__(self, base_url: str, region: str, boto3_session=None):
        if not base_url.startswith("https://"):
            raise ValueError("the API base URL must use https")
        self._base = base_url.rstrip("/") + "/"
        self._region = region
        if boto3_session is None:
            import boto3
            boto3_session = boto3.Session(region_name=region)
        self._session = boto3_session

    def _signed_request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None):
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = AWSRequest(method=method, url=self._base + path.lstrip("/"), data=data,
                             headers={"Content-Type": "application/json"})
        credentials = self._session.get_credentials()
        if credentials is None:
            raise RuntimeError("no AWS credentials available; configure them in your terminal first")
        SigV4Auth(credentials.get_frozen_credentials(), "execute-api", self._region).add_auth(request)
        return request.prepare()

    def call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        prepared = self._signed_request(method, path, body)
        req = urllib.request.Request(prepared.url, data=prepared.body, method=method,
                                     headers=dict(prepared.headers))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - https enforced above
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {"http_status": exc.code, **json.loads(exc.read().decode("utf-8") or "{}")}

    def request_authority(self, request):
        return self.call("POST", "authority/requests", request)

    def mint_after_approval(self, approval_id, request):
        return self.call("POST", "authority-grants/mint", {"approval_id": approval_id, "request": request})

    def execute(self, grant_id, request):
        return self.call("POST", f"authority-grants/{grant_id}/execute", request)

    def get_grant(self, grant_id):
        return self.call("GET", f"authority-grants/{grant_id}")

    def revoke(self, grant_id, reason):
        return self.call("POST", f"authority-grants/{grant_id}/revoke", {"reason": reason})

    def set_scope(self, agent_id, scope_level, reason):
        return self.call("POST", f"admin/agents/{agent_id}/scope", {"scope_level": scope_level, "reason": reason})

    def kill_switch(self, agent_id, reason):
        return self.call("POST", f"admin/agents/{agent_id}/kill-switch", {"reason": reason})

    def approve(self, approval_id, conditions=""):
        return self.call("POST", f"approvals/{approval_id}/approve", {"conditions": conditions})
