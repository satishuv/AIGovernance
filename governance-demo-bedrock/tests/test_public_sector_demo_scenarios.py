"""The customer demo: every scenario passes, and the local UI is locked down."""

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo", "public_sector_hallpass")
if DEMO not in sys.path:
    sys.path.insert(0, DEMO)

from api_client import LiveApiClient, OfflineSession  # noqa: E402
from scenarios import SCENARIOS, run_all  # noqa: E402


@pytest.fixture(scope="module")
def session():
    s = OfflineSession()
    yield s
    s.close()


def test_every_scenario_matches_its_expected_outcome(session):
    results = run_all(session.runner)
    failures = [(r.number, r.title, r.outcome, r.steps) for r in results if not r.passed]
    assert not failures, failures
    assert len(results) == len(SCENARIOS) == 12


def test_scenarios_are_repeatable_in_any_order(session):
    for name in reversed(SCENARIOS):
        result = getattr(session.runner, name)()
        assert result.passed, (name, result.outcome, result.steps)


def test_scenario_payloads_never_contain_secrets(session):
    blob = json.dumps([getattr(session.runner, n)().to_dict() for n in SCENARIOS], default=str)
    for marker in ("_secret", "SecretAccessKey", "SessionToken", "aws_session_token"):
        assert marker not in blob


@pytest.fixture
def ui(session):
    import hallpass_ui as app
    app.SESSION = session
    server = HTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield app, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def _post(url, token=None, host=None):
    req = urllib.request.Request(url, data=b"", method="POST")
    if token:
        req.add_header("X-Demo-Token", token)
    if host:
        req.add_header("Host", host)
    try:
        # nosec B310: the URL is the loopback demo server this fixture started (http://127.0.0.1)
        with urllib.request.urlopen(req, timeout=60) as resp:  # nosec B310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, None


class TestLocalUi:
    def test_page_embeds_token_and_security_headers(self, ui):
        app, base = ui
        with urllib.request.urlopen(base + "/") as resp:  # nosec B310 (loopback demo server)
            page = resp.read().decode()
            assert app.TOKEN in page
            assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]

    def test_post_without_token_is_rejected(self, ui):
        _, base = ui
        assert _post(base + "/api/run/1")[0] == 403

    def test_foreign_host_header_is_rejected(self, ui):
        app, base = ui
        assert _post(base + "/api/run/1", app.TOKEN, "attacker.example")[0] == 403

    def test_scenario_runs_through_the_ui(self, ui):
        app, base = ui
        status, body = _post(base + "/api/run/1", app.TOKEN)
        assert status == 200 and body["passed"] and body["decision"]["aarm_decision"] == "ALLOW"


class TestSigV4ApiClient:
    def test_requests_are_sigv4_signed_for_execute_api(self):
        import boto3
        session = boto3.Session(aws_access_key_id="AKIDEXAMPLE", aws_secret_access_key="secret",
                                region_name="ca-central-1")
        client = LiveApiClient("https://abc123.execute-api.ca-central-1.amazonaws.com/prod/", "ca-central-1", session)
        prepared = client._signed_request("POST", "authority/requests", {"agent_id": "x"})
        auth = prepared.headers["Authorization"]
        assert auth.startswith("AWS4-HMAC-SHA256") and "/ca-central-1/execute-api/aws4_request" in auth
        assert prepared.url.endswith("/prod/authority/requests")

    def test_plain_http_is_refused(self):
        with pytest.raises(ValueError):
            LiveApiClient("http://example.com/prod", "ca-central-1")
