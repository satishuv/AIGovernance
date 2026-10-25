"""Deterministic scenarios for the Public Sector Agent Delegated Authority Demo.

Every scenario is self-contained (it performs its own prerequisite steps), so
any one can be run on its own, in any order, against the same demo state. Each
returns the four UI panels (agent, requested action, governance decision,
delegated authority + execution) plus an ordered step list and a PASS/FAIL
against its expected outcome.

All names are generic. No customer information belongs in this file.
"""

import copy
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
GE = os.path.normpath(os.path.join(HERE, "..", "..", "lambdas", "governance_engine"))
if GE not in sys.path:
    sys.path.insert(0, GE)

from authority_control_plane import chain_summary  # noqa: E402


@dataclass
class ScenarioResult:
    number: int
    key: str
    title: str
    story: str
    expected: str
    outcome: str = ""
    passed: bool = False
    agent: Dict[str, Any] = field(default_factory=dict)
    request: Dict[str, Any] = field(default_factory=dict)
    decision: Dict[str, Any] = field(default_factory=dict)
    grant: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
    steps: List[Dict[str, str]] = field(default_factory=list)

    def step(self, label: str, status: str, detail: str = "") -> None:
        self.steps.append({"label": label, "status": status, "detail": detail})

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def purchase_request(item: str, quantity: int, amount, session: str) -> Dict[str, Any]:
    return {
        "agent_id": "procurement-agent", "session_id": session, "provider": "servicenow",
        "operation_id": "Subscription.Purchase", "target_resource": f"catalog/software/approved/{item}",
        "environment": "prod",
        "tool_parameters": {"catalog_item_id": item, "quantity": quantity, "cost_centre": "CC-1234"},
        "financial_context": {"currency": "CAD", "transaction_amount": amount},
        "business_reason": "seats for a new intake team",
    }


def governance_request(agent_id: str, operation_id: str, target: str, params: Dict[str, Any],
                       session: str) -> Dict[str, Any]:
    return {"agent_id": agent_id, "session_id": session, "provider": "governance",
            "operation_id": operation_id, "target_resource": target, "environment": "prod",
            "tool_parameters": params}


class ScenarioRunner:
    """Runs scenarios against one OfflineDemo (moto-backed) instance."""

    def __init__(self, demo):
        self.demo = demo
        self.cp = demo.control_plane
        self._counter = 0

    def _session(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:03d}"

    def _decision_panel(self, resp: Dict[str, Any]) -> Dict[str, Any]:
        return {"verdict": resp.get("verdict"), "aarm_decision": resp.get("aarm_decision"),
                "risk_score": resp.get("risk_score"), "risk_factors": resp.get("risk_factors", {}),
                "stages": resp.get("stages", []), "decision_id": resp.get("decision_id"),
                "explanation": resp.get("explanation", ""), "approval_id": resp.get("approval_id"),
                "request_digest": resp.get("request_digest", "")}

    def _execution_panel(self, out: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        panel = copy.deepcopy(out)
        decision_id = out.get("decision_id")
        if decision_id:
            panel["evidence_chain"] = chain_summary(self.cp.evidence.chain(agent_id, decision_id))
        return panel

    def _start(self, number, key, title, story, expected, agent_id, request):
        r = ScenarioResult(number, key, title, story, expected)
        r.agent = self.cp.describe_agent(agent_id)
        r.request = copy.deepcopy(request)
        return r

    # ------------------------------------------------------------------ 1
    def s01_autonomous_purchase(self) -> ScenarioResult:
        req = purchase_request("productivity-suite", 4, 168, self._session("proc"))
        r = self._start(1, "autonomous_purchase", "Normal autonomous transaction",
                        "A scope-3 procurement agent buys 4 seats of an approved CAD 42 subscription.",
                        "ALLOW -> grant -> credential -> execute -> CONSUMED -> evidence", "procurement-agent", req)
        resp = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        r.decision = self._decision_panel(resp)
        r.step("Governance decision", resp["verdict"].upper(), resp["explanation"][:180])
        if resp["verdict"] != "allow":
            r.outcome = "unexpected verdict"
            return r
        r.grant = resp["grant"]
        r.step("Hall pass issued", "PASS", f"{r.grant['grant_id']} expires {r.grant['expires_at']}")
        out = self.cp.execute(r.grant["grant_id"], req, self.demo.agent("procurement-agent"))
        r.execution = self._execution_panel(out, "procurement-agent")
        r.step("Credential exchange", "PASS" if out.get("credential") else "FAIL",
               (out.get("credential") or {}).get("credential_reference", out.get("reason", "")))
        r.step("Execution", out["status"].upper(), str((out.get("execution") or {}).get("summary", {}).get("order_id", "")))
        r.step("Grant after execution", out.get("grant_status_after", ""), "single use")
        r.step("Evidence", "VERIFIED" if out.get("evidence_chain_verified") else "FAIL",
               out.get("evidence_chain_detail", ""))
        r.passed = (out["status"] == "executed" and out["grant_status_after"] == "CONSUMED"
                    and out["evidence_chain_verified"] and r.grant["signature_verified"])
        r.outcome = "executed under a one-use, 5-minute hall pass" if r.passed else out.get("reason", "")
        return r

    # ------------------------------------------------------------------ 2
    def _escalated(self, session: str):
        req = purchase_request("analytics-suite", 4, 1800, session)
        resp = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        return req, resp

    def s02_budget_escalation(self) -> ScenarioResult:
        req, resp = self._escalated(self._session("proc"))
        r = self._start(2, "budget_escalation", "Budget escalation",
                        "Same agent requests CAD 1,800 while its autonomous per-transaction limit is CAD 500.",
                        "STEP_UP, approval created, no grant and no credential", "procurement-agent", req)
        r.decision = self._decision_panel(resp)
        r.step("Governance decision", resp["aarm_decision"], resp["explanation"][:200])
        r.step("Approval record", "CREATED" if resp.get("approval_id") else "MISSING", resp.get("approval_id") or "")
        r.step("Credential", "NONE ISSUED" if "grant" not in resp else "UNEXPECTED", "nothing to exchange yet")
        r.passed = resp["verdict"] == "escalate" and bool(resp.get("approval_id")) and "grant" not in resp
        r.outcome = "held for a human; no authority exists yet" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 3
    def s03_human_approves_exact_transaction(self) -> ScenarioResult:
        req, resp = self._escalated(self._session("proc"))
        r = self._start(3, "human_approval", "Human approves the exact transaction",
                        "The agent's own business owner cannot approve. A finance approver approves the "
                        "exact CAD 1,800 request; the agent then exchanges that approval for a hall pass.",
                        "owner approval DENIED; approver approval -> one-use grant -> executed",
                        "procurement-agent", req)
        r.decision = self._decision_panel(resp)
        owner = self.cp.approve_request(resp["approval_id"], self.demo.human("service_owner"))
        r.step("Agent owner tries to approve", owner["status"].upper(), owner.get("reason", ""))
        # The approver reviews the bound request, then approves by naming the digest they reviewed.
        reviewed = self.cp.describe_approval(resp["approval_id"], self.demo.human("finance_approver"))
        r.step("Finance approver reviews the exact request", reviewed.get("status", "").upper(),
               f"{reviewed.get('operation_id', '')} digest {str(reviewed.get('request_digest', ''))[:12]}")
        approver = self.cp.approve_request(resp["approval_id"], self.demo.human("finance_approver"),
                                           reviewed_digest=reviewed.get("request_digest", ""))
        r.step("Finance approver approves", approver["status"].upper(), approver.get("approver_id", ""))
        mint = self.cp.mint_after_approval(resp["approval_id"], req, self.demo.agent("procurement-agent"))
        r.step("Exact request verified against approval digest", mint["verdict"].upper(),
               mint.get("reason", "digest matched; approval consumed"))
        if mint["verdict"] != "allow":
            return r
        r.grant = mint["grant"]
        out = self.cp.execute(r.grant["grant_id"], req, self.demo.agent("procurement-agent"))
        r.execution = self._execution_panel(out, "procurement-agent")
        r.step("Execution", out["status"].upper(), str((out.get("execution") or {}).get("summary", {}).get("total", "")))
        again = self.cp.mint_after_approval(resp["approval_id"], req, self.demo.agent("procurement-agent"))
        r.step("Approval reused", again["verdict"].upper(), again.get("reason", ""))
        r.passed = (owner["status"] == "denied" and approver["status"] == "approved"
                    and out["status"] == "executed" and again["verdict"] == "deny"
                    and r.grant["approval_id"] == resp["approval_id"])
        r.outcome = "approved once, executed once" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 4
    def s04_tamper_after_approval(self) -> ScenarioResult:
        req, resp = self._escalated(self._session("proc"))
        tampered = copy.deepcopy(req)
        tampered["tool_parameters"]["quantity"] = 40
        tampered["financial_context"]["transaction_amount"] = 18000
        r = self._start(4, "tamper_after_approval", "Post-approval tampering",
                        "After the CAD 1,800 approval, the request is changed to CAD 18,000 (40 seats).",
                        "DENY: approved request digest does not match", "procurement-agent", tampered)
        r.decision = self._decision_panel(resp)
        reviewed = self.cp.describe_approval(resp["approval_id"], self.demo.human("finance_approver"))
        self.cp.approve_request(resp["approval_id"], self.demo.human("finance_approver"),
                                reviewed_digest=reviewed.get("request_digest", ""))
        r.step("Finance approver approves CAD 1,800", "APPROVED", resp["approval_id"])
        mint = self.cp.mint_after_approval(resp["approval_id"], tampered, self.demo.agent("procurement-agent"))
        r.step("Agent presents CAD 18,000 against the approval", mint["verdict"].upper(), mint.get("reason", ""))
        record = self.cp.approvals.get_record(resp["approval_id"])
        r.step("Approval still unused", "UNCONSUMED" if not record.get("consumed") else "CONSUMED",
               "the tampered attempt did not burn the approval")
        r.passed = mint["verdict"] == "deny" and "digest does not match" in mint.get("reason", "") \
            and not record.get("consumed")
        r.outcome = "tampering detected; nothing executed" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 5
    def s05_replay(self) -> ScenarioResult:
        req = purchase_request("productivity-suite", 2, 84, self._session("proc"))
        r = self._start(5, "replay", "Replay attack",
                        "A hall pass that was already used is presented again.",
                        "DENY: grant CONSUMED", "procurement-agent", req)
        resp = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        r.decision = self._decision_panel(resp)
        r.grant = resp.get("grant")
        first = self.cp.execute(r.grant["grant_id"], req, self.demo.agent("procurement-agent"))
        r.step("First use", first["status"].upper(), first.get("grant_status_after", ""))
        replay = self.cp.execute(r.grant["grant_id"], req, self.demo.agent("procurement-agent"))
        r.execution = replay
        r.step("Replay", replay["status"].upper(), replay.get("reason", ""))
        r.passed = first["status"] == "executed" and replay["status"] == "denied" and "CONSUMED" in replay["reason"]
        r.outcome = "replay rejected" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 6
    def s06_worker_privilege_escalation(self) -> ScenarioResult:
        session = self._session("proc")
        req = governance_request("procurement-agent", "Governance.GrantScope", "agent/procurement-agent",
                                 {"new_scope_level": 4}, session)
        r = self._start(6, "worker_escalation", "Agent privilege escalation",
                        "The worker asks to raise itself from scope 3 to scope 4, then tries to smuggle "
                        "new_scope into an ordinary purchase.",
                        "DENY both: authority changes are human-only", "procurement-agent", req)
        resp = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        r.decision = self._decision_panel(resp)
        r.step("GrantScope request", resp["aarm_decision"], next(
            (s["detail"] for s in resp["stages"] if s["stage"] == "role_boundary"), ""))
        smuggled = dict(purchase_request("productivity-suite", 1, 42, session), new_scope=4)
        resp2 = self.cp.request_authority(smuggled, self.demo.agent("procurement-agent"))
        r.step("Purchase carrying new_scope", resp2["aarm_decision"], resp2["stages"][0]["detail"])
        scope = self.cp.describe_agent("procurement-agent")["current_scope"]
        r.step("Scope after attempts", str(scope), "unchanged")
        r.passed = resp["verdict"] == "deny" and resp2["verdict"] == "deny" and scope == 3
        r.outcome = "no self-escalation path exists" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 7
    def s07_guardian_cannot_grant_authority(self) -> ScenarioResult:
        req = governance_request("guardian-agent", "Governance.UpdateAgentScope", "agent/procurement-agent",
                                 {"new_scope_level": 4}, self._session("guard"))
        r = self._start(7, "guardian_boundary", "Guardian-agent boundary",
                        "The guardian tries to raise the worker's scope, then tries the admin plane directly.",
                        "DENY: guardians observe and recommend; they never grant authority", "guardian-agent", req)
        resp = self.cp.request_authority(req, self.demo.agent("guardian-agent"))
        r.decision = self._decision_panel(resp)
        r.step("UpdateAgentScope via agent plane", resp["aarm_decision"], next(
            (s["detail"] for s in resp["stages"] if s["stage"] == "role_boundary"), ""))
        admin = self.cp.admin_set_scope("procurement-agent", 4, self.demo.agent("guardian-agent"))
        r.step("Scope change via admin plane", admin["status"].upper(), admin.get("reason", ""))
        r.passed = resp["verdict"] == "deny" and admin["status"] == "denied"
        r.outcome = "guardian holds no authority-changing power" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 8
    def s08_guardian_oversight(self) -> ScenarioResult:
        session = self._session("guard")
        inspect = governance_request("guardian-agent", "Governance.InspectDecisionHistory",
                                     "agent/procurement-agent", {"limit": 5}, session)
        r = self._start(8, "guardian_oversight", "Guardian oversight",
                        "The guardian inspects the worker's signed decision history and recommends suspension.",
                        "ALLOW: read-only inspection and a recommendation that changes no authority",
                        "guardian-agent", inspect)
        resp = self.cp.request_authority(inspect, self.demo.agent("guardian-agent"))
        r.decision = self._decision_panel(resp)
        out = self.cp.execute(resp["grant"]["grant_id"], inspect, self.demo.agent("guardian-agent"))
        rows = (out.get("execution") or {}).get("summary", {}).get("decisions", [])
        r.step("Inspect decision history", out["status"].upper(),
               f"{len(rows)} decisions, all signatures verified: {all(x['signature_verified'] for x in rows)}")
        rec = governance_request("guardian-agent", "Governance.RecommendSuspension", "agent/procurement-agent",
                                 {"reason": "purchase velocity is unusual for this session"}, session)
        resp2 = self.cp.request_authority(rec, self.demo.agent("guardian-agent"))
        out2 = self.cp.execute(resp2["grant"]["grant_id"], rec, self.demo.agent("guardian-agent"))
        summary = (out2.get("execution") or {}).get("summary", {})
        r.grant, r.execution = resp2.get("grant"), self._execution_panel(out2, "guardian-agent")
        r.step("Recommend suspension", out2["status"].upper(),
               f"{summary.get('status')}; effect on authority: {summary.get('effect_on_authority')}")
        scope = self.cp.describe_agent("procurement-agent")["current_scope"]
        r.step("Worker scope", str(scope), "unchanged until a human acts")
        r.passed = (out["status"] == "executed" and out2["status"] == "executed"
                    and summary.get("effect_on_authority") == "none" and scope == 3)
        r.outcome = "agents watch agents; humans decide" if r.passed else "unexpected"
        return r

    # ------------------------------------------------------------------ 9
    def s09_revoke_before_execution(self) -> ScenarioResult:
        req = purchase_request("productivity-suite", 3, 126, self._session("proc"))
        r = self._start(9, "revocation", "Revoke an active grant",
                        "A security operator revokes a freshly issued hall pass before the agent uses it.",
                        "DENY: grant REVOKED", "procurement-agent", req)
        resp = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        r.decision = self._decision_panel(resp)
        r.grant = resp["grant"]
        rev = self.cp.revoke_grant(r.grant["grant_id"], self.demo.human("security_operator"), "manual review")
        r.step("Operator revokes", rev["status"].upper(), rev.get("detail", ""))
        out = self.cp.execute(r.grant["grant_id"], req, self.demo.agent("procurement-agent"))
        r.execution = out
        r.step("Agent tries to use it", out["status"].upper(), out.get("reason", ""))
        r.passed = rev["status"] == "revoked" and out["status"] == "denied" and "REVOKED" in out["reason"]
        r.outcome = "revocation is immediate" if r.passed else "unexpected"
        return r

    # ----------------------------------------------------------------- 10
    def s10_kill_switch(self) -> ScenarioResult:
        session = self._session("proc")
        req = purchase_request("productivity-suite", 1, 42, session)
        r = self._start(10, "kill_switch", "Emergency kill switch",
                        "An operator activates the kill switch while the agent holds a live hall pass.",
                        "live grant revoked; every new request DENIED; scope restored only by a human admin",
                        "procurement-agent", req)
        live = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        ks = self.cp.activate_kill_switch("procurement-agent", self.demo.human("security_operator"), "drill")
        r.step("Kill switch", ks["status"].upper(), f"revoked grants: {ks.get('revoked_grants')}")
        after = self.cp.request_authority(purchase_request("productivity-suite", 1, 42, session),
                                          self.demo.agent("procurement-agent"))
        r.decision = self._decision_panel(after)
        r.step("New request", after["aarm_decision"], next(
            (s["detail"] for s in after["stages"] if s["stage"] == "kill_switch"), ""))
        used = self.cp.execute(live["grant"]["grant_id"], req, self.demo.agent("procurement-agent"))
        r.step("Previously issued hall pass", used["status"].upper(), used.get("reason", ""))
        restored = self.cp.admin_set_scope("procurement-agent", 3, self.demo.human("governance_admin"),
                                           "drill complete")
        r.step("Governance admin restores scope 3", restored["status"].upper(), "human-only admin plane")
        r.passed = (live["grant"]["grant_id"] in ks["revoked_grants"] and after["verdict"] == "deny"
                    and used["status"] == "denied" and restored["status"] == "updated")
        r.outcome = "one action stops the agent everywhere" if r.passed else "unexpected"
        return r

    # ----------------------------------------------------------------- 11
    def s11_aws_provider_native(self) -> ScenarioResult:
        bucket = self.demo.bucket
        req = {"agent_id": "procurement-agent", "session_id": self._session("aws"), "provider": "aws",
               "operation_id": "AWS.ReadObject",
               "target_resource": f"aws/s3/{bucket}/reports/approved/price-benchmark-2026.csv",
               "environment": "prod", "tool_parameters": {}}
        mode = self.demo.adapters["aws"].mode
        r = self._start(11, "aws_sts", "Provider-native enforcement on AWS",
                        f"The grant becomes an STS session whose inline policy allows one action on one object "
                        f"until the grant expires (AWS adapter mode: {mode}).",
                        "ALLOW approved object; DENY restricted object before any credential", "procurement-agent", req)
        resp = self.cp.request_authority(req, self.demo.agent("procurement-agent"))
        r.decision, r.grant = self._decision_panel(resp), resp.get("grant")
        out = self.cp.execute(r.grant["grant_id"], req, self.demo.agent("procurement-agent"))
        r.execution = self._execution_panel(out, "procurement-agent")
        details = (out.get("credential") or {}).get("details", {})
        r.step("Session policy", "SCOPED", f"{details.get('session_policy_actions')} on "
               f"{details.get('session_policy_resource')} until {details.get('session_policy_deadline')}")
        r.step("Read approved object", out["status"].upper(), str((out.get("execution") or {}).get("summary", {})))
        restricted = dict(req, target_resource=f"aws/s3/{bucket}/reports/restricted/salary-bands.csv")
        denied = self.cp.request_authority(restricted, self.demo.agent("procurement-agent"))
        r.step("Request restricted object", denied["aarm_decision"], next(
            (s["detail"] for s in denied["stages"] if s["stage"] == "resource"), ""))
        r.passed = out["status"] == "executed" and denied["verdict"] == "deny" and "grant" not in denied
        r.outcome = "AWS IAM enforces exactly what governance granted" if r.passed else "unexpected"
        return r

    # ----------------------------------------------------------------- 12
    def s12_same_contract_other_providers(self) -> ScenarioResult:
        session = self._session("rec")
        base = {"agent_id": "records-agent", "session_id": session, "environment": "prod"}
        entra = dict(base, provider="entra", operation_id="Entra.GetUser", target_resource="entra/user/j.doe",
                     tool_parameters={"user_id": "j.doe"})
        r = self._start(12, "vendor_neutral", "Same contract, different providers",
                        "A different agent uses Microsoft Entra and Google through the same request, grant "
                        "and evidence contract (mock adapters).",
                        "ALLOW and execute on Entra and Google; identical lifecycle", "records-agent", entra)
        ok = True
        for req in (entra, dict(base, provider="google", operation_id="Google.ReadDriveFile",
                                target_resource="google/drive/file/doc-000123",
                                tool_parameters={"file_id": "doc-000123"})):
            resp = self.cp.request_authority(req, self.demo.agent("records-agent"))
            out = self.cp.execute(resp["grant"]["grant_id"], req, self.demo.agent("records-agent")) \
                if resp["verdict"] == "allow" else {"status": "denied"}
            r.step(f"{req['provider']}: {req['operation_id']}", out["status"].upper(),
                   (out.get("credential") or {}).get("credential_type", ""))
            ok = ok and out["status"] == "executed"
            r.decision, r.grant, r.execution = self._decision_panel(resp), resp.get("grant"), out
        r.passed = ok
        r.outcome = "the governance model is vendor-neutral" if ok else "unexpected"
        return r


SCENARIOS: List[str] = [
    "s01_autonomous_purchase", "s02_budget_escalation", "s03_human_approves_exact_transaction",
    "s04_tamper_after_approval", "s05_replay", "s06_worker_privilege_escalation",
    "s07_guardian_cannot_grant_authority", "s08_guardian_oversight", "s09_revoke_before_execution",
    "s10_kill_switch", "s11_aws_provider_native", "s12_same_contract_other_providers",
]


def run_all(runner: ScenarioRunner, progress: Optional[Callable[[ScenarioResult], None]] = None) -> List[ScenarioResult]:
    results = []
    for name in SCENARIOS:
        result = getattr(runner, name)()
        results.append(result)
        if progress:
            progress(result)
    return results
