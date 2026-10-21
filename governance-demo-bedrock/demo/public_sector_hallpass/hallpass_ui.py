"""Public Sector Agent Delegated Authority Demo (local UI server).

    python demo/public_sector_hallpass/app.py            # http://127.0.0.1:8765
    python demo/public_sector_hallpass/app.py --port 9000

A presentation aid, not a production UI. It runs the real control-plane code
in-process against an AWS emulator (no account, no network, no credentials)
and shows each scenario as four panels: agent, requested action, governance
decision, and delegated authority with execution and evidence.

Security posture for a local tool:
  * binds to 127.0.0.1 only;
  * every POST needs the per-process token embedded in the page, and the Host
    header must be the loopback address, which blocks cross-site requests and
    DNS-rebinding from other browser tabs;
  * no credential is ever displayed; secrets never leave the credential handle.
"""

import argparse
import html
import json
import logging
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from api_client import OfflineSession  # noqa: E402
from scenarios import SCENARIOS  # noqa: E402

logging.disable(logging.WARNING)

TOKEN = secrets.token_urlsafe(24)
LOCK = threading.Lock()
SESSION = None

TITLES = [
    "Normal autonomous transaction", "Budget escalation", "Human approves the exact transaction",
    "Post-approval tampering", "Replay attack", "Agent privilege escalation", "Guardian-agent boundary",
    "Guardian oversight", "Revoke an active grant", "Emergency kill switch",
    "Provider-native enforcement on AWS", "Same contract, different providers",
]

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Public Sector Agent Delegated Authority Demo</title>
<style>
:root{--bg:#f6f7f9;--fg:#14171a;--card:#ffffff;--muted:#4a5560;--line:#d5dbe1;--pass:#0b6b2f;
--fail:#a3121b;--step:#8a4b00;--na:#5c6670;--accent:#1d4f91}
@media (prefers-color-scheme: dark){:root{--bg:#121417;--fg:#eef1f4;--card:#1c2026;--muted:#aab4be;
--line:#323a44;--pass:#5fd68a;--fail:#ff7b84;--step:#ffc46b;--na:#98a2ad;--accent:#8ab4ff}}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:14px 20px;border-bottom:1px solid var(--line);background:var(--card)}
h1{font-size:20px;margin:0 0 4px}header p{margin:0;color:var(--muted)}
nav{display:flex;flex-wrap:wrap;gap:6px;padding:12px 20px}
button{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);cursor:pointer}
button:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
button.primary{border-color:var(--accent);color:var(--accent);font-weight:600}
main{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;padding:0 20px 20px}
@media (max-width:1100px){main{grid-template-columns:repeat(2,minmax(0,1fr))}}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;min-height:200px}
section h2{font-size:15px;margin:0 0 8px;color:var(--accent)}
dl{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-word}
ol{margin:0;padding-left:18px}li{margin:2px 0}
.pass{color:var(--pass)}.fail{color:var(--fail)}.step_up,.flag{color:var(--step)}.na{color:var(--na)}
.verdict{font-size:22px;font-weight:700;margin:8px 0}
.story{margin:0 20px 12px;padding:10px 12px;border-left:4px solid var(--accent);background:var(--card)}
code,pre{font:12px/1.4 Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.badge{display:inline-block;padding:1px 6px;border-radius:4px;border:1px solid currentColor;font-size:12px}
footer{padding:0 20px 20px;color:var(--muted);font-size:13px}
</style></head><body>
<header><h1>Public Sector Agent Delegated Authority Demo</h1>
<p>Humans approve the boundaries. Governance evaluates every action. Authority is short-lived, exact and revocable.</p>
<p id="modes"></p></header>
<nav aria-label="Scenarios" id="nav"></nav>
<div class="story" id="story" aria-live="polite">Choose a scenario.</div>
<main>
<section aria-labelledby="h-agent"><h2 id="h-agent">Agent</h2><div id="agent"></div></section>
<section aria-labelledby="h-req"><h2 id="h-req">Requested action</h2><div id="request"></div></section>
<section aria-labelledby="h-gov"><h2 id="h-gov">Governance decision</h2><div id="decision"></div></section>
<section aria-labelledby="h-auth"><h2 id="h-auth">Delegated authority and execution</h2><div id="authority"></div></section>
</main>
<footer>Demo data is generic. Adapters: ServiceNow, Entra and Google run in mock mode; AWS runs the real STS
call path against an emulator unless deployed live. This page shows no credentials.</footer>
<script>
const TOKEN = "__TOKEN__"; const TITLES = __TITLES__;
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ICON = {pass:"\u2714 PASS", fail:"\u2716 FAIL", step_up:"\u26A0 STEP-UP", flag:"\u26A0 FLAG", na:"\u2013 N/A"};
function dl(obj){return "<dl>"+Object.entries(obj).map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(typeof v==="object"?JSON.stringify(v):v)}</dd>`).join("")+"</dl>";}
async function post(path){const r=await fetch(path,{method:"POST",headers:{"X-Demo-Token":TOKEN}});return r.json();}
function renderAgent(a){if(!a||!a.agent_id){return "";}
 const sp=a.spend_policy||{};return dl({"Agent":a.agent_id,"Type":a.agent_type,"Purpose":a.purpose,"Business owner":a.business_owner,
 "Current scope":a.current_scope,"Approved scope":a.approved_scope,"Status":a.status,"Risk tier":a.risk_tier,
 "Approved providers":(a.allowed_providers||[]).join(", "),"Approved operations":(a.allowed_operations||[]).join(", "),
 "Per-transaction limit":sp.per_transaction_max?`${sp.currency} ${sp.per_transaction_max}`:"none",
 "Daily autonomous limit":sp.daily_max?`${sp.currency} ${sp.daily_max}`:"none","Guardians":(a.guardian_agent_ids||[]).join(", ")||"none"});}
function renderRequest(q){if(!q){return "";}const f=q.financial_context||{};
 return dl({"Provider":q.provider,"Operation":q.operation_id,"Target":q.target_resource,"Environment":q.environment,
 "Parameters":q.tool_parameters,"Amount":f.transaction_amount!==undefined?`${f.currency} ${f.transaction_amount}`:"n/a",
 "Free-text reason (context only)":q.business_reason||""});}
function renderDecision(d){if(!d||!d.stages){return "";}
 const rows=d.stages.map(s=>`<li><span class="${esc(s.result)}">${ICON[s.result]||esc(s.result)}</span> <b>${esc(s.stage)}</b>: ${esc(s.detail)}</li>`).join("");
 const cls={ALLOW:"pass",STEP_UP:"step_up",DENY:"fail"}[d.aarm_decision]||"na";
 return `<ol>${rows}</ol><p>Risk: <b>${esc(Math.round(d.risk_score||0))}/100</b></p><div class="verdict ${cls}">VERDICT: ${esc(d.aarm_decision)}</div>`+
 (d.approval_id?`<p>Approval: <code>${esc(d.approval_id)}</code></p>`:"");}
function renderAuthority(r){let out="";const g=r.grant;
 if(g){out+=`<h3>Hall pass</h3>`+dl({"Grant":g.grant_id,"Agent":g.agent_id,"Operation":g.operation_id,"Target":g.target_resource,
 "Maximum":g.spend_limit&&g.spend_limit.amount!==undefined?`${g.spend_limit.currency} ${g.spend_limit.amount}`:"n/a",
 "Delegated by":g.delegated_by,"Issued":g.issued_at,"Expires":g.expires_at,"Uses":`${g.uses_remaining}/${g.max_uses}`,
 "Signature":g.signature_verified?"VERIFIED (ECDSA P-256)":"NOT VERIFIED","Status at issue":g.status});}
 const e=r.execution;if(e){const c=e.credential;
  if(c){out+=`<h3>Credential exchange</h3>`+dl({"Provider":c.provider,"Type":c.credential_type,"Reference":c.credential_reference,
   "Secret":c.secret_preview,"Usable until":c.effective_until,"Scopes":(c.scopes||[]).join(", "),"Mode":c.mode});
   if(c.details&&c.details.session_policy_resource){out+=dl({"Session policy":`${(c.details.session_policy_actions||[]).join(",")} on ${c.details.session_policy_resource}`,"Deadline":c.details.session_policy_deadline});}}
  out+=`<h3>Execution</h3>`+dl({"Status":e.status,"Reason":e.reason||"","Result":e.execution?e.execution.summary:"",
   "Grant after":e.grant_status_after||e.grant_status||"","Evidence":e.evidence_chain_detail||""});}
 out+=`<h3>Steps</h3><ol>`+r.steps.map(s=>`<li><b>${esc(s.label)}</b>: <span class="badge">${esc(s.status)}</span> ${esc(s.detail)}</li>`).join("")+"</ol>";
 out+=`<p class="${r.passed?"pass":"fail"}"><b>${r.passed?"\u2714 Expected outcome":"\u2716 Unexpected outcome"}</b>: ${esc(r.expected)}</p>`;return out;}
async function run(n){document.getElementById("story").textContent="Running scenario "+n+"...";
 const r=await post("/api/run/"+n);if(r.error){document.getElementById("story").textContent=r.error;return;}
 document.getElementById("story").innerHTML=`<b>${r.number}. ${esc(r.title)}</b>: ${esc(r.story)}`;
 document.getElementById("agent").innerHTML=renderAgent(r.agent);document.getElementById("request").innerHTML=renderRequest(r.request);
 document.getElementById("decision").innerHTML=renderDecision(r.decision);document.getElementById("authority").innerHTML=renderAuthority(r);}
async function reset(){await post("/api/reset");document.getElementById("story").textContent="Demo state reset.";
 ["agent","request","decision","authority"].forEach(id=>document.getElementById(id).innerHTML="");}
const nav=document.getElementById("nav");
TITLES.forEach((t,i)=>{const b=document.createElement("button");b.textContent=`${i+1}. ${t}`;b.onclick=()=>run(i+1);nav.appendChild(b);});
const rb=document.createElement("button");rb.textContent="Reset demo state";rb.className="primary";rb.onclick=reset;nav.appendChild(rb);
fetch("/api/meta").then(r=>r.json()).then(m=>{document.getElementById("modes").textContent="Adapters: "+Object.entries(m.provider_modes).map(([k,v])=>k+"="+v).join(", ");});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HallPassDemo/1.0"

    def log_message(self, fmt, *args):  # quiet console
        return

    def _send(self, status, body, content_type="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, json.dumps({"error": "forbidden host"}))
        if self.path in ("/", "/index.html"):
            page = PAGE.replace("__TOKEN__", html.escape(TOKEN)).replace("__TITLES__", json.dumps(TITLES))
            return self._send(200, page, "text/html; charset=utf-8")
        if self.path == "/api/meta":
            with LOCK:
                modes = SESSION.provider_modes()
            return self._send(200, json.dumps({"provider_modes": modes, "scenarios": TITLES}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-Demo-Token") != TOKEN:
            return self._send(403, json.dumps({"error": "forbidden"}))
        if self.path == "/api/reset":
            with LOCK:
                SESSION.reset()
            return self._send(200, json.dumps({"status": "reset"}))
        if self.path.startswith("/api/run/"):
            try:
                number = int(self.path.rsplit("/", 1)[1])
                if number < 1:
                    raise IndexError
                name = SCENARIOS[number - 1]
            except (ValueError, IndexError):
                return self._send(404, json.dumps({"error": "unknown scenario"}))
            with LOCK:
                try:
                    result = getattr(SESSION.runner, name)().to_dict()
                except Exception as exc:  # show the failure rather than a blank page
                    result = {"error": f"scenario failed: {type(exc).__name__}: {exc}"}
            return self._send(200, json.dumps(result, default=str))
        return self._send(404, json.dumps({"error": "not found"}))


def main(argv=None) -> int:
    global SESSION
    parser = argparse.ArgumentParser(description="Public Sector Agent Delegated Authority Demo UI")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    SESSION = OfflineSession()
    server = HTTPServer(("127.0.0.1", args.port), Handler)  # loopback only, never 0.0.0.0
    print(f"Delegated authority demo running at http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        SESSION.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
