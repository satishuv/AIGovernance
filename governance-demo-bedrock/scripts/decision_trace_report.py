"""Auditor Decision-Trace Report.

Renders a human-readable "why did the governance engine decide this?" report for
a decision, from its signed decision trace. Verifies the trace signature offline
with the KMS public key so the report states whether the rationale is
cryptographically intact.

Scope: this reports the GOVERNANCE reasoning (which checks ran, what each
concluded, which was decisive). It does NOT include or vouch for the AI agent's
own stated rationale, which is not verifiable.

Usage:
    python scripts/decision_trace_report.py <decision_id>
    python scripts/decision_trace_report.py --file trace.json      # offline, from a saved trace
    python scripts/decision_trace_report.py <decision_id> --out report.md

Requires (live mode): AWS credentials for the demo account, boto3, the
DECISION_TRACE_TABLE_NAME, and kms:GetPublicKey on the signing key.
"""

import argparse
import base64
import hashlib
import json
import sys
from typing import Any, Dict, Optional

REGION = "us-east-1"
_HASH_EXCLUDED = ("record_hash", "trace_hash", "signature", "signing_key_id", "signing_algorithm")


def verify_offline(trace: Dict[str, Any], public_key_pem: bytes) -> bool:
    """Verify the trace signature offline with the KMS public key (no AWS call)."""
    sig_b64 = trace.get("signature", "")
    if not sig_b64:
        return False
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
        from cryptography.hazmat.primitives.asymmetric import ec, utils as au
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        # Prefer the exact signed canonical string when present (DynamoDB
        # normalizes numbers, so recomputing from parsed fields can differ).
        canonical = trace.get("_canonical_body")
        if canonical is None:
            vd = {k: v for k, v in trace.items() if k not in _HASH_EXCLUDED}
            canonical = json.dumps(vd, sort_keys=True, default=str)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        try:
            pub = load_pem_public_key(public_key_pem)
        except Exception:
            pub = load_der_public_key(public_key_pem)
        try:
            pub.verify(base64.b64decode(sig_b64), bytes.fromhex(digest),
                       ec.ECDSA(au.Prehashed(hashes.SHA256())))
            return True
        except InvalidSignature:
            return False
    except ImportError:
        return False


def render_report(trace: Dict[str, Any], signature_status: str = "not checked") -> str:
    """Render a markdown auditor report from a decision trace. Pure, no AWS."""
    verdict = trace.get("verdict", "?")
    aarm = trace.get("aarm_decision", "?")
    decisive = trace.get("decisive_stage", "?")
    stages = trace.get("stages", [])

    # Plain-English "why".
    decisive_detail = ""
    for s in stages:
        if s.get("decisive"):
            decisive_detail = s.get("detail", "")
            break
    why = (f"The verdict was **{verdict.upper()}** (AARM: {aarm}). "
           f"The decisive check was **{decisive}**"
           + (f": {decisive_detail}" if decisive_detail else "") + ".")

    lines = []
    lines.append(f"# Decision Rationale: {trace.get('decision_id','')}")
    lines.append("")
    lines.append(f"- **Agent:** {trace.get('agent_id','')}")
    lines.append(f"- **Session:** {trace.get('session_id','') or '(none)'}")
    lines.append(f"- **Action:** {trace.get('action_requested','')}")
    lines.append(f"- **Verdict:** {verdict}  (AARM decision: {aarm})")
    lines.append(f"- **Timestamp:** {trace.get('timestamp','')}")
    lines.append(f"- **Policy:** {trace.get('policy_id','') or '(none matched)'}")
    lines.append(f"- **Signature:** {signature_status}")
    lines.append("")
    lines.append("## Why")
    lines.append("")
    lines.append(why)
    lines.append("")
    lines.append("## Stage-by-stage reasoning")
    lines.append("")
    lines.append("| # | Stage | Result | Decisive | Detail |")
    lines.append("|---|-------|--------|----------|--------|")
    for i, s in enumerate(stages, 1):
        detail = (s.get("detail", "") or "").replace("|", "\\|")[:120]
        mark = "YES" if s.get("decisive") else ""
        lines.append(f"| {i} | {s.get('stage','')} | {s.get('result','')} | {mark} | {detail} |")
    lines.append("")

    rf = trace.get("risk_factors", {})
    if rf:
        lines.append("## Risk factors applied")
        lines.append("")
        for k, v in rf.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    lines.append("---")
    lines.append("*Scope: governance reasoning only. The AI agent's own stated "
                 "rationale is NOT included and is not verified.*")
    return "\n".join(lines)


def _fetch_live(decision_id: str) -> (Optional[Dict[str, Any]], str):
    import os
    import boto3
    table_name = os.environ.get("DECISION_TRACE_TABLE_NAME", "")
    if not table_name:
        # Best-effort discovery from the governance engine lambda env.
        lam = boto3.client("lambda", region_name=REGION)
        cfg = lam.get_function_configuration(
            FunctionName="GovernanceBedrockStack-GovernanceEngineLambda76BBC-BJrhSwyaE07y")
        env = cfg.get("Environment", {}).get("Variables", {})
        table_name = env.get("DECISION_TRACE_TABLE_NAME", "")
    ddb = boto3.resource("dynamodb", region_name=REGION)
    item = ddb.Table(table_name).get_item(Key={"decision_id": decision_id}).get("Item")
    if not item:
        return None, "not found"
    status = "unsigned"
    if item.get("signature"):
        try:
            kms = boto3.client("kms", region_name=REGION)
            pub = kms.get_public_key(KeyId=item["signing_key_id"])["PublicKey"]
            status = "VERIFIED (offline)" if verify_offline(item, pub) else "INVALID (tamper detected)"
        except Exception as exc:
            status = f"verify error: {exc}"
    return item, status


def main() -> int:
    ap = argparse.ArgumentParser(description="Auditor decision-trace report")
    ap.add_argument("decision_id", nargs="?", help="decision_id to report on")
    ap.add_argument("--file", help="render from a saved trace JSON file (offline)")
    ap.add_argument("--out", help="write markdown to this path instead of stdout")
    args = ap.parse_args()

    if args.file:
        with open(args.file) as f:
            trace = json.load(f)
        status = "not checked (offline file; no public key)"
    elif args.decision_id:
        trace, status = _fetch_live(args.decision_id)
        if trace is None:
            print(f"No decision trace found for {args.decision_id}", file=sys.stderr)
            return 1
    else:
        ap.error("provide a decision_id or --file")

    report = render_report(trace, signature_status=status)
    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"wrote {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
