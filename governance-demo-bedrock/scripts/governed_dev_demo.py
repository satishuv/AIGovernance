"""Governed Development Demo - Arasaka-876 User Story

Demonstrates the AI Governance Framework wrapping each step of a real
development workflow. Each action the AI developer takes is governed by
the 93-control security pipeline before execution.

Steps governed:
1. READ codebase (Scope 1) - ReadPipelineStatus equivalent
2. PROPOSE changes (Scope 2) - ProposeChanges equivalent
3. WRITE code (Scope 3) - StagingDeployment equivalent
4. REQUEST review (Scope 4) - ProductionDeployment equivalent (escalates)

Each step invokes the LIVE governance engine Lambda and generates
real evidence records in S3/DynamoDB.
"""

import json
import sys
import time
from datetime import datetime, timezone

import boto3

REGION = "us-east-1"
GOV_ENGINE = "GovernanceBedrockStack-GovernanceEngineLambda76BBC-BJrhSwyaE07y"

lambda_client = boto3.client("lambda", region_name=REGION)


def invoke_governance(action_group, target_resource, input_text, scope_level, agent_id="demo-agent"):
    """Invoke the live governance engine and return the decision."""
    payload = {
        "agent_id": agent_id,
        "action_group": action_group,
        "target_resource": target_resource,
        "input_text": input_text,
        "scope_level": scope_level,
    }

    response = lambda_client.invoke(
        FunctionName=GOV_ENGINE,
        Payload=json.dumps(payload),
    )

    result = json.loads(response["Payload"].read().decode("utf-8"))
    return result


def print_decision(step_name, result):
    """Pretty-print a governance decision."""
    verdict = result.get("verdict", "unknown")
    decision_id = result.get("decision_id", "N/A")
    risk_score = result.get("risk_score", "N/A")
    explanation = result.get("explanation", "")
    latency = result.get("latency_breakdown", {})

    icon = {"allow": "ALLOW", "deny": "DENY", "escalate": "ESCALATE"}.get(verdict, "???")

    print(f"\n  {'='*60}")
    print(f"  STEP: {step_name}")
    print(f"  {'='*60}")
    print(f"  Verdict:     [{icon}]")
    print(f"  Decision ID: {decision_id}")
    print(f"  Risk Score:  {risk_score}")
    if explanation:
        print(f"  Explanation: {explanation[:100]}")
    if latency:
        total = sum(latency.values()) if isinstance(latency, dict) else 0
        print(f"  Latency:     {total:.1f}ms")
    print(f"  Timestamp:   {result.get('timestamp', 'N/A')}")
    print(f"  {'='*60}")
    return verdict


def main():
    print("=" * 70)
    print("GOVERNED DEVELOPMENT DEMO")
    print("User Story: Arasaka-876 - SAS consultants edit control verdicts")
    print("Agent: dev-agent-satishuv (AI-assisted developer)")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    all_decisions = []

    # =====================================================================
    # STEP 1: Read codebase (Scope 1 - Read only)
    # =====================================================================
    print("\n\n[STEP 1/6] REQUEST: Read existing codebase patterns")
    print("  Action: ReadPipelineStatus (read code structure)")
    print("  Scope:  1 (read-only)")
    print("  Input:  'Read assessment-controls.ts, hooks, and mock handlers'")

    result = invoke_governance(
        action_group="ReadPipelineStatus",
        target_resource="default",
        input_text="Show me the current assessment controls API structure and evaluation hooks",
        scope_level=1,
    )
    verdict = print_decision("Read Codebase", result)
    all_decisions.append({"step": "read_codebase", "verdict": verdict, "id": result.get("decision_id")})

    if verdict != "allow":
        print("\n  [BLOCKED] Cannot proceed - governance denied read access.")
        sys.exit(1)

    # =====================================================================
    # STEP 2: Read user story (Scope 1 - validate input is safe)
    # =====================================================================
    print("\n\n[STEP 2/6] REQUEST: Process user story text")
    print("  Action: ReadPipelineStatus (read requirements)")
    print("  Scope:  1 (read-only)")
    print("  Input:  User story text from Taskei Arasaka-876")

    user_story_text = (
        "As a SAS consultant, I want to review and edit AI-generated control "
        "evaluation results including compliance status rationale gaps and remediation "
        "because some findings require human judgment that the automated evaluation "
        "cannot capture"
    )

    result = invoke_governance(
        action_group="ReadPipelineStatus",
        target_resource="default",
        input_text=user_story_text,
        scope_level=1,
    )
    verdict = print_decision("Process User Story", result)
    all_decisions.append({"step": "read_user_story", "verdict": verdict, "id": result.get("decision_id")})

    if verdict != "allow":
        print("\n  [BLOCKED] User story text failed governance check (possible injection).")
        sys.exit(1)

    # =====================================================================
    # STEP 3: Propose code changes (Scope 2 - design)
    # =====================================================================
    print("\n\n[STEP 3/6] REQUEST: Propose implementation design")
    print("  Action: ProposeChanges (draft implementation plan)")
    print("  Scope:  2 (propose)")
    print("  Input:  Implementation plan for VerdictEditor component")

    proposal_text = (
        "Propose creating: src/api/assessment-controls.ts (add updateAssessmentControl), "
        "src/hooks/useUpdateAssessmentControl.ts (mutation hook), "
        "src/pages/control-detail/ControlDetail.tsx (page component), "
        "src/pages/control-detail/components/VerdictEditor.tsx (edit form with error handling), "
        "test/pages/control-detail/VerdictEditor.test.tsx (11 unit tests for all error cases). "
        "Follows existing patterns: CBOR fetch for pre-SDK ops, useMutation with invalidateQueries, "
        "Alert-based error display consistent with AssessmentDetails.tsx."
    )

    result = invoke_governance(
        action_group="ProposeChanges",
        target_resource="default",
        input_text=proposal_text,
        scope_level=2,
    )
    verdict = print_decision("Propose Changes", result)
    all_decisions.append({"step": "propose_changes", "verdict": verdict, "id": result.get("decision_id")})

    if verdict != "allow":
        print("\n  [BLOCKED] Governance denied the proposed changes.")
        sys.exit(1)

    # =====================================================================
    # STEP 4: Write code to staging (Scope 3 - implement)
    # =====================================================================
    print("\n\n[STEP 4/6] REQUEST: Write implementation to feature branch")
    print("  Action: StagingDeployment (write code to non-production branch)")
    print("  Scope:  3 (staging)")
    print("  Input:  Commit 6 files to satishuv/arasaka-876-control-verdict-editing")

    result = invoke_governance(
        action_group="StagingDeployment",
        target_resource="staging",
        input_text="Write 6 files implementing VerdictEditor component to feature branch for deployment validation",
        scope_level=3,
    )
    verdict = print_decision("Write Code (Staging)", result)
    all_decisions.append({"step": "write_code", "verdict": verdict, "id": result.get("decision_id")})

    if verdict == "deny":
        print("\n  [BLOCKED] Governance denied writing code to staging.")
        sys.exit(1)
    elif verdict == "escalate":
        print("\n  [ESCALATED] Requires human approval - simulating approval granted...")
        print("  (In production: SNS notification sent, approval queue populated)")
    else:
        print("\n  [ALLOWED] Code written to feature branch.")

    # =====================================================================
    # STEP 5: Attempt production deployment (Scope 2 - should DENY or ESCALATE)
    # =====================================================================
    print("\n\n[STEP 5/6] REQUEST: Deploy to production (CR merge)")
    print("  Action: ProductionDeployment (merge to mainline)")
    print("  Scope:  2 (INSUFFICIENT - needs Scope 4)")
    print("  Input:  Merge feature branch to mainline")
    print("  EXPECTED: DENY (scope too low for production)")

    result = invoke_governance(
        action_group="ProductionDeployment",
        target_resource="production",
        input_text="Merge satishuv/arasaka-876-control-verdict-editing to mainline via CR",
        scope_level=2,
    )
    verdict = print_decision("Deploy to Production (blocked)", result)
    all_decisions.append({"step": "prod_deploy_blocked", "verdict": verdict, "id": result.get("decision_id")})

    if verdict == "allow":
        print("\n  [WARNING] Production deploy was allowed at Scope 2 - unexpected!")
    else:
        print("\n  [CORRECT] Production deploy blocked - requires higher scope + approval.")

    # =====================================================================
    # STEP 6: Request production deployment with proper scope (Scope 4 - escalates)
    # =====================================================================
    print("\n\n[STEP 6/6] REQUEST: Deploy to production with Scope 4")
    print("  Action: ProductionDeployment (merge to mainline)")
    print("  Scope:  4 (full autonomy)")
    print("  Input:  Merge to mainline after CR approval")
    print("  EXPECTED: ESCALATE (high-risk action requires human approval)")

    result = invoke_governance(
        action_group="ProductionDeployment",
        target_resource="production",
        input_text="Merge approved CR to mainline - production deployment of Arasaka-876 verdict editing feature",
        scope_level=4,
    )
    verdict = print_decision("Deploy to Production (escalated)", result)
    all_decisions.append({"step": "prod_deploy_escalated", "verdict": verdict, "id": result.get("decision_id")})

    # =====================================================================
    # SUMMARY
    # =====================================================================
    print("\n\n" + "=" * 70)
    print("GOVERNANCE AUDIT TRAIL")
    print("=" * 70)
    print(f"\n  Total decisions: {len(all_decisions)}")
    print(f"  Allowed:         {sum(1 for d in all_decisions if d['verdict'] == 'allow')}")
    print(f"  Denied:          {sum(1 for d in all_decisions if d['verdict'] == 'deny')}")
    print(f"  Escalated:       {sum(1 for d in all_decisions if d['verdict'] == 'escalate')}")

    print("\n  Decision IDs (evidence in S3):")
    for d in all_decisions:
        print(f"    {d['step']:25s} [{d['verdict']:8s}] {d['id']}")

    print("\n  Evidence stored in:")
    print("    - DynamoDB: DecisionHistoryTable")
    print("    - S3: ImmutableEvidenceBucket (Object Lock, SHA-256)")
    print("    - CloudWatch: AGCP/Governance metrics")

    print("\n" + "=" * 70)
    print("DEMO COMPLETE - Every development action was governed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
