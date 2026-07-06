# HIPAA Demo Guide: PII Detection & Redaction for AI Agents

## How This Architecture Relates to HIPAA

### The Core Problem

Healthcare organizations are adopting AI agents to improve productivity: clinical decision support, automated claims processing, patient-facing chatbots, and developer tools for health-tech applications. These agents access backend systems containing Protected Health Information (PHI).

The AI agent itself cannot distinguish between "data I need to show" and "data I must never expose." It retrieves whatever the database returns and passes it along. Without a guardrail layer, PHI leaks to unauthorized users, ends up in logs, gets posted in Slack channels, or appears in patient-facing responses where it shouldn't.

### What This Guardrail Does

It sits between the AI agent and the end user. Every response the agent generates passes through the guardrail BEFORE reaching the user's screen. The guardrail:

1. **BLOCKS** responses containing critical identifiers (SSN, credit card numbers)
2. **ANONYMIZES** responses containing non-critical but sensitive identifiers (MRN, NPI, names, DOB)
3. **PASSES** responses containing no PHI (zero false positives on normal data)

### Key HIPAA Terms

| Term | Meaning | How We Handle It |
|------|---------|-----------------|
| **PHI** | Health info + identifier that can identify a patient | Guardrail detects and blocks/anonymizes |
| **PII** | Name, SSN, DOB, address, phone, email | Guardrail PII entities detect all standard types |
| **Minimum Necessary** (164.502) | Only disclose the minimum PHI needed for the purpose | Guardrail strips identifiers, keeps clinical data |
| **Access Controls** (164.312a) | Restrict who/what can access PHI | OPA policies + scope levels |
| **Audit Controls** (164.312b) | Record who accessed what and when | Evidence pipeline (SHA-256, 7-year retention) |
| **Transmission Security** (164.312e) | Protect PHI in transit | Output guardrails strip PHI before transit |

---

## Pre-Demo Setup

### Console Tabs to Open

1. **Tab 1:** Lambda > Functions > GovernanceEngineLambda (Test tab)
2. **Tab 2:** Bedrock > Guardrails > ai-governance-hipaa-guardrail (Test panel)

### What the Audience Should See in Tab 2 (Guardrail Config)

When you open the guardrail, briefly show:
- **PII entities:** Name, Email, Phone, SSN (BLOCK), Credit Card (BLOCK), Address, Age
- **Custom regex:** Medical Record Number, Insurance ID, Date of Birth, NPI Number
- **Content filters:** All set to HIGH

---

## Demo Scenarios

### Scenario A: Quality Analyst Reviewing Patient Outcomes (OUTPUT)

#### The situation

A hospital's quality improvement team uses an AI agent to analyze patient outcomes across departments. A quality analyst asks:

> "Summarize the diabetes management outcomes for Q1 2026 across all departments."

The AI agent queries the clinical database, aggregates results, and generates a summary report. The analyst needs the CLINICAL PATTERNS (what percentage have A1C under control, which medications are most prescribed) but does NOT need to know WHICH specific patients have diabetes. The report is shared with the hospital board, posted on internal dashboards, and included in quarterly reviews.

The agent's response includes individual patient identifiers because the database query returned per-patient rows before aggregation.

#### Why this matters

- The quality analyst needs clinical patterns, not individual identities
- The summary report is shared widely (board meetings, dashboards, emails)
- Patient identifiers in a shared report are a HIPAA violation
- The analyst never asked for individual patient data; they asked for aggregated outcomes

#### The flow in our architecture

```
Analyst: "Summarize diabetes management outcomes for Q1 2026"
     |
     v
[AI Agent] queries clinical database, gets per-patient rows
     |
     v
Agent's response (what it WANTS to return):
  "Q1 Diabetes Summary: 847 patients tracked.
   Example outcomes: MRN-4829301 A1C 7.2% (improved from 8.1%),
   patient John Smith on Metformin 500mg,
   referred by Dr. Wilson NPI 1234567890.
   Overall: 72% have A1C under 7.5%..."
     |
     v
[OUTPUT GUARDRAIL] intercepts before analyst sees it
     |
     v
Analyst sees:
  "Q1 Diabetes Summary: 847 patients tracked.
   Example outcomes: {Medical_Record_Number} A1C 7.2% (improved from 8.1%),
   patient {NAME} on Metformin 500mg,
   referred by Dr. {NAME} {NPI_Number}.
   Overall: 72% have A1C under 7.5%..."
```

#### Demo action

**In Tab 2 (Guardrail test panel):**

**First, explain the context to the audience:**
> "A quality analyst asks the AI agent to summarize diabetes outcomes for the quarter. The analyst needs the clinical trends: what percentage improved, which medications work best. They do NOT need to know which specific patients have diabetes. That report goes on a dashboard visible to the whole hospital leadership."

Select Source: **OUTPUT**

Why OUTPUT? The analyst's question was fine (asking for aggregated data). The danger is in the agent's response which includes individual patient identifiers from the underlying database rows.

Paste:
```
Q1 2026 Diabetes Management Summary: 847 patients tracked. Example outcomes: MRN-4829301 A1C 7.2% improved from 8.1%, patient John Smith on Metformin 500mg, referred by Dr. Wilson NPI 1234567890. Overall: 72% achieved A1C below 7.5%.
```

Click **Run**.

**Expected result:** INTERVENED (anonymized):
```
Q1 2026 Diabetes Management Summary: 847 patients tracked. Example outcomes: {Medical_Record_Number} A1C 7.2% improved from 8.1%, patient {NAME} on Metformin 500mg, referred by Dr. {NAME} {NPI_Number}. Overall: 72% achieved A1C below 7.5%.
```

#### What to say

> "The analyst asked for a quarterly summary. The AI agent pulled data from the clinical database. But its response included individual patient names and MRN numbers from the underlying rows.
>
> The guardrail anonymized the identifiers. The analyst still sees everything they need: 847 patients, A1C trending down, 72% under control, Metformin most common. They can make quality improvement decisions without ever knowing which specific patient is which.
>
> That report goes on a dashboard. Gets emailed to the board. Gets discussed in meetings. None of those people need John Smith's MRN. The guardrail enforces minimum necessary automatically."

---

### Scenario B: Deployment Report Contains PHI from Test Logs

#### The situation

A CI/CD pipeline uses an AI agent to generate deployment summaries. After integration tests run, the agent reads the test output and creates a report: "What passed, what failed, how long it took."

The integration tests ran against a staging database that contains realistic data (cloned from production, not fully masked). The test assertions include patient identifiers in their descriptions:

```
PASS: verify_patient_lookup("MRN-4829301") returned 200 in 45ms
PASS: verify_provider_npi("1234567890") resolved correctly
PASS: verify_dob_format("03/15/1985") parsed successfully
```

The AI agent reads these logs and includes the identifiers in the deployment report that gets posted to the team's Slack channel.

#### Why this matters

- Deployment reports are shared: Slack, wikis, email, JIRA tickets
- Anyone on the team (including contractors, offshore teams) sees the report
- PHI in a deployment report is a HIPAA violation the moment it leaves the secured environment
- Nobody reviewing the report asked for patient data. They want to know if tests passed.

#### The flow in our architecture

```
Pipeline: "Summarize the integration test results"
     |
     v
[Deployment Agent] reads test output logs
     |
     v
Agent's summary (what it WANTS to post to Slack):
  "All tests passed. Patient MRN-4829301 lookup: 45ms.
   NPI 1234567890 resolution: OK. DOB 03/15/1985 parsing: OK."
     |
     v
[OUTPUT GUARDRAIL] intercepts before it goes to Slack
     |
     v
What actually gets posted:
  "All tests passed. Patient {Medical_Record_Number} lookup: 45ms.
   {NPI_Number} resolution: OK. {Date_of_Birth} parsing: OK."
```

#### Demo action

**In Tab 2 (Guardrail test panel):**

Select Source: **OUTPUT**

Why OUTPUT? The pipeline trigger was fine. The danger is the agent's SUMMARY which includes PHI from the test logs.

Paste:
```
Integration test summary: Patient record retrieval for MRN-4829301 completed in 45ms. NPI 1234567890 provider lookup returned 200 OK. Patient DOB: 03/15/1985 verified against source. All 142 tests passed.
```

Click **Run**.

**Expected result:** INTERVENED (anonymized)
```
Integration test summary: Patient record retrieval for {Medical_Record_Number} completed in 45ms. {NPI_Number} provider lookup returned 200 OK. Patient {Date_of_Birth} verified against source. All 142 tests passed.
```

**What the team sees in Slack:** The useful information (45ms, 200 OK, 142 tests passed) with identifiers replaced by placeholders.

#### What to say

> "The deployment report needs to tell the team: did tests pass? How fast? Any failures? It does NOT need to include actual patient identifiers. The guardrail keeps the metrics, strips the identifiers. The report is just as useful without MRN-4829301. Nobody reading it cares about that number. But if it's there, it's a HIPAA violation the moment someone forwards the Slack message."

---

### Scenario C: Patient Tries to Access Another Patient's Records

#### The situation

A healthcare organization has a patient-facing chatbot on their portal. Patients use it to check their own appointments, lab results, and billing. The chatbot is connected to the hospital's backend systems.

A patient tries to access someone ELSE's records by providing their identifier:

> "Can you look up my mother's medical records? Her SSN is 987-65-4321 and her date of birth is 05/22/1958."

This is a social engineering attack (intentional or not). The patient is providing another person's identifiers hoping the chatbot will retrieve their records.

#### Why this matters

- The chatbot should ONLY return the authenticated patient's own records
- Accepting identifiers from user input and using them to query records = unauthorized access
- Even if the patient is a legitimate family member, the system cannot verify that from a chat message
- HIPAA requires explicit authorization (written consent, power of attorney) for accessing another person's records

#### The flow in our architecture

```
Patient types: "Look up my mother's records, SSN 987-65-4321"
     |
     v
[INPUT GUARDRAIL] intercepts the REQUEST before the agent processes it
     |
     v
Result: BLOCKED (SSN detected in user input)
     |
     v
Patient sees: "Request blocked. I cannot process requests containing
              personal identifiers for other individuals."

The AI agent NEVER sees this request.
No database query is made.
No records are accessed.
```

#### Demo action

**In Tab 2 (Guardrail test panel):**

Select Source: **INPUT**

Why INPUT this time? Because the danger is in the USER'S REQUEST itself. The patient is providing someone else's SSN. We block BEFORE the agent even thinks about it.

Paste:
```
Look up the medical records for my mother. Her SSN is 987-65-4321 and her date of birth is 05/22/1958.
```

Click **Run**.

**Expected result:** BLOCKED entirely

**What the patient sees:** "Request blocked: contains protected health information."

#### What to say

> "This is different from the first two scenarios. There, the danger was in the agent's RESPONSE. Here, the danger is in the user's REQUEST. The patient is providing another person's SSN. Whether they're a legitimate family member or not, the chatbot cannot accept identifiers and use them to pull records. That requires a formal authorization process. The INPUT guardrail blocks this at the door. The agent never processes the request. No records are accessed. This prevents social engineering attacks where someone provides a known SSN to extract medical records."

---

### Scenario D: Normal Request (No False Positives)

#### The situation

After showing three block/anonymize scenarios, demonstrate that normal requests work fine.

#### Demo action

Select Source: **OUTPUT**. Paste:
```
Build-47 deployed successfully to staging. 142 integration tests passed, 0 failed. Deployment duration: 45 seconds. Branch: main, commit: a1b2c3d. No rollback required.
```

Click **Run**.

**Expected result:** No action taken. Passes through unchanged.

#### What to say

> "And normal operational data passes through completely untouched. No false positives. The deployment log has no PHI, so the guardrail doesn't interfere. This is critical: you can't have a security control that blocks legitimate work."

---

## How These Scenarios Map to HIPAA

| Scenario | HIPAA Rule | What It Proves |
|----------|-----------|---------------|
| A (Developer debug) | 164.502 Minimum necessary | Agent strips PHI from responses, keeps debugging info |
| B (Deployment report) | 164.312(e) Transmission security | PHI never leaves secured environment in shared reports |
| C (Patient portal) | 164.312(a) Access controls | Unauthorized access attempts blocked at input |
| D (Normal data) | N/A | Zero false positives, normal operations unaffected |

---

## How This Connects to Our Architecture

| What we demo in the console | What runs automatically in production |
|----------------------------|---------------------------------------|
| Paste text, click Run, see result | `bedrock_guardrails.py` calls `ApplyGuardrail` API on every request |
| Select OUTPUT, test agent response | `_validate_agent_output()` in Scope Enforcer scans every response |
| Select INPUT, test user request | Governance Engine checks every input before agent processes it |
| See "INTERVENED" or "BLOCKED" | Lambda returns deny verdict with `content_safety_blocked` category |

The console test panel is a window INTO the same API call that runs automatically on every single request in production. No manual intervention. No human reviewing each response. Automated. Continuous. Audit-logged.

---

## Automated Reasoning (Bonus if time permits)

### What it does

Automated Reasoning validates that the AI agent's response is factually consistent with the source data it retrieved. It prevents hallucination in clinical contexts.

### Example

Agent retrieves: `A1C: 7.2% (elevated, above normal range of 4.0-5.6%)`
Agent responds: "Your A1C is normal, nothing to worry about."
Automated Reasoning: **FLAGS DISCREPANCY** (7.2% is NOT normal)

### Why it matters for healthcare

A hallucinated "your results are normal" when they're actually elevated could delay treatment. Automated Reasoning catches this by comparing the response against the source document.

### How to mention it

> "Beyond PII detection, the guardrail also validates factual accuracy. If the agent says 'your A1C is normal' but the actual lab result shows 7.2% which is elevated, Automated Reasoning flags the contradiction. In healthcare, wrong information can be as dangerous as leaked information."

---

## Common Questions and Answers

### "How is this different from just masking data in the database?"

> "Database masking is static. You mask once during the clone. If someone adds new data, creates a new table, or the masking script has a bug, real data leaks through. The guardrail is dynamic. It catches PHI regardless of where it came from, even if your masking is incomplete. Defense-in-depth: mask the database AND run the guardrail."

### "What if the AI agent needs the PHI to function correctly?"

> "The agent can still ACCESS the data internally to reason about it. The guardrail only filters what LEAVES the system to the user. The agent can know that MRN-4829301 has an elevated A1C and make clinical recommendations. It just can't include the raw MRN in its response. The clinical insight passes through. The identifier doesn't."

### "Can't the developer just query the database directly?"

> "If they have direct database access, yes. That's a separate access control problem (revoke prod DB access from devs). The guardrail protects the AI agent channel. In modern development, more and more data access happens THROUGH AI agents, not through direct SQL. The guardrail governs that channel."

### "What about performance?"

> "The guardrail adds approximately 100-200ms per request. For clinical workflows with 2-5 second response times, this is imperceptible. For CI/CD reports that run in the background, it's invisible."

### "Is this HIPAA compliant?"

> "This provides the TECHNICAL safeguards that HIPAA requires. It doesn't replace a full compliance program (policies, training, BAAs, risk assessments). But it gives you the runtime controls that auditors will look for: access controls, audit trails, transmission security, and the minimum necessary principle enforced automatically."

### "What's the difference between BLOCK and ANONYMIZE?"

> "BLOCK means the entire response is suppressed. The user sees nothing. We block when critical identifiers are present (SSN, credit card) because even partial exposure is a violation.
>
> ANONYMIZE means identifiers are replaced with placeholders ({NAME}, {Medical_Record_Number}) but the rest of the content passes through. We anonymize when the content itself is useful but the identifiers aren't needed. The choice between block and anonymize is configurable per PII type."

---

## If Something Goes Wrong During Demo

| Problem | What to say |
|---------|-------------|
| Guardrail doesn't block SSN | "Let me verify the PII entities config." Show the config section. |
| Guardrail blocks normal text | "That's the content filter being cautious. We can tune sensitivity." |
| Test panel doesn't load | Switch to Tab 1 (Lambda). Show the governance engine catching attacks instead. |
| Any other failure | "The architecture's default is deny. When in doubt, it blocks. It never fails open." |

---

## Pre-Demo Checklist

1. Open Tab 1 (Lambda) and Tab 2 (Guardrails)
2. In Tab 2, verify you can see the guardrail test panel
3. Run one quick test: paste "Hello world", verify it passes (NONE)
4. Run the validation script: `python test_datasets/run_demo_validation.py`
5. Confirm: "ALL SCENARIOS PASS. SAFE TO DEMO LIVE."
