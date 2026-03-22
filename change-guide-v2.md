# Change Guide: text in the blog.md - v2 Improvements

Instructions: Use Ctrl+H (Find and Replace) in your document editor. Find the exact text in "FIND" and replace with the text in "REPLACE WITH". Work top to bottom.

---

## Change 1: Remove Akanksha from authors

**FIND:**
```
Akanksha Chaturvedi, Senior Assurance Consultant, Security Assurance Services 
```

**REPLACE WITH:**
*(delete this entire line)*

**Why:** Akanksha is no longer a co-author.

---

## Change 2: Fix "execute" (inclusive language) in intro

**FIND:**
```
Unlike traditional AI systems that respond to prompts or execute narrowly defined tasks
```

**REPLACE WITH:**
```
Unlike traditional AI systems that respond to prompts or run narrowly defined tasks
```

**Why:** "Execute" flagged for inclusive language. "Run" is cleaner.

---

## Change 3: Tighten the second intro paragraph

**FIND:**
```
For organizations operating in regulated environments, this makes governance, auditability, and operational control foundational requirements rather than optional enhancements.
```

**REPLACE WITH:**
```
For organizations in regulated environments, governance, auditability, and operational control become foundational requirements, not optional enhancements.
```

**Why:** Removes "rather than" (weasel word), tightens phrasing, more direct.

---

## Change 4: Change "post" to "whitepaper" (3 occurrences)

**FIND (occurrence 1):**
```
This post outlines a practical governance framework
```

**REPLACE WITH:**
```
This whitepaper outlines a practical governance framework
```

**FIND (occurrence 2):**
```
What this post shows
```

**REPLACE WITH:**
```
What this whitepaper covers
```

**FIND (occurrence 3):**
```
This post shows:
```

**REPLACE WITH:**
```
This whitepaper covers:
```

**Why:** Content is a whitepaper/compliance guide, not a blog post.

---

## Change 5: Fix long sentence in intro summary

**FIND:**
```
It introduces a scope based model for classifying agent autonomy, identifies core security dimensions, and describes how organizations can align agentic AI governance with existing risk, compliance, and assurance programs.
```

**REPLACE WITH:**
```
It introduces a scope-based model for classifying agent autonomy and identifies core security dimensions. It also describes how organizations can align agentic AI governance with existing risk, compliance, and assurance programs.
```

**Why:** Original is 30 words in one sentence. Split into two for readability.

---

## Change 6: Fix vague language in agentic AI section

**FIND:**
```
In more advanced implementations, multiple agents may collaborate to accomplish complex objectives.
```

**REPLACE WITH:**
```
In advanced implementations, agents collaborate to accomplish complex objectives.
```

**Why:** Removes "more" (vague quantifier), "multiple" (vague), and "may" (modal uncertainty). More direct.

---

## Change 7: Fix passive voice, "are especially important"

**FIND:**
```
Two characteristics are especially important for governance:
```

**REPLACE WITH:**
```
Two characteristics matter most for governance:
```

**Why:** Active voice, more direct.

---

## Change 8: Fix passive voice, "were designed"

**FIND:**
```
Traditional AI governance models were designed for systems that operate at human decision speed, where actions are discrete, reviewable, and directly attributable to a person or process.
```

**REPLACE WITH:**
```
Traditional AI governance models target systems that operate at human decision speed, where actions are discrete, reviewable, and directly attributable to a person or process.
```

**Why:** Removes passive voice. "Target" is active and precise.

---

## Change 9: Fix passive voice, "can be managed"

**FIND:**
```
These models assume that risk can be managed through periodic reviews, static approvals, and policy based controls enforced outside the system itself.
```

**REPLACE WITH:**
```
These models assume that organizations can manage risk through periodic reviews, static approvals, and policy-based controls enforced outside the system.
```

**Why:** Active voice. Also adds hyphen to "policy-based".

---

## Change 10: Fix "invalidate many"

**FIND:**
```
Agentic AI systems invalidate many of these assumptions.
```

**REPLACE WITH:**
```
Agentic AI systems break these assumptions.
```

**Why:** "Many" is a vague quantifier. "Break" is stronger and more direct.

---

## Change 11: Fix "execute" and "multiple" in governance breakdown section

**FIND:**
```
Unlike conventional AI applications, agentic systems can reason across multiple steps, select tools dynamically, maintain persistent state, and execute actions at machine speed.
```

**REPLACE WITH:**
```
Agentic systems reason across steps, select tools dynamically, maintain persistent state, and act at machine speed.
```

**Why:** Removes "Unlike conventional AI applications" (already established), "multiple" (vague), and "execute" (inclusive language). Tighter.

---

## Change 12: Fix "typically" and "Common", break up long sentence

**FIND:**
```
In this environment, governance failures do not typically occur because policies are missing, but because controls are not technically enforced at the point of action. Common failure patterns include agents exceeding their intended authority through tool chaining, privilege amplification via delegated identities, memory or state influencing future decisions in unintended ways, and silent escalation of autonomy without formal approval.
```

**REPLACE WITH:**
```
In this environment, governance failures occur not because policies are missing, but because controls are not technically enforced at the point of action. Observed failure patterns include:

- Authority escalation through tool chaining: agents combine permitted actions to achieve outcomes beyond their intended scope
- Privilege amplification through delegated identities: agents inherit or accumulate permissions that exceed their authorization
- State-influenced decision drift: memory or context from prior interactions shapes subsequent decisions in unintended ways
- Silent autonomy escalation: agents gradually operate at higher scope levels without formal approval or detection
```

**Why:** Removes "typically" (vague frequency) and "Common" (vague descriptor). Replaces "via" with "through" (Latinism fix). Breaks 34-word run-on sentence into a structured bulleted list with named patterns.

---

## Change 13: Fix passive voice, "cannot be mitigated" and "must be embedded"

**FIND:**
```
These risks cannot be mitigated through documentation or human review alone. Effective governance for agentic AI systems must be embedded into system architecture, with enforceable boundaries, continuous monitoring, and auditable evidence of behavior.
```

**REPLACE WITH:**
```
Documentation and human review alone cannot mitigate these risks. Organizations must embed governance into system architecture through enforceable boundaries, ongoing monitoring, and auditable evidence of behavior.
```

**Why:** Two passive voice fixes. Also replaces "continuous" with "ongoing" (superlative flag). More direct.

---

## Change 14: Fix "Fig:2." caption formatting

**FIND:**
```
Fig:2., Agent autonomy is treated as a dynamic property that can be elevated only after control effectiveness is demonstrated and automatically reduced when risk conditions, control failures, or anomalous behavior are detected.
```

**REPLACE WITH:**
```
Figure 2 illustrates how agent autonomy is treated as a dynamic property, elevated only after control effectiveness is demonstrated, and automatically reduced when risk conditions, control failures, or anomalous behavior are detected.
```

**Why:** Fixes formatting ("Fig:2.," is inconsistent with "Figure 1" used elsewhere). Improves sentence flow.

---

## Change 15: Fix "may" in scope elevation section

**FIND:**
```
Triggers for scope elevation may include expanded tool access, reduced human oversight, or deployment into higher impact environments.
```

**REPLACE WITH:**
```
Triggers for scope elevation include expanded tool access, reduced human oversight, or deployment into higher-impact environments.
```

**Why:** Removes "may" (modal uncertainty). Adds hyphen to "higher-impact".

---

## Change 16: Fix "increase" to "amplify" in six dimensions intro

**FIND:**
```
but agentic systems combine them in ways that increase the impact of gaps or misconfiguration.
```

**REPLACE WITH:**
```
but agentic systems combine them in ways that amplify the impact of gaps or misconfiguration.
```

**Why:** "Amplify" is more precise and impactful than "increase" in this context.

---

## Change 17: Fix "executing" in agent controls section

**FIND:**
```
Guardrails are necessary to prevent agents from producing harmful outputs or executing unsafe actions.
```

**REPLACE WITH:**
```
Guardrails prevent agents from producing harmful outputs or running unsafe actions.
```

**Why:** "Executing" to "running" (inclusive language). Also removes "are necessary to" for directness.

---

## Change 18: Fix "may include" in agent controls

**FIND:**
```
These controls may include input validation, output filtering, behavioral constraints, and isolation mechanisms to limit blast radius if a system behaves unexpectedly.
```

**REPLACE WITH:**
```
These controls include input validation, output filtering, behavioral constraints, and isolation mechanisms to limit blast radius if a system behaves unexpectedly.
```

**Why:** Removes "may" (modal uncertainty). The controls DO include these things.

---

## Change 19: Fix "what actions were taken" (passive voice in audit section)

**FIND:**
```
Governance requires visibility into what actions were taken, when they occurred, and the context that led to those decisions.
```

**REPLACE WITH:**
```
Governance requires visibility into what actions the system took, when they occurred, and the context that led to those decisions.
```

**Why:** Active voice. The system took the actions.

---

## Change 20: Fix "may not account for" in incident response

**FIND:**
```
Traditional incident response models assume human initiated actions and may not account for the speed or complexity of agent driven incidents.
```

**REPLACE WITH:**
```
Traditional incident response models assume human-initiated actions and do not account for the speed or complexity of agent-driven incidents.
```

**Why:** "May not" to "do not" (more definitive). Added hyphens to compound adjectives.

---

## Change 21: Fix "may include" in incident types

**FIND:**
```
Agent specific incidents may include unauthorized action execution, boundary violations, incorrect or harmful remediation, memory corruption, or unintended goal pursuit.
```

**REPLACE WITH:**
```
Agent-specific incidents include unauthorized action execution, boundary violations, incorrect or harmful remediation, memory corruption, or unintended goal pursuit.
```

**Why:** Removes "may". These ARE the incident types. Added hyphen to "Agent-specific".

---

## Change 22: Add hyphens to compound adjectives throughout

These are quick fixes. Search for each and add the hyphen:

| FIND | REPLACE WITH |
|------|-------------|
| `scope based` | `scope-based` |
| `multi step` | `multi-step` |
| `read only` | `read-only` |
| `human initiated` | `human-initiated` |
| `one time` | `one-time` |
| `evidence based` | `evidence-based` |
| `kill switch` | `kill-switch` |
| `post incident` | `post-incident` |
| `task level` | `task-level` |
| `low risk` | `low-risk` |
| `higher impact` | `higher-impact` |
| `lower scope` | `lower-scope` |
| `higher scope` | `higher-scope` |
| `agent related` | `agent-related` |
| `agent driven` | `agent-driven` |
| `agent specific` | `agent-specific` |
| `policy based` | `policy-based` |
| `Free form` | `Free-form` |

**Why:** Compound adjectives before nouns need hyphens per standard style guides.

---

## Summary of Changes

| Category | Count |
|----------|-------|
| Passive voice fixes | 5 |
| Weasel word removals | 7 |
| Inclusive language fixes | 3 |
| Latinism fix | 1 |
| Sentence splits (readability) | 2 |
| Long sentence to bulleted list | 1 |
| "Post" to "Whitepaper" | 3 |
| Compound adjective hyphens | ~18 |
| Author cleanup | 1 |
| Caption formatting fix | 1 |
| **Total changes** | **~42** |
