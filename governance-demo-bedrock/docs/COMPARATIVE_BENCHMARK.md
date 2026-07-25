# Comparative Detection Benchmark

Addresses the SAS review's highest-impact recommendation (P2 #7): compare this
framework's injection detection head-to-head against external guardrail models
on the same prompts, instead of reporting only self-measured numbers.

Reproduce: `python scripts/comparative_benchmark.py --n 40 --out paper/bench/comparative_results.json`

## Setup

- **Same prompt set through every detector.** Attacks sampled from the tracked
  `deepset_prompt_injections` and `jailbreakbench` datasets; benign prompts are
  operational CI/CD-governance phrasing (the framework's actual usage context),
  labeled benign, not hand-picked to flatter any detector.
- Detection rate = fraction of attacks flagged UNSAFE. False-positive rate =
  fraction of benign flagged UNSAFE. A useful detector needs BOTH high detection
  and low false positives; either alone is easy to game.

## Detectors

| # | Detector | How run |
|---|----------|---------|
| 1 | **AIGovernance input-defense** (InputSanitizer + ThreatDetector) | Local, deterministic, in-process, no network |
| 2 | Bedrock `openai.gpt-oss-safeguard-20b` | Live via Bedrock; a purpose-built safety classifier (closest available analog to Llama Guard) |
| 3 | Meta Llama 3 8B Instruct as a guard prompt | Live via Bedrock; "use a general LLM as a guard" |

## Results (n=40 attacks, 10 benign, 2026-07-25, us-east-1)

| Detector | Detection rate | False-positive rate |
|----------|---------------:|--------------------:|
| **AIGovernance input-defense** | **62.5%** | **0%** |
| Bedrock safeguard-20b | 30.0% | 0% |
| Llama 3 8B as guard | 70.0% | 60% |

## Honest reading

- The framework's deterministic layer **detects roughly 2x what the purpose-built
  safeguard model does (62.5% vs 30%) at zero false positives** on this set.
- A general LLM as a guard catches slightly more attacks (70%) but is **unusable
  in this context: a 60% false-positive rate** would block the majority of
  legitimate operations. This is the concrete, comparative validation of the
  framework's "0% FP on a locked-down agent" design claim.
- The framework's 62.5% is not a ceiling claim: it is the deterministic layer
  alone. In the full pipeline it is one of several layers (Bedrock Guardrails,
  behavioral invariants, scope/tool checks) that compose.

## Caveats (must be read with the numbers)

- **Scope:** this measures marker/lexical injection detection, the class the
  deterministic layer targets. It does NOT measure semantically-embedded
  injections, which the framework already reports at ~0% and are explicitly
  scoped out of V1. Do not read these numbers as coverage of sophisticated
  semantic attacks.
- **NeMo Guardrails is PENDING, not fabricated.** Literal Llama Guard and NeMo
  are not runnable in this environment (no HuggingFace/web access; not offered
  in this Bedrock account/region). The safeguard model and Llama-as-guard are
  real, live stand-ins. NeMo results are intentionally absent rather than
  invented.
- Small sample (n=40/10) and a single run; treat as indicative, not definitive.
  Re-run with larger `--n` for tighter intervals.
