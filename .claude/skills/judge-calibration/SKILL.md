---
name: judge-calibration
description: Systematically calibrate the independent Judge and detect drift — dual-judge across the ground-truth set and a stratified live sample, compute agreement / false-negative / uncertainty / calibration-error / drift metrics, set per-category confidence and drift thresholds, and disable LLM-only dispositions for a category that breaches. Use this WHENEVER the user says "calibrate the judge", "check judge drift", "is the judge honest", or before trusting Judge verdicts at a checkpoint. This is systematic ground-truth work, NEVER a per-incident triage of one failing eval (that is eval-triage). It maintains the guardrail on the Judge invariant, but the invariant itself is deterministic (oracle precedence, D13) — calibration governs the LLM-only, non-oracle path.
---

# Judge Calibration

The Judge's invariant — never approve a confirmed exploit — is **deterministic and fail-closed** (D13):
oracle/canary hits override the LLM. Calibration does not create that invariant; it governs the **non-oracle
LLM path**, where the risk is a *false negative* (a real exploit judged safe) or drift over time.

## When this runs
"calibrate the judge", "check judge drift", before trusting verdicts at a checkpoint. Systematic, scheduled
— never a one-off reaction to a single failing case.

## Inputs
The labelled ground-truth set (`evals/ground-truth/`) and Judge verdicts across runs.

## Method — asynchronous dual-judging (NOT per-case second-Judge concurrence)
Requiring a second Judge to concur on *every* live case raises false negatives on disagreement and doubles
cost/latency. Instead, dual-judge asynchronously across:
- the **complete ground-truth set**,
- a **stratified random sample** of live non-oracle cases (across categories, severities, target versions),
- selected **threshold-near / disputed** cases.

## Metrics (per category)
inter-judge agreement · category-specific **false-negative rate** · **uncertainty rate** · **confidence-
calibration error** · **drift over time**.

## Thresholds and the drift kill-switch
Set **per-category confidence and drift thresholds**. When a category breaches its drift threshold,
**disable LLM-only dispositions for that category** — affected findings become `INDETERMINATE` (never
counted safe) **without stopping unrelated campaign work** (fail-closed on the verdict, not the run).
Re-enabling a category requires **human review + recalibration**.

## MVP minimum slice
Until the full system ships (FINAL-COMMITTED), a **minimum ground-truth calibration slice** establishes
initial per-category thresholds. Until that slice passes for a category, the MVP Judge routes every
non-oracle case in that category to `INDETERMINATE` (see IMPLEMENTATION_PLAN.md MVP Judge rule). Do not
weaken this to meet a deadline.

## Key rule
Calibration *may* detect a non-oracle false negative; thresholds, the drift kill-switch, and human review
*contain* the residual — they do not guarantee detection. State the residual honestly; never present
calibration as proof the Judge cannot be fooled.
