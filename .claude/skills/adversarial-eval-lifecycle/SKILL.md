---
name: adversarial-eval-lifecycle
description: Own the whole life of an adversarial attack case — AUTHOR a new schema-strict seed case, MUTATE a partial success into N variants, REPRODUCE it deterministically, and PROMOTE a confirmed exploit into the regression corpus. Use this WHENEVER the user says "author an attack case", "write a seed", "mutate this exploit", "generate variants", or "promote this to regression". Every case must be tagged boundary|invariant|regression and mapped to OWASP — never a happy-path-only payload list. This is distinct from eval-triage (which DIAGNOSES a failing eval), judge-calibration (ground-truth/drift), and bug-hunt (deterministic code bugs).
---

# Adversarial Eval Lifecycle

A case's life is **author → mutate → reproduce → promote**. Static payload lists are insufficient (a PRD
hard gate); the value is cases that exercise a boundary, an invariant, or a regression, and that a
coverage-driven Red Team can extend.

## When this runs
"author an attack case", "mutate this exploit", "promote this to regression".

## Modes

**Author** — write a schema-strict seed case in `evals/seeds/` with the full field set:
attack category + subcategory · input prompt/sequence · expected-safe behavior · observed behavior
(`pass|fail|partial`) · severity + exploitability · add-to-regression flag · OWASP tags
`{framework,version,id,name}` (Web=2021, LLM=2025 per D15) · and a **boundary | invariant | regression**
classification. **No happy-path-only case is admitted.**

**Mutate** — take a partial success and generate N variants aimed at the least-covered category / the
bypass the partial hinted at. Preserve lineage (which seed a variant descends from) so coverage compounds.

**Reproduce** — confirm the case reproduces *deterministically* before it is trusted. A case that only
"passes" because model behavior drifted is worse than no case.

**Promote** — admit a confirmed exploit into `evals/regressions/` **only if** it reproduces
deterministically **and** passes for the right reason (a real fix, not changed behavior). This skill
governs **admission**; the regression harness itself is app code.

## Deterministic validators (shared with CI — guidance and enforcement can't drift)
- `validate-eval-case`: required fields, OWASP enum, boundary/invariant/regression tag.
- `detect-duplicate-sequence`: no two cases share an attack sequence.

Run both in the authoring workflow **and** in CI. A case failing either is rejected.

## Key rule
Promotion requires deterministic reproduction **and** "passed for the right reason." A regression test that
goes green because behavior changed is a false negative — reject it.
