# Reproduction controls

`headshot-repro-controls-v1.json` holds the **negative controls** and **invariant guards** for the
three platform-scanner reproductions R1/R2/R3 (see
[`docs/red-team/reproductions/`](../../docs/red-team/reproductions/README.md)).

## Why these are not AttackCases

`src/agentforge/evals/schemas/attack-case.v1.json` fixes `input_sequence_trust` to the const
`"hostile"`. A negative control is a **benign or authorized** probe, so it can never be a valid
AttackCase — and the frozen adversarial corpus stays adversarial-only, honoring "no happy-path case
is admitted." These probes are therefore a **separate artifact kind** (`reproduction_control_manifest`),
dispatched through the same governed live path and pre-registering their expected outcome. This mirrors
how finding 004's negative controls are direct probes ("issue each GET with the credential omitted and
assert 401/403"), not corpus cases.

## Structure

Each `findings[]` entry carries:
- a **`positive_case`** — a reference (by `case_id` + `case_sha256`) to one of g's frozen,
  reviewer-approved cases in `headshot-live-100-v1`; **never mutated here** — plus its pre-registered
  confirmed condition and honest fallback.
- **`controls[]`** — `negative_control` probes (expect the bound oracle to **not** fire) and
  `invariant_guard` probes (expect the oracle/precedence invariant to hold even under evaluator
  injection).

## Anti-cheat invariants (machine-enforced)

`scripts/validate_repro_controls.py` enforces AC1–AC4 (see the file header and the manifest's
`anti_cheat_invariants`): the oracle's token is never in its own input; decoys are never seeded;
non-decoy controls bind the same instrument as their positive; and pre-registration shape is correct.
Run it in CI and before any reproduction:

```
python3 scripts/validate_repro_controls.py --corpus-dir evals/workloads/live-100-cases
```

Exit 0 ⇒ the manifest is honest by construction. The `--corpus-dir` (g's `live-100-cases`) enables
the anti-echo check on the positive arms too; without it, that check is reported as deferred.

## Canonical vs design input

This manifest is the **canonical** live-reproduction control set. g's
`evals/reproduction/rt2-negative-controls.v1.json` (on `rtg/wp11-wp14`) is the fixture-level control
set for g's deterministic *mechanism* proof and is **design input**, not a competing lineage — the
two are complementary and both stay outside the frozen 100-case corpus. Report IDs and the full
mapping are in [`../../docs/red-team/reproductions/RECONCILIATION.md`](../../docs/red-team/reproductions/RECONCILIATION.md).
