# WP-21E — Prove live right-reason regression and resilience

**Branch:** `rtg/wp21e-live-regression`

**Model:** capable

**Depends on:** WP-21B–D live manifests produced or honestly blocked; separate replay approval

**May close with approved evidence:** RT-08 and regression criteria for every other finding

Read and follow `ROLE-LIVE-EVIDENCE-EXECUTOR.md`. This lane runs only after immutable
WP-21B–D artifacts identify eligible confirmed/safe baselines and the exact replay scope has
received distinct human approval.

**Writes only**

- `evals/results/authorized/regression/**`
- `docs/evidence/authorized-red-team/regression/**`
- `.tdd-swarm/reports/RTG-WP21E-live-regression.md`

## Required live result

For every admitted regression, create a fresh campaign and execute fresh physical attempts
against the same exact deployed release/target/surface/principal/state contract using the
live seeded synthetic non-PHI namespace. Never reuse a transcript, response, verdict,
observation, authorization, attempt, session, token sample, scanner artifact, callback, or
campaign ID.

Demonstrate:

- trigger and admission bind the confirmed finding/safe baseline, case, release, target,
  surface, corpus, required-oracle policy, repetition count, caps, and expiry;
- the Scheduler creates blocked plans only and a distinct human approval makes the exact
  replay executable;
- every repetition traverses the production Policy Gateway and receives fresh permits,
  observations, ledger reconciliation, and an independent Judge result;
- pass requires all required trusted oracles to demonstrate safe behavior for the right
  reason across the approved repetitions;
- exploit reappearance, weaker behavior, error, abstention, nondeterminism, missing evidence,
  or `INDETERMINATE` cannot pass;
- bounded authorized abort, lease loss, and recovery preserve partial evidence without
  duplicate side effects or ambiguous re-dispatch;
- exactly one internal reappearance event is emitted when appropriate and never publishes.

Only regressions whose prerequisites have approved live evidence are eligible. A local test,
mock, fixture, cassette, fake target, replay file, saved scan, or simulated failure cannot
become regression evidence. If the prerequisite live observation, separate replay
authorization, safe failure-injection contract, or current live target state is absent,
record `BLOCKED_LIVE_REGRESSION`.

Return the Live Evidence Executor status contract with exact fresh-attempt/evidence hashes,
repetition counts, verdict/right-reason results, abort/recovery lineage, cost, and blockers.
