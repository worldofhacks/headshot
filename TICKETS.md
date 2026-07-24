# Tickets — Final submission gap closure (review-repaired)

[locked-decision] Base `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, dual CI green. Four slots total means coordinator + at most three workers. No deadline compresses RED → test review → freeze → GREEN → coordinator gate rerun → code review → security review.

## Waves

| wave | tickets | concurrency/collision note |
|---:|---|---|
| 0 | T-F00 | Mechanical gates before all code |
| 1 | T-F01a, T-F02, T-F03a | Three disjoint workers |
| 2 | T-F04a, T-F14b | Red Team vs contracts, disjoint |
| 3 | T-F05a, T-F11, T-F14a | Runtime, authorized docs, security tools disjoint |
| 4 | T-F03b, T-F04b, T-F06a | Two authorized provider evals + replay code |
| 5 | T-F05b, T-F07a | Campaign evidence vs offline performance |
| 6 | T-F06b, T-F07b, T-F12 | Replay evidence, separately authorized load, architecture docs |
| 7 | T-F08, T-F09b, T-F13 | Cost, drills, integration docs disjoint |
| 8 | T-F09a, T-F10b | ATO vs reports/reproductions |
| 9 | T-F10a | Owner-merged release evidence |
| 10 | T-F10c | Demo/social package after release/report evidence |
| 11 | T-F15 | Project story after package |
| 12 | T-F01b | Final matrix/doc reconciliation last |

## Dependency graph

```text
T-F00 -> {T-F01a,T-F02,T-F03a,T-F14a}
T-F02 -> {T-F04a,T-F14b}
T-F03a -> T-F03b
T-F04a -> T-F04b
{T-F03a,T-F04a} -> T-F05a
T-F01a -> T-F11
{T-F01a,T-F03b,T-F04b,T-F05a,T-F11} -> T-F05b
{T-F05a,T-F14b} -> T-F06a -> {T-F06b,T-F07a}
T-F05b -> {T-F06b,T-F07b,T-F08,T-F09b,T-F10b,T-F13}
T-F07a -> {T-F07b,T-F08}
{T-F08,T-F11,T-F12,T-F13,T-F14a,T-F14b} -> T-F09a
{T-F08,T-F09a,T-F09b,T-F13} -> T-F10a
{T-F10a,T-F10b} -> T-F10c -> T-F15 -> T-F01b
```

[locked-decision] `runner.py` is serialized T-F05a → T-F06a. `contracts/**` is serialized T-F02 → T-F14b. `docs/integration/**` is owned only by post-interface T-F13. Same-wave scopes otherwise do not overlap.

## Deadline triage (2026-07-24 noon)

### P0 — maximum safe by-noon proof path

[proposed] Owner lane immediately requests campaign, Judge, Red Team, load, replay/reproduction/publication, Railway/Clerk and GitLab authorities. This does not consume a worker slot.

1. Coordinator runs T-F00 alone.
2. Three workers run T-F01a/T-F02/T-F03a through full gates.
3. Three workers run T-F04a/T-F14b plus T-F11 only if its authorization already exists; otherwise substitute T-F14a.
4. Three workers run T-F05a/T-F06a (after prerequisite) and remaining deterministic ticket.
5. Preserve green deterministic artifacts/hashes and report every human-gated ticket BLOCKED if authority is absent.

[locked-decision] This is a maximum safe proof path, not a promise of full submission completion by noon.

### P1 — human/external evidence likely blocking noon

T-F03b, T-F04b, T-F05b, T-F06b, T-F07b, T-F10b reproduction/publication, T-F10a deploy/dual-CI.

### P2 — downstream packaging after immutable P0/P1 artifacts

T-F07a, T-F08, T-F09a/b, T-F12, T-F13, T-F10a/b/c, T-F15, final T-F01b. These remain honest blockers if prerequisites miss the deadline.

## Human gates

- [open-question] Fresh staging SMART lease/exact target authorization/synthetic fixture/distinct Approver.
- [open-question] Separate bounded Judge and Red Team provider authorization artifacts and budgets.
- [open-question] Separate replay, 100-case stress, reproduction, failure-drill, critical-publication and social-publication authority.
- [open-question] True production isolation/credentials; absent this, staging only.
- [open-question] Owner main merge/deploy and equal dual-remote green CI.

[locked-decision] Fewer than three genuine independently reproduced findings leaves PRD-32 incomplete.
