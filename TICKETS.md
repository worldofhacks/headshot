# Tickets — Final submission gap closure (session-lease scope repair round 3)

> **Historical backlog, not the current plan.** This file and `tickets/T-F*.md` preserve the
> pre-release work decomposition and must not be used to infer current implementation, deployment,
> migration, test, or CI status. Many tickets landed through differently named commits and later
> migrations. Current facts are in [`docs/CURRENT_STATE.md`](docs/CURRENT_STATE.md); current work and
> gates are in [`PLAN.md`](PLAN.md). Do not execute this file's waves against the current platform.

[locked-decision] Base `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, dual CI green.
Four slots total means coordinator + at most three workers. No deadline compresses RED → test review
→ freeze → GREEN → coordinator gate rerun → code review → security review.

## Status reconciliation (2026-07-25, base `107c11c`)

> This section states the ticket plan's real status. It does not alter the plan, the waves, the
> dependency graph, or any locked decision below.

**The plan has not started.** All **46** tickets defined here (`tickets/T-F00.md` … `T-F15.md`; wave
table below) carry `status: backlog` and `attempts: 0` in their own frontmatter at this base. No T-F
commit exists (`git log --grep="T-F"` returns nothing at `107c11c`); 2 of 32 declared ticket test files
exist and both pre-date the plan, added by non-ticket commits; 70 of 175 declared `file_scopes` exist,
mostly pre-existing files a ticket would *edit* rather than create.

| Ticket state | Count |
|---|---:|
| Defined | **46** |
| Landed with evidence | **0** |
| Blocked as a recorded disposition | 0 |
| Deferred / out of scope | 0 |
| Not started | **46** |

The seven `[open-question]` human gates under *Human gates* below are the real blockers and remain
open. They are not ticket dispositions; no ticket has been formally marked blocked.

**The stale pin in the header above.** `23490ea` **is** an ancestor of this base, but it is 70 commits
behind it, so the "1001 Python passed / 3 skipped, 75 console, 4 browser, dual CI green" figures do not
describe this tree. `tests/` now defines **1,284** test functions, so the Python count cannot be
current. GitHub CI is the sole current gate and GitLab is a passive mirror, so the old dual-CI
criterion is itself superseded. The same stale pin appears in `.tdd-swarm/gates.md`. Treat those
numbers as a historical measurement, not a gate.

**On the "24/39/2/7" scorecard.** That tally **does not exist at this base.** It exists only at
`refs/heads/codex/final-integration-release:docs/requirements/REQUIREMENTS_MATRIX.md`, on a branch that
is neither an ancestor nor a descendant of `107c11c`. Reconciling against it would import another
branch's numbers and contradict this base's own ledger. Two further reasons not to use it:

1. **It is a requirements tally, not a ticket tally** — `complete / partial / missing / blocked` over
   72 requirements. There is no 46-ticket status scorecard anywhere in the repository, and the table
   above is the first one.
2. **This base's own tally is different.** `docs/requirements/REQUIREMENTS_MATRIX.md` reads
   **25 complete / 34 partial / 6 missing / 7 blocked = 72**, and its CSV independently tallies to
   exactly that:

| Scope | Complete | Partial | Missing | Blocked | Total |
|---|---:|---:|---:|---:|---:|
| Canonical PRD | 17 | 13 | 4 | 3 | 37 |
| Optional engineering deliverables | 7 | 9 | 1 | 1 | 18 |
| User deployment constraints | 1 | 5 | 0 | 1 | 7 |
| Implementation-lead acceptance | 0 | 7 | 1 | 2 | 10 |
| **All requirements** | **25** | **34** | **6** | **7** | **72** |

Relative to this base, the other branch shows 4 fewer `missing` (6 → 2) and 5 more `partial`
(34 → 39). That direction is consistent with either real work or a reclassification of `missing` rows
as `partial`; the per-row evidence on that branch was **not** verified in this pass, so which it is
remains open. **Whoever integrates that branch owns saying which.**

[open-question] Does `codex/final-integration-release`'s 24/39/2/7 reflect landed work or
reclassification? Until answered, `25/34/6/7` is the number this base states.

**The matrix itself is stale in both directions.** It records `Audited parent commit: 215584f4`, which
is 72 commits behind this base and predates migrations `0017`–`0021`, the four hosted role models, and
every live-target artifact. Rows now wrong in the *pessimistic* direction include PRD-22 and PRD-32
(evidence path `docs/vulnerabilities (absent)` and "No genuine report files exist" — six report files
are present) and PRD-07/PRD-18. Rows wrong in the *optimistic* direction include USR-02, marked
`complete` while its own remaining-work column names an unperformed verification and
`docs/security/AUTHENTICATION.md` at `107c11c` stated the Clerk integration was not deployed. Staging
now proves only the shell and missing-token boundary; the real-user acceptance named by the row remains
unperformed. **Do not flip any row from this document** — the matrix needs its own dated re-audit
against `107c11c`.

Capability status, as opposed to requirement status, lives in
[`docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md`](docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md).
The `[locked-decision]` at the end of this file — "Fewer than three genuine independently reproduced
findings leaves PRD-32 incomplete" — still controls. **Post-PR #48 reconciliation:** six draft reports
exist, and 004–006 now embed runnable offline re-derivations over the retained captures. Those checks
are real evidence, but no report is published and there is no independent reviewer attestation, run
manifest, or separately retained reproduction artifact (`docs/evidence/reproductions/` still does not
exist). The embedded derivations therefore do not close PRD-32.

## Waves

| wave | tickets | concurrency/collision note |
|---:|---|---|
| 0 | T-F00 | Mechanical gates before all code |
| 1 | T-F01a, T-F02, T-F04c | Export, baseline contracts, hosted configuration staging are disjoint |
| 2 | T-F04g, T-F14a, T-F14b | Read-only hosted preflight, security signals, failure contracts |
| 3 | T-F04f, T-F11 | Reserved provider transport vs authorized target documentation |
| 4 | T-F03a, T-F04a | Judge and Red Team behavior are disjoint |
| 5 | T-F03b, T-F04b, T-F04h | Authorized role evals plus target-free smoke contracts |
| 6 | T-F04d | Hosted advisory adapters and target-free execute CLI |
| 7 | T-F05a, T-F05d, T-F05p | Lineage, target-session fixture, and tracked target catalog are disjoint |
| 8 | T-F04e, T-F05h | Target-free smoke reviews and authenticated deployment state |
| 9 | T-F05i | Authenticated current read-only repeatable-read control state |
| 10 | T-F05e | Immutable SMART lease context and fresh-state validator |
| 11 | T-F05j | Configuration/reference plus immutable job/queue persistence |
| 12 | T-F05k, T-F05l | Secure context loader and fixed controller-observation source are disjoint |
| 13 | T-F05m | Closed non-cached runtime fresh-state provider |
| 14 | T-F05f, T-F05o | Runner enforcement and bounded rotation control history are disjoint |
| 15 | T-F05n | Signed activation event and ordered rotation evidence |
| 16 | T-F05g | Zero-overlap configuration and complete-chain verifier/runbooks |
| 17 | T-F05c, T-F06a | Live-grant preflight and replay code are disjoint landed-chain consumers |
| 18 | T-F05b, T-F07a | Campaign evidence vs offline performance |
| 19 | T-F06b, T-F07b, T-F12 | Replay evidence, separately authorized load, architecture docs |
| 20 | T-F08, T-F09b, T-F13 | Cost, drills, integration docs |
| 21 | T-F09a, T-F10b | ATO vs reports/reproductions |
| 22 | T-F10a | Owner-merged release evidence |
| 23 | T-F10c | Demo/social package after release/report evidence |
| 24 | T-F15 | Project story after package |
| 25 | T-F01b | Final matrix/doc reconciliation last |

## Dependency graph

```text
T-F00 -> {T-F01a,T-F02,T-F04c,T-F14a}
T-F02 -> T-F14b
T-F04c -> T-F04g
{T-F04c,T-F04g} -> T-F04f
{T-F04c,T-F04f,T-F04g} -> T-F03a
{T-F02,T-F04c,T-F04f,T-F04g} -> T-F04a
T-F03a -> T-F03b
T-F04a -> T-F04b
{T-F02,T-F03a,T-F04a,T-F04f,T-F14b} -> T-F04h
{T-F03a,T-F04a,T-F04f,T-F04g,T-F04h} -> T-F04d
{T-F03a,T-F04a,T-F04c,T-F04d,T-F04h} -> T-F05a
T-F01a -> T-F11
T-F04h -> {T-F05d,T-F05p}
{T-F03b,T-F04b,T-F04d,T-F04h,T-F05a} -> T-F04e
{T-F05a,T-F05d} -> T-F05h
{T-F05a,T-F05h} -> T-F05i
{T-F05a,T-F05d,T-F05h,T-F05i,T-F05p} -> T-F05e
{T-F05e,T-F05h,T-F05i} -> T-F05j
{T-F05e,T-F05j} -> T-F05k
{T-F05h,T-F05j} -> T-F05l
{T-F05e,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l} -> T-F05m
{T-F05a,T-F05d,T-F05e,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05p} -> T-F05f
{T-F05h,T-F05i,T-F05j} -> T-F05o
{T-F05e,T-F05f,T-F05h,T-F05i,T-F05j,T-F05o} -> T-F05n
{T-F05e,T-F05f,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p} -> T-F05g
{T-F04h,T-F05a,T-F05d,T-F05e,T-F05f,T-F05g,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p} -> T-F05c
{T-F05a,T-F05d,T-F05e,T-F05f,T-F05g,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p,T-F14b} -> T-F06a
{T-F01a,T-F03b,T-F04b,T-F04e,T-F05a,T-F05c,T-F05d,T-F05e,T-F05f,T-F05g,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p,T-F11} -> T-F05b
T-F06a -> T-F07a
{T-F05b,T-F05d,T-F05e,T-F05f,T-F05g,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p,T-F06a} -> T-F06b
{T-F05b,T-F05d,T-F05e,T-F05f,T-F05g,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p,T-F07a} -> T-F07b
T-F05b -> {T-F08,T-F09b,T-F10b}
T-F07a -> T-F08
T-F07b -> T-F08
{T-F05b,T-F06b,T-F14b} -> T-F09b
{T-F08,T-F09b,T-F11,T-F12,T-F13,T-F14a,T-F14b} -> T-F09a
{T-F08,T-F09a,T-F09b,T-F13} -> T-F10a
{T-F10a,T-F10b} -> T-F10c -> T-F15
{T-F05d,T-F05e,T-F05f,T-F05g,T-F05h,T-F05i,T-F05j,T-F05k,T-F05l,T-F05m,T-F05n,T-F05o,T-F05p,T-F10c,T-F11,T-F12,T-F13,T-F15} -> T-F01b
```

[locked-decision] T-F04h is target-free smoke only. T-F05p owns the one tracked non-secret
Clinical Co-Pilot catalog: exactly two staging targets, identical Web/Runner bytes and hash,
chat surfaces enabled, other listed surfaces disabled, and only opaque Runner-resolved credential
bindings. Each campaign chooses one target, one chat/session generation, and one T-F05d patient.

T-F05h verifies signed controller observations; T-F05l is the only production acquisition channel;
T-F05m invokes T-F05l → T-F05h plus T-F05i on every call. T-F05j/T-F05k split
configuration/persistence from install/load/pin. T-F05o freezes and terminates the exact predecessor
campaign/job set. T-F05n authenticates activation and binds start → terminal → zero generations →
activation → one final generation. T-F05g verifies the whole chain. T-F05f uses the existing queue
sanitizer's fixed public message and a separate stable machine code/status.

Collision serialization includes root contracts T-F02 → T-F04h → T-F05d → T-F05h → T-F05i →
T-F05e → T-F05j → T-F05o → T-F05n; target/config T-F04c → T-F05p → T-F05e → T-F05j and
T-F05p → T-F05g; Runner T-F04c → T-F05a → T-F05f → T-F06a; `.env.example` and Railway Runner
T-F04c → T-F05p → T-F05g; runbooks T-F05g → T-F12/T-F13 → T-F01b. Every dependency is in a
strictly earlier wave; same-wave prefix/glob scopes do not overlap.

## Deadline triage (2026-07-24 noon)

### P0 — maximum safe deterministic proof path

1. Preserve the existing T-F00 through T-F04d deterministic order.
2. Land disjoint T-F05a lineage, T-F05d fixture authority, and T-F05p target catalog in wave 7.
3. Land T-F05h → T-F05i → T-F05e → T-F05j.
4. Run disjoint T-F05k loader and T-F05l fixed observation source, then T-F05m provider.
5. Run disjoint T-F05f Runner enforcement and T-F05o bounded history, then T-F05n evidence and T-F05g verifier.
6. Run T-F05c/T-F06a only after every T-F05d–T-F05p prerequisite passes independent review.
7. Keep controller/database/activation/campaign/replay/stress actions zero-call `BLOCKED` without exact authority.

[locked-decision] External authority may block operational evidence, never deterministic contracts,
tests, source channel, bounded history, event/evidence, delivery, Runner, rotation, or preflight.

### P1 — human/external evidence likely blocking noon

T-F03b, T-F04b, T-F04e, actual T-F05l/T-F05i observations, activation receipt, T-F05b, T-F06b,
T-F07b, T-F10b reproduction/publication, and T-F10a production deploy/GitHub-green exact GitLab
mirror.

### P2 — downstream packaging after immutable P0/P1 artifacts

T-F07a, T-F08, T-F09a/b, T-F12, T-F13, T-F10a/b/c, T-F15, final T-F01b.

## Human gates

- [open-question] Supply immutable `campaign.json` selecting exactly one T-F05p target, one enabled chat surface, one session generation, one complete T-F05d patient identity, exact caps/principals, and all dependency hashes.
- [open-question] Supply reviewed deployment/controller and control-projector trust roots, workload DB identity, immutable context reference, and maximum lifetime; none is inferred/defaulted.
- [open-question] Authorize actual controller IPC, private read-only database projection, activation action/receipt, campaign, replay, and stress separately. Absence means zero-action `BLOCKED`.
- [open-question] Provision only Runner-side sealed credential variables matching the catalog's opaque bindings. Web, jobs, prompts, reports, and artifacts never receive a value.
- [open-question] Keep non-chat surface adapters disabled until their own deterministic tests and independent code/security reviews land.
- [open-question] Retain distinct Evidence/Security reviewers, launcher/Approver, Judge, Red Team, replay, stress, reproduction, drill, publication, Railway/Clerk, and deployment authorities.
- [open-question] True production isolation plus owner main merge/deploy and equal dual-remote green CI remain required.

[locked-decision] Fewer than three genuine independently reproduced findings leaves PRD-32 incomplete.
