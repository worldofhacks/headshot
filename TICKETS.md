# Tickets — Final submission gap closure (session-lease scope repair round 3)

[locked-decision] Base `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, dual CI green.
Four slots total means coordinator + at most three workers. No deadline compresses RED → test review
→ freeze → GREEN → coordinator gate rerun → code review → security review.

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
T-F07b, T-F10b reproduction/publication, and T-F10a deploy/dual-CI.

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

## Console page-truth remediation addendum

Planning sources: `docs/planning/full-console-remediation.md` and
`docs/planning/console-pages-remediation.md`. The one global sequence below is mechanical:
T-F16f owns target/surface fanout; T-F17 owns hosted-agent runtime; T-F19 owns per-tool ScanPlan,
brokers, fanout, reconciliation, and event producers; T-F18 owns read models and console behavior.
Do not start RED before every listed dependency completion commit is present. Rebase the combined
branch after T-F16f/T-F17f and before T-F19a. Shared file scopes serialize by these waves.

| wave | ticket | outcome | dependencies |
|---:|---|---|---|
| 29 | T-F18j | Accounting/Birdseye unknown-usage bridge | T-F17b, T-F17c |
| 30 | T-F17e | Hosted runtime deployment | T-F17d, T-F18j |
| 31 | T-F17f | Agents/runtime projection | T-F17e |
| 32 | T-F19a | Versioned persisted Tool ScanPlan | T-F16f, T-F17f |
| 33 | T-F19b | Offline/repository tool brokers | T-F19a |
| 34 | T-F19c | Separately authorized passive ZAP | T-F19b |
| 35 | T-F19d | Per-tool fanout and reconciliation | T-F19c |
| 36 | T-F19e | Real event producers and polling recovery | T-F19d |
| 37 | T-F18a, T-F18b | Navigation plus collection seam | T-F16f, T-F17f, T-F19e |
| 38 | T-F18o | Residual DB pagination | T-F18b, T-F17f, T-F19e |
| 39 | T-F18c | Coverage & Regression | T-F18a, T-F18o |
| 40 | T-F18d | Five-state Tooling projection | T-F18c, T-F19e |
| 41 | T-F18e | Evidence-derived Birdseye | T-F18d, T-F19e |
| 42 | T-F18f | Complete Findings | T-F18e, T-F18o |
| 43 | T-F18g | Exhaustive material-command confirmation | T-F18b, T-F18f, T-F17f |
| 44 | T-F18h | Canonical target/readiness truth | T-F18g, T-F16f |
| 45 | T-F18i | Unified trace lineage | T-F18b, T-F18h, T-F17f |
| 46 | T-F18p | Full Costs UI, filters, and stable DB paging | T-F18j, T-F17f, T-F18b, T-F18o, T-F18i |
| 47 | T-F18k | Durable Live selection and refresh | T-F18d/e/g/h/i/p, T-F19e |
| 48 | T-F18m | Configuration plus embedded Audit | T-F18k, T-F18o, T-F17f, T-F19e |
| 49 | T-F18l | Deterministic route/accessibility manifest | all deterministic predecessors |
| 50 | T-F18n | Authenticated exact-SHA production evidence | T-F16f, T-F17f, T-F19e, T-F18l |
| 51 | T-F19f | Separately approved per-target 100-case/tool-plan runs | T-F16f, T-F17f, T-F19e, T-F18n |

T-F18j is an early backend-only bridge between T-F17c and T-F17e so unknown hosted usage cannot be
coerced to zero in the deployment path. T-F18p owns the later Costs UI/filter/paging after T-F17f,
T-F18b/o, and T-F18i. T-F18n and T-F19f are operational and use execute/evidence/security review
rather than RED/GREEN; either may truthfully remain `BLOCKED` when owner grants are absent.

[locked-decision] Coverage stays and is renamed **Coverage & Regression**. The standalone
Resilience page/navigation is removed, while `/resilience` temporarily replace-redirects to
`/coverage`. Audit remains permission-gated inside Configuration. Tooling cannot claim all-tools
completion unless installed, configured, generated, executed, and evidenced/adjudicated are
independently supported for every applicable immutable ScanPlan item.
