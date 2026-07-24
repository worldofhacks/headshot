# Tickets — Final submission gap closure (final review repair)

[locked-decision] Base `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, dual CI green. Four slots total means coordinator + at most three workers. No deadline compresses RED → test review → freeze → GREEN → coordinator gate rerun → code review → security review.

## Waves

| wave | tickets | concurrency/collision note |
|---:|---|---|
| 0 | T-F00 | Mechanical gates before all code |
| 1 | T-F01a, T-F02, T-F04c | Export, baseline contracts, atomic hosted configuration staging are disjoint |
| 2 | T-F04g, T-F14a, T-F14b | Read-only hosted preflight, security signals, failure contracts are disjoint |
| 3 | T-F04f, T-F11 | Reserved provider transport vs authorized target documentation |
| 4 | T-F03a, T-F04a | Judge and Red Team behavior are disjoint consumers |
| 5 | T-F03b, T-F04b, T-F04h | Two optional authorized role evals plus deterministic smoke contracts/verifier |
| 6 | T-F04d | Hosted advisory adapters and composed target-free execute CLI |
| 7 | T-F05a | Durable lineage after contract and composition interfaces |
| 8 | T-F04e, T-F05c, T-F06a | Authorized target-free smoke/reviews, deterministic live-grant preflight, replay code |
| 9 | T-F05b, T-F07a | Campaign evidence vs offline performance |
| 10 | T-F06b, T-F07b, T-F12 | Replay evidence, separately authorized load, architecture docs |
| 11 | T-F08, T-F09b, T-F13 | Cost, drills, integration docs are disjoint |
| 12 | T-F09a, T-F10b | ATO vs reports/reproductions |
| 13 | T-F10a | Owner-merged release evidence |
| 14 | T-F10c | Demo/social package after release/report evidence |
| 15 | T-F15 | Project story after package |
| 16 | T-F01b | Final matrix/doc reconciliation last |

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
{T-F03b,T-F04b,T-F04d,T-F04h,T-F05a} -> T-F04e
{T-F04h,T-F05a} -> T-F05c
{T-F01a,T-F03b,T-F04b,T-F04e,T-F05a,T-F05c,T-F11} -> T-F05b
{T-F05a,T-F14b} -> T-F06a -> {T-F06b,T-F07a}
T-F05b -> {T-F06b,T-F07b,T-F08,T-F09b,T-F10b,T-F13}
T-F07a -> {T-F07b,T-F08}
{T-F03a,T-F04a,T-F04c,T-F04d,T-F04e,T-F04f,T-F04g,T-F04h,T-F05a,T-F05c,T-F06a,T-F11,T-F14a,T-F14b} -> T-F12
{T-F02,T-F03a,T-F04a,T-F04c,T-F04d,T-F04e,T-F04f,T-F04g,T-F04h,T-F05a,T-F05b,T-F05c,T-F06a,T-F14a,T-F14b} -> T-F13
{T-F08,T-F09b,T-F11,T-F12,T-F13,T-F14a,T-F14b} -> T-F09a
{T-F08,T-F09a,T-F09b,T-F13} -> T-F10a
{T-F10a,T-F10b} -> T-F10c -> T-F15 -> T-F01b
```

[locked-decision] T-F04c owns configuration/settings/runtime/store/model/migration and atomic staging with release+canonical-full-input idempotency. T-F04g separately owns activation/preflight/Birdseye projection and performs no writes. T-F04f owns provider credential resolution, atomic worst-case reservation, reconciliation, and transport. T-F04h owns registry/schemas/fixture/verifier; T-F04d owns adapters/composition/execute plus create-only atomic dual-manifest publication. T-F05c separately owns the additive read-only `campaign.json` plus reviewed-smoke live preflight. Runtime/store overlap remains serialized T-F04c → T-F05a; Birdseye overlap is serialized T-F04g → T-F05a; runner remains T-F05a → T-F06a. Root/package contracts are serialized T-F02 → T-F14b → T-F04h. Same-wave scopes do not overlap.

## Deadline triage (2026-07-24 noon)

### P0 — maximum safe deterministic proof path

[proposed] Owner lane immediately requests campaign, Judge, Red Team, load, replay/reproduction/publication, Railway/Clerk and GitLab authorities. This does not consume a worker slot.

1. Coordinator runs T-F00 alone.
2. Three workers run T-F01a/T-F02/T-F04c through full gates.
3. Three workers run T-F04g/T-F14a/T-F14b through full gates.
4. T-F04f and T-F11 proceed when their code/document prerequisites are present; missing target authority affects only T-F11 evidence.
5. T-F03a/T-F04a deterministic code proceeds after T-F04f/T-F04g without waiting for Judge or Red Team provider authorization.
6. T-F04h deterministic contracts/fixture/verifier proceeds after its code dependencies even when T-F03b/T-F04b remain zero-call `BLOCKED`.
7. T-F04d deterministic adapters/composed CLI proceeds after T-F04h and its code dependencies; it must not wait for external provider authorization. Its injected-transport stage→preflight→execute→offline-verify proof remains zero-network.
8. T-F05c deterministic code proceeds after T-F04h/T-F05a without a live grant; injected fixtures prove that its public verifier reads `campaign.json`, derives smoke/review expectations from it, and composes existing Policy Gateway checks with zero actions.
9. Only T-F03b, T-F04b, T-F04e and later operational evidence require exact external authorizations. T-F05b cannot bypass T-F05c, either immutable T-F04e review record, the target/allowlist/synthetic gate, or the SMART lease/caps.
10. Preserve green deterministic artifacts/hashes and report missing human authority honestly.

[locked-decision] This is a maximum safe proof path, not a promise of full submission completion by noon. External authorization may block evidence, never deterministic T-F04h/T-F04d/T-F05c implementation or their no-network tests.

### P1 — human/external evidence likely blocking noon

T-F03b, T-F04b, T-F04e execution/evidence/security reviews, T-F05b, T-F06b, T-F07b, T-F10b reproduction/publication, T-F10a deploy/dual-CI.

### P2 — downstream packaging after immutable P0/P1 artifacts

T-F07a, T-F08, T-F09a/b, T-F12, T-F13, T-F10a/b/c, T-F15, final T-F01b. These remain honest blockers if prerequisites miss the deadline.

## Human gates

- [open-question] Immutable `campaign.json` grant binding exact staging target/surface/scheme-host-port/allowlist+hash, corpus ID/hash, synthetic-only fixture IDs/hashes, release/current deployment, T-F04g provider-role configuration and policy hashes, canonical T-F04e manifest plus unequal review hashes, aggregate/per-role calls/retries/input-output-reasoning tokens/USD/rate/concurrency/timeout/wall-clock/abort caps, expiry/operation nonce, launcher, distinct Approver, and SMART credential-reference/session-lease generation/expiry/target binding.
- [open-question] Separate bounded Judge and Red Team provider authorization artifacts and budgets.
- [open-question] A bounded `target_scope:none` four-role OpenRouter smoke authorization binding exact requested/returned/upstream identities, four role-scoped sealed credential references, policy/catalog/data-policy hashes, authorization-bound catalog input/output/reasoning prices and `max_price`, maximum input/output/reasoning tokens, synthetic fixture hash, expiry, approver, and aggregate/per-role call/token/USD/rate/time/retry/concurrency caps.
- [open-question] Distinct non-executor Evidence and Security reviewer identities for create-only T-F04e review records; campaign authorization must bind their unequal canonical SHA-256 values.
- [open-question] Owner acceptance or replacement of the readiness report's proposed four distinct model IDs, catalog-price snapshot, `max_price`, and spend envelope; none is a runtime default or authorization.
- [open-question] Separate replay, 100-case stress, reproduction, failure-drill, critical-publication and social-publication authority.
- [open-question] True production isolation/credentials; absent this, staging only.
- [open-question] Owner main merge/deploy and equal dual-remote green CI.

[locked-decision] Fewer than three genuine independently reproduced findings leaves PRD-32 incomplete.
