# Clinical Co-Pilot target and session readiness

**Reconciled:** 2026-07-26

**Target contract:** [`TARGETS.md`](TARGETS.md)

**Platform state:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

The external target passed read-only `/health` and `/ready` checks during this audit, and the latest
staging campaign made 16 authenticated target calls. Target reachability is therefore proven. It does
not make the full platform run-ready: campaign reliability, exact lease coverage, release parity,
hosted configuration, and authorization are separate gates.

## Observed and enforced facts

| Property | Current fact |
|---|---|
| Transport | exact allowlisted HTTPS host; redirects/private destinations denied |
| Governed surface | authenticated `POST /chat` |
| Request | one sealed session plus one authored turn |
| Multi-turn behavior | one physical target request per authored turn; all are policy-metered |
| Human auth | Clerk token terminates at Web and is never a target credential |
| Data | reviewed synthetic fixtures/canaries only |
| Client state | one campaign-owned `httpx` client preserves cookies/connections |
| Target retry | zero for live-100 |
| Latest traffic | 16 physical calls: 15 HTTP `200`, one HTTP `422` |
| Observed input constraint | the HTTP `422` rejected a message over the target's 4,000-character limit |
| Latest mean pace | roughly 72 seconds per completed case at provider concurrency one |

`target_request.status = succeeded` currently means a response was observed and durably recorded. It
does not mean the target accepted the application request; preserve the HTTP status and call the `422`
an application rejection.

## Session and lease invariant

One campaign may use one exact target-session generation:

1. The target definition contains an opaque credential reference and generation.
2. Runner-only binding resolves that reference to a sealed variable name.
3. Runner-only lease metadata records generation, UTC expiry, value hash, and expiry source.
4. Network-free preflight requires the lease to cover `now + run_timeout`, bounded by authorization
   expiry.
5. At first dispatch, Runner resolves the value and verifies its hash.
6. The same in-memory secret and campaign client are used for all turns.
7. Expiry or target-confirmed invalidity aborts; there is no silent refresh, replacement, or patient
   switch.
8. Terminalization closes the client and releases the runtime lease.

The usable launch deadline is `lease_expiry - approved_run_timeout`, not the lease expiry itself. For
a two-hour timeout, a lease ending at 20:00Z cannot launch after 18:00Z.

## Safe lease refresh

A lease timestamp is evidence, not an arbitrary number:

1. pause launches and confirm no deployment/restart or active campaign;
2. test the exact target session through an approved credential-safe liveness procedure;
3. confirm the revealed value still hashes to the same generation binding;
4. set only an issuer-supplied or conservatively justified expiry source;
5. restart/refresh the private Runner as required by configuration loading;
6. wait for a fresh Runner heartbeat and repeat preflight; and
7. create and approve a fresh campaign request after the final lease/policy/config state.

Never extend an expired or untested session just to pass preflight. Never print or copy its value/hash
into documentation or chat.

## Remaining target-specific unknowns

- issuer-guaranteed absolute lifetime versus the owner-reported 72-hour idle lifetime;
- exact cookie/response-derived state and cross-case conversation-history behavior;
- target-wide concurrency/rate ceiling;
- p95/p99 latency and timeout behavior across the full six-category workload;
- all application validation limits beyond the observed 4,000-character message limit; and
- enabled behavior for currently disabled upload, evidence-search, and write surfaces.

These require separate synthetic-only, authorized observation. Do not infer them from a health check.

## Launch checklist

- [x] live target is reachable in read-only health checks;
- [x] chat request shape and credential placement have offline contract tests;
- [x] one credential generation is pinned and silent replacement is rejected;
- [x] one campaign client is reused;
- [x] each multi-turn physical call is independently gated/accounted;
- [x] target-expired session is a typed abort;
- [x] the latest run proved authenticated target traffic and exact call lineage;
- [ ] the current lease covers the full new run timeout;
- [ ] Web/Runner/Scheduler and database head are re-verified;
- [ ] the reliability fixes in `PLAN.md` P1–P4 are deployed and accepted;
- [ ] exact current Judge calibration is enabled or advisory status is accepted;
- [ ] a fresh two-user authorization covers the exact batch;
- [ ] a complete 34-case batch and all Langfuse observations reconcile.

Until the unchecked per-run gates pass, do not launch merely because target health is green.
