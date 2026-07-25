# WP-21B — Validate platform controls on the deployed system

**Branch:** `rtg/wp21b-live-platform-controls`

**Model:** capable

**Depends on:** approved WP-21A manifest admitting this lane

**May close with approved evidence:** live-control portions of RT-09–RT-14

Read and follow `ROLE-LIVE-EVIDENCE-EXECUTOR.md`. Use only this lane's immutable manifest
entry and exact authorizations.

**Writes only**

- `evals/results/authorized/platform-controls/**`
- `docs/evidence/authorized-red-team/platform-controls/**`
- `.tdd-swarm/reports/RTG-WP21B-live-platform-controls.md`

## Required live matrix

Exercise the exact deployed Railway release and production paths, using provisioned live
test users and seeded synthetic non-PHI records:

1. **Clerk and public boundary:** verify meaningful console/API access requires the exact
   Headshot organization and backend custom permission; test cross-org, missing/revoked/
   expired membership, CSRF/origin/session, object ownership, and public-route denial.
2. **Private service and DB roles:** demonstrate from deployed service attestations and
   authorized live operations that Web, Runner, Scheduler, Recorder, and migration roles
   have only their intended Postgres privileges and cannot borrow an authority-bearing pool.
3. **Physical dispatch:** demonstrate a fresh persisted permit immediately before every
   authorized send/retry/turn/frame/reconnect, exact target/surface binding, final cap
   recheck, and zero alternate target egress.
4. **Destination and delivery:** demonstrate production DNS resolution/pinning, certificate
   identity, Host/SNI binding, redirect denial, and typed delivery certainty on exact
   owner-provided live validation surfaces. If the live target contract does not expose a
   safe case for an invariant, report it blocked; do not create a local substitute.
5. **Abort, lease, and recovery:** under separately authorized bounded failure injection,
   demonstrate target-wide abort, lease loss, worker termination/reclaim, ambiguous-delivery
   quarantine, and no duplicate side effect in the isolated live test environment. Never
   induce a destructive or unbounded condition or perform failure injection on a production
   patient environment.
6. **Readiness and evidence status:** verify the deployed API becomes ready only with the
   sole packaged DB head, actual role/grant checks, and required private dependencies.
   Separately verify that the API/UI show this lane's evidence as pending review until the
   later WP-21 reconciliation; stale or local-only artifacts cannot turn evidence status
   green. Final reconciliation is not a readiness dependency.
7. **Release security tools:** verify fresh genuine GitHub and GitLab Semgrep, pip-audit,
   npm-audit, and Gitleaks jobs for the exact deployed SHA, pinned versions/configuration,
   complete retained artifacts, exit semantics, attestations, and cross-CI parity. Checked-in
   sample output or a local rule-vector run cannot satisfy this item. Record approved output
   only as `VERIFIED_RELEASE_CONTROL`, never an operational target capability or behavioral
   coverage.

Every result must bind release/deployment identity, service identity, authorization,
principal/resource namespace, operation/permit/send/delivery/DB/evidence ledgers, timestamps,
caps, abort epoch, and sanitized observations. A test that cannot be performed safely and
live remains `BLOCKED_LIVE_CONTROL_EVIDENCE`.

Do not use a local Postgres instance, local app server, loopback endpoint, fake DNS resolver,
fake target, injected transport, mock Clerk token, cassette, or simulated queue/process as
evidence. Do not alter deployment configuration, privileges, routes, authorizations, or
production data.

Run independent cleanup verification for the lane's seeded live resources. Return the Live
Evidence Executor status contract with exact manifest/evidence hashes and per-control
pass/partial/blocked states.
