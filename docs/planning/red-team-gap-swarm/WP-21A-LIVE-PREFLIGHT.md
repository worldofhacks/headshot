# WP-21A — Lock the live authorization and deployment preflight

**Branch:** `rtg/wp21a-live-preflight`

**Model:** capable

**Depends on:** reviewer-approved WP-20 release candidate

**Closes:** nothing; this zero-call prompt admits or blocks live execution

Use an identity distinct from every executor, campaign approver, Evidence Reviewer, Security
Reviewer, Judge, and publisher. Read `ROLE-LIVE-EVIDENCE-EXECUTOR.md` for the live-only
contract, but perform no live execution in this package.

**Writes only**

- `docs/evidence/authorized-red-team/preflight/live-preflight-manifest.json`
- `docs/evidence/authorized-red-team/preflight/live-preflight-summary.md`
- `.tdd-swarm/reports/RTG-WP21A-live-preflight.md`

Source, tests, deployment configuration, authorizations, credentials, prior evidence, and
review records are read-only.

## Required result

Produce one canonical, signed/hash-bound, immutable manifest that either admits exact live
lanes or blocks them before any secret resolution, process start, provider call, or target
request. Verify from owner-provided immutable attestations:

- the same exact SHA is deployed on Railway, present at `origin/main` and `gitlab/main`, and
  has green GitHub and GitLab CI;
- only Railway Web is public and Runner, Scheduler, and Postgres remain private;
- the exact Headshot Clerk organization, custom permissions, and test-user memberships;
- a valid WP-08 ownership record for the exact deployed OpenEMR URL, IP/network policy,
  certificate identity, target version, and each exact surface;
- the target is a deployed live test environment isolated from production patient data,
  with a bounded seeded synthetic non-PHI live-data namespace and provisioned test
  principals, opaque resource IDs, cleanup/rollback policy, and an explicit attestation
  that its environment and backing data stores contain no real PHI or production patient
  records;
- exact release, target, surface, corpus, case, provider/model, native tool/image/profile,
  browser, ZAP, OAST, collector, Judge, oracle-policy, and contract hashes;
- fresh credential leases, collector identities/key versions, calibration eligibility,
  evidence destinations, retention, and sanitation rules;
- distinct launcher/approver/executor/reviewer/Judge/publisher identities;
- separate immutable authorization for provider generation, target campaigns, active ZAP,
  browser, OAST, upload/write, load/resource tests, and any failure-injection operation;
- exact request/turn/frame/reconnect/attempt/token/USD/time/rate/concurrency/data-write/
  callback caps and the lower-of-authorization/platform rule;
- one persisted target-wide limiter and abort epoch checked before every physical action.

Create disjoint lane records for WP-21B, WP-21C, and WP-21D. Each binds its exact surfaces,
principals, seeded live resource namespace, campaign IDs, authorizations, caps, evidence
directory, start window, and cleanup owner. Parallel execution is allowed only when:

1. lane resource/principal/session namespaces and output directories are disjoint;
2. the sum of lane maxima is at or below every target-wide cap;
3. the production limiter and abort path enforce the aggregate cap atomically;
4. concurrent state cannot invalidate an oracle or contaminate another lane;
5. the owner authorization explicitly permits that concurrency.

Otherwise set `execution_mode: serial`. Never infer permission from three available agent
slots.

Reject a wildcard, stale, mutable, self-approved, mismatched, unverifiable, or partially
signed input. Reject any proposal to use a mock, fixture adapter, cassette, fake target,
loopback/in-process harness, simulated artifact, local application server, or production
patient data. A missing live dependency produces a lane-specific blocker, not substitute
evidence.

## Verification

Canonicalize and recompute every referenced hash with checked-in read-only tools. Perform no
network lookup, health request, secret resolution, deployment/route mutation, process start,
provider/tool invocation, target request, scan, OAST reservation, spend, publication, push,
or merge. If the required deployment/CI/authorization attestations are not already
available and verifiable, return `BLOCKED(preflight evidence missing)`.

Return:

`APPROVED_FOR_EXACT_LANES | BLOCKED(reason)`

plus the manifest SHA-256, admitted/blocked lanes, required execution mode, aggregate caps,
expiry, and one-line blocker summary.
