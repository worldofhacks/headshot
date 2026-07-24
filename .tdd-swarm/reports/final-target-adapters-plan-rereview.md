# Final-target adapter remediation — plan re-review

**Verdict: REVIEW_CHANGES_REQUIRED**

**Findings: 0 Critical, 3 Important, 1 Minor.**

The repair closes the prior retry arithmetic, UI credential key, fixture
descriptor, immutable versioning, environment separation, conditional document
activation, ticket ownership, and prompt-write-scope findings. The specified
baseline `1ac3ee02be7855b638dd1fa43bb0612a3db5f025` exists at the equal local
`origin/swarm/final-submission-gap-closure` and
`gitlab/swarm/final-submission-gap-closure` refs, contains partial commit
`54b3a4d`, and matches the partial profile/catalog behavior described by the
plan. T-F16 execution worktrees must be created from that exact commit; the
current planning worktree's older HEAD is not an acceptable execution base.

## Remaining findings

### I1 — T-F16f does not own the user-launch authorization and persistence path required for real fanout

The plan says one user launch creates a versioned parent ScanPlan with distinct
authorized children (`docs/planning/final-target-adapters.md:112-118`), and
T-F16f requires a parent authorization hash and separate child scopes
(`tickets/T-F16f.md:30-38`). But T-F16f owns only campaign modules, Runner,
contracts, and migration documentation (`tickets/T-F16f.md:8-20`) and
explicitly excludes authorization creation (`tickets/T-F16f.md:52-53`). No
ticket owns the required control-plane/API/store/queue changes. At baseline,
the durable authorization and queue lifecycle still represents one
`AuthorizationScope`/surface. Runner-only fanout cannot safely convert that
single-surface authority into several child authorities, and an injected test
can pass without wiring a user's scan launch.

Required repair: add a predecessor or expand T-F16f to own a versioned,
durably persisted parent scan-authorization request/decision, its child scope
records, two-person approval, API launch contract, queue payload, idempotency,
and recovery. Tests must start at the real launch command/API, reload the
persisted plan, and prove each child was separately approved before Runner
fanout. The deployment grant in T-F16g cannot substitute for campaign
authorization.

### I2 — `full_surface_scan` can still be true while the known document surface is inactive

The repaired manifest correctly says no `full_surface_scan` claim is allowed
when any child is absent or incomplete
(`.tdd-swarm/final-submission-manifest.md:68`). The plan and T-F16f instead add
document children only when `2.1.0` is active and allow completion when every
*active* mandatory child succeeds
(`docs/planning/final-target-adapters.md:112,118`;
`tickets/T-F16f.md:34,37`). Under `2.0.0`, the known Week 2 document surface can
therefore be reported `not_authorized_or_not_active` while the aggregate still
claims `full_surface_scan=true`. That contradicts both the manifest and the
owner requirement that a launched full scan use every available target
surface.

Required repair: the expected child set must always include lab and intake
document child records. An inactive/unproved document surface must force
`full_surface_scan=false`; if useful, expose a distinct
`active_surface_scan_complete=true` field. Add RED tests for v2.0, failed
fixture proof, and partial v2.1 activation.

### I3 — The networkless verifier has no trusted freshness/provenance contract for “current state”

T-F16g compares the grant to caller-supplied release, deployment, session,
fixture, scan, and rollback files (`tickets/T-F16g.md:29-33`). It claims to
prove current Railway topology/deployments and a Runner-only fixture binding,
while its tests require zero network, zero fixture open, and zero resolver
access (`tickets/T-F16g.md:35-38`). Neither T-F16g nor T-F16h requires those
state files to be signed by a trusted observer, content-addressed in the grant,
fresh within a bounded `observed_at/max_age` window, or regenerated after each
deployment step. A stale or fabricated manifest can therefore agree with the
grant while the linked Railway project, deployment, secret generation, or
fixture binding differs. Re-running the same offline comparison “before every
mutation” does not close that TOCTOU gap
(`.tdd-swarm/prompts/T-F16h-execute.md:2`).

Required repair: define a versioned, signed/provider-observed current-state
attestation with issuer, environment/project/service IDs, observation time,
expiry/max age, monotonic deployment identifiers, and raw-response digest.
Bind its hash and trusted issuer key to the deployment grant. T-F16h must
refresh it through an exact read-only observation step after each deployment
transition, then rerun T-F16g before the next mutation. Runner fixture
availability must also receive an actual post-deploy zero-target-call check
before the v2.1 activation event.

### M1 — The exact preflight command uses an unavailable interpreter name

T-F16g and T-F16h mandate `python scripts/preflight_final_target_adapters.py`
(`tickets/T-F16g.md:29`; `.tdd-swarm/prompts/T-F16h-execute.md:2`), but this
workspace has no `python` executable; only `python3` is discoverable. An “exact”
security gate that cannot run is not an executable contract.

Required repair: use the repository's mechanically discovered and
provenance-recorded interpreter (or an exact `python3` command) consistently in
the ticket, tests, execute prompt, and release evidence.

## Closed prior findings

- Retry policy is hash-bound; upload retry is zero; lab is 34 logical/67
  physical; intake is 2/2; capacity 66 refuses before upload.
- UI uses exact query key `sid`; chat/documents use `session_id`; evidence is
  credential-free.
- Complete fixture descriptors are authorization-bound.
- v1 remains immutable; environment-specific v2.0 catalogs keep documents
  disabled; v2.1 activation is fixture-proof gated.
- T-F16f and T-F16g now own deterministic fanout and grant-verifier code,
  respectively, subject to I1/I3.
- All T-F16a-g Test/Implementation prompts include their exact report paths in
  their write allowlists, and same-wave T-F16c/T-F16d scopes are disjoint.
