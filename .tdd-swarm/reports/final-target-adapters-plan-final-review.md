# Final-target adapter remediation — final plan review

**Verdict: REVIEW_PASS**

**Findings: 0 Critical, 0 Important, 0 Minor.**

## Scope

Re-reviewed the repaired final-target plan, T-F16a-h tickets, all T-F16
prompts, `TICKETS.md`, and the final-submission manifest against the two prior
review reports. Also verified the integration baseline and migration sequence
without opening either credential-bearing `Runtime.bru`.

## Closure of the four prior findings

1. **Durable user-launch authority — closed.** T-F16f now owns the real
   API/control-plane/store/migration/queue path. Its acceptance criteria and
   RED/implementation/review prompts require an immutable parent ScanPlan, the
   fixed eight-child declared scope, distinct durable parent/child decisions,
   two-person approval, atomic idempotent launch, content-addressed queue
   payloads, authoritative reload/recovery, and Runner revalidation before
   fanout.
2. **Truthful full-surface reporting — closed.** `full_surface_scan` is rejected
   throughout the plan, ticket, manifest, and prompts. All eight child records
   are always present; inactive or unproved lab/intake children force
   `declared_scope_complete=false`. `active_surface_scan_complete` is explicitly
   narrower and cannot support a full-target claim.
3. **Trusted current-state provenance/freshness — closed.** T-F16g now owns an
   injectable read-only observer, canonical Ed25519-signed current-state
   attestation, trusted issuer/key binding, freshness/maximum age, monotonic
   deployment state, raw provider-response digests, input hashes, and a
   zero-action verifier. T-F16h requires a fresh observation and a distinct
   approver's attestation-bound immutable transition grant before every next
   mutation/call, including actual post-deployed-Runner fixture proof before
   document activation.
4. **Executable interpreter contract — closed.** Tickets and execution/test/
   review prompts consistently use exact `python3` observer and verifier
   commands and bind interpreter realpath, version, executable digest, script,
   dependency set, and release provenance.

## Preserved gates

- Exact UI query key `sid`; chat/document key `session_id`; anonymous evidence
  has no credential resolution.
- Retry policy is authorization/hash-bound; upload retries are zero; lab is 34
  logical/67 physical and intake 2/2, with aggregate retry-inclusive
  reservation before dispatch.
- Complete fixture descriptors are bound and verified through a Runner-only,
  zero-target-call check.
- Version `1.0.0` remains immutable history; environment-specific `2.0.0`
  catalogs leave documents disabled; `2.1.0` is separately hashed and
  proof-gated.
- Same-wave T-F16c/T-F16d scopes remain disjoint. T-F16a-g test and
  implementation prompts retain exact report paths in their write allowlists.
- Migration `0016` follows the baseline's existing `0015` head.
- The exact execution baseline remains
  `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`, which includes `54b3a4d`.

## Operational boundary

This pass approves the remediation packet for TDD dispatch; it does not assert
that the code or deployment already exists. T-F16h correctly remains
`BLOCKED` until the separately supplied signed transition grants, trusted
observer/signing identity, Runner-only fixture binding, and distinct production
promotion authority are available. That honest external-authority gate is not
a plan defect.
