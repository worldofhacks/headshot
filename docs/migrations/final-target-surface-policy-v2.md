# Final target surface-policy v2 migration

This migration replaces target-wide request shaping with one immutable policy for each attack
surface. The version sequence is `1.0.0 -> 2.0.0 -> 2.1.0`.

## Hash break

Version 2 adds the complete `surface_policy` and its independently reproducible
`surface_policy_sha256` to every surface definition and authorization scope. Both values become
inputs to `scope_hash`. Exact adapter profile, authentication facts, credential placement and
field, typed operations, retry-inclusive limits, and complete fixture descriptors therefore change
the authorization hash even when a target ID or route is unchanged.

## Old approval invalidation

`1.0.0 approvals cannot authorize 2.0.0`. Stored v1 approvals remain immutable audit and rollback
history, but they do not contain the v2 policy bytes or policy digest and must fail closed during
registry resolution. Operators must request and independently approve each exact v2 surface scope;
an old target-wide approval, path heuristic, or target authentication fallback is not reusable.

## Staged activation

Activate the canonical non-document target and surface definitions at `2.0.0` first. At `2.0.0`,
document surfaces remain disabled while chat, UI, and anonymous evidence surfaces can be validated
under their separate policy hashes. After the Runner proves the exact private fixture descriptors
without a target call, stage the separately hashed `2.1.0` definitions and approve the document
surfaces individually. No in-place mutation of either version is permitted.

## Rollback

On any policy, fixture, authorization, deployment, or bounded-proof failure, perform a
rollback to 2.0.0 and disable document surfaces. Revoke or expire affected `2.1.0` approvals and
record the lifecycle transition as an append-only event. Rollback never converts a v1 approval
into v2 authority and never changes the frozen definitions or hashes retained for audit.

## Legacy compatibility

A legacy single-profile, single-surface chat catalog remains readable for controlled v1 and
synthetic compatibility. A legacy target-wide `payload_profiles` set, a mixed legacy/v2 entry, or a
v2 target without complete per-surface policy is ambiguous and rejected. Legacy compatibility does
not authorize new UI, evidence, or document surfaces.
