# Final-target adapter remediation — adversarial plan review

**Verdict: REVIEW_CHANGES_REQUIRED**

**Findings: 1 Critical, 6 Important, 1 Minor.**

## Scope reviewed

This review checked `Week_3_AgentForge.pdf`, `AGENTS.md`, `CLAUDE.md`,
`.claude/skills/tdd-swarm/SKILL.md`, `docs/planning/final-target-adapters.md`,
`tickets/T-F16a.md` through `tickets/T-F16f.md`, all 28 T-F16 prompts,
`TICKETS.md`, `.tdd-swarm/final-submission-manifest.md`, the current target,
Runner, Policy Gateway, coordinator, serialization, registry, and catalog code,
the tracked final-target catalog, and the owner Bruno request contracts without
opening either `Runtime.bru`.

## Findings

### C1 — Retry-aware physical capacity is understated, so a state-changing flow can start without capacity to finish

The plan calls the lab workflow's `1 + 30 + 3` operations “34 physical
requests” and the intake workflow “2” (`docs/planning/final-target-adapters.md:49-51`;
`tickets/T-F16d.md:31`). At the same time, T-F16b explicitly retains retries and
requires each retry to be charged (`tickets/T-F16b.md:26-30`), while the current
gateway permits three physical dispatch attempts per operation
(`src/agentforge/policy/gateway.py:427-440`). A flow in which each operation
fails twice and succeeds on the third can therefore consume 102 physical lab
requests, not 34. That already exceeds each tracked target's
`max_attempts_per_run: 100` (`config/targets/clinical-copilot-20260724.json:24-28`,
`169-173`). Reserving only 34 permits the upload to occur before a later cap
failure, directly contradicting the promised complete-flow check before the
first state-changing operation (`docs/planning/final-target-adapters.md:69`;
`tickets/T-F16b.md:26`).

Required repair:

- Bind an exact retry policy per operation class into the canonical surface
  policy and authorization hash.
- Define the declared physical maximum as the sum of all possible physical
  attempts, including retries, or explicitly prohibit retries for the document
  operations.
- For state-changing uploads, specify the idempotency evidence that permits a
  retry after an ambiguous timeout; otherwise retry must be zero.
- Make preflight reserve attempts, cost, rate-window time, authorization time,
  and trace capacity using that physical maximum.
- Add RED tests for fail-twice/succeed-third paths, a full 30-poll path, an
  ambiguous upload timeout, and refusal with zero calls when the full physical
  maximum cannot fit.

### I1 — The UI credential query key does not match the owner contract

The owner README's Week 1 and Week 2 UI URLs use the query key `sid`. The plan
and ticket instead specify `session_id`
(`docs/planning/final-target-adapters.md:36`;
`tickets/T-F16c.md:26`). The document endpoints do use `session_id`; the two
placements are not interchangeable. T-F16a binds a generic “credential
placement” but does not require the exact parameter name
(`tickets/T-F16a.md:29-31`), so the policy hash would not prevent this mistake.
The resulting UI probe can return an unauthenticated shell or failure and still
be misclassified as surface availability.

Required repair: bind the exact credential field name into every operation
policy and its hash; use `sid` only for `/app` and `/week2`, retain
`session_id` for chat/document contracts, and add literal-canary tests proving
that no alternate query/header/cookie/body placement is accepted or retained.

### I2 — T-F16e attempts to mutate immutable catalog versions in place

The tracked targets and all seven surfaces are version `1.0.0`
(`config/targets/clinical-copilot-20260724.json:6`, `34-36`, `65-67`,
`96-98`, `151`, `179-181`, `210-212`, `241-243`, `272-274`). T-F16e changes
their serialized definitions by adding surface policies and flips five
`enabled` values, but neither its acceptance criteria nor prompts require new
target/surface versions (`tickets/T-F16e.md:23-31`;
`.tdd-swarm/prompts/T-F16e-implement.md:2`). The control plane rejects an
existing surface ID/version as immutable
(`src/agentforge/control_plane/store.py:312-380`), and catalog synchronization
reuses idempotency keys derived from the existing target version
(`src/agentforge/target/catalog.py:192-203`). Because surface registration also
requires a draft target (`src/agentforge/control_plane/store.py:340-353`), this
cannot be repaired by silently adding a new surface snapshot under the already
ready target version.

Required repair: define a concrete new target version with new surface versions,
preserve the old snapshots/approvals, synchronize the new draft target and its
surfaces, transition it through validation/readiness, and activate only via
state events. Tests must prove old approvals fail against the new policy hashes
and repeated synchronization is idempotent.

### I3 — One staging-bound catalog cannot satisfy the promised production validation

Both tracked target definitions say `environment: staging` and carry staging
credential references (`config/targets/clinical-copilot-20260724.json:8-14`,
`153-159`). `TrustedTargetCatalog.from_environment` rejects any target whose
embedded environment differs from the selected control-plane environment
(`src/agentforge/target/catalog.py:118-146`). Nevertheless T-F16e says this one
catalog loads for “Staging or production” (`tickets/T-F16e.md:29`), and T-F16f
claims production promotion enables the same seven policies
(`tickets/T-F16f.md:28`). Production cannot pass the current loader with this
artifact, and rewriting it during deploy would change authorization hashes.

Required repair: own separate secret-free staging and production catalogs, or
own a deterministic environment overlay whose exact output is hashed and
authorized. Environment, credential reference, ownership/promotion
authorization, policy hashes, and fixture binding must be environment-specific.
Web/Runner parity is required within each environment; the two environments
must not be asserted byte-identical.

### I4 — Fixture identity is not fully authorization-bound, yet T-F16e enables the document surface unconditionally

T-F16a binds fixture references but does not require each reference's expected
digest, byte length, media type, and fixed `doc_type` in the canonical policy
(`tickets/T-F16a.md:29-33`). T-F16d relies on those values to decide what bytes
may be uploaded (`tickets/T-F16d.md:25`), leaving an unstated choice between
target-specific constants in code and mutable deployment metadata. The plan
also admits that no Runner-only fixture binding is proven
(`docs/planning/final-target-adapters.md:103-106`), while T-F16e requires all
seven surfaces enabled in the tracked catalog
(`tickets/T-F16e.md:29`; `.tdd-swarm/prompts/T-F16e-implement.md:2`).
Deterministic adapter tests cannot prove deploy-time fixture availability, so
this produces an enabled capability that may be unusable.

Required repair: make the complete fixture descriptor
`{opaque_ref, sha256, byte_length, media_type, doc_type, workflow_id}` part of
the surface policy and authorization hash. Keep the document surface disabled
in deployable environment catalogs until zero-call preflight verifies the
Runner-only no-follow binding. Activation must be a separately authorized state
change after that proof; failure must leave chat/evidence/UI unchanged.

### I5 — The current one-surface campaign lifecycle cannot execute the claimed all-seven scan

An authorization scope contains one `surface_id`, method, and relative path
(`src/agentforge/target/spec.py:479-605`). Runner resolves one surface and
builds one `PreparedRun` (`src/agentforge/runner.py:334-419`), and the
coordinator owns one adapter and one run-scoped gateway
(`src/agentforge/campaign/coordinator.py:240-256`, `560-585`). T-F16e is scoped
only to `runner.py` and the catalog, yet AC-5 claims a full platform run across
all seven surfaces (`tickets/T-F16e.md:30`). A test can manually instantiate
seven adapters, but that does not make a user-launched scan fan out across
seven separately authorized surfaces or aggregate their outcomes.

Required repair: add an explicit scan-plan/coordinator ticket that derives
seven child executions from one user launch, each with its own exact
surface-policy scope/hash and cap reservation, then aggregates sanitized
outcomes without sharing an anonymous/authenticated credential context. Define
failure and abort semantics, session pinning, document fixture selection, and
whether a failed child prevents later children. Without that work, narrow
T-F16e's claim to per-surface composition rather than “full” scan execution.

### I6 — No deterministic ticket owns the deployment-grant verifier that T-F16f requires

T-F16f requires an “exact zero-call grant/current-state preflight” before any
mutation (`.tdd-swarm/prompts/T-F16f-execute.md:2`) and AC-1 specifies a new
deployment-grant contract (`tickets/T-F16f.md:24`). But T-F16f owns only
documentation/evidence paths and has no tests (`tickets/T-F16f.md:8-12`);
T-F16a-e own no deployment verifier or grant schema. Repository search shows
no existing final-target deployment verifier. The operational executor would
therefore have to invent security-critical parsing/verification logic outside
the RED/freeze/GREEN workflow, or treat a prose checklist as a mechanical
gate.

Required repair: add a deterministic predecessor ticket owning a versioned
grant schema, a networkless verifier/CLI, frozen hostile-input tests, and the
exact command/exit contract. It must verify current SHA, environment/service,
catalog/policy/fixture/session-generation hashes, physical caps, expiry,
distinct identities, rollback release, and production-promotion scope. T-F16f
must invoke only that reviewed command.

### M1 — Ten Test/Implementation prompts contradict their own write allowlists

Each T-F16a-e Test prompt says its only allowed write is the test file but also
requires a report under `.tdd-swarm/reports/`; each Implementation prompt makes
the equivalent source-only statement and also requires an implementation
report. Examples:
`.tdd-swarm/prompts/T-F16a-test.md:2-4`,
`.tdd-swarm/prompts/T-F16a-implement.md:2-4`,
`.tdd-swarm/prompts/T-F16e-test.md:2-4`, and
`.tdd-swarm/prompts/T-F16e-implement.md:2-4`.
An agent cannot satisfy both literal instructions, which weakens mechanical
scope enforcement.

Required repair: list the exact report path as a second allowed write for each
affected prompt, while retaining exclusive test/source ownership.

## Re-review gate

Do not dispatch T-F16a tests until all Critical and Important findings are
repaired consistently in the plan, tickets, index/manifest, and affected
prompts. Re-review must additionally confirm:

1. UI uses `sid`, while chat/documents use `session_id`.
2. Retry-inclusive physical maxima fit the configured caps before any upload.
3. Catalog migration creates new immutable versions and has valid,
   environment-specific activation artifacts.
4. Document enablement is conditional on a hash-bound private fixture proof.
5. User-launched multi-surface scan orchestration has a real owner and tests.
6. T-F16f invokes a reviewed networkless grant verifier rather than an
   executor-authored checklist.
