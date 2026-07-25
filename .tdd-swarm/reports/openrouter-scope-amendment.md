# OpenRouter four-role scope amendment — final review repair

**Disposition:** **REPAIRED IN PLAN / pending independent re-review.**  
This is a planning self-check, not independent approval, implementation evidence, or execution authorization.

## Final re-review closure

| finding | planned closure | enforcing artifacts |
|---|---|---|
| Critical C1 — `campaign.json` and immutable smoke reviews not mechanically bound before live action | **closed in plan**: new bounded deterministic T-F05c owns a public zero-call verifier that accepts and parses `campaign.json`, derives smoke/review expectations from the grant, compares exact target/host/surface/allowlist, corpus/synthetic-only, release/current deploy, current provider-role configuration/policies, caps/rate/concurrency/timeout/USD/abort, expiry/operation nonce, launcher/distinct approver, and SMART credential lease bindings, and composes existing Policy Gateway plus T-F04h review checks. T-F05b depends on it and invokes its exact command before any mutation, secret, adapter, provider, target, or spend action. | `tickets/T-F05c.md`; five T-F05c prompts; `tickets/T-F05b.md`; T-F05b Execute/Evidence-review prompts |
| Important I1 — smoke producer can overwrite or partially publish an “immutable” manifest | **closed in plan**: T-F04d owns fixed-root dual result/evidence publication with absent-leaf validation, no-follow/create-exclusive same-directory staging, full writes/fsyncs, no-replace recoverable commit, identical bytes/hash, and refusal/rollback/recovery for existing path, symlink, escape, reused ID, partial failure, and crash. T-F04e reviews accept only the committed immutable pair. | T-F04d AC-3–AC-7 and five prompts; T-F04e AC-2–AC-7 and three prompts |
| Minor M1 — staging idempotency identity ambiguous | **closed in plan**: T-F04c defines the full-input hash as schema-versioned canonical complete four-role input sorted by role and the identity as domain+release SHA+full-input hash; actor is audit-only. Same release/input returns the original set, same release/changed input conflicts without mutation, and a new release permits a later staged version. | T-F04c AC-3/AC-4, Test Plan, and five prompts |

## Residual finding closure

| finding | planned closure | enforcing artifacts |
|---|---|---|
| C1 — no reachable persisted four-role set creation | **closed in plan**: T-F04c owns the exact public zero-network `stage_openrouter_role_configurations.py` command. It parses once, validates all four records, commits four-or-zero plus one set record, leaves the set staged/inactive, emits only its SHA-256, is idempotent for identical canonical input, and conflicts on changed input. T-F04g and T-F04d tests consume that public output rather than seeding store internals. | `tickets/T-F04c.md`, `tests/test_hosted_role_configuration_staging.py` scope, five T-F04c prompts; `tickets/T-F04g.md`; T-F04d AC-1/AC-7 |
| I1 — T-F04c/T-F04d exceed half-day boundary | **closed in plan**: configuration is split into T-F04c domain/settings/staging/persistence/migration and T-F04g read-only preflight/projection/drift; smoke implementation is split into T-F04h schemas/fixture/registry/conformance/offline verifier and T-F04d Orchestrator/Documentation adapters/composed execute CLI. Each code ticket has one unique test scope and five TDD prompts. | T-F04c/T-F04g/T-F04h/T-F04d tickets and prompt sets |
| I2 — no pre-dispatch worst-case spend reservation | **closed in plan**: T-F04f atomically reserves role/global calls, maximum input/output/reasoning tokens, and worst-case USD before every physical attempt using the authorization-bound catalog price hash/vector and `max_price`; exact usage/cost reconciles afterward. Tests explicitly cover last affordable, retry reservation, missing usage, price drift, reasoning growth, and concurrent roles. | `tickets/T-F04f.md`; five T-F04f prompts; `tests/test_openrouter_transport.py` scope |
| M1 — contract registry/conformance ownership implicit | **closed in plan**: T-F04h explicitly owns `registry.py` and generic conformance. The four schemas are `OPERATIONAL_SCHEMAS`, excluded from `SUCCESS_SCHEMAS`, with root/package/wheel parity and lookup checks. | `tickets/T-F04h.md`; T-F04h Test/Implement/Code-review prompts |
| M2 — deterministic T-F04d conditioned on external authority | **closed in plan**: waves and deadline text state T-F04h/T-F04d proceed after code prerequisites with injected zero-network transports regardless of T-F03b/T-F04b authority; only operational evidence tickets remain zero-call `BLOCKED`. | `TICKETS.md` Deadline triage; `.tdd-swarm/final-submission-manifest.md` Deadline triage |

## Bounded ownership chain

```text
T-F04c configuration domain/settings + atomic staging/persistence/migration
  -> T-F04g read-only authorization preflight/projection/drift
    -> T-F04f atomic reservation + credential/identity/transport/reconciliation
      -> T-F03a Judge semantics + T-F04a Red Team semantics
        -> T-F04h operational schemas/fixture/registry/conformance/offline verifier
          -> T-F04d hosted Orchestrator/Documentation adapters + composed execute CLI
            -> T-F05a durable lineage
              -> T-F04e authorized smoke + two independent immutable reviews
                -> T-F05c campaign.json + reviewed-smoke zero-call preflight
                  -> T-F05b live campaign gate
```

- T-F04c performs the only settings interpretation and write; T-F04g performs the only authorization projection and is read-only.
- T-F04f accepts only T-F04g-approved persisted records. One shared ledger reserves worst-case authorization-bound capacity before transport and cannot be reset by client reconstruction.
- T-F04h owns no role adapter or execution. T-F04d owns no schema, fixture, registry, conformance, or offline-verifier implementation.
- T-F04d durably publishes one canonical manifest as a create-only identical result/evidence pair; T-F04e has three principals and disjoint writes over only the committed pair.
- T-F05c invokes T-F04h review logic with expected hashes read from `campaign.json` and composes existing Policy Gateway checks; T-F05b invokes T-F05c before every other action.

## Exact public command contracts

Atomic create-only staging:

```text
python scripts/stage_openrouter_role_configurations.py --release-sha <RELEASE_SHA> --actor-ref <ACTOR_REF> --hash-only
```

Zero-call read-only preflight:

```text
python scripts/preflight_openrouter_roles.py --authorization docs/evidence/authorizations/openrouter-four-role-smoke.json --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture evals/fixtures/openrouter-four-role-smoke-v1.json --check-only
```

Target-free four-role execution:

```text
python scripts/run_openrouter_four_role_smoke.py execute --authorization docs/evidence/authorizations/openrouter-four-role-smoke.json --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture evals/fixtures/openrouter-four-role-smoke-v1.json --result-output evals/results/openrouter-smoke/<RUN_ID>/manifest.json --evidence-output docs/evidence/openrouter-smoke/<RUN_ID>/manifest.json
```

Offline manifest verification:

```text
python scripts/verify_openrouter_four_role_smoke.py manifest --authorization docs/evidence/authorizations/openrouter-four-role-smoke.json --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture evals/fixtures/openrouter-four-role-smoke-v1.json --manifest <SMOKE_MANIFEST>
```

Offline smoke-review verification:

```text
python scripts/verify_openrouter_four_role_smoke.py reviews --manifest <SMOKE_MANIFEST> --evidence-review <EVIDENCE_REVIEW> --security-review <SECURITY_REVIEW> --expected-evidence-review-sha256 <EVIDENCE_REVIEW_SHA256> --expected-security-review-sha256 <SECURITY_REVIEW_SHA256> --release-sha <RELEASE_SHA> --configuration-set-sha256 <CONFIGURATION_SET_SHA256>
```

Live campaign grant prerequisite:

```text
python scripts/preflight_live_campaign.py --authorization docs/evidence/authorizations/campaign.json --target-observation <TARGET_OBSERVATION> --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --corpus-manifest <CORPUS_MANIFEST> --synthetic-fixture-manifest <SYNTHETIC_FIXTURE_MANIFEST> --configuration-projection <HOSTED_CONFIGURATION_PROJECTION> --smoke-manifest <SMOKE_MANIFEST> --evidence-review <EVIDENCE_REVIEW> --security-review <SECURITY_REVIEW> --smart-lease-metadata <SMART_LEASE_METADATA> --launcher-ref <LAUNCHER_REF> --check-only
```

The live command accepts no caller-selected expected smoke/review hashes; T-F05c reads them from `campaign.json`.

These are planned interfaces. None was implemented or executed by this amendment.

## Create-only immutable smoke publication

T-F04d validates both output paths beneath fixed roots before any dispatch. It serializes one canonical byte sequence, uses create-exclusive/no-follow temporary files in each destination directory, fully writes and fsyncs both plus their directories, and publishes with no-replace semantics under a recoverable commit marker. A pre-existing file, symlink/reparse point, path escape, reused run ID, partial write, fsync failure, second-publish failure, or simulated crash cannot overwrite an object or produce a reviewable half-set. Rollback/recovery may remove only inode/token-verified transaction-owned paths. Success and T-F04e review input require both durable bytes and canonical hashes to be identical.

## Staging idempotency domain

T-F04c computes `FULL_FOUR_ROLE_INPUT_SHA256` over a schema-versioned canonical serialization of every complete role input sorted by role. The idempotency identity is `SHA256("hosted-role-stage-v1" || RELEASE_SHA || FULL_FOUR_ROLE_INPUT_SHA256)`; actor reference is audit-only. The same release/input returns the existing set without rows, the same release/changed input conflicts without mutation, and a different release creates a legitimate later identity.

## Reservation and reconciliation contract

For every physical attempt, T-F04f:

1. verifies the current provider capability/price snapshot equals the authorization-bound catalog price hash and does not exceed `max_price`;
2. under one role/global atomic lock reserves a call, concurrency slot, maximum input/output/reasoning tokens, and worst-case USD computed from the bound price vector;
3. refuses before transport when any cap would be exceeded, while allowing the last exactly affordable reservation;
4. obtains a new reservation for every retry;
5. replaces the reservation with exact returned usage/measured cost and releases only unused capacity;
6. retains the full estimate for missing usage/cost and terminates on price drift or reasoning growth beyond the reservation;
7. preserves reservations/reconciliation/abort evidence across concurrent clients and reconstruction.

## Operational contract classification

T-F04h owns the authorization, fixture, manifest, and review schemas as repository operational contracts. It adds them exactly once to `OPERATIONAL_SCHEMAS`, explicitly keeps them out of `SUCCESS_SCHEMAS`, publishes byte-identical root copies, and extends the generic registry/package/wheel conformance test. This classification does not weaken validation: T-F04h's exact offline verifier remains authoritative for manifest and review semantics.

## Repaired waves

| wave | tickets |
|---:|---|
| 0 | T-F00 |
| 1 | T-F01a, T-F02, T-F04c |
| 2 | T-F04g, T-F14a, T-F14b |
| 3 | T-F04f, T-F11 |
| 4 | T-F03a, T-F04a |
| 5 | T-F03b, T-F04b, T-F04h |
| 6 | T-F04d |
| 7 | T-F05a |
| 8 | T-F04e, T-F05c, T-F06a |
| 9 | T-F05b, T-F07a |
| 10 | T-F06b, T-F07b, T-F12 |
| 11 | T-F08, T-F09b, T-F13 |
| 12 | T-F09a, T-F10b |
| 13 | T-F10a |
| 14 | T-F10c |
| 15 | T-F15 |
| 16 | T-F01b |

Hidden overlaps are serialized: T-F04c → T-F05a for runtime/store, T-F04g → T-F05a for Birdseye, T-F02 → T-F14b → T-F04h for root contracts, and T-F05a → T-F06a for runner. Same-wave exact scopes are disjoint.

## Files changed by this repair

### Added

- `tickets/T-F04g.md`, `tickets/T-F04h.md`
- five T-F04g prompts and five T-F04h prompts
- `tickets/T-F05c.md`
- five T-F05c prompts

### Rewritten or amended

- `TICKETS.md`
- `.tdd-swarm/final-submission-manifest.md`
- `.tdd-swarm/reports/openrouter-scope-amendment.md`
- T-F04c/T-F04f/T-F04d tickets and all five prompts for each
- T-F03a/T-F03b/T-F04a/T-F04b/T-F04e/T-F05a/T-F05b tickets or dependent prompts
- downstream wave/dependency context in T-F01b, T-F06a/b, T-F07a/b, T-F08, T-F09a/b, T-F10a/b/c, T-F12, T-F13, T-F14a, T-F15

No application source, test implementation, credential, authorization, provider/target call, deployment, git state, commit, push, or external state changed.

## Open human gates

1. [open-question] Accept or replace four exact distinct model IDs; readiness recommendations remain proposals, not defaults.
2. [open-question] Provision four role-scoped sealed credential references and expected upstream identities, with Judge materially independent from Red Team.
3. [open-question] Approve catalog price hash/vector, `max_price`, maximum input/output/reasoning tokens, endpoint capability, data policy/ZDR, expiry, fixture hash, and exact per-role/global caps.
4. [open-question] Supply separate T-F03b Judge and T-F04b Red Team authorization artifacts.
5. [open-question] Supply the T-F04e smoke authorization binding release/configuration set/fixture/all identity, price, policy, and cap hashes with `target_scope:none`.
6. [open-question] Assign executor, Evidence Reviewer, and Security Reviewer as three distinct principals.
7. [open-question] Supply immutable `campaign.json` with exact target/allowlist, corpus/synthetic-only, current deploy/release, role-configuration/policies, canonical smoke/unequal review hashes, complete caps, expiry/principals, and SMART lease bindings only after both T-F04e records pass.

## Structural self-check

Planning checks performed after the repair:

- all 33 ticket frontmatters parse; every dependency exists and points to an earlier wave;
- wave index and ticket frontmatter/context agree for waves 0–16;
- same-wave exact file/test scopes do not collide;
- T-F04c/T-F04g/T-F04f/T-F04h/T-F04d/T-F05c contribute exactly 30 Test/Test-review/Implement/Code-review/Security prompts and unique test scopes;
- T-F04e retains exactly Execute/Evidence-review/Security-review prompts and T-F05b exactly Execute/Evidence-review;
- strict prompts retain exact inputs/outputs/write scopes, named verifier, maximum three attempts, four-status return contract, network/spend bounds, and no main merge/push;
- public stage→preflight→dual-output execute→offline-verify reachability is required with one unchanged set hash and one immutable manifest hash;
- T-F04f names atomic worst-case reservation and all five required boundary/race cases;
- T-F04h owns registry/conformance and explicit operational classification;
- T-F04d/T-F04e name create-only/no-follow/fsync/no-replace/crash-safe immutable dual-output cases;
- T-F05b names the exact T-F05c `campaign.json` command, which derives smoke/review expectations from the grant and composes Policy Gateway checks;
- T-F04c names the schema-versioned full-four-role input hash, release-bound actor-independent idempotency identity, same-input return, changed-input conflict, and later-release path;
- changed tickets/prompts contain none of the readiness report's proposed model IDs.

**Self-check result:** **PASS, pending independent plan re-review.**
