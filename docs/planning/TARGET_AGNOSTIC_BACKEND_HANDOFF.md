# Target-agnostic backend foundation handoff

## Status and scope

This branch adds the offline, framework-neutral domain foundation for versioned targets,
versioned attack surfaces, canonical authorization scope, exact registry resolution, and trusted
adapter-factory selection. It is based on `origin/main` commit
`211665dfb024f169a1d3e2daa8f1dc96864d29cd`.

Only new files are used. No existing gateway, coordinator, contract, schema, corpus, configuration,
storage, CI, or adapter file is modified. The active M11 coordinator was inspected read-only from
pinned Git object `3cf7b35d769a378ac3307c0f399497fd7d23f69e`; its worktree and branch were not accessed or
changed.

This slice does **not** authorize a run, access a credential, open a network connection, contact a
target, or claim a live result. Registry persistence and runtime integration remain follow-up work.

## Binding anchors

- `ARCHITECTURE.md` §2: target reach stays behind a pluggable `TargetAdapter` invoked only through
  the trusted gateway; the mechanism remains target-neutral.
- `ARCHITECTURE.md` §5 and D14: untrusted attack generation cannot select execution or evidence
  facts; the trusted gateway/recorder owns dispatch and evidence identity.
- D10: the new core is stdlib-only and framework-neutral. No schema or contract is silently changed.
- D16: target definitions are environment-scoped, exact-host bound, synthetic-only, and
  credential-reference-only.
- `ARCHITECTURE.md` §16: existing target-specific connectors remain explicit plugins; the generic
  registry never constructs an arbitrary network adapter or supplies a fallback.

## Delivered domain

### `TargetDefinition`

Each immutable snapshot contains:

- stable target ID and semantic version;
- editable display name through a new-version revision that preserves the target ID;
- adapter kind and environment;
- exact HTTPS base URL and exact allowlisted host authorities;
- auth mode plus one canonical, byte-exact credential reference, never a credential value;
- explicit no-auth when `auth_mode == none`;
- synthetic-data-only attestation reference;
- opaque canary/oracle references;
- finite positive target safety maxima; and
- the adjacent lifecycle `draft → validating → ready → disabled → archived`.

No lifecycle transition can skip, move backward, or leave `archived`.

### `AttackSurfaceDefinition`

Each immutable `(surface_id, version)` snapshot binds to an exact `(target_id, target_version)` and
contains:

- kind: `chat`, `completion`, `responses`, `messages`, `tool`, `rag`, `memory`, `file`, `action`, or
  `custom`;
- protocol and method;
- a validated relative path;
- trust-boundary identifier, authentication requirement, risk, structured OWASP mappings,
  per-surface oracle references, and enabled state.

Paths reject leading slash, scheme/authority syntax, backslashes, queries, fragments, percent
encoding, empty segments, and traversal. The trusted adapter must concatenate the registered base
URL and registered relative path; it must never use attacker input or `urljoin()` to select an
origin.

### `TargetRegistry`

The in-memory registry provides:

- dynamic target and surface registration;
- monotonically increasing, immutable registered-definition history plus separate lifecycle event
  history;
- stable surface ownership by target ID;
- exact-version lookup plus immutable tuple histories; and
- fail-closed dispatch resolution from one canonical `AuthorizationScope`.

Surfaces can be registered only while their exact target version is `draft`. Moving that target to
`validating` freezes the surface set; a later-added enabled surface therefore cannot bypass the
validation cycle. Revisions use a new target/surface version.

Dispatch requires a `ready` target, enabled surface, exact target/surface version relationship,
matching environment/adapter/host/auth/credential-or-no-auth/endpoint fields, and run caps no
greater than the target maxima. Unknown, draft, validating, disabled, archived, cross-target, or
version-mismatched definitions are rejected with typed errors.

Multiple target IDs may intentionally share the same adapter kind. Adapter kind is a plugin type,
not a target identity.

### `AdapterRegistry`

The adapter registry binds one trusted `TargetRegistry` and defensively copies a trusted factory map
at construction. It:

- accepts only a canonical `AuthorizationScope` and resolves it through the bound target registry;
- never accepts a caller-constructed resolved snapshot;
- selects only `resolved.target.adapter_kind` after exact registry verification;
- performs no dynamic import;
- has no wildcard, default, or fallback key;
- rejects unknown adapter kinds;
- verifies the factory returns the existing generic `TargetAdapter` interface; and
- verifies the returned adapter kind matches the trusted definition.

OpenEMR remains an explicitly registered plugin at the trusted composition root. It is never
imported by the generic registry and is not a generic arbitrary-network fallback.

## Canonical authorization scope

`AuthorizationScope.for_definitions()` derives authoritative routing values from immutable registry
definitions rather than from attack content. Its canonical payload and SHA-256 bind:

```text
target_id
target_version
surface_id
surface_version
adapter_kind
environment
exact_host
auth_mode
credential_ref | null plus explicit_no_auth
protocol
method
relative_path
corpus_hash
caps = budget, attempts, request rate, timeout
run_nonce
```

Changing the corpus hash, caps, nonce, endpoint, target, surface, host, adapter, or authorization
posture changes the scope hash. The persisted human authorization must bind that exact hash.

## Required active-coordinator integration

The line references below describe pinned coordinator object `3cf7b35`; re-resolve them after its
branch lands.

1. **Resolve target and surface before authorization or adapter construction.**
   - Replace `RunConfig.binding` and the global canary field in
     `src/agentforge/campaign/coordinator.py:81-94` with exact target/surface references and corpus
     hash.
   - At the start of `_run_case_gated()` (`:197-238`), call `TargetRegistry.resolve()` with the
     canonical scope. Recheck before every case so an administrative disable stops an existing
     run.

2. **Replace the coordinator and gateway singleton adapter.**
   - Replace the injected single adapter at `campaign/coordinator.py:122-127` with trusted
     `TargetRegistry` and `AdapterRegistry` dependencies.
   - Replace `PolicyGateway.adapter` at `policy/gateway.py:105-120` and caller-selected
     `target_id` at `:129-180` with a resolved, authorized dispatch snapshot.
   - The attack attempt must carry no authoritative adapter, host, credential, or endpoint choice.

3. **Remove `target_id == adapter_name`.**
   - Delete the assertion at `campaign/coordinator.py:_verify_binding():310-314` and replace its
     corresponding test at `tests/test_campaign_coordinator.py:444-459`.
   - Retain `adapter.name == target.adapter_kind`. Two unrelated target IDs must be able to use the
     same adapter kind.

4. **Build an adapter only after scope verification.**
   - Replace `_dispatch()` at `campaign/coordinator.py:318-355`.
   - Do not mutate a shared adapter credential and do not create an allowlist from caller-selected
     binding data.
   - Bind `AdapterRegistry` to the trusted `TargetRegistry`, then resolve a fresh/per-run adapter
     from the canonical scope. Resolve the exact authorized credential reference only at the
     verified send boundary; no-auth injects none.
   - `Allowlist.resolve()` currently returns a target-to-adapter entry, but the gateway discards
     it at `policy/gateway.py:152-159`. If retained as a separate environment gate, verify its
     target/surface versions, adapter kind, and exact host against the registry snapshot.

5. **Correct credential-reference use.**
   - `campaign/binding.py:134-144` passes a selected reference into `CredentialBinding`, but
     `policy/credentials.py:36-60` ignores `self.secret_ref` and derives a reference from only the
     target ID.
   - The integrated resolver must dereference or validate the exact reference already bound into
     the authorization scope. Otherwise the authorized reference and used reference can differ.

6. **Expand the persisted authorization hash.**
   - Replace `campaign/authorization.py:operation_hash():46-79`, which omits target version,
     surface identity/version, auth mode, explicit no-auth, corpus hash, and endpoint identity.
   - Reuse `AuthorizationScope.scope_hash()` as the single canonical input. Never rebuild a
     partially overlapping hash in the coordinator.

7. **Make CLI input identity-only.**
   - Replace the binding file, raw canary argument, and arbitrary adapter-factory route at
     `campaign/cli.py:47-87, 130-149` with target ID/version, surface ID/version, corpus hash, caps,
     run nonce, and a persisted authorization over the canonical scope.
   - The trusted composition root supplies registries. CLI or corpus content cannot supply a host,
     adapter class, credential value, or endpoint.

## Evidence and contract follow-up

Do not break the strict v1 contracts. Add compatible v2 schemas and a migration path.

1. `AttemptResult` v2 must source these values from registry snapshots, not adapter output:

   ```text
   target_id
   target_version
   surface_id
   surface_version
   adapter_kind
   authorization_scope_hash
   ```

   The current gateway incorrectly derives `target_version` from adapter response metadata at
   `policy/gateway.py:340`.

2. Add the same identity to the trusted portion of `EvidenceEnvelope` v2, recorder hash/persisted
   fields, immutable config/evidence/result manifests, and verdict correlation as appropriate.

3. Add a generic `attack-case.v2.json` without editing `attack-case.v1.json`. V2 should reference
   exact target and surface IDs/versions and use generic surface/trust-boundary identifiers. Change
   `validate_attack_case()` from the fixed v1 schema at `evals/validation.py:820-835` to a trusted
   version-to-schema map. Unknown versions fail closed; all nine v1 cases remain unchanged and
   valid.

4. Trusted routing comes from the validated corpus selected by `corpus_hash`, never from an
   untrusted `AttackAttempt`. `seed_to_attempt()` currently retains only case reference, sequence,
   and category; any traceability fields added later must be checked for exact equality to the
   authorized scope, not treated as authority.

## Per-surface oracle registration follow-up

Replace the global canary-only path in `campaign/coordinator.py:_adjudicate():421-453` with a trusted
oracle-factory registry keyed by the opaque references in the resolved surface snapshot.

- Instantiate only registered evaluators declared by that surface.
- Evaluate them over re-read, hash-verified recorder evidence.
- Route canary predicates to `canary_hits` and other deterministic predicates to
  `oracle_results`.
- Remove caller-controlled `run_oracle` and the raw CLI canary argument.
- Missing, disabled, or unknown oracle registrations provide no deterministic confirmation; the
  existing Judge therefore remains `INDETERMINATE` unless another trusted source resolves it.

The existing generic `Oracle` interface and canary implementation remain reusable plugins.

## Persistence and audit follow-up

Add forward migrations only after the active integration branch establishes its migration head:

- append-only target snapshots keyed by target ID/version and content hash;
- append-only surface snapshots keyed by surface ID/version with target ID/version reference;
- registry lifecycle/audit events with actor reference, transition, prior/new hashes, and time;
- immutable run configuration plus canonical authorization-scope payload/hash; and
- AttemptResult v2 target/surface identity columns and indexes.

Prior definitions must never be updated or deleted. Registry administration is a trusted write
path; Red Team has no registry access. Extend the explicit DB grant matrix accordingly. Existing
run manifests remain artifacts, not a registry system of record.

## Test evidence

Tests were authored before implementation. The first focused run failed collection with three
`ModuleNotFoundError` failures for the absent modules. Independent review then produced a second
test-first RED run with 21 failures covering forged adapter snapshots, post-validation surface
registration, lifecycle-history mutation, ambiguous credential handles, and noncanonical base URLs.
After both minimal implementation passes:

```sh
pytest tests/target -q
```

passes 85 deterministic tests. Coverage includes shared adapter kinds, multiple versioned surfaces,
all lifecycle refusals, exact scope substitution, auth-none/authenticated modes, hostile path forms,
immutable history, no fallback, import purity, no-network resolution, and generic-vocabulary checks.

No test accesses a network, hosted model, secret, `.env.local`, or live service.

## Independent review resolutions

Two read-only reviews reported no Critical findings. All Important findings were resolved before
publication:

- surface registration is now limited to a draft target version, closing the validation bypass;
- adapter resolution now re-resolves the canonical scope through its bound trusted target registry,
  so forged snapshots never reach a factory;
- credential handles reject encoding, backslashes, traversal, empty segments, and noncanonical
  spellings; and
- base URLs reject encoded paths and noncanonical authorities, while target definition history and
  lifecycle-event history are stored separately.
