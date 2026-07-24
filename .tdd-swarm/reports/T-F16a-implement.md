# T-F16a Implementation Agent report

Status: `DONE_WITH_CONCERNS`

## Provenance and scope

- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F16a`
- Branch: `ticket/T-F16a-surface-policy-contract`
- Implementation base / frozen review commit: `e392cac`
- Product baseline: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
- Frozen test commit: `295e9ccd0b8e1d2c13ad1ccfd8074e762461860f`
- Frozen test SHA-256:
  `fdf129e50018a13d7e69e74d9eb9f08821daba1312dc5bf84d7492583890145e`
- Frozen test Git blob: `af6df0ff25e4e53aa0b6aca691d6494ff1d1e501`

Writes stayed within the implementation prompt:

- `src/agentforge/target/spec.py`
- `src/agentforge/target/catalog.py`
- `src/agentforge/target/registry.py`
- `src/agentforge/control_plane/serialization.py`
- `docs/migrations/final-target-surface-policy-v2.md`
- `.tdd-swarm/reports/T-F16a-implement.md`

No test, ticket, plan, runtime adapter, fixture, credential source, or deployment file changed.

## Implemented contract

- Added immutable, canonical schema-v2 values for typed operation templates, complete six-field
  fixture descriptors, and per-surface transport/authorization policy.
- Bound the exact policy and independently recomputed policy SHA-256 into attack-surface
  definitions and authorization scopes while leaving legacy scope bytes unchanged when no v2
  policy exists.
- Enforced exact credential placement and field names, explicit anonymous evidence policy,
  complete opaque fixture identity, finite retry counts, zero upload retries, one-retry document
  read/poll ceilings, and exact logical/physical arithmetic.
- Added strict serialization with exact field sets and no ignored policy, operation, or fixture
  fields.
- Split catalog decoding into compatible v1 single-profile entries and transport-policy-free v2
  per-surface entries. Mixed shapes, target-wide profile sets, duplicate surfaces/fixtures,
  profile/operation mismatch, v2.0 enabled documents, and legacy-shaped v2 targets fail closed.
- Registry registration and resolution now derive authentication from v2 surface policy and compare
  the exact policy/hash before any adapter, credential, or fixture boundary can run. Legacy
  definitions continue to derive authentication from the target.
- Added the required hash-break, old-approval invalidation, staged `2.0.0 -> 2.1.0`, rollback, and
  legacy-compatibility migration note.

## RED and GREEN evidence

Initial focused RED:

```text
python -m pytest tests/test_final_target_surface_policy.py -q --tb=no
-> exit 1; 103 failed, 0 passed, 0 collection/setup errors
```

Focused convergence remained inside three focused invocations:

1. `102 passed, 1 failed` — migration prose did not contain the exact required rollback phrase.
2. `102 passed, 1 failed` — Markdown delimiters still interrupted that literal phrase.
3. `103 passed` — final canonical contract GREEN.

Final focused and compatibility verification:

```text
python -m pytest -o addopts='' tests/test_final_target_surface_policy.py -q
-> exit 0; 103 passed in 0.22s

python -m pytest -o addopts='' \
  tests/target/test_relative_path_parameters.py tests/target/test_target_spec.py -q
-> exit 0; 79 passed in 0.04s

python -m pytest -o addopts='' tests/contract -q
-> exit 0; 51 passed in 0.10s
```

Adjacent registry, adapter-registry, store, runner, and accounting suites passed. The final full
backend run exited `0`; collection reported `1231` tests and execution completed with `1228 passed,
3 skipped`. The only warning was the existing Starlette `TestClient` deprecation warning.

## Static, integrity, and secret checks

- Scoped `ruff check` -> exit `0`, all checks passed.
- Scoped `ruff format --check` -> exit `0`, all four changed Python files formatted.
- `git diff --check` -> exit `0`.
- `git diff --exit-code -- tests` -> exit `0`.
- Frozen test SHA-256 and Git blob still exactly match the freeze report.
- No added `TODO`, `FIXME`, `HACK`, `print`, debugger, socket, credential read, fixture-byte read,
  adapter construction, or target call.
- `bash scripts/secret_scan.sh` -> exit `0`; `secret scan clean (851 files)`.

## Concerns

The prompt-mandated wrapper remains absent at this dependency base:

```text
.tdd-swarm/run-local-gates.sh tickets/T-F16a.md \
  1ac3ee02be7855b638dd1fa43bb0612a3db5f025
-> exit 127; no such file or directory
```

This is the already-recorded T-F00 infrastructure blocker, not an implementation failure. Direct
execution of every available mapped backend gate above is green.

Whole-repository Ruff is also not a clean baseline: `ruff check .` reports `114` findings and
`ruff format --check .` reports `18` files requiring format. Every reported path is outside this
ticket's changed/allowed files; the scoped product files are clean. Those unrelated files were
preserved.
