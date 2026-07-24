# T-F16b Test Agent report

Status: `DONE`

## Four-status contract

- Test status: `RED` — 33 feature assertions fail cleanly; the one inherited-path regression
  control passes.
- Baseline status: `GREEN` — the untouched suite passes when the new RED scope is excluded.
- Static/spec status: `GREEN` — Ruff format/lint and the T-F00 criterion mapper pass.
- Post-GREEN wrapper status: `BLOCKED(DEPENDENCY)` — this accepted T-F16a base does not contain
  T-F00's `.tdd-swarm/run-local-gates.sh`; the independently executable T-F00 spec-lint was run
  from its accepted worktree instead.

## Provenance and scope

- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F16b`
- Branch: `ticket/T-F16b-physical-operation-gateway`
- Exact base: `cda81d87a3ff44bceb66492588c37c5ee033b50a`
- Product baseline under that review commit:
  `993bb19`/`1899c6a` landed T-F16a over `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`.
- Test-owned artifacts:
  - `tests/test_surface_operation_gateway.py`
  - `.tdd-swarm/reports/T-F16b-test.md`

No product source, target/catalog configuration, migration, ticket, plan, runtime fixture,
credential source, or owner artifact was changed or read. All "transport" behavior is an injected
callable; the operation-flow path installs a legacy adapter that raises if reached, and a socket
constructor canary proves the tests make no network call.

## Submitted operation-flow contract

The RED suite defines the smallest generic interface T-F16c/T-F16d can build on without adding a
parallel transport stack:

- frozen typed `SurfaceOperation` and `SurfaceOperationResponse` values live at the existing
  target boundary;
- `PolicyGateway.execute_operation_flow()` alone owns the injected `operation_sender`;
- a pure state machine exposes only `start()` and `advance(operation, response)`;
- the canonical T-F16a `SurfacePolicy`, never an adapter-declared maximum, supplies operation
  templates, order, logical ceilings, retry ceilings, response limits, and retry-inclusive
  physical maximum;
- a single frozen reservation describes logical/physical maximum, projected cost, minimum rate
  window, authorization/lease validity, run deadline, and trace slots before the first send;
- an immediate pre-operation context carries the exact policy hash, typed operation, resolved
  original-host URL, response/timeout limits, remaining capacity, and stable retry coordinates;
- immutable sanitized observations and `OperationFlowAborted` retain only bounded terminal reason,
  actual physical count, and trace references.

The canonical lab test policy is the landed T-F16a contract: upload `1 x 1`, status
`30 x 2`, and report/preview/readback `3 x 2`, for exactly `34` logical and `67` maximum physical
attempts. It uses only a test-created opaque fixture descriptor; no fixture bytes are opened.

## RED map

| Criterion | Intentional RED coverage |
|---|---|
| AC-1 | Canonical lab `34/67` derivation; reservation is observed before upload; exact maximum cost/rate-window/authorization/lease/run/trace projection; separately deficient physical `66`, budget `.66`, timeout `65`, authorization `65`, lease `65`, and trace `66` all require zero sends/charges |
| AC-2 | Generic retry-two fail/fail/succeed uses coordinates `0/1/2`, three gates, charges, observations, and actual count; authorization/abort/lease/integrity revocation immediately before retry prevents that send; context pins policy hash, method/path, exact-host destination, response limit, request timeout, and remaining capacity; stale policy hash refuses before sender |
| AC-3 | Upload-to-status typed transition accepts one closed `Doc_7-safe` segment; absolute/scheme-relative host, traversal, single/double encoding, query injection, extra/empty segment attacks stop after the completed upload; unlisted class, wrong method/template, and listed-but-invalid next transition fail; thirty polls are the exact ceiling |
| AC-4 | Zero-retry ambiguous state-changing upload produces exactly one charged/observed call; generic retry-two succeeds only on the third reserved unit; retry-one document read stops after the second failure |
| AC-5 | Oversized response is charged/traced but never advanced; terminal error has a <=160-character reason, exact actual count/trace refs, no payload/body fields or canaries, and a frozen trace; lease failure before the next operation preserves the completed upload trace and prevents status/report |
| AC-6 | Adapter-declared physical maximum `1` cannot reduce the policy reservation from `67`; operation-flow method may use only the injected sender, never `adapter.send`/`flow.send`; socket construction is denied; existing atomic and sequential chat delivery retains exact physical coordinates, observations, logical count, and evidence hash |

## RED evidence

Final focused command:

```text
PYTHONPATH=src /Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m pytest -o addopts='' -q --tb=no tests/test_surface_operation_gateway.py
```

Result: exit `1`; `34` collected, `33` intentional assertion failures, `1` passing inherited-path
regression, `0` collection/setup errors.

Every RED failure has the same feature-specific root: the accepted baseline has no
`SurfaceOperation`, `SurfaceOperationResponse`, `OperationFlowAborted`, or
`PolicyGateway.execute_operation_flow`. The helper reports those absent public boundaries as a
normal assertion rather than an import/collection error. The passing control proves current
atomic/sequential chat and `WorkUnitCoordinates` behavior remains executable before implementation.

Test-design attempts stayed within the ticket's maximum three:

1. initial draft: `31` intentional RED / `1` regression pass;
2. expanded hostile/terminal contract: `33` intentional RED / `1` regression pass;
3. final `PYTHONPATH=src` confirmation against the exact worktree source:
   `33` intentional RED / `1` regression pass.

## Baseline, regression, and static evidence

Untouched full baseline, excluding only the new intentional RED scope:

```text
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python -c \
  'import sys, pytest; sys.path.insert(0, "src"); raise SystemExit(pytest.main(
  ["-o", "addopts=", "-q", "--ignore=tests/test_surface_operation_gateway.py"]))'
```

Result: exit `0`; `1228` passed, `3` skipped.

The parent process inserts this worktree's `src` without exporting `PYTHONPATH`; that matters
because packaging tests intentionally spawn an isolated wheel venv and must not inherit a source
checkout path.

Existing focused gateway/work-unit controls:

```text
PYTHONPATH=src /Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m pytest -o addopts='' -q tests/test_gateway.py tests/test_work_unit_accounting.py
```

Result: exit `0`; `36` passed.

Formatting/lint:

```text
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m ruff check tests/test_surface_operation_gateway.py
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m ruff format --check tests/test_surface_operation_gateway.py
```

Result: both exit `0`.

Criterion map, using the accepted T-F00 executable while operating on this worktree:

```text
PYTHONPATH=src \
  PATH="/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin:$PATH" \
  /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F00/.tdd-swarm/spec-lint.sh \
  tickets/T-F16b.md cda81d87a3ff44bceb66492588c37c5ee033b50a
```

Result: exit `0`;
`spec-lint: T-F16b maps 6 acceptance criteria across 1 pytest-collected scopes`.

Secret/diff checks:

```text
bash scripts/secret_scan.sh
gitleaks git --pre-commit --staged --redact --verbose --no-banner
git diff --cached --check
```

Result: all exit `0`; repository scan reports `secret scan clean (854 files)`, gitleaks scans the
two staged test-owned artifacts with no leaks, and the staged diff has no whitespace error.

The missing in-tree wrapper is not replaced or copied because both are outside Test Agent
ownership. Once T-F00 is integrated, the post-implementation verifier is:

```text
.tdd-swarm/run-local-gates.sh \
  tickets/T-F16b.md cda81d87a3ff44bceb66492588c37c5ee033b50a
```
