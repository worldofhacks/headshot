# T-F16b Test Design Review

Status: `DONE`

Verdict: `CHANGES_REQUIRED`

Freeze verdict: `NOT_FROZEN`

Reviewed commit: `cdf584303f7791108d1b58bdeee893434d765982`

Reviewed test identity:

- `tests/test_surface_operation_gateway.py`
  - SHA-256: `3e5c37ee54e9e7fdc321c51fba1e108c8755cb0e82dedf8127043ef46183fafa`
  - Git blob: `20b40610c149a0a47dec1f794f589f45ee3e17b6`

This records the reviewed candidate only. The test is not frozen and must not be dispatched to an
Implementation Agent until the Important findings are repaired and independently re-reviewed.

## Findings

### Important — the operation flow is never connected to durable physical work-unit rows

The new tests represent reservation and observation with list callbacks
(`tests/test_surface_operation_gateway.py:394-440,497-530`) and represent completed work with frozen
in-memory trace objects (`tests/test_surface_operation_gateway.py:850-893`). They never use
`migrated_db`, `ControlPlaneStore.reserve_campaign_work_unit`,
`ControlPlaneStore.observe_campaign_work_unit`, or the ticket-scoped campaign coordinator. The one
durable regression control exercises only the inherited chat `PolicyGateway.execute` path
(`tests/test_surface_operation_gateway.py:971-1014`).

A lazy implementation can add a self-contained `execute_operation_flow` that sends and appends
in-memory observations but is never wired into the Runner/coordinator's append-only
`campaign_work_unit_reservations` ledger. All 34 cases still pass, despite AC-2/AC-5 requiring one
reserved, charged, immutable physical row for every success and failure. Add a real PostgreSQL
integration case through the coordinator/store seams and assert each operation attempt and retry is
reserved before its send, observed exactly once afterward, survives terminal failure, and cannot be
mutated or replayed.

### Important — retry-time budget, capacity, rate, and timeout enforcement can remain one-time checks

The retry gate parameterization proves only that an injected callback is invoked a second time and
can raise an `AbortError` labelled authorization/abort/lease/integrity
(`tests/test_surface_operation_gateway.py:533-578`). The context carries remaining capacity, rate,
and timeout facts, but no case makes budget, physical capacity, rate timing, or the run deadline
become invalid between physical attempts. The fail/fail/succeed case has all three units available,
a large budget/deadline, and backoffs longer than its rate interval
(`tests/test_surface_operation_gateway.py:497-530`).

An implementation that performs all native budget/cap/rate/timeout checks only at preflight, then
blindly invokes the callback before retries, passes. Add deterministic revocation/exhaustion races
for those native dimensions immediately before a retry and before a later logical operation. Each
must stop before the next sender call and leave no unobserved reservation.

### Important — failure accounting and retry eligibility are incomplete

Every sender failure in the RED suite is `TargetUnreachableError`
(`tests/test_surface_operation_gateway.py:503-507,554-556,781-783,824-826`), the retryable typed
case. There is no non-retryable typed failure and no unexpected exception after transport entry.
Thus a gateway that retries every failure class, or that reserves/counts a generic raised attempt
but does not charge or terminally observe it, can pass AC-2 and AC-4.

Add a non-retryable typed failure under a retry-capable read policy and an unexpected sender
exception. Both must consume exactly one reserved/charged/observed physical unit; neither may be
retried, and neither may advance the flow.

### Important — the mixed canonical 67-attempt path is only asserted, not exercised

The preflight test reads the already-validated policy's `34`/`67` maxima and checks the reservation
copy (`tests/test_surface_operation_gateway.py:392-439`). Runtime retry coverage is split between a
single generic three-attempt read (`tests/test_surface_operation_gateway.py:495-530`), one
two-attempt bounded read (`tests/test_surface_operation_gateway.py:819-847`), and thirty successful
polls that consume only 31 total sends including upload
(`tests/test_surface_operation_gateway.py:752-773`).

No case executes the locked worst-case lab mix: one upload, thirty polls with one retry each, and
three terminal reads with one retry each, for 67 physical attempts. A per-flow retry counter,
cross-operation retry reset bug, or mixed-class off-by-one can pass the isolated cases. Exercise the
complete mixed flow and prove it fits exactly 67 while 66 refuses before upload; also prove no 68th
attempt can be emitted.

### Important — terminal sanitization does not cover hostile exception text

The sanitization case places canaries only in an oversized returned response
(`tests/test_surface_operation_gateway.py:850-893`). All raised transport and gate messages are
short benign literals. A terminal implementation can copy a raw exception containing a session,
body fragment, or thousands of attacker-controlled characters into `terminal_reason`, trace
representation, or the durable observation and still pass.

Add a raised transport/gate failure containing both canaries and an overlong hostile string. Assert
the bounded typed terminal reason, exception rendering, in-memory trace, and durable work-unit row
contain none of the raw content.

### Minor — AC-6 inspects source spelling instead of behavior

`tests/test_surface_operation_gateway.py:963-966` requires the implementation source to contain the
literal `operation_sender` and forbids two literal call spellings. A valid implementation that
delegates to a private gateway-owned helper can fail, while an unsafe alias or `getattr` bypass can
pass the string scan. Keep the poisoned legacy adapter/socket checks, but replace source inspection
with behavioral sender-ownership probes over every success, retry, and terminal path.

## Coverage that is sound

- AC-1 checks the canonical 34-logical/67-physical arithmetic, reservation ordering before upload,
  all named projected-capacity dimensions, and zero-send behavior for each deficient dimension.
- AC-2 checks stable retry coordinates, remaining-capacity context, policy-hash refusal, and exact
  accounting/observation for typed retryable failures and success.
- AC-3 has strong valid and hostile dynamic-segment coverage for authority, query, traversal,
  encoding, extra/empty segments, method/class/template mismatch, transition order, and per-class
  logical ceilings.
- AC-4 directly proves zero retry for an ambiguous write and the configured two-attempt read limit.
- AC-5 proves later-operation stop behavior, bounded/sanitized oversized-response handling, frozen
  trace values, and preservation of a completed prior trace.
- AC-6 proves flow-declared understatement cannot lower the canonical policy reservation and keeps
  the inherited atomic/sequential chat coordinate, count, observation, and evidence-hash controls
  green.

The typed public operation seam is a reasonable contract for downstream T-F16c/T-F16d. Apart from
the source-spelling assertion above, the suite does not overconstrain private helper structure,
backoff implementation, or transport library. The candidate changes only the declared test and
Test Agent report; no product, policy, catalog, migration, or deployment artifact changed.

## Independent evidence

Focused RED:

```text
<venv-python> -m pytest -o addopts='' -q --tb=short \
  tests/test_surface_operation_gateway.py
```

Result: `33 failed, 1 passed` in `0.34s`. Every intentional RED case stops at the explicit missing
operation-flow-boundary assertion. The inherited chat-path regression passes; there are no import,
collection, fixture, database, or network errors.

Preserved full baseline:

```text
<venv-python> -c 'import sys, pytest; sys.path.insert(0, "src");
raise SystemExit(pytest.main(["-o", "addopts=", "-q",
"--ignore=tests/test_surface_operation_gateway.py"]))'
```

Result: `1228 passed, 3 skipped` in `28.18s`.

Preserved focused gateway/work-unit baseline:

```text
PYTHONPATH=src <venv-python> -m pytest -o addopts='' -q \
  tests/test_gateway.py tests/test_work_unit_accounting.py
```

Result: `36 passed` in `1.58s`.

Additional gates:

- T-F00 criterion mapper: all six ACs mapped across one pytest scope.
- Ruff check: pass.
- Ruff format check: pass.
- Python compilation: pass.
- Diff check from `cda81d87a3ff44bceb66492588c37c5ee033b50a`: pass.
- Secret scan: `secret scan clean (854 files)`.
- `.tdd-swarm/run-local-gates.sh` is absent on the accepted T-F16a dependency base and remains
  blocked on T-F00 integration.

Final severity: Critical `0`; Important `5`; Minor `1`.
