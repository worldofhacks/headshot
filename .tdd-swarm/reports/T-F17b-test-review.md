# T-F17b Test Design Review

Status: `DONE`

Verdict: `CHANGES_REQUIRED`

Freeze verdict: `NOT_FROZEN`

Reviewed commit: `c135b1b31de3956dd3272e84cc6c525219344224`

Reviewed test identity:

- `tests/test_provider_call_lineage.py`
  - SHA-256: `e299fe1a295d3ab61fe3f769e0d8f3decaa184841cebeba4a5abcecf63d8b607`
  - Git blob: `4704d4d91c747318aa88d36bb51723b256a9f4e9`

This identity records the reviewed candidate only. The test is not frozen and must not be handed to
an Implementation Agent until the Important findings below are repaired and independently
re-reviewed.

## Findings

### Important — AC-2 failure records are validated only in memory, not through persistence

`test_spec_T_F17b_AC_2_failures_are_typed_bounded_and_never_fabricate_measurements`
(`tests/test_provider_call_lineage.py:414-504`) constructs terminal dataclasses for timeout,
retryable failure, terminal failure, model/provider mismatch, invalid usage, and invalid output,
but never sends them through `finish_physical_attempt` or reads them back from PostgreSQL. The only
ordinary failure status persisted elsewhere is `retryable_failure`
(`tests/test_provider_call_lineage.py:529-550,1132-1147`).

A lazy store that accepts only success and retryable failure—or drops status, error, observed
identity, usage, or nullable cost for the other five required failure classes—passes all 25 tests.
Add durable round-trip coverage for the distinct required failure classes, including an ordinary
final terminal failure, and assert the stored typed error and unavailable/observed fact shapes.

### Important — AC-7 does not prove final-failure terminalization or transaction atomicity

The retry integration case proves that a non-final failure leaves the logical row running and that a
final success terminalizes it (`tests/test_provider_call_lineage.py:509-581`). Crash reconciliation
proves a separate `outcome_unknown` path (`tests/test_provider_call_lineage.py:1011-1073`). No test
calls `finish_physical_attempt(..., final=True)` with `terminal_failure`, and no test forces the
logical terminal update to fail and then verifies that the physical event was rolled back.

Consequently, an implementation can leave ordinary final failures running, or commit the event and
logical update in separate transactions, and still pass. Add a final terminal-failure case and a
deterministic rollback probe that makes logical terminalization fail after the event insert; the
assertion must show that neither the terminal event nor a partial logical transition commits.

### Important — exactly-one event ownership is not enforced by the schema contract

The schema test checks composite foreign keys and sequence uniqueness only on
`provider_call_invocations` (`tests/test_provider_call_lineage.py:772-804`). It does not require a
composite organization/invocation foreign key from `provider_call_events`, nor a unique constraint
that limits a committed invocation to exactly one terminal event. Store-level exact replay coverage
(`tests/test_provider_call_lineage.py:975-1008`) cannot replace those database invariants.

A schema with no event-to-invocation foreign key and no one-event-per-invocation constraint passes
the suite while allowing orphaned, cross-organization, or duplicate terminal facts through the
Runner's direct INSERT grant. Require and behaviorally exercise the composite event ownership
foreign key and exactly-one terminal-event uniqueness, including reattribution rejection.

### Important — AC-8 leaves newly recovered logical unknown cost unconstrained

Crash recovery correctly asserts a nullable `not_observed` physical event
(`tests/test_provider_call_lineage.py:1034-1045`), but the subsequent logical-row assertion reads
only `status` and `error_code` (`tests/test_provider_call_lineage.py:1064-1073`). The logical
aggregation case covers only a known `partial` plus a known `measured` amount
(`tests/test_provider_call_lineage.py:1124-1179`). The historical migration case does not cover a
newly recovered execution.

An implementation can therefore reconcile the physical event honestly while writing logical
`measured_cost = 0`, marking it measured, or omitting its source event id, and pass. Assert the
logical `measured_cost`, `cost_measurement_state`, and `provider_event_ids` after unknown recovery;
also persist/read an `invalid` physical cost state so the closed four-state contract is not only a
dataclass check.

## Coverage that is sound

- AC-1 binds the required immutable requested/configured/observed identity, hashes, usage, cost,
  timing, and status fields.
- AC-3 proves distinct visible pre-call retry contexts, ordered physical sequences, non-final
  running state, invocation-side composite attribution, and duplicate-sequence rejection.
- AC-4 checks real PostgreSQL privileges for Runner/Web and all named service roles, including
  genuine SQLSTATE `42501` rejection for INSERT/UPDATE/DELETE/TRUNCATE, plus organization-filtered
  application reads.
- AC-5 exercises an isolated `0015 -> head -> 0015` migration, historical-zero reclassification,
  lossless baseline restoration, nullable observations, and the required lookup indexes.
- AC-6 uses synthetic secret/session/private-key/evidence shapes, non-disclosing validation errors,
  a closed raw-error constructor boundary, and no external provider or target.
- AC-7 exact replay and changed-replay conflict behavior is specific, including preservation of the
  first stored terminal fact; crash reconciliation is idempotent, reserved-invocation-only, and
  guarded against network calls.
- AC-8 exact Decimal handling, nullable unknown physical values, historical-zero migration, known
  subtotal aggregation, ordered source ids, and replay no-double-count behavior are well covered
  apart from the gaps above.

The public seam and type names are grounded in the ticket and locked plan. The tests do not
overconstrain private SQL/ORM structure, UUID generation, or transport implementation, and the
candidate changes no product, migration, configuration, or deployment file.

## Independent evidence

Focused RED:

```text
<venv-python> -m pytest -o addopts='' tests/test_provider_call_lineage.py -q --tb=short
```

Result: `25 failed` in `1.24s`. Twenty-two cases stop at the explicit missing-lineage-module
assertion and three stop at the explicit missing-lineage-tables assertion. Collection, PostgreSQL
connectivity, seed setup, isolated migration teardown, and fixtures remain healthy.

Preserved full baseline:

```text
<venv-python> -m pytest -o addopts='' tests \
  --ignore=tests/test_provider_call_lineage.py -q
```

Result: `1125 passed, 3 skipped` in `29.95s`.

Preserved migration/role/hosted/store slice:

```text
<venv-python> -m pytest -o addopts='' \
  tests/test_migrations.py tests/test_db_roles.py \
  tests/test_hosted_configuration.py tests/test_postgres_api_m1d.py -q
```

Result: `40 passed` in `2.10s`.

Additional gates:

- Ruff check: pass.
- Ruff format check: pass.
- Python compilation: pass.
- Diff check from `0803849aab0e99387ee80566b359384cb216f2b1`: pass.
- Secret scan: `secret scan clean (844 files)`.
- Candidate diff is limited to the declared test and Test Agent report.

Final severity: Critical `0`; Important `4`; Minor `0`.
