# T-F17b Test Design Re-review

Status: `DONE`

Verdict: `CHANGES_REQUIRED`

Freeze verdict: `NOT_FROZEN`

Reviewed commit: `990b0c3d0da3e02b86ee0e877d7d1787f079ebe6`

Reviewed candidate identity:

- `tests/test_provider_call_lineage.py`
  - SHA-256: `eec8dc7f30aa71735ed877c63a504abb553a6ae6b8b8089ceda869e45c669503`
  - Git blob: `0ff845a2e3bcf2016155770c1660cfc6f623224c`

This identity records the repaired candidate only. The test remains unfrozen and must not be handed
to an Implementation Agent until the Important finding below is repaired and independently
re-reviewed.

## Finding

### Important — the atomicity probe requires one private SQL mutation order

The repaired rollback test requires the terminal event to exist before the logical execution
UPDATE. Its trigger raises SQLSTATE `23503` when no event is visible
(`tests/test_provider_call_lineage.py:698-706`), then the assertion requires SQLSTATE `23514`
(`tests/test_provider_call_lineage.py:723-728`). A correct implementation that updates the logical
row first and inserts the event second in the same transaction is atomic under AC-7, but this test
rejects it solely because of statement order. That contradicts the Test Agent report's claim that
the contract does not prescribe private SQL statement shape.

Replace this order-dependent assertion with complementary transaction-failure probes that permit
either valid ordering. For example, make the logical UPDATE fail unconditionally and assert no
event survives, then make the event INSERT fail and assert no logical transition survives. Together
those probes catch split transactions whether an implementation is event-first or logical-first,
without selecting either implementation.

## Prior Important findings

- **AC-2 durable failure records — closed.** All six required failure classes now pass through
  `finish_physical_attempt`, are read directly from PostgreSQL, and assert exact status, typed
  error, identity, nullable usage, and nullable cost state. The durable `invalid_usage` case also
  proves physical `invalid` plus SQL null.
- **AC-7 final failure and atomicity — partially closed.** The ordinary `final=True`
  `terminal_failure` case now proves the failed logical terminal state, source event id, nullable
  cost, and one durable event. The rollback half remains overconstrained as described above.
- **Event ownership and cardinality — closed.** Schema inspection requires the composite
  `(organization_id, invocation_id)` event FK and a one-event-per-invocation uniqueness invariant.
  Direct SQL separately exercises duplicate terminal facts and cross-organization reattribution
  with otherwise-valid attribution values.
- **Recovered unknown cost — closed.** Crash recovery now requires logical
  `measured_cost IS NULL`, `cost_measurement_state = 'not_observed'`, and the exact recovered source
  event id.

## Independent evidence

Focused RED:

```text
<venv-python> -m pytest -o addopts='' tests/test_provider_call_lineage.py -q --tb=short
```

Result: `28 failed` in `1.52s`. Twenty-five cases fail only at the explicit missing-lineage-module
assertion and three fail only at the explicit missing-lineage-tables assertion. Collection,
PostgreSQL connectivity, fixtures, and migration setup remain healthy.

Preserved full baseline:

```text
<venv-python> -m pytest -o addopts='' tests \
  --ignore=tests/test_provider_call_lineage.py -q
```

Result: `1125 passed, 3 skipped` in `27.69s`.

Preserved migration/role/hosted/store slice:

```text
<venv-python> -m pytest -o addopts='' \
  tests/test_migrations.py tests/test_db_roles.py \
  tests/test_hosted_configuration.py tests/test_postgres_api_m1d.py -q
```

Result: `40 passed` in `2.28s`.

Static and hygiene evidence:

- Candidate T-F00 spec-lint: `T-F17b maps 8 acceptance criteria across 1 pytest-collected scopes`.
- Ruff check: pass.
- Ruff format check: pass.
- Python compilation: pass.
- Diff check from repair base `0bb876fdbc8008d1dd511e1c3624e2701a013ef7`: pass.
- Secret scan: `secret scan clean (845 files)`.
- Gitleaks over `0bb876f..990b0c3`: one commit scanned, no leaks found.
- Repair diff is limited to `tests/test_provider_call_lineage.py` and the Test Agent report.
- No product, migration, provider, target, credential, configuration, or deployment file changed.

Final severity: Critical `0`; Important `1`; Minor `0`.
