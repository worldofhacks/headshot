# T-F17b Final Test Design Review

Status: `DONE`

Verdict: `PASS`

Freeze verdict: `FROZEN`

Reviewed commit: `38219747238377b283cedfe80f9a14a2ae7661f2`

Frozen test identity:

- `tests/test_provider_call_lineage.py`
  - SHA-256: `717ec3e316becc39bf3d5f02cdd1ad6970c3cc6c1f54815b23fa05b20afa8f8b`
  - Git blob: `a4f2e3964771a80b5da6bb34fdf7860e2e0a3838`

The Implementation Agent must preserve this exact test identity. Any test change invalidates this
freeze and requires a new independent test-design review.

## Findings

No Critical, Important, or Minor findings.

## Final atomicity repair

The two AC-7 trigger cases at `tests/test_provider_call_lineage.py:666-750` are complementary and
do not prescribe private statement order:

- the logical-target case makes the `agent_executions` UPDATE fail. An event-first implementation
  must roll back its earlier event INSERT, while a logical-first implementation fails before its
  later event write;
- the event-target case makes the `provider_call_events` INSERT fail. A logical-first
  implementation must roll back its earlier logical UPDATE, while an event-first implementation
  fails before its later logical write.

Both cases require the committed pre-call invocation to remain, the terminal event count to be zero,
and the logical execution to remain exactly `running` with no error, finish time, or source event id.
Therefore either valid same-transaction ordering passes, while an event-first or logical-first
split-transaction implementation leaves a partial durable state in one of the two probes and fails.
The successful final-terminal-failure case separately proves that, without injection, both writes
occur and produce the required failed logical state and exact source event id.

## Previous repair preservation

- **AC-2 durable failure records:** all six required failure classes round-trip through
  `finish_physical_attempt` and PostgreSQL with exact status, bounded typed error, observed identity
  shape, nullable usage, and nullable cost. Durable invalid usage proves `invalid` plus SQL null.
- **AC-7 final failure:** ordinary `final=True` terminal failure writes exactly one event and
  terminalizes the logical row as failed with nullable/not-observed cost and its exact source id.
- **Event ownership and cardinality:** schema inspection and direct SQL require the composite
  organization/invocation FK, one terminal event per invocation, and rejection of duplicate and
  cross-organization terminal facts.
- **Recovered unknown cost:** crash recovery requires logical nullable/not-observed cost and the
  exact recovered source event id, with one event and no network call.

The remaining AC-1 through AC-8 coverage from the prior reviews is unchanged: immutable provider
identity and usage facts, committed per-retry contexts, append-only role grants, isolated migration
round-trip and indexes, hostile-content rejection, exact replay/conflict behavior, crash-to-unknown
reconciliation, closed Decimal cost states, source-id accounting, and historical-zero
reclassification.

## Independent evidence

Focused RED:

```text
<venv-python> -m pytest -o addopts='' tests/test_provider_call_lineage.py -q --tb=short
```

Result: `29 failed` in `1.46s`. Twenty-six cases fail only at the explicit missing-lineage-module
assertion and three fail only at the explicit missing-lineage-tables assertion. Collection,
PostgreSQL connectivity, fixtures, and migration setup remain healthy.

Preserved full baseline:

```text
<venv-python> -m pytest -o addopts='' tests \
  --ignore=tests/test_provider_call_lineage.py -q
```

Result: `1125 passed, 3 skipped` in `27.10s`.

Preserved migration/role/hosted/store slice:

```text
<venv-python> -m pytest -o addopts='' \
  tests/test_migrations.py tests/test_db_roles.py \
  tests/test_hosted_configuration.py tests/test_postgres_api_m1d.py -q
```

Result: `40 passed` in `2.10s`.

Static and hygiene evidence:

- Candidate T-F00 spec-lint: `T-F17b maps 8 acceptance criteria across 1 pytest-collected scopes`.
- Ruff check: pass.
- Ruff format check: pass.
- Python compilation: pass.
- Diff check from final repair base `a1e2777118c930c7ddfdf35fd684248d2250c330`: pass.
- Secret scan: `secret scan clean (845 files)`.
- Gitleaks over `a1e2777..3821974`: one commit scanned, no leaks found.
- Final repair diff is limited to `tests/test_provider_call_lineage.py` and the Test Agent report.
- No product, migration, provider, target, credential, configuration, or deployment file changed.

Final severity: Critical `0`; Important `0`; Minor `0`.
