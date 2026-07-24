# T-F17b Test Agent Report

Status: `DONE`

## Scope and identity

- Base: `0803849aab0e99387ee80566b359384cb216f2b1`
- Branch: `ticket/T-F17b-provider-call-lineage`
- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17b`
- Test ownership: `tests/test_provider_call_lineage.py`
- Report ownership: `.tdd-swarm/reports/T-F17b-test.md`
- No production, migration, provider, target, credential, deployment, configuration, or main-branch
  file was changed.
- All identifiers, payload fragments, provider-key shapes, sessions, and evidence strings are
  synthetic test fixtures. No external network, provider call, target call, credential resolution,
  spend, or deployment occurred. PostgreSQL checks used only the already-running local disposable
  test service.

## Frozen-contract candidate

The suite defines the T-F17b interface consumed by T-F17c:

- immutable `ProviderLogicalContextV1`, `ProviderInvocationContextV1`, and
  `ProviderTerminalEventV1` records in `agentforge.providers.lineage`;
- Runner-owned `ControlPlaneStore.begin_physical_attempt(logical_context, sequence)`;
- `ControlPlaneStore.finish_physical_attempt(invocation, event, final=...)`;
- `ControlPlaneStore.reconcile_unknown_physical_attempt(invocation)`; and
- organization-filtered `ControlPlaneStore.list_provider_call_events(organization_id=...)`.

These names express the planning document's public physical-attempt factory and the minimum
terminal/recovery/read seams required by the next transport and API tickets. The tests do not
prescribe private helpers, SQL statement shape, ORM use, trigger implementation, or UUID algorithm.

## Criterion mapping

- AC-1: one immutable committed invocation and one append-only success event bind organization,
  run, campaign attempt, logical/parent execution, role, sequence, requested/configured identity,
  prompt/configuration/policy hashes, provider-confirmed identity/request, all three token kinds,
  exact Decimal measured cost, status, timestamps, and duration.
- AC-2: timeout, retryable response, terminal response, returned model/provider mismatch, invalid
  usage, and invalid structured output each have a closed status/error taxonomy, bounded sanitized
  errors, nullable unavailable facts, no fabricated token counts, and no unknown-as-zero cost.
- AC-3: retry then success commits and independently exposes sequences 1 and 2 before later work;
  the first terminal event leaves the logical execution running, the final success terminalizes
  it, and duplicate sequence, cross-organization execution, and wrong campaign-attempt attribution
  are rejected. Schema checks require composite organization/execution/attempt foreign keys and the
  sequence uniqueness constraint.
- AC-4: real PostgreSQL privileges allow only the Runner to insert and only Web/Runner to select;
  Runner included, no role may UPDATE, DELETE, or TRUNCATE either lineage table. Denials must be
  genuine SQLSTATE `42501`. A two-organization read test requires the store projection to return
  only the requested authenticated organization.
- AC-5: the additive migration must create both lineage relations, nullable observation fields,
  composite foreign keys, uniqueness, and organization/role/time, campaign-order,
  provider-request-id, and logical-execution indexes. A dedicated isolated database is migrated to
  `0015`, seeded with an existing terminal logical execution, upgraded to head, verified for
  lossless non-cost fields and honest zero reclassification, downgraded to `0015`, and compared
  exactly before teardown.
- AC-6: provider-key-, session-, private-key-, and hostile-evidence-shaped values are rejected with
  non-disclosing errors. Contract fields structurally exclude raw prompt/message/request/response/
  exception/credential/session/evidence content, an unexpected raw exception argument is rejected,
  and its synthetic secret cannot appear in lineage or audit persistence.
- AC-7: exact terminal replay is idempotent, changed replay conflicts without changing the stored
  row, retryable non-final versus final logical state is explicit, and crash recovery creates
  exactly one `outcome_unknown` event for an already committed invocation. Recovery is network
  denied, cannot invent an unreserved sequence, and leaves exactly one invocation/event.
- AC-8: `measured`, `partial`, `not_observed`, and `invalid` are the only cost states; amounts are
  exact Decimal and allowed only for measured/partial, while unavailable cost is SQL/Python null,
  never numeric zero. Retry/final physical costs roll into one partial logical known subtotal whose
  two source event ids are unique and replay-stable. The migration test proves an unproven
  historical logical zero becomes `not_observed`/null, then round-trips losslessly.

## RED evidence

Focused command:

```text
python -m pytest -o addopts='' tests/test_provider_call_lineage.py -q --tb=short
```

Result: exit `1`; `25 failed`.

- 22 cases fail only at the explicit
  `T-F17b provider-call lineage module is missing` assertion.
- The three migration/grant/schema cases fail only at
  `T-F17b migration has not created lineage tables:
  ['provider_call_events', 'provider_call_invocations']`.
- There are no collection, import, fixture, PostgreSQL-connectivity, seed-data, isolated-migration
  setup, teardown, provider, target, or external-network errors.
- Collection is healthy: `25 tests collected`; all eight ticket criteria are mapped.

## Preservation and gates

- Existing repository suite excluding the new intentional RED file:
  `1125 passed, 3 skipped`.
- Existing migration, DB-role, hosted-configuration, and control-plane-store regression slice:
  `41 passed`.
- Candidate T-F00 spec-lint, run from the isolated T-F00 worktree because this exact planning base
  does not contain the script:
  `T-F17b maps 8 acceptance criteria across 1 pytest-collected scopes`.
- `ruff check tests/test_provider_call_lineage.py`: pass.
- `ruff format --check tests/test_provider_call_lineage.py`: pass.
- `python -m py_compile tests/test_provider_call_lineage.py`: pass.
- `git diff --check`: pass.
- `bash scripts/secret_scan.sh`: `secret scan clean (844 files)`.
- Diff hygiene scan: no new `TODO`, `FIXME`, `HACK`, or `print(`.
- `.tdd-swarm/run-local-gates.sh` and the canonical spec/import/coverage gates are absent from
  `0803849` and remain blocked on T-F00 integration; no blocked gate is reported as green.
- The repo-wide Ruff commands expose a pre-existing planning-base backlog (`116` lint errors and
  `19` files requiring formatting). The ticket-owned file is clean, and this Test Agent did not
  edit those unrelated files.

## Pre-commit isolation record

```text
pwd: /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17b
top-level: /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17b
branch: ticket/T-F17b-provider-call-lineage
base: 0803849aab0e99387ee80566b359384cb216f2b1
allowed changes:
  A .tdd-swarm/reports/T-F17b-test.md
  A tests/test_provider_call_lineage.py
```

Verdict: all 25 criterion-tagged cases are clean missing-feature RED, while the complete
pre-existing baseline and focused storage/control-plane regressions remain green. The candidate is
ready for independent test-design review and remains explicitly **not frozen** until that reviewer
passes and records its hashes.
