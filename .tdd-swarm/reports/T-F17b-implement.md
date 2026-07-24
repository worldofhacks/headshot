# T-F17b Implementation Agent report

Status: `IMPLEMENTED / BLOCKED(FROZEN_TEST_FIXTURE)`

## Scope

Implemented the frozen provider-call lineage contract in the ticket-owned product scope:

- validated immutable logical, invocation, and terminal-event contracts;
- committed pre-call physical attempt identity and append-only terminal facts;
- logical-row serialization, durable final intent, atomic final-only terminalization, exact replay,
  and race-idempotent crash reconciliation;
- nullable four-state cost measurement with ordered physical source event IDs;
- exact `NUMERIC(14,6)` cost validation, model/upstream binding, and secret-shape rejection;
- additive `0016` schema, indexes, composite ownership, role grants, and migration note.

No frozen test, provider transport, Runner composition, API, console, target, credential, or
deployment file was changed.

`list_provider_call_events(organization_id=...)` is an organization-filtered repository primitive;
the caller must pass the organization already authorized by the API boundary. T-F17b explicitly
excludes API projection/authentication, and the frozen signature supplies no `Principal`.

## Frozen contract status

Frozen identity remains:

- SHA-256: `717ec3e316becc39bf3d5f02cdd1ad6970c3cc6c1f54815b23fa05b20afa8f8b`
- Git blob: `a4f2e3964771a80b5da6bb34fdf7860e2e0a3838`

All 29 frozen nodes pass when each runs with the fresh database isolation described by the fixture
docstring.

The standard focused run reaches 13 passes and 16 failures. All 16 failures stop in the frozen seed
helper at duplicate `pk_campaign_authorization_requests`, before the store method under test. The
session-scoped `migrated_db` fixture retains the first case's rows while every case and parameter
unconditionally inserts identical campaign request/run/execution primary keys. AC-2 and AC-7 also
self-collide between their own parameters.

Repair requires Test Agent ownership: make the database function-scoped, clean rows between cases,
or derive unique per-node seed identity, then re-freeze.

## Verification evidence

- Frozen isolated contract: 29/29 pass.
- Focused standard invocation: 13 pass, 16 fixture-collision failures.
- Preservation slice (`migrations`, DB roles, hosted configuration, PostgreSQL API, Runner):
  53/53 pass.
- Non-ticket baseline excluding the frozen file and the stale `0015` readiness assertion:
  1,124 pass, 3 existing skips (1,127 collected).
- Unfiltered non-ticket baseline: the same 1,124 pass/3 skip plus one failure because
  `tests/test_readiness_m1d.py` hard-codes `0015` while the real single head is now `0016`.
- Migration probes: baseline upgrade/downgrade, schema/grants/indexes, and a new terminal-failure
  `0016 -> 0015 -> 0016` translation all pass.
- Race/edge probes: unfinished-attempt rejection, final-intent conflict, canonical output hash,
  changed durable identity rejection, concurrent reconciliation convergence, false-success
  rejection, secret-shape rejection, non-representable Decimal rejection, and PostgreSQL
  `NaN`/`Infinity` rejection pass.
- Scoped Ruff check/format, compileall, and `git diff --check`: pass. Repository-wide Ruff remains
  red on 116 pre-existing errors outside the six ticket paths (18 unrelated files also need format).
- Alembic: exactly one head, `0016`.
- Fast secret scan: clean across 849 files.
- Staged gitleaks scan: no leaks in the six ticket-owned files.
- Frozen SHA-256/blob: unchanged at the values above.
- Independent final code and security re-reviews: no remaining Critical or Important findings.

## Handoff

- Product implementation: `GREEN`.
- Frozen focused suite: `BLOCKED(FROZEN_TEST_FIXTURE)` despite 29/29 isolated pass.
- Integration debt: update the out-of-scope readiness-head assertion from `0015` to `0016`.
- External/live effects: none.
