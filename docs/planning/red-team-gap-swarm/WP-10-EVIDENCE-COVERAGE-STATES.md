# WP-10 — Replace binary coverage with an evidence-state ledger

**Branch:** `rtg/wp10-evidence-coverage-states`

**Model:** capable

**Depends on:** WP-02, WP-09

**Implements toward (live validation pending):** RT-01

Read the current coverage view/API/UI, authoritative result tables, corpus/results
boundaries, RT-01, and the WP-09 evidence-status contract.

**Implementation writes only**

- `src/agentforge/coverage/__init__.py`
- `src/agentforge/coverage/model.py`
- `src/agentforge/coverage/projection.py`
- `src/agentforge/observability/coverage_view.sql`
- `src/agentforge/storage/models.py`
- `migrations/versions/<MIGRATION_REV>_coverage_evidence_states.py`
- `src/agentforge/api/backend.py`
- `src/agentforge/api/router.py`
- `src/agentforge/api/postgres.py`
- `src/agentforge/api/read_models.py`
- `console/src/api/paths.ts`
- `console/src/api/read-models.ts`
- `console/src/types.ts`
- `console/src/screens/ConsoleScreens.tsx`

**Test writes only**

- `tests/coverage/test_evidence_ledger.py`
- `tests/api/test_coverage_evidence_api.py`
- `console/tests/coverage-evidence.test.tsx`

## Required result

Expose independent stages:

1. mapped;
2. authored;
3. surface executable;
4. authorized;
5. dispatched;
6. live observed;
7. oracle backed;
8. decisively adjudicated;
9. regression admitted;
10. regression replayed.

`demonstrated` requires live observation, trusted oracle evidence, and decisive
adjudication. `regression_protected` requires admitted and replayed. Mappings, prompts,
tool candidates, passive scans, cassettes, and `NOT_EXECUTED` metadata never count as live
behavior. Chat simulation cannot prove a RAG/tool/write surface. `INDETERMINATE` and
`ERROR` are never decisive or passing. A confirmed exploit remains visibly vulnerable,
not “safe coverage.”

Only hash-verified evidence bound to exact organization, target/version, surface/version,
corpus, authorization-scope hash, run, and attempt advances a stage. Deduplicate run/attempt
pairs. Tampering or missing evidence produces a degraded record with a bounded blocker.
Remove `_REQUIRED_*` subsets as a security-success claim while preserving compatibility for
old consumers.

For stages 6–10, “evidence” means approved WP-21 output from the exact deployed Railway
release and owner-authorized deployed target through production paths. Local tests, mocks,
fixtures, fake targets, simulated artifacts, and imported/saved outputs are rejected at the
projection boundary, not merely labeled lower confidence.

The aggregation identity is case version × primary taxonomy risk/version × exact surface
version × target version, within organization and corpus. Build the projection from the
authored manifest outward, not attempts inward: an authored case with zero database
attempts must still appear with `not_authorized`, `not_dispatched`, or another exact
blocker. Never let missing rows make a required case disappear.

An applicability exclusion is a separate audited state, never demonstrated coverage. It
can remove a matrix cell from the required denominator only when the WP-14 record and
distinct human approval hashes are valid for the exact taxonomy, subject, surface, target,
and corpus; pending/stale/missing-surface records remain visible blockers.

The console shows the stage matrix and blockers—never an unqualified 100% badge.

**Focused verifier**

```bash
python -m pytest tests/coverage/test_evidence_ledger.py tests/api/test_coverage_evidence_api.py tests/test_migrations.py tests/test_readiness_m1d.py -q
cd console && npm test -- coverage-evidence.test.tsx
```

Then run the full Python and console gates.

**Handoff:** WP-11 supplies oracle stages; WP-12 real surface stages; WP-14 taxonomy
requirements; WP-15 mutation gaps; WP-19 replay stages.
