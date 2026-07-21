export const meta = {
  name: 'm6a-observability-core',
  description: 'M6a: provider-neutral observability core — OTEL-shaped local tracing, durable correlation IDs, Postgres SoR coverage view (S6), hash reconciliation (S9), alert interfaces (O3), Langfuse-out fallback (O7). TDD + reviewer + security.',
  phases: [
    { title: 'Tests', detail: 'RED: tracing, reconcile, coverage view, alerts' },
    { title: 'Implement', detail: 'GREEN: observability/*, coverage_view.sql, migration 0003' },
    { title: 'Review', detail: 'reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/wt-m6a'

const SPEC = `
REPO (git worktree, ISOLATED): ${REPO}   BRANCH: ticket/m6a-observability (off swarm; has M2).
This worktree has its OWN venv at ${REPO}/.venv. Activate it for EVERY command:
  \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`
Do NOT cd to any other repo/worktree. Python 3.12; SQLAlchemy2+Alembic+psycopg3 installed; Postgres 16 UP.
Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`. DO NOT git commit/push. The M2 schema
+ migrated_db fixture (tests/conftest.py, tests/_db.py) exist on this branch — reuse them; migrated_db runs
\`alembic upgrade head\`, which will include YOUR new migration 0003.

WHAT M6a DELIVERS — the provider-neutral OBSERVABILITY CORE (ARCHITECTURE §9/§13, D5; PRESEARCH invariants).
Map S6, S9, O3, O6, O7, PRD-25/26 (local half). Deps M2✓. **EXTERNAL-OUT: NO Langfuse Cloud, NO opentelemetry
SDK, NO network** — this is the LOCAL, framework-neutral core; the real OTEL SDK + Langfuse exporter land in
M6b. Read ARCHITECTURE.md §9 (the six questions, S6/S9/O3/O7), §13 (O7 fallback), §6 (correlation IDs O6),
and src/agentforge/storage/models.py (attempt_result, verdict — verdict→attempt_result FK exists) first.

FILE SCOPE (impl): src/agentforge/observability/tracing.py, reconcile.py, alerts.py,
  src/agentforge/observability/coverage_view.sql, migrations/versions/0003_coverage_view.py.
  Do NOT touch models.py / 0001 / 0002 / policy / target / config / secrets / app / health / contracts.
FILE SCOPE (tests, Test Agent owns): tests/test_observability.py. Do NOT modify conftest.py/_db.py or any
  other existing test.

DESIGN (build to this; ACs are the contract):

tracing.py — provider-neutral, STDLIB-ONLY (no opentelemetry import). A Span (name, attributes, parent,
  start/end via an INJECTABLE clock — no wall-clock in tests), a Tracer that opens a root span per request
  (one-request = one-trace) and child spans for {red_team, gateway, judge, documentation}, a NoOpExporter and
  a ConsoleExporter (stdlib logging/print — redact secrets, never raw). A CorrelationContext carries
  campaign_id / attempt_id / finding_id (O6) and stamps them + the tags {agent, attack_category, owasp_web,
  owasp_llm, system_version, verdict} onto every span. The exporter is swappable so M6b can drop in the OTEL
  SDK with zero re-instrumentation.

reconcile.py — S9 evidence-hash reconciliation. reconcile(attempt_result_row_or_hash, span_transcript_hash)
  → a status enum {ok, degraded}. The authoritative content_hash is the attempt_result's; if the span's
  transcript_hash diverges, the run is marked DEGRADED (not trusted, not blocked) — a divergence is detectable
  because both carry the same hash by construction (§9). Fail-closed: a missing/malformed hash → degraded.

coverage_view.sql + migration 0003 — the Postgres SoR coverage view (S6). A view (e.g. coverage_metric) that
  computes coverage ONLY from hash-verified, run-nonce-DEDUPED verdict records — never from raw spans: join
  verdict → attempt_result on (campaign_run_id, attempt_id) (the FK guarantees the evidence exists), count
  DISTINCT (campaign_run_id, attempt_id) pairs, group by category/target_version, and expose a covered flag
  that is TRUE only with ≥N distinct verified attempts AND ≥1 deterministic-oracle/human-spot-checked case
  (S6 sanity gate). A duplicate pair counts once. Migration 0003 (down_revision 0002) CREATEs the view from
  coverage_view.sql (load it via importlib.resources.files('agentforge.observability')/'coverage_view.sql' so
  it ships in the wheel and is the single apply path); downgrade drops the view. Keep 0001/0002 untouched.

alerts.py — O3 alert interfaces. Alert(kind, source, payload) + an AlertChannel protocol + a deterministic
  CapturingAlertChannel (in-memory; NO real webhook/network). Alert kinds fire on: human-approval-pending
  (with SLA), regression-detected/finding-reopened, budget-circuit-breaker-tripped, target-unreachable-beyond-
  backoff, queue-depth-over-threshold, emission-failure (Langfuse/DB). Alerts are tied to the DURABLE source
  (exploit DB / queue), not Langfuse alone, so an observability outage does not silence them.

ACCEPTANCE (each test pins an edge/error, never happy-path only):
  AC-1 one-request=one-trace with child spans; correlation IDs (campaign_id/attempt_id/finding_id) + the tag
  set are on every span; NoOp + Console exporters both work; assert NO opentelemetry import. AC-2 durable
  correlation IDs propagate across spans. AC-3 the coverage_metric view exists (migration 0003) and reads from
  the DB SoR. AC-4 (S9 invariant) matching hash → ok; a MISMATCHED transcript_hash → degraded; missing hash →
  degraded (fail-closed). AC-5 (S6 invariant) coverage counts ONLY hash-verified, nonce-deduped verdicts — a
  duplicate pair counts once; a category is NOT 'covered' without ≥N distinct verified attempts AND an
  oracle/human case; raw spans are NEVER a coverage source. AC-6 each O3 alert kind fires, tied to the durable
  source, deterministically. AC-7 (O7) with the 'Langfuse' exporter unavailable, coverage/priority are still
  computed from Postgres (never random, never blocked). AC-8 synthetic data only — no PHI.

CONSTRAINTS: stdlib-only core (observability imports storage/config/secrets, NOT fastapi, NOT opentelemetry,
NOT langfuse). No network. Secrets redacted in any exporter output (use agentforge.secrets). Postgres SoR only.
`

phase('Tests')
const TEST_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    test_files: { type: 'array', items: { type: 'string' } },
    acs_covered: { type: 'array', items: { type: 'string' } },
    red_confirmed: { type: 'boolean' },
    red_evidence: { type: 'string' },
    notes: { type: 'string' },
  },
  required: ['test_files', 'red_confirmed', 'red_evidence'],
}
const testResult = await agent(
  `You are the TEST AGENT for M6a. Write failing (RED) tests ONLY (tests/test_observability.py) — no src/ or
migration code. Cover every AC incl. edges: hash MISMATCH → degraded (S9), duplicate pair counted once + the
'covered' gate (S6), each O3 alert kind, the O7 Langfuse-out fallback, and an assertion that NO opentelemetry
module is imported. Use the M2 migrated_db fixture for the coverage-view / reconcile DB tests (it runs
\`alembic upgrade head\` — your 0003 view will exist once the impl lands, so RED now is: view missing /
agentforge.observability.* import errors). Deterministic only (injectable clock; in-memory alert channel).
Run \`. .venv/bin/activate && python -m pytest tests/test_observability.py -q\` and CONFIRM RED. Make the tests
ruff-clean. Do NOT edit conftest.py/_db.py or any src file. Return the structured result.`,
  { label: 'test:m6a', phase: 'Tests', schema: TEST_SCHEMA },
)

phase('Implement')
const IMPL_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    impl_files: { type: 'array', items: { type: 'string' } },
    tests_untouched: { type: 'boolean' },
    ruff_clean: { type: 'boolean' },
    pytest_summary: { type: 'string' },
    green_confirmed: { type: 'boolean' },
    s6_s9_mechanism: { type: 'string' },
    design_notes: { type: 'string' },
  },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 's6_s9_mechanism'],
}
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for M6a. Make the frozen RED tests GREEN by editing ONLY
src/agentforge/observability/{tracing,reconcile,alerts}.py, src/agentforge/observability/coverage_view.sql, and
migrations/versions/0003_coverage_view.py. Do NOT edit ANY tests/ file or 0001/0002 (if a frozen test looks
wrong, STOP and explain). Build to the DESIGN above. Also add the observability *.sql to
[tool.setuptools.package-data] ONLY if a separate package-data entry is needed — prefer a broad "agentforge.*"
= ["*.sql"] rule; DO NOT otherwise touch pyproject beyond that single package-data line if required for the
wheel to ship coverage_view.sql.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — all green (incl. the pre-existing M2 suite,
which now upgrades through your 0003). \`ruff check .\` + \`ruff format --check .\` clean. Verify
\`git status --porcelain tests/\` shows no impl-made changes. In s6_s9_mechanism, describe exactly how the
coverage view excludes unverified/duplicate records (S6) and how reconcile marks divergence degraded (S9).
Return the structured result with the exact pytest summary line.`,
  { label: 'impl:m6a', phase: 'Implement', schema: IMPL_SCHEMA },
)

phase('Review')
const REVIEW_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['critical', 'important', 'minor'] },
          location: { type: 'string' },
          problem: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['severity', 'location', 'problem', 'fix'],
      },
    },
    summary: { type: 'string' },
  },
  required: ['verdict', 'findings', 'summary'],
}
const [review, security] = await parallel([
  () => agent(
    `Independent CODE REVIEWER for M6a in ${REPO} (git --no-pager diff; read observability/*, coverage_view.sql,
migration 0003, test_observability.py). Verify: one-request=one-trace + correlation IDs + tags; migration 0003
is additive (touches nothing in 0001/0002) and round-trips; the coverage view genuinely excludes unverified +
duplicate records (S6) and the tests would fail if it counted raw/duplicate rows; reconcile marks a hash
divergence degraded (S9) and is not a tautology. Run the tests + confirm the full suite still upgrades through
0003. Report real issues only. ${SPEC}`,
    { label: 'review:m6a', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
  () => agent(
    `Independent SECURITY REVIEWER for M6a in ${REPO}. Adversarially audit:
  - Can coverage be computed from RAW spans or from UNVERIFIED / DUPLICATE verdict rows (S6 bypass)? Prove the
    view only counts hash-verified, nonce-deduped, oracle/human-gated records.
  - Can a hash divergence go unnoticed (S9)? Prove a mismatched/missing transcript_hash forces 'degraded',
    fail-closed.
  - Does any exporter/log/alert leak a raw secret or raw adversarial content (must be redacted via secrets)?
  - Is the core truly external-out: NO opentelemetry, NO langfuse, NO network import? (assert via sys.modules)
  - Does 0003 mutate 0001/0002 or risk data loss? Any real PHI?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local/os.environ. ${SPEC}`,
    { label: 'security:m6a', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
])

return { test: testResult, impl: implResult, review, security }
