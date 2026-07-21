export const meta = {
  name: 'm6a-observability-impl',
  description: 'M6a (main-repo re-run): finish the observability core against the frozen tests — coverage_view.sql + migration 0003 + O7 fallback; keep salvaged tracing/reconcile/alerts green. Then reviewer ∥ security.',
  phases: [
    { title: 'Implement', detail: 'GREEN: coverage_view.sql + migration 0003 + O7 fallback' },
    { title: 'Review', detail: 'reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'

const SPEC = `
REPO (main repo): ${REPO}   BRANCH: ticket/m6a-observability (off swarm; has M2 + M4). venv at ${REPO}/.venv.
Activate it for EVERY command: \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Python 3.12; SQLAlchemy2 +
Alembic + psycopg3 installed; Postgres 16 UP. Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.
DO NOT git commit/push (the orchestrator integrates).

STATE: The FROZEN test tests/test_observability.py ALREADY EXISTS (Test-Agent-owned, FROZEN — do NOT edit it or
conftest.py/_db.py). A PARTIAL impl is already in place and PASSING its portion:
src/agentforge/observability/{tracing.py, reconcile.py, alerts.py} exist and their tracing/reconcile/alerts
tests are GREEN. The REMAINING RED (9 tests) is entirely the Postgres coverage view + its migration + the O7
fallback that reads it:
  test_coverage_metric_view_exists_after_migration, test_coverage_view_exposes_the_sor_grouping_and_gate_columns,
  test_coverage_counts_distinct_pairs_only_a_duplicate_counts_once, test_coverage_ignores_unverified_evidenceless_verdicts,
  test_covered_flag_requires_min_verified_and_oracle, test_covered_flag_false_without_the_oracle_anchor_even_at_volume,
  test_covered_flag_true_only_with_full_evidence, test_langfuse_out_fallback_derives_coverage_from_postgres,
  test_langfuse_out_fallback_is_not_random.
READ tests/test_observability.py FIRST — it is the exact contract for the view's columns, the S6 covered-flag
gate, and the fallback function's name/signature. Build to it; do not guess.

WHAT REMAINS (ARCHITECTURE §9 S6/S9/O3/O7, §6 correlation, D5; external-out — NO opentelemetry, NO langfuse,
NO network). Read src/agentforge/storage/models.py (attempt_result, verdict — verdict→attempt_result FK exists;
attempt_result has content_hash; the join key is (campaign_run_id, attempt_id)).

FILE SCOPE (impl, ONLY these): src/agentforge/observability/coverage_view.sql,
  migrations/versions/0003_coverage_view.py, and IF the frozen tests require it, a small O7 fallback function
  in src/agentforge/observability/ (e.g. coverage.py or in reconcile.py — match whatever the frozen test
  imports). You MAY refine the existing tracing.py/reconcile.py/alerts.py ONLY if a frozen test needs it, but
  keep their currently-green tests green. Also add package-data so coverage_view.sql SHIPS in the wheel:
  in pyproject.toml [tool.setuptools.package-data] add \`"agentforge.observability" = ["*.sql"]\` (leave the
  existing "agentforge.storage" entry). Touch NOTHING else (not models/0001/0002/policy/target/config/tests).

DESIGN:
- coverage_view.sql — a Postgres view (name it EXACTLY as the frozen test queries, e.g. coverage_metric) that
  computes coverage ONLY from hash-verified, run-nonce-DEDUPED verdict records — never raw spans. Join
  verdict → attempt_result on (campaign_run_id, attempt_id) (the FK guarantees evidence exists), count
  DISTINCT (campaign_run_id, attempt_id) pairs (a duplicate counts once), group by the grouping the test
  expects (category/target_version), and expose the gate columns the test asserts — a covered flag TRUE only
  with ≥N distinct verified attempts AND ≥1 oracle/human-anchored case (S6). Match the exact column names /
  thresholds the frozen test checks.
- migration 0003_coverage_view.py — down_revision "0002". upgrade() creates the view from coverage_view.sql
  (load via importlib.resources.files('agentforge.observability')/'coverage_view.sql' so the migration is the
  single apply path and the file ships in the wheel). downgrade() drops the view. Do NOT touch 0001/0002.
- O7 fallback — the function the frozen test imports (read the test for its name/location/signature): when the
  'Langfuse' path is unavailable, derive coverage/priority from Postgres (the coverage view), deterministically
  — never random, never blocked.

CONSTRAINTS: stdlib-only observability core (imports storage/config/secrets, NOT fastapi/opentelemetry/langfuse
/network). Secrets redacted in any exporter output (agentforge.secrets). Synthetic data only — no PHI.
GOAL: FULL suite green (incl. M2/M4 which now upgrade through 0003), ruff clean, tests untouched.
`

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
  `You are the IMPLEMENTATION AGENT finishing M6a. READ tests/test_observability.py to learn the exact
coverage-view columns, S6 covered-flag gate, and O7 fallback signature. Then make the 9 remaining RED tests
GREEN by creating src/agentforge/observability/coverage_view.sql + migrations/versions/0003_coverage_view.py
(+ the O7 fallback where the test imports it), and add the observability package-data line to pyproject.toml.
Do NOT edit any tests/ file, 0001/0002, models, or policy. Keep the already-green tracing/reconcile/alerts tests green.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — ALL green (M2/M4 now upgrade through your
0003). \`ruff check .\` + \`ruff format --check .\` clean. Verify \`git status --porcelain tests/\` shows no changes
you made. In s6_s9_mechanism describe exactly how the view excludes unverified/duplicate records (S6). Return
the structured result with the exact pytest summary line.`,
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
migration 0003, tests/test_observability.py). Verify migration 0003 is additive (touches nothing in 0001/0002)
and round-trips; the coverage view genuinely excludes unverified + duplicate records (S6) and the covered-flag
gate requires the min verified + oracle anchor; reconcile marks a hash divergence degraded (S9); the tracing
core stays stdlib-only. Run the full suite (confirm it upgrades through 0003). Report real issues only. ${SPEC}`,
    { label: 'review:m6a', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
  () => agent(
    `Independent SECURITY REVIEWER for M6a in ${REPO}. Adversarially audit:
  - Can coverage be computed from RAW spans or UNVERIFIED/DUPLICATE verdict rows (S6 bypass)? Prove the view
    only counts hash-verified, nonce-deduped, oracle/human-gated records.
  - Can a hash divergence go unnoticed (S9)? Prove a mismatched/missing transcript_hash forces 'degraded'.
  - Does any exporter/log/alert leak a raw secret or raw adversarial content (must redact via secrets)?
  - Is the core external-out: NO opentelemetry, NO langfuse, NO network import? (assert via sys.modules AND
    a source-grep). Does 0003 mutate 0001/0002 or risk data loss? Any real PHI?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local/os.environ. ${SPEC}`,
    { label: 'security:m6a', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
])

return { impl: implResult, review, security }
