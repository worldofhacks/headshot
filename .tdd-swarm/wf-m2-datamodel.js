export const meta = {
  name: 'm2-datamodel-roles-migrations',
  description: 'M2: exploit-DB data model + Alembic expand/contract migrations + per-agent DB roles (append-only, DB-enforced) with S1/S2 invariant tests, via TDD + independent reviewer + security',
  phases: [
    { title: 'Tests', detail: 'RED: models, DB-role rejection (S1/S2), migration round-trip' },
    { title: 'Implement', detail: 'GREEN: storage/models.py, migrations/**, storage/roles.sql' },
    { title: 'Review', detail: 'independent reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const DSN = 'postgresql+psycopg://agentforge:local_dev_only@localhost:5432/agentforge'

const SPEC = `
REPO: ${REPO}   BRANCH: ticket/m2-datamodel (already checked out off swarm/mvp-local-slice)
PACKAGE: src-layout, package = agentforge (pytest pythonpath=["src"]). Python 3.12.
Activate the venv for EVERY command: \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`.
Stack (installed, confirmed): SQLAlchemy 2.0 + Alembic 1.18 + psycopg 3 (driver). Postgres 16 is UP locally.
Ruff: ruff.toml (line-length 100; select E,F,I,UP,B,SIM). Run \`ruff check .\` and \`ruff format --check .\`.

DATABASE. A local Postgres is running. Admin/superuser DSN (SQLAlchemy+psycopg3 dialect):
  ${DSN}
CI provides the same via env DATABASE_URL=postgresql://agentforge:local_dev_only@localhost:5432/agentforge
(note the CI value uses the bare postgresql:// scheme — code MUST translate it to postgresql+psycopg:// for
SQLAlchemy 2.x + psycopg3). The 'agentforge' login is the cluster SUPERUSER, so it can CREATE ROLE and GRANT,
and \`SET ROLE <role>\` from it is subject to that role's grants (tables are OWNED by agentforge, so the
per-agent roles are non-owners and GRANT checks apply — this is how the role tests prove the invariant).

WHAT M2 DELIVERS (exploit-DB data model + migrations + per-agent DB roles). Anchors: ARCHITECTURE §6/§7,
D6/D7/D14; PRESEARCH §5 (domain model, state machines, invariants). Map S1/S2, PRD-OPT-13/14/15/16.
Read ARCHITECTURE.md §4 (AttemptResult field set), §5 (S1/S2), §6 (data model) and PRESEARCH.md §5.1/§5.2/§5.3
before writing anything.

FILE SCOPE (impl): src/agentforge/storage/models.py, src/agentforge/storage/roles.sql,
  migrations/** (Alembic: alembic.ini, migrations/env.py, migrations/script.py.mako, migrations/versions/*.py).
  (pyproject.toml already has sqlalchemy+alembic — do NOT touch it. Do NOT touch app.py/config.py/health.py/
  contracts/target — out of scope. The M1a /ready schema_check wiring is a deliberate later step, NOT M2.)
FILE SCOPE (tests, Test Agent owns): tests/test_models.py, tests/test_db_roles.py, tests/test_migrations.py,
  and a DB fixture (tests/conftest.py or tests/_db.py). The Impl agent MUST NOT edit anything under tests/.

DATA MODEL — model the entities whose STATE MACHINES (PRESEARCH §5.2) or the S1/S2 evidence spine the local
MVP slice needs; do NOT model the whole 18-noun zoo (CostRecord/CoverageMetric/GroundTruthLabel/ContractVersion/
Incident/Target/TargetAdapter/AllowlistEntry/CredentialBinding/Transcript land with their consumers — leave a
short module docstring noting that deferral so it is intentional, not forgotten). Tables (Postgres, SQLAlchemy
2.0 DeclarativeBase, timezone-aware timestamps, server_default where sensible):
  - campaign(state: queued→running→{complete|halted|aborted}) — business key campaign_id UNIQUE.
  - attack_case(state: draft→active→retired) — plus attack_class enum {boundary,invariant,regression} and an
    owasp tags column (jsonb) so no happy-path-only case is representable without its tags.
  - attempt(state: queued→running→{success|fail|partial}|error) with typed_error enum nullable
    {target_unreachable,budget_exceeded,judge_timeout,rate_limited,adapter_error}; fk campaign.
  - red_team_staging — the Red Team's INSERT-only staging table it CANNOT read back: id, campaign_run_id,
    attempt_id, payload jsonb, created_at.
  - attempt_result — the AUTHORITATIVE, APPEND-ONLY, hashed evidence table (D14 field set): schema_version,
    campaign_run_id, attempt_id, campaign_id, target_id, target_version, attack_attempt (jsonb),
    request_transcript + response_transcript (jsonb/text), policy_decision_id, executed_at, trace_id,
    correlation_id, recorder_identity, recorder_version, content_hash (TEXT NOT NULL). **UNIQUE(campaign_run_id,
    attempt_id)** (S3 replay-rejection foundation). Index on target_version.
  - verdict — verdict_state enum {EXPLOIT_CONFIRMED,EXPLOIT_LIKELY,NO_EXPLOIT_OBSERVED,INDETERMINATE,ERROR},
    confidence, campaign_run_id, attempt_id (references the attempt_result pair), created_at.
  - finding(state: candidate→judged→documented→approved→published→remediated→validated→{resolved|regressed})
    with finding_id UNIQUE, severity enum {low,medium,high,critical}, category text, target_version text.
    **Indexes on severity, category, target_version** (the three PRD-OPT-16 query patterns).
  - regression_case(state: admitted→passing→{failing}) — minimal.
  Referential integrity via FKs; no orphan finding without a resolvable campaign chain (invariant §5.3#6).

MIGRATIONS (Alembic, D7 expand/contract, §12):
  - migrations/env.py reads DATABASE_URL (translate bare postgresql:// → postgresql+psycopg://; fall back to the
    admin DSN above), uses models' MetaData as target_metadata, offline+online modes.
  - Version 0001 (initial): create ALL tables + enums + indexes + the UNIQUE(campaign_run_id, attempt_id)
    constraint. Then create the per-agent ROLES and GRANTs by executing the canonical SQL in
    src/agentforge/storage/roles.sql (load it via importlib.resources.files('agentforge.storage')/'roles.sql'
    so it ships with the package and stays DRY — the migration is the single apply path, roles.sql the source).
    Roles must be created IDEMPOTENTLY (Postgres has no CREATE ROLE IF NOT EXISTS — use a DO $$ ... $$ block
    with a pg_roles check). downgrade() drops the objects.
  - Version 0002 (expand/contract demonstrator): an EXPAND-only migration that ADDS a nullable column to an
    existing table (e.g. finding.exploitability or attempt_result.notes) WITHOUT touching existing rows and
    WITHOUT dropping/renaming any column a consumer uses. downgrade() drops just that added column.

PER-AGENT DB ROLES (src/agentforge/storage/roles.sql) — S1/S2, append-only enforced BY DB PERMISSIONS:
  - headshot_redteam: GRANT INSERT ON red_team_staging only. NO SELECT/UPDATE/DELETE on it (no read-back).
    NO privileges on attempt_result. (NOLOGIN role is fine — tests use SET ROLE.)
  - headshot_recorder: GRANT SELECT ON red_team_staging (to read RT submissions) + GRANT INSERT ON
    attempt_result. **NO UPDATE and NO DELETE on attempt_result (or anything)** — append-only by grant absence.
  - headshot_judge: GRANT SELECT ON attempt_result (+ verdict, finding). NO INSERT/UPDATE/DELETE on attempt_result.
  - CRITICAL: no role is the table OWNER, and NO role anywhere receives UPDATE or DELETE on attempt_result —
    append-only is DB-enforced, not conventional. Revoke default PUBLIC privileges as needed so grants are exact.

TESTS (Test Agent writes first, RED; connect to REAL Postgres — these invariants must RUN, not skip):
  - DB fixture: create a fresh throwaway test DATABASE per session (e.g. name derived from os.getpid()), DROP
    IF EXISTS + CREATE via an autocommit superuser connection on the admin DSN; run \`alembic upgrade head\`
    against it; yield an Engine; DROP the DB at teardown. Roles are cluster-global — create idempotently.
    If Postgres is unreachable, the DB tests must FAIL with a clear "start Postgres (docker compose up -d
    postgres)" message — do NOT add a silent skip that would let CI go green without exercising S1/S2.
  - tests/test_models.py: tables/enums/constraints exist; UNIQUE(campaign_run_id, attempt_id) rejects a
    duplicate pair (IntegrityError); content_hash is NOT NULL; the severity/category/target_version indexes
    exist (query pg_indexes); a bad enum value is rejected.
  - tests/test_db_roles.py (S1/S2 INVARIANT — the crux): using SET ROLE + savepoints/rollback on the admin
    connection, assert EACH of:
      * headshot_redteam INSERT into red_team_staging  -> ALLOWED
      * headshot_redteam SELECT red_team_staging        -> DB REJECTS (permission denied) — no read-back
      * headshot_redteam INSERT into attempt_result     -> DB REJECTS (the S2 headline: a Red Team write to the
        Recorder-owned append-only AttemptResult table is rejected by the DB, not by convention)
      * headshot_recorder SELECT red_team_staging        -> ALLOWED
      * headshot_recorder INSERT into attempt_result     -> ALLOWED
      * headshot_recorder UPDATE attempt_result          -> DB REJECTS (append-only)
      * headshot_recorder DELETE attempt_result          -> DB REJECTS (append-only)
      * headshot_judge SELECT attempt_result             -> ALLOWED
      * headshot_judge INSERT/UPDATE/DELETE attempt_result -> DB REJECTS (SELECT-only)
    Use psycopg's error type / SQLSTATE 42501 (insufficient_privilege) to assert the rejection is a genuine
    DB permission error, not an app-layer guard.
  - tests/test_migrations.py: seed rows at 0001; \`alembic upgrade\` to 0002; assert existing rows preserved
    AND the new nullable column present; \`alembic downgrade\` back to 0001; assert rows STILL present and the
    column gone. Assert the expand step did NOT drop/rename an existing column (0002 column set ⊇ 0001 set for
    the touched table). Prove migrations don't lose data (NFR7).

CONSTRAINTS (all agents): No real PHI — synthetic fixtures only. No secrets in code/tests (the compose password
'local_dev_only' is a throwaway local-dev value already committed, not a secret). Do NOT weaken .gitignore.
The framework-neutral core (config/domain/contracts/secrets) must remain import-clean — SQLAlchemy is imported
ONLY under agentforge.storage / migrations; a bare \`import agentforge.config\` must NOT import sqlalchemy.
`

// ---- Stage 1: Test Agent ------------------------------------------------------------
phase('Tests')
const TEST_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    test_files: { type: 'array', items: { type: 'string' } },
    invariants_covered: { type: 'array', items: { type: 'string' } },
    red_confirmed: { type: 'boolean' },
    red_evidence: { type: 'string' },
    db_fixture_design: { type: 'string' },
    notes: { type: 'string' },
  },
  required: ['test_files', 'red_confirmed', 'red_evidence', 'db_fixture_design'],
}
const testResult = await agent(
  `You are the TEST AGENT for M2. Write failing (RED) tests + the DB fixture ONLY — do NOT write any src/ or
migrations/ code. Freeze the tests.
${SPEC}

Deliver tests/test_models.py, tests/test_db_roles.py, tests/test_migrations.py and the DB fixture exactly as
specified above. Run \`. .venv/bin/activate && python -m pytest tests/test_models.py tests/test_db_roles.py
tests/test_migrations.py -q\` and CONFIRM RED for the right reason (agentforge.storage.models / migrations do
not exist yet → import/collection errors, or the fixture's \`alembic upgrade head\` fails because there are no
versions). Make the tests lint-clean (ruff check + ruff format). Do NOT modify existing tests or any src/ file.
Return the structured result, listing which S1/S2 invariant assertions you encoded.`,
  { label: 'test:m2-datamodel', phase: 'Tests', schema: TEST_SCHEMA },
)

// ---- Stage 2: Impl Agent ------------------------------------------------------------
phase('Implement')
const IMPL_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    impl_files: { type: 'array', items: { type: 'string' } },
    tests_untouched: { type: 'boolean' },
    ruff_clean: { type: 'boolean' },
    pytest_summary: { type: 'string' },
    green_confirmed: { type: 'boolean' },
    append_only_mechanism: { type: 'string' },
    design_notes: { type: 'string' },
  },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 'append_only_mechanism'],
}
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for M2. Make the frozen RED tests GREEN by editing ONLY src/agentforge/storage/**
and migrations/**. You MUST NOT create, edit, delete, or reformat ANY file under tests/. If a frozen test looks
wrong, STOP and explain in design_notes rather than editing it.
${SPEC}

Build storage/models.py, the Alembic scaffold (alembic.ini, migrations/env.py, migrations/script.py.mako,
migrations/versions/0001_*.py and 0002_*.py), and storage/roles.sql per the spec. Then run the FULL suite
\`. .venv/bin/activate && python -m pytest -q\` — ALL tests pass (the pre-existing suite too). Run \`ruff check .\`
and \`ruff format --check .\` — both clean. Verify \`git status --porcelain tests/\` is empty (report tests_untouched).
Describe the exact append-only mechanism (which grants exist and, crucially, which do NOT) in append_only_mechanism.
Return the structured result with the exact pytest summary line.`,
  { label: 'impl:m2-datamodel', phase: 'Implement', schema: IMPL_SCHEMA },
)

// ---- Stage 3: Reviewer ∥ Security ---------------------------------------------------
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
    `You are an independent CODE REVIEWER for M2. Review the uncommitted diff on branch ticket/m2-datamodel in
${REPO} (\`git --no-pager diff\` + read storage/models.py, storage/roles.sql, migrations/**, and the three test
files). Verify: the SQLAlchemy models match the §5.2 state machines and the D14 AttemptResult field set; the
UNIQUE(campaign_run_id, attempt_id) + severity/category/target_version indexes exist; the migrations are genuine
expand/contract (0002 adds a nullable column, drops nothing a consumer uses) and round-trip without data loss;
the role tests actually assert DB-level rejection (SQLSTATE 42501) and are NOT tautologies (would they fail if a
grant were too broad?). Run the tests yourself. Report only real issues with confidence. ${SPEC}`,
    { label: 'review:reviewer', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
  () => agent(
    `You are an independent SECURITY REVIEWER for M2. Adversarially audit the uncommitted diff on branch
ticket/m2-datamodel in ${REPO}. This is the S1/S2 storage-integrity spine — attack it:
  - Can the Red Team role read back red_team_staging, or INSERT/read attempt_result by ANY path? (must be NO)
  - Is append-only genuinely DB-enforced? Try: does ANY role hold UPDATE or DELETE on attempt_result? Is any
    per-agent role the OWNER of attempt_result (owner bypasses grants)? Does PUBLIC retain a default privilege
    that widens access? Prove a Recorder UPDATE/DELETE is rejected with SQLSTATE 42501, not an app guard.
  - Does SET ROLE in the tests actually drop superuser (i.e. are the rejection tests meaningful, or is a
    superuser silently bypassing the grant)? Confirm the current_user during the denied op is the target role.
  - Can a replay (duplicate campaign_run_id, attempt_id) overwrite rather than be rejected? (must be rejected)
  - Any real secret or real PHI in models/migrations/tests? (must be only synthetic + the throwaway local pw)
  - Is the framework-neutral core still import-clean (a bare import agentforge.config must not import sqlalchemy)?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local or os.environ. ${SPEC}`,
    { label: 'review:security', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
])

return { test: testResult, impl: implResult, review, security }
