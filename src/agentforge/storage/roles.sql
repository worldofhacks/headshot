-- agentforge.storage.roles.sql — per-agent DB roles + GRANTs (S1/S2).
--
-- Anchors: ARCHITECTURE.md §5 (S1/S2 storage-layer enforcement, per-agent DB roles), §6,
-- §18; PRESEARCH.md §5.3 (invariants 1/2). This file is the SINGLE canonical source of the
-- role/grant matrix; Alembic migration 0001 is the SINGLE apply path (it loads this file
-- via importlib.resources so the SQL ships with the package and stays DRY).
--
-- THE APPEND-ONLY INVARIANT, ENFORCED BY THE DB (not by convention):
--   * The tables are OWNED by the `agentforge` cluster superuser (the migration runs as it).
--     None of the three per-agent roles below is a table OWNER, so GRANT checks apply to
--     every statement they run under `SET ROLE`.
--   * NO role anywhere is granted UPDATE or DELETE on `attempt_result`. Append-only is the
--     ABSENCE of those grants, checked by Postgres — a Recorder INSERT succeeds, but a
--     Recorder (or anyone's) UPDATE/DELETE raises SQLSTATE 42501 (insufficient_privilege).
--   * The Red Team role gets INSERT-only on `red_team_staging` and NO SELECT there (no
--     read-back) and NOTHING on `attempt_result` (its write is DB-rejected — the S2 headline).
--
-- Roles are NOLOGIN (the tests exercise them via `SET ROLE`, not by connecting as them) and
-- are created IDEMPOTENTLY (Postgres has no CREATE ROLE IF NOT EXISTS — a DO block guards on
-- pg_roles) because roles are cluster-global and may already exist from a prior run.

-- ---------------------------------------------------------------------------
-- 1. Roles (idempotent create; NOLOGIN — SET ROLE only).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'headshot_redteam') THEN
        CREATE ROLE headshot_redteam NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'headshot_recorder') THEN
        CREATE ROLE headshot_recorder NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'headshot_judge') THEN
        CREATE ROLE headshot_judge NOLOGIN;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 2. Baseline: revoke the PUBLIC defaults so grants below are EXACT.
--
-- New tables do not grant table privileges to PUBLIC by default, but the roles inherit
-- USAGE on the public schema via PUBLIC. We revoke schema privileges from the per-agent
-- roles' PUBLIC path is not needed for table-privilege denial (a missing table GRANT already
-- denies), but we explicitly revoke ALL from each role on the sensitive tables first so a
-- re-run from a drifted state converges to exactly the matrix below.
-- ---------------------------------------------------------------------------
REVOKE ALL ON red_team_staging FROM headshot_redteam, headshot_recorder, headshot_judge;
REVOKE ALL ON attempt_result   FROM headshot_redteam, headshot_recorder, headshot_judge;
REVOKE ALL ON verdict          FROM headshot_redteam, headshot_recorder, headshot_judge;
REVOKE ALL ON finding          FROM headshot_redteam, headshot_recorder, headshot_judge;

-- Each per-agent role needs USAGE on the schema to reference objects in it. USAGE alone
-- grants no table privileges — those are exact, per-table, below.
GRANT USAGE ON SCHEMA public TO headshot_redteam, headshot_recorder, headshot_judge;

-- ---------------------------------------------------------------------------
-- 3. headshot_redteam — INSERT-only into staging it CANNOT read back; NOTHING on evidence.
--    * INSERT red_team_staging  -> ALLOWED
--    * SELECT red_team_staging  -> DENIED  (no read-back, S1)
--    * anything on attempt_result -> DENIED (the S2 headline: RT write to the append-only
--      Recorder-owned evidence table is rejected BY THE DB, not by convention)
-- ---------------------------------------------------------------------------
GRANT INSERT ON red_team_staging TO headshot_redteam;
-- The `id` column is a serial (identity) backed by a sequence; an INSERT must advance it,
-- which needs USAGE on that sequence. This grants NO table privilege — it cannot read back a
-- row (no SELECT) — so the no-read-back invariant is intact.
GRANT USAGE ON SEQUENCE red_team_staging_id_seq TO headshot_redteam;
-- (no SELECT/UPDATE/DELETE on red_team_staging; no privileges of any kind on attempt_result)

-- ---------------------------------------------------------------------------
-- 4. headshot_recorder — reads RT submissions, APPENDS evidence; append-only by grant absence.
--    * SELECT red_team_staging  -> ALLOWED
--    * INSERT attempt_result    -> ALLOWED
--    * UPDATE attempt_result    -> DENIED (no UPDATE grant — append-only)
--    * DELETE attempt_result    -> DENIED (no DELETE grant — append-only)
-- ---------------------------------------------------------------------------
GRANT SELECT ON red_team_staging TO headshot_recorder;
GRANT INSERT ON attempt_result   TO headshot_recorder;
-- The `id` serial needs sequence USAGE for the INSERT to advance it. Sequence USAGE is NOT
-- a table privilege: it grants no UPDATE and no DELETE on attempt_result, so the append-only
-- invariant (proven by the role tests) is unaffected — a Recorder can only ever APPEND.
GRANT USAGE ON SEQUENCE attempt_result_id_seq TO headshot_recorder;
-- (deliberately NO UPDATE and NO DELETE on attempt_result — the append-only invariant)

-- ---------------------------------------------------------------------------
-- 5. headshot_judge — SELECT-only on the authoritative evidence (+ verdict, finding).
--    * SELECT attempt_result           -> ALLOWED
--    * INSERT/UPDATE/DELETE attempt_result -> DENIED (SELECT-only)
-- ---------------------------------------------------------------------------
GRANT SELECT ON attempt_result TO headshot_judge;
GRANT SELECT ON verdict        TO headshot_judge;
GRANT SELECT ON finding        TO headshot_judge;
-- (no INSERT/UPDATE/DELETE anywhere for the Judge)
