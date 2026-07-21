-- coverage_view.sql — the S6 System-of-Record coverage view (ARCHITECTURE.md §9 S6, O3/O7).
--
-- The single DRY source of the `coverage_metric` VIEW. Migration 0003 is the only apply path:
-- it loads this file via importlib.resources and executes it (so the SQL also SHIPS in the
-- wheel via [tool.setuptools.package-data]). The O7 fallback (derive_coverage_fallback) reads
-- this same view, so the online and Langfuse-unavailable paths surface an IDENTICAL number.
--
-- S6 — coverage is computed ONLY from HASH-VERIFIED, NONCE-DEDUPED verdict records, NEVER from
-- raw spans:
--
--   * VERIFIED / evidence-backed: the source is `verdict` JOINed to `attempt_result` on the
--     (campaign_run_id, attempt_id) pair. That pair is a FOREIGN KEY (fk_verdict_run_attempt_
--     attempt_result) onto attempt_result's UNIQUE pair, so a verdict cannot even exist without
--     its authoritative, content-hashed evidence row. The join therefore can never count an
--     evidenceless (raw-span-only) record — an unverified verdict is unrepresentable in the SoR.
--
--   * NONCE-DEDUPED: attempt_count is COUNT(DISTINCT (ar.campaign_run_id, ar.attempt_id)). A
--     replay-shaped duplicate — a SECOND verdict over the SAME evidence pair — collapses to one.
--     A (run, attempt) pair is counted exactly ONCE regardless of how many verdict rows point at
--     it, so a duplicate can never inflate coverage.
--
-- The S6 sanity gate (`covered`) is TRUE only when BOTH hold for a target_version:
--     (1) attempt_count >= 2  (MIN_ATTEMPTS_FOR_COVERAGE — kept in sync with tracing.py's
--         module constant of the same name; the test pins to that constant, not a literal), AND
--     (2) at least one DISTINCT verified pair carries a DECISIVE / oracle-grade verdict
--         (state = 'EXPLOIT_CONFIRMED', the deterministic-oracle disposition). A non-decisive,
--         LLM-only disposition ('EXPLOIT_LIKELY') is NOT an anchor — volume alone never flips
--         `covered`, and a lone non-decisive attempt never flips it either.
--
-- The grouping dimension is `target_version` (a real, frozen attempt_result column) — the only
-- coverage axis derivable within 0003's view-only scope (the base tables are frozen; 0003 adds
-- a VIEW, never a column). Rows with a NULL target_version are excluded (an ungrouped record is
-- not attributable to a target and cannot count toward its coverage).

CREATE VIEW coverage_metric AS
WITH verified_pairs AS (
    -- One row per DISTINCT (campaign_run_id, attempt_id) evidence pair that has BOTH a verdict
    -- and its authoritative attempt_result evidence. The FK guarantees the evidence exists; the
    -- DISTINCT collapses replay-shaped duplicate verdicts over the same pair to a single row.
    -- bool_or(...) marks whether ANY verdict over the pair is the decisive/oracle disposition.
    SELECT
        ar.target_version AS target_version,
        ar.campaign_run_id AS campaign_run_id,
        ar.attempt_id AS attempt_id,
        bool_or(v.state = 'EXPLOIT_CONFIRMED') AS has_oracle_anchor
    FROM attempt_result AS ar
    JOIN verdict AS v
        ON v.campaign_run_id = ar.campaign_run_id
        AND v.attempt_id = ar.attempt_id
    WHERE ar.target_version IS NOT NULL
    GROUP BY ar.target_version, ar.campaign_run_id, ar.attempt_id
)
SELECT
    target_version,
    -- DISTINCT-pair count: a duplicate (run, attempt) pair counts once (nonce-dedup, S6).
    COUNT(*) AS attempt_count,
    -- S6 gate: enough distinct verified attempts AND at least one oracle/decisive anchor.
    (COUNT(*) >= 2 AND bool_or(has_oracle_anchor)) AS covered
FROM verified_pairs
GROUP BY target_version;
