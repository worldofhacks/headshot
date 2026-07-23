"""agentforge.storage.models — M2/M3 Postgres metadata (SQLAlchemy 2.0 DeclarativeBase).

Anchors: ARCHITECTURE.md §4 (AttemptResult / D14 evidence field set), §5 (S1/S2 trust
boundaries, per-agent DB roles), §6 (data model, PRD-OPT-16 indexes, S3 replay UNIQUE);
PRESEARCH.md §5.2 (state machines) / §5.3 (invariants).

Scope decision (deliberate, not forgotten). This module models ONLY the entities whose
state machines (PRESEARCH §5.2) or the S1/S2 evidence spine the local MVP slice needs:
``campaign``, ``attack_case``, ``attempt``, ``red_team_staging``, ``attempt_result``,
``verdict``, ``finding``, ``regression_case``. The remaining nouns from ARCHITECTURE §6 /
PRESEARCH §5.1 — ``CostRecord``, ``CoverageMetric``, ``GroundTruthLabel``,
``ContractVersion``, ``Incident``, ``Target``, ``TargetAdapter``, ``AllowlistEntry``,
``CredentialBinding``, ``Transcript``, ``RegressionRun``, and the LangGraph checkpoint tables
— are **intentionally deferred** and land with their consumers in later milestones. The M3
``jobs`` queue is modelled here because this module is Alembic's autogenerate metadata source.

Referential integrity, scoped (deliberate). This slice DB-enforces the links whose targets
exist here: ``attempt`` → ``campaign`` (FK, CASCADE), ``regression_case`` → ``finding`` (FK,
SET NULL), and ``verdict`` → ``attempt_result`` on the UNIQUE ``(campaign_run_id,
attempt_id)`` pair (FK — no orphan verdict over non-existent evidence). NOT yet FK-enforced,
and deferred to their consumer milestones **on purpose**: ``finding``'s closure into the
evidence/campaign chain (a finding can aggregate multiple attempts; its linking column lands
with the Judge/Documentation consumer) and ``attempt_result.campaign_id`` → ``campaign`` (the
recorder writes evidence whose campaign row is created on the control-plane side; kept a soft
correlation key here). So invariant §5.3 #6 is *partly* schema-enforced in this slice — the
verdict→evidence hole is closed; the finding-chain closure is a named, tracked deferral.

Framework-purity note (D10). SQLAlchemy is imported ONLY under ``agentforge.storage`` and
``migrations``. The framework-neutral core (``agentforge.config`` / ``domain`` /
``contracts`` / ``secrets``) never imports this module, so ``import agentforge.config``
stays SQLAlchemy-free.

Conventions:
  * Postgres native ENUM types for every state machine / taxonomy (a bad value is rejected
    by the DB, not silently coerced — PRESEARCH §5.3). ``create_type=False`` because the
    Alembic migration owns enum creation; the models only reference the types.
  * Timezone-aware timestamps (``TIMESTAMP WITH TIME ZONE``) with ``server_default=now()``
    where sensible.
  * ``attempt_result`` is APPEND-ONLY. That invariant is enforced by the DB (grant absence
    in ``roles.sql``), not by anything here — this module only shapes the table.
"""

from __future__ import annotations

import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Enum type definitions (Postgres native enums).
#
# The migration (0001) is the single apply path that CREATEs these types; the models
# reference them with create_type=False so DeclarativeBase.metadata.create_all is never the
# path that emits them. The name= must match the pg_type.typname the tests introspect.
# ---------------------------------------------------------------------------

_ENUM_KW = {"create_type": False}

campaign_state = Enum(
    "queued",
    "running",
    "complete",
    "halted",
    "aborted",
    name="campaign_state",
    **_ENUM_KW,
)

attack_case_state = Enum(
    "draft",
    "active",
    "retired",
    name="attack_case_state",
    **_ENUM_KW,
)

attack_class = Enum(
    "boundary",
    "invariant",
    "regression",
    name="attack_class",
    **_ENUM_KW,
)

attempt_state = Enum(
    "queued",
    "running",
    "success",
    "fail",
    "partial",
    "error",
    name="attempt_state",
    **_ENUM_KW,
)

attempt_typed_error = Enum(
    "target_unreachable",
    "budget_exceeded",
    "judge_timeout",
    "rate_limited",
    "adapter_error",
    name="attempt_typed_error",
    **_ENUM_KW,
)

verdict_state = Enum(
    "EXPLOIT_CONFIRMED",
    "EXPLOIT_LIKELY",
    "NO_EXPLOIT_OBSERVED",
    "INDETERMINATE",
    "ERROR",
    name="verdict_state",
    **_ENUM_KW,
)

finding_state = Enum(
    "candidate",
    "judged",
    "documented",
    "approved",
    "published",
    "remediated",
    "validated",
    "resolved",
    "regressed",
    name="finding_state",
    **_ENUM_KW,
)

finding_severity = Enum(
    "low",
    "medium",
    "high",
    "critical",
    name="finding_severity",
    **_ENUM_KW,
)

regression_case_state = Enum(
    "admitted",
    "passing",
    "failing",
    name="regression_case_state",
    **_ENUM_KW,
)

job_queue = Enum(
    "agent_work",
    "regression_run",
    name="job_queue",
    **_ENUM_KW,
)

job_status = Enum(
    "queued",
    "leased",
    "completed",
    "cancelled",
    "dead_letter",
    name="job_status",
    **_ENUM_KW,
)


# A naming convention keeps constraint/index names stable across Alembic autogenerate and
# hand-written migrations (so downgrade() can drop by name deterministically).
_NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base carrying storage metadata used by Alembic ``target_metadata``."""

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)


# ---------------------------------------------------------------------------
# campaign — queued → running → {complete | halted | aborted}
# ---------------------------------------------------------------------------
class Campaign(Base):
    """A red-team campaign. Business key ``campaign_id`` is UNIQUE (§6, durable correlation)."""

    __tablename__ = "campaign"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(campaign_state, nullable=False, server_default="queued")
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# attack_case — draft → active → retired; carries attack_class + owasp tags
# ---------------------------------------------------------------------------
class AttackCase(Base):
    """A seed/attack case. Carries ``attack_class`` (boundary|invariant|regression) and an
    ``owasp_tags`` (jsonb) column so no happy-path-only case is representable without its
    tags (PRESEARCH §5.3 #9, §6 AttackCase schema)."""

    __tablename__ = "attack_case"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(attack_case_state, nullable=False, server_default="draft")
    attack_class: Mapped[str] = mapped_column(attack_class, nullable=False)
    owasp_tags: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="[]")
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# attempt — queued → running → {success | fail | partial} | error(typed)
# ---------------------------------------------------------------------------
class Attempt(Base):
    """One execution of an attack case within a campaign. ``typed_error`` (nullable) carries
    the taxonomy of operational failures (PRESEARCH §5.2, ARCHITECTURE §4)."""

    __tablename__ = "attempt"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("campaign.id", ondelete="CASCADE"), nullable=False
    )
    state: Mapped[str] = mapped_column(attempt_state, nullable=False, server_default="queued")
    typed_error: Mapped[str | None] = mapped_column(attempt_typed_error, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# red_team_staging — the Red Team's INSERT-only staging it CANNOT read back (S1)
# ---------------------------------------------------------------------------
class RedTeamStaging(Base):
    """Red Team submission staging. The ``headshot_redteam`` role has INSERT-only here and
    NO SELECT (no read-back) — enforced by grant absence in ``roles.sql`` (S1)."""

    __tablename__ = "red_team_staging"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# attempt_result — AUTHORITATIVE, APPEND-ONLY, hashed evidence (D14 field set)
# ---------------------------------------------------------------------------
class AttemptResult(Base):
    """The authoritative evidence object (ARCHITECTURE §4/§6, D14).

    APPEND-ONLY: only the ``headshot_recorder`` role may INSERT, and NO role anywhere holds
    UPDATE or DELETE — that append-only property is DB-enforced in ``roles.sql``, not here.
    ``UNIQUE(campaign_run_id, attempt_id)`` is the storage half of the S3 replay defense:
    the DB rejects a duplicate pair rather than overwriting. ``content_hash`` is TEXT NOT
    NULL — evidence is always hashed. Indexed on ``target_version`` (query pattern, §6)."""

    __tablename__ = "attempt_result"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, server_default="1")
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    organization_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    surface_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    surface_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    authorization_scope_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attack_attempt: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    request_transcript: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    response_transcript: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recorder_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recorder_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("campaign_run_id", "attempt_id", name="uq_attempt_result_run_attempt"),
        Index("ix_attempt_result_target_version", "target_version"),
        Index("ix_attempt_result_org_run", "organization_id", "campaign_run_id"),
    )


# ---------------------------------------------------------------------------
# verdict — the Judge's enumerated verdict over an attempt_result pair
# ---------------------------------------------------------------------------
class Verdict(Base):
    """An independent Judge verdict (ARCHITECTURE §5 verdict states).

    ``(campaign_run_id, attempt_id)`` is a **foreign key** onto ``attempt_result``'s UNIQUE
    pair — a verdict cannot reference a non-existent evidence row (referential integrity,
    PRESEARCH §5.3 #6; the DB rejects an orphan verdict with SQLSTATE 23503). Because
    ``attempt_result`` is append-only (never deleted), the FK target is stable."""

    __tablename__ = "verdict"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    state: Mapped[str] = mapped_column(verdict_state, nullable=False)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    organization_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["campaign_run_id", "attempt_id"],
            ["attempt_result.campaign_run_id", "attempt_result.attempt_id"],
            name="fk_verdict_run_attempt_attempt_result",
        ),
        Index("ix_verdict_org_run", "organization_id", "campaign_run_id"),
    )


# ---------------------------------------------------------------------------
# finding — candidate → … → {resolved | regressed}; indexed for PRD-OPT-16
# ---------------------------------------------------------------------------
class Finding(Base):
    """A confirmed/candidate vulnerability finding. ``finding_id`` is a UNIQUE business key
    (invariant §5.3 #6). Indexed on severity / category / target_version — the three
    PRD-OPT-16 query patterns (§6)."""

    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    organization_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(finding_state, nullable=False, server_default="candidate")
    severity: Mapped[str] = mapped_column(finding_severity, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    target_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Added by the forward-only 0002 expand migration.  Keeping ORM metadata aligned
    # prevents a later autogenerate from proposing a destructive drop.
    exploitability: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "finding_id", name="uq_finding_org_finding_id"),
        Index("ix_finding_severity", "severity"),
        Index("ix_finding_category", "category"),
        Index("ix_finding_target_version", "target_version"),
        Index("ix_finding_org_state", "organization_id", "state"),
    )


# ---------------------------------------------------------------------------
# regression_case — admitted → passing → {failing}
# ---------------------------------------------------------------------------
class RegressionCase(Base):
    """A promoted regression case (minimal). State: admitted → passing → {failing}
    (PRESEARCH §5.2)."""

    __tablename__ = "regression_case"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    regression_case_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(
        regression_case_state, nullable=False, server_default="admitted"
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("finding.finding_id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# vuln_report / regression_disposition — append-only draft and admission proof
# ---------------------------------------------------------------------------
class VulnReport(Base):
    """A schema-validated Documentation Agent draft; never publication authority."""

    __tablename__ = "vuln_reports"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reproduction_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    publication_state: Mapped[str] = mapped_column(String(48), nullable=False)
    contract_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_vuln_report_finding",
        ),
        ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "attempt_id"],
            [
                "attempt_result.organization_id",
                "attempt_result.campaign_run_id",
                "attempt_result.attempt_id",
            ],
            name="fk_vuln_report_attempt_result",
        ),
        UniqueConstraint("organization_id", "finding_id", name="uq_vuln_report_org_finding"),
        UniqueConstraint(
            "organization_id",
            "reproduction_sha256",
            name="uq_vuln_report_org_reproduction",
        ),
        CheckConstraint(
            "reproduction_sha256 ~ '^[0-9a-f]{64}$'",
            name="vuln_report_reproduction_hash",
        ),
        CheckConstraint("status = 'draft'", name="vuln_report_draft_only"),
        CheckConstraint(
            "publication_state IN ('draft_unpublished','blocked_pending_human_approval')",
            name="vuln_report_publication_draft_only",
        ),
        CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="vuln_report_payload_object",
        ),
        CheckConstraint(
            "((contract_payload->>'report_id' = report_id) AND "
            "(contract_payload->>'finding_id' = finding_id) AND "
            "(contract_payload->>'campaign_run_id' = campaign_run_id) AND "
            "(contract_payload->>'attempt_id' = attempt_id) AND "
            "(contract_payload->>'reproduction_sha256' = reproduction_sha256) AND "
            "(contract_payload->>'status' = status) AND "
            "(contract_payload->>'publication_state' = publication_state)) IS TRUE",
            name="payload_projection",
        ),
        CheckConstraint(
            "((contract_payload->>'severity' <> 'critical') OR "
            "publication_state = 'blocked_pending_human_approval') IS TRUE",
            name="critical_publication",
        ),
        Index(
            "ix_vuln_reports_run_attempt",
            "organization_id",
            "campaign_run_id",
            "attempt_id",
        ),
    )


class RegressionDisposition(Base):
    """Append-only deterministic decision about regression-corpus admission."""

    __tablename__ = "regression_dispositions"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    disposition_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    report_id: Mapped[str] = mapped_column(String(80), nullable=False)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(48), nullable=False)
    admitted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    contract_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_regression_disposition_finding",
        ),
        ForeignKeyConstraint(
            ["organization_id", "report_id"],
            ["vuln_reports.organization_id", "vuln_reports.report_id"],
            name="fk_regression_disposition_report",
        ),
        ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "attempt_id"],
            [
                "attempt_result.organization_id",
                "attempt_result.campaign_run_id",
                "attempt_result.attempt_id",
            ],
            name="fk_regression_disposition_attempt_result",
        ),
        CheckConstraint(
            "state IN ('pending_deterministic_reproduction','rejected_non_deterministic',"
            "'rejected_wrong_reason','blocked_pending_human_approval','admitted')",
            name="regression_disposition_state",
        ),
        CheckConstraint(
            "(state = 'admitted' AND admitted) OR (state <> 'admitted' AND NOT admitted)",
            name="regression_disposition_admitted_consistent",
        ),
        CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="regression_disposition_payload_object",
        ),
        CheckConstraint(
            "((contract_payload->>'disposition_id' = disposition_id) AND "
            "(contract_payload->>'finding_id' = finding_id) AND "
            "(contract_payload->>'report_id' = report_id) AND "
            "(contract_payload->>'campaign_run_id' = campaign_run_id) AND "
            "(contract_payload->>'attempt_id' = attempt_id) AND "
            "(contract_payload->>'state' = state) AND "
            "(contract_payload->>'admitted' = "
            "CASE WHEN admitted THEN 'true' ELSE 'false' END)) IS TRUE",
            name="payload_projection",
        ),
        CheckConstraint(
            "((state <> 'admitted') OR "
            "((contract_payload->>'reproduction_attempted' = 'true') AND "
            "(contract_payload->>'deterministic_reproduction' = 'true') AND "
            "(contract_payload->>'passes_for_right_reason' = 'true') AND "
            "(contract_payload->>'human_approved' = 'true'))) IS TRUE",
            name="admission_proof",
        ),
        Index(
            "ix_regression_dispositions_run_attempt",
            "organization_id",
            "campaign_run_id",
            "attempt_id",
        ),
        Index(
            "ix_regression_dispositions_finding_history",
            "organization_id",
            "finding_id",
            "created_at",
        ),
    )


class RegressionReplayPlan(Base):
    """Append-only, execution-blocked plan tied to a persisted disposition."""

    __tablename__ = "regression_replay_plans"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    replay_id: Mapped[str] = mapped_column(String(67), primary_key=True)
    regression_case_id: Mapped[str] = mapped_column(String(67), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    report_id: Mapped[str] = mapped_column(String(80), nullable=False)
    disposition_id: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_target_version: Mapped[str] = mapped_column(String(128), nullable=False)
    replay_target_version: Mapped[str] = mapped_column(String(128), nullable=False)
    attack_sequence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_regression_replay_plan_finding",
        ),
        ForeignKeyConstraint(
            ["organization_id", "report_id"],
            ["vuln_reports.organization_id", "vuln_reports.report_id"],
            name="fk_regression_replay_plan_report",
        ),
        ForeignKeyConstraint(
            ["organization_id", "disposition_id"],
            ["regression_dispositions.organization_id", "regression_dispositions.disposition_id"],
            name="fk_regression_replay_plan_disposition",
        ),
        CheckConstraint(
            "attack_sequence_sha256 ~ '^[0-9a-f]{64}$'",
            name="regression_replay_plan_attack_hash",
        ),
        CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="regression_replay_plan_payload_object",
        ),
        CheckConstraint(
            "((contract_payload->>'replay_id' = replay_id) AND "
            "(contract_payload->>'regression_case_id' = regression_case_id) AND "
            "(contract_payload->>'finding_id' = finding_id) AND "
            "(contract_payload->>'report_id' = report_id) AND "
            "(contract_payload->>'target_id' = target_id) AND "
            "(contract_payload->>'source_target_version' = source_target_version) AND "
            "(contract_payload->>'replay_target_version' = replay_target_version) AND "
            "(contract_payload->>'attack_sequence_sha256' = attack_sequence_sha256) AND "
            "(contract_payload->>'authorization_state' = 'pending_human_authorization') AND "
            "(contract_payload->>'execution_state' = 'blocked')) IS TRUE",
            name="regression_replay_plan_payload_projection",
        ),
        Index(
            "ix_regression_replay_plans_target_version",
            "organization_id",
            "target_id",
            "replay_target_version",
        ),
        Index(
            "ix_regression_replay_plans_case",
            "organization_id",
            "regression_case_id",
            "created_at",
        ),
    )


class RegressionReplayResult(Base):
    """Append-only replay evidence tied to a two-person-authorized campaign."""

    __tablename__ = "regression_replay_results"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    result_id: Mapped[str] = mapped_column(String(68), primary_key=True)
    replay_id: Mapped[str] = mapped_column(String(67), nullable=False)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    authorization_scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    replay_target_version: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    reappeared: Mapped[bool] = mapped_column(Boolean, nullable=False)
    contract_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "replay_id"],
            ["regression_replay_plans.organization_id", "regression_replay_plans.replay_id"],
            name="fk_regression_replay_result_plan",
        ),
        ForeignKeyConstraint(
            ["organization_id", "campaign_run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_regression_replay_result_campaign",
        ),
        UniqueConstraint(
            "organization_id", "replay_id", "campaign_run_id", name="uq_replay_result_run"
        ),
        CheckConstraint(
            "authorization_scope_hash ~ '^[0-9a-f]{64}$'",
            name="regression_replay_result_scope_hash",
        ),
        CheckConstraint(
            "state IN ('passing','failing','inconclusive')",
            name="regression_replay_result_state",
        ),
        CheckConstraint(
            "(state = 'failing' AND reappeared) OR (state <> 'failing')",
            name="regression_replay_result_reappearance",
        ),
        CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="regression_replay_result_payload_object",
        ),
        CheckConstraint(
            "((contract_payload->>'result_id' = result_id) AND "
            "(contract_payload->>'replay_id' = replay_id) AND "
            "(contract_payload->>'campaign_run_id' = campaign_run_id) AND "
            "(contract_payload->>'authorization_scope_hash' = authorization_scope_hash) AND "
            "(contract_payload->>'target_id' = target_id) AND "
            "(contract_payload->>'replay_target_version' = replay_target_version) AND "
            "(contract_payload->>'state' = state) AND "
            "(contract_payload->>'reappeared' = "
            "CASE WHEN reappeared THEN 'true' ELSE 'false' END)) IS TRUE",
            name="regression_replay_result_payload_projection",
        ),
        Index(
            "ix_regression_replay_results_target_version",
            "organization_id",
            "target_id",
            "replay_target_version",
            "state",
        ),
    )


class RegressionCaseVersion(Base):
    """Human-admitted, immutable version of one deterministic regression case."""

    __tablename__ = "regression_case_versions"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    regression_case_id: Mapped[str] = mapped_column(String(67), primary_key=True)
    case_version: Mapped[str] = mapped_column(String(32), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    report_id: Mapped[str] = mapped_column(String(80), nullable=False)
    admission_disposition_id: Mapped[str] = mapped_column(String(80), nullable=False)
    admission_result_id: Mapped[str] = mapped_column(String(68), nullable=False)
    source_case_id: Mapped[str] = mapped_column(String(120), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_target_version: Mapped[str] = mapped_column(String(128), nullable=False)
    attack_sequence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    attack_attempt: Mapped[dict] = mapped_column(JSONB, nullable=False)
    required_oracle_ids: Mapped[list] = mapped_column(JSONB, nullable=False)
    planned_repetitions: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_regression_case_version_finding",
        ),
        ForeignKeyConstraint(
            ["organization_id", "report_id"],
            ["vuln_reports.organization_id", "vuln_reports.report_id"],
            name="fk_regression_case_version_report",
        ),
        ForeignKeyConstraint(
            ["organization_id", "admission_disposition_id"],
            ["regression_dispositions.organization_id", "regression_dispositions.disposition_id"],
            name="fk_regression_case_version_admission",
        ),
        ForeignKeyConstraint(
            ["organization_id", "admission_result_id"],
            ["regression_replay_results.organization_id", "regression_replay_results.result_id"],
            name="fk_regression_case_version_result",
        ),
        CheckConstraint(
            "case_version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$'",
            name="regression_case_version_semver",
        ),
        CheckConstraint(
            "attack_sequence_sha256 ~ '^[0-9a-f]{64}$'",
            name="regression_case_version_attack_hash",
        ),
        CheckConstraint(
            "jsonb_typeof(attack_attempt) = 'object'",
            name="regression_case_version_attack_object",
        ),
        CheckConstraint(
            "jsonb_typeof(required_oracle_ids) = 'array' AND "
            "jsonb_array_length(required_oracle_ids) > 0",
            name="regression_case_version_oracles",
        ),
        CheckConstraint(
            "planned_repetitions BETWEEN 2 AND 20",
            name="regression_case_version_repetitions",
        ),
        Index(
            "ix_regression_case_versions_target",
            "organization_id",
            "target_id",
            "source_target_version",
        ),
        Index(
            "ix_regression_case_versions_finding",
            "organization_id",
            "finding_id",
            "case_version",
        ),
    )


# ---------------------------------------------------------------------------
# jobs — M3 durable at-least-once work/regression queue
# ---------------------------------------------------------------------------
class Job(Base):
    """Queue metadata kept aligned with migration 0004 for Alembic autogenerate safety."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    queue: Mapped[str] = mapped_column(job_queue, nullable=False)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_schema: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    enqueue_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    run_after: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="3")
    status: Mapped[str] = mapped_column(job_status, nullable=False, server_default="queued")
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    leased_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    lease_expires_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    last_heartbeat_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    last_failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_failure_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_failure_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    last_failure_worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    completion_worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    completion_lease_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    completed_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    dead_lettered_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "queue", "campaign_run_id", "attempt_id", name="uq_jobs_queue_campaign_attempt"
        ),
        CheckConstraint("payload_version > 0", name="job_payload_version_positive"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="job_payload_object"),
        CheckConstraint("char_length(enqueue_fingerprint) = 64", name="job_fingerprint_length"),
        CheckConstraint(
            "attempts >= 0 AND max_attempts > 0 AND attempts <= max_attempts",
            name="job_attempt_bounds",
        ),
        CheckConstraint(
            "status <> 'queued'::job_status OR attempts < max_attempts",
            name="job_queued_attempt_budget",
        ),
        CheckConstraint(
            "(status = 'leased'::job_status AND worker_id IS NOT NULL "
            "AND lease_token IS NOT NULL AND leased_at IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL "
            "AND lease_expires_at > leased_at) OR "
            "(status <> 'leased'::job_status AND worker_id IS NULL "
            "AND lease_token IS NULL AND leased_at IS NULL "
            "AND lease_expires_at IS NULL AND last_heartbeat_at IS NULL)",
            name="job_active_lease_shape",
        ),
        CheckConstraint(
            "(status = 'completed'::job_status AND completed_at IS NOT NULL "
            "AND completion_worker_id IS NOT NULL AND completion_lease_token IS NOT NULL) OR "
            "(status <> 'completed'::job_status AND completed_at IS NULL "
            "AND completion_worker_id IS NULL AND completion_lease_token IS NULL)",
            name="job_completion_shape",
        ),
        CheckConstraint(
            "(status = 'cancelled'::job_status) = (cancelled_at IS NOT NULL)",
            name="job_cancellation_shape",
        ),
        CheckConstraint(
            "(status = 'dead_letter'::job_status) = (dead_lettered_at IS NOT NULL)",
            name="job_dead_letter_shape",
        ),
        CheckConstraint(
            "last_failure_message IS NULL OR char_length(last_failure_message) <= 512",
            name="job_failure_message_length",
        ),
    )


Index(
    "ix_jobs_claim",
    Job.queue,
    Job.priority.desc(),
    Job.run_after,
    Job.id,
    postgresql_where=text("status = 'queued'::job_status"),
)
Index(
    "ix_jobs_reap",
    Job.lease_expires_at,
    Job.id,
    postgresql_where=text("status = 'leased'::job_status"),
)
Index(
    "ix_jobs_campaign_cancel",
    Job.campaign_run_id,
    Job.queue,
    Job.id,
    postgresql_where=text("status = 'queued'::job_status"),
)
Index("ix_jobs_depth", Job.queue, Job.status)


# ---------------------------------------------------------------------------
# M1d control-plane identity, workflow, audit, and idempotency tables.
# Definition/workflow/event rows are append-only by migration-level triggers.
# ---------------------------------------------------------------------------
class TargetIdentity(Base):
    __tablename__ = "target_identities"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("organization_id ~ '^org_[A-Za-z0-9]+$'", name="target_identity_org_id"),
    )


class TargetDefinitionRecord(Base):
    __tablename__ = "target_definitions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_session_id: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["target_identities.organization_id", "target_identities.target_id"],
            name="fk_target_definitions_identity",
        ),
        UniqueConstraint(
            "organization_id", "target_id", "version", name="uq_target_definitions_org_id_version"
        ),
        UniqueConstraint(
            "organization_id",
            "target_id",
            "version",
            "content_hash",
            name="uq_target_definitions_org_id_version_hash",
        ),
        CheckConstraint("content_hash ~ '^[0-9a-f]{64}$'", name="target_definition_hash"),
        CheckConstraint(
            "version ~ '^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'",
            name="target_definition_semver",
        ),
        CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name="target_definition_payload_object"
        ),
    )


class TargetLifecycleEvent(Base):
    __tablename__ = "target_lifecycle_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_version: Mapped[str] = mapped_column(String(32), nullable=False)
    from_lifecycle: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_lifecycle: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_session_id: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "target_id", "target_version"],
            [
                "target_definitions.organization_id",
                "target_definitions.target_id",
                "target_definitions.version",
            ],
            name="fk_target_lifecycle_definition",
        ),
        CheckConstraint(
            "to_lifecycle IN ('draft','validating','ready','disabled','archived')",
            name="target_lifecycle_to_allowed",
        ),
        CheckConstraint(
            "from_lifecycle IS NULL OR from_lifecycle IN "
            "('draft','validating','ready','disabled','archived')",
            name="target_lifecycle_from_allowed",
        ),
        Index(
            "ix_target_lifecycle_latest",
            "organization_id",
            "target_id",
            "target_version",
            "id",
        ),
    )


class SurfaceIdentity(Base):
    __tablename__ = "surface_identities"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    surface_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "surface_id",
            "target_id",
            name="uq_surface_identities_org_surface_target",
        ),
        ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["target_identities.organization_id", "target_identities.target_id"],
            name="fk_surface_identities_target",
        ),
    )


class AttackSurfaceDefinitionRecord(Base):
    __tablename__ = "attack_surface_definitions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    surface_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_version: Mapped[str] = mapped_column(String(32), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_session_id: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "surface_id", "target_id"],
            [
                "surface_identities.organization_id",
                "surface_identities.surface_id",
                "surface_identities.target_id",
            ],
            name="fk_attack_surface_identity",
        ),
        ForeignKeyConstraint(
            ["organization_id", "target_id", "target_version"],
            [
                "target_definitions.organization_id",
                "target_definitions.target_id",
                "target_definitions.version",
            ],
            name="fk_attack_surface_target_definition",
        ),
        UniqueConstraint(
            "organization_id", "surface_id", "version", name="uq_attack_surface_org_id_version"
        ),
        UniqueConstraint(
            "organization_id",
            "surface_id",
            "version",
            "target_id",
            name="uq_attack_surface_org_id_version_target",
        ),
        CheckConstraint("content_hash ~ '^[0-9a-f]{64}$'", name="attack_surface_hash"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="attack_surface_payload_object"),
    )


class SurfaceStateEvent(Base):
    __tablename__ = "surface_state_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    surface_id: Mapped[str] = mapped_column(String(64), nullable=False)
    surface_version: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    from_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    to_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_session_id: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "surface_id", "surface_version", "target_id"],
            [
                "attack_surface_definitions.organization_id",
                "attack_surface_definitions.surface_id",
                "attack_surface_definitions.version",
                "attack_surface_definitions.target_id",
            ],
            name="fk_surface_state_definition",
        ),
        Index(
            "ix_surface_state_latest",
            "organization_id",
            "surface_id",
            "surface_version",
            "id",
        ),
    )


class CampaignAuthorizationRequestRecord(Base):
    __tablename__ = "campaign_authorization_requests"

    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    launcher_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    launcher_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "request_id",
            "scope_hash",
            name="uq_campaign_authorization_request_scope",
        ),
        CheckConstraint(
            "scope_hash ~ '^[0-9a-f]{64}$'", name="campaign_authorization_request_hash"
        ),
        CheckConstraint(
            "jsonb_typeof(scope_payload) = 'object'", name="campaign_authorization_scope_object"
        ),
        CheckConstraint(
            "launcher_user_id LIKE 'user_%'", name="campaign_authorization_launcher_user"
        ),
        CheckConstraint(
            "launcher_session_id LIKE 'sess_%'", name="campaign_authorization_launcher_session"
        ),
        Index("ix_campaign_authorization_requests_org_created", "organization_id", "created_at"),
    )


class CampaignAuthorizationDecisionRecord(Base):
    __tablename__ = "campaign_authorization_decisions"

    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    approver_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    approver_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    self_approval_override: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "request_id", "scope_hash"],
            [
                "campaign_authorization_requests.organization_id",
                "campaign_authorization_requests.request_id",
                "campaign_authorization_requests.scope_hash",
            ],
            name="fk_campaign_authorization_decision_request",
        ),
        UniqueConstraint(
            "organization_id", "request_id", name="uq_campaign_authorization_decision_request"
        ),
        CheckConstraint(
            "decision IN ('approved','rejected')", name="campaign_authorization_decision_allowed"
        ),
        CheckConstraint(
            "scope_hash ~ '^[0-9a-f]{64}$'", name="campaign_authorization_decision_hash"
        ),
        CheckConstraint(
            "approver_user_id LIKE 'user_%'", name="campaign_authorization_approver_user"
        ),
        CheckConstraint(
            "approver_session_id LIKE 'sess_%'", name="campaign_authorization_approver_session"
        ),
    )


class CampaignRunRecord(Base):
    __tablename__ = "campaign_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    authorization_request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    launcher_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    launcher_session_id: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "authorization_request_id", "scope_hash"],
            [
                "campaign_authorization_requests.organization_id",
                "campaign_authorization_requests.request_id",
                "campaign_authorization_requests.scope_hash",
            ],
            name="fk_campaign_run_authorization_request",
        ),
        UniqueConstraint(
            "organization_id", "authorization_request_id", name="uq_campaign_run_authorization_once"
        ),
        UniqueConstraint("organization_id", "run_id", name="uq_campaign_runs_org_run"),
        CheckConstraint("scope_hash ~ '^[0-9a-f]{64}$'", name="campaign_run_scope_hash"),
    )


class CampaignRunEvent(Base):
    __tablename__ = "campaign_run_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    actor_session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_campaign_run_event_run",
        ),
        CheckConstraint(
            "state IN ('queued','running','complete','aborted','failed')",
            name="campaign_run_event_state_allowed",
        ),
        Index("ix_campaign_run_events_latest", "organization_id", "run_id", "id"),
    )


class CampaignAttemptRecord(Base):
    __tablename__ = "campaign_attempts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    case_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_technique: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_campaign_attempt_run",
        ),
        UniqueConstraint(
            "organization_id", "run_id", "attempt_id", name="uq_campaign_attempt_identity"
        ),
        UniqueConstraint(
            "organization_id", "run_id", "ordinal", name="uq_campaign_attempt_ordinal"
        ),
        CheckConstraint("ordinal >= 0", name="campaign_attempt_ordinal_nonnegative"),
    )


class AgentConfigurationVersion(Base):
    """Append-only operator configuration for one role's actual or staged engine."""

    __tablename__ = "agent_configuration_versions"

    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_role: Mapped[str] = mapped_column(String(32), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    execution_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    activation_state: Mapped[str] = mapped_column(String(48), nullable=False)
    configuration_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="agent_configuration_role",
        ),
        CheckConstraint("version > 0", name="agent_configuration_version_positive"),
        CheckConstraint(
            "execution_mode IN ('deterministic','hosted_advisory')",
            name="agent_configuration_execution_mode",
        ),
        CheckConstraint(
            "activation_state IN ('active','staged_pending_authorization')",
            name="agent_configuration_activation_state",
        ),
        CheckConstraint(
            "configuration_sha256 ~ '^[0-9a-f]{64}$'",
            name="agent_configuration_hash",
        ),
        Index(
            "ix_agent_configuration_latest",
            "organization_id",
            "agent_role",
            "version",
        ),
    )


class AgentExecution(Base):
    """Durable real-time activity and measured accounting for one agent invocation."""

    __tablename__ = "agent_executions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    execution_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_execution_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="running")
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    execution_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    configuration_version: Mapped[int] = mapped_column(Integer, nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    measured_cost: Mapped[float] = mapped_column(Numeric(14, 6), nullable=False, server_default="0")
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default="USD")
    trace_id: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime.datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    duration_ms: Mapped[float | None] = mapped_column(Numeric(14, 3), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "campaign_run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_agent_execution_campaign",
        ),
        CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="agent_execution_role",
        ),
        CheckConstraint(
            "status IN ('running','succeeded','failed','skipped')",
            name="agent_execution_status",
        ),
        CheckConstraint(
            "execution_mode IN ('deterministic','hosted_advisory')",
            name="agent_execution_mode",
        ),
        CheckConstraint(
            "input_sha256 ~ '^[0-9a-f]{64}$' AND "
            "(output_sha256 IS NULL OR output_sha256 ~ '^[0-9a-f]{64}$')",
            name="agent_execution_hashes",
        ),
        CheckConstraint(
            "input_tokens IS NULL OR input_tokens >= 0",
            name="agent_execution_input_tokens",
        ),
        CheckConstraint(
            "output_tokens IS NULL OR output_tokens >= 0",
            name="agent_execution_output_tokens",
        ),
        CheckConstraint("measured_cost >= 0", name="agent_execution_cost"),
        CheckConstraint(
            "jsonb_typeof(detail) = 'object'",
            name="agent_execution_detail_object",
        ),
        CheckConstraint(
            "(status = 'running' AND finished_at IS NULL AND duration_ms IS NULL "
            "AND output_sha256 IS NULL AND error_code IS NULL) OR "
            "(status <> 'running' AND finished_at IS NOT NULL AND duration_ms IS NOT NULL "
            "AND output_sha256 IS NOT NULL)",
            name="agent_execution_terminal_shape",
        ),
        Index(
            "ix_agent_execution_campaign_order",
            "organization_id",
            "campaign_run_id",
            "id",
        ),
        Index(
            "ix_agent_execution_role_started",
            "organization_id",
            "agent_role",
            "started_at",
        ),
    )


class CommandIdempotency(Base):
    __tablename__ = "command_idempotency"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    command_type: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "actor_user_id",
            "command_type",
            "idempotency_key",
            name="uq_command_idempotency_scope",
        ),
        CheckConstraint("request_hash ~ '^[0-9a-f]{64}$'", name="command_idempotency_request_hash"),
        CheckConstraint(
            "jsonb_typeof(response_payload) = 'object'", name="command_idempotency_response_object"
        ),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    cursor: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(String(96), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    actor_session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="audit_event_payload_object"),
        Index("ix_audit_events_org_cursor", "organization_id", "cursor"),
    )


class FindingDecisionEvent(Base):
    __tablename__ = "finding_decision_events"

    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_finding_decision_finding",
        ),
        CheckConstraint(
            "decision IN ('approved','rejected','resolved')", name="finding_decision_allowed"
        ),
        CheckConstraint(
            "char_length(rationale) BETWEEN 1 AND 2000",
            name="finding_decision_rationale_length",
        ),
        Index("ix_finding_decision_history", "organization_id", "finding_id", "created_at"),
    )
