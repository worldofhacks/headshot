"""agentforge.storage.models — the M2 exploit-DB data model (SQLAlchemy 2.0 DeclarativeBase).

Anchors: ARCHITECTURE.md §4 (AttemptResult / D14 evidence field set), §5 (S1/S2 trust
boundaries, per-agent DB roles), §6 (data model, PRD-OPT-16 indexes, S3 replay UNIQUE);
PRESEARCH.md §5.2 (state machines) / §5.3 (invariants).

Scope decision (deliberate, not forgotten). This module models ONLY the entities whose
state machines (PRESEARCH §5.2) or the S1/S2 evidence spine the local MVP slice needs:
``campaign``, ``attack_case``, ``attempt``, ``red_team_staging``, ``attempt_result``,
``verdict``, ``finding``, ``regression_case``. The remaining nouns from ARCHITECTURE §6 /
PRESEARCH §5.1 — ``CostRecord``, ``CoverageMetric``, ``GroundTruthLabel``,
``ContractVersion``, ``Incident``, ``Target``, ``TargetAdapter``, ``AllowlistEntry``,
``CredentialBinding``, ``Transcript``, ``RegressionRun``, the LangGraph checkpoint tables,
and the ``jobs`` work/regression queue — are **intentionally deferred** and land with their
consumers in later milestones. They are not modelled here on purpose.

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
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
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
    """Declarative base carrying the M2 storage MetaData (Alembic ``target_metadata``)."""

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
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
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
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["campaign_run_id", "attempt_id"],
            ["attempt_result.campaign_run_id", "attempt_result.attempt_id"],
            name="fk_verdict_run_attempt_attempt_result",
        ),
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
    state: Mapped[str] = mapped_column(finding_state, nullable=False, server_default="candidate")
    severity: Mapped[str] = mapped_column(finding_severity, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    target_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_finding_severity", "severity"),
        Index("ix_finding_category", "category"),
        Index("ix_finding_target_version", "target_version"),
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
