"""Private scheduler for target-version regression planning.

The scheduler has no target adapter, credential resolver, or execution authority.  It watches
the authoritative PostgreSQL registry for a new READY target version and materializes one
content-addressed, execution-blocked replay plan for every admitted regression case that has not
yet been planned against that version.  The existing campaign authorization workflow must still
approve the exact replay scope before the Runner can execute anything.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import sys
import threading
from collections.abc import Callable
from typing import Any

from sqlalchemy import Connection, Engine, text

from agentforge.campaign.runtime import production_engine
from agentforge.readiness import expected_alembic_head
from agentforge.regression import RegressionReplayGate

_DEFAULT_POLL_SECONDS = 15.0
_MIN_POLL_SECONDS = 1.0
_MAX_POLL_SECONDS = 3600.0


class SchedulerUnavailable(RuntimeError):
    """The private scheduler cannot establish its authoritative DB composition."""


def enqueue_due_work(*, schedule_repository: Any, queue: Any) -> int:
    """Compatibility seam for repositories that expose persisted due schedules.

    The production scheduler below does not invent schedules from process memory; it derives
    target-version replay plans directly from immutable database records.  This seam remains for
    callers that already supply an authoritative repository and durable queue.
    """

    if schedule_repository is None or queue is None:
        raise SchedulerUnavailable("authoritative_schedule_repository_missing")
    due = schedule_repository.claim_due()
    count = 0
    for schedule in due:
        queue.enqueue_schedule(schedule)
        schedule_repository.mark_enqueued(schedule)
        count += 1
    return count


def _schema_is_current(engine: Engine) -> bool:
    try:
        with engine.connect() as connection:
            current = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
        return current == expected_alembic_head()
    except Exception:
        return False


def _candidate_rows(connection: Connection) -> list[dict[str, Any]]:
    """Return admitted cases missing a replay plan for the latest READY target version."""

    return [
        dict(row)
        for row in connection.execute(
            text(
                "WITH latest_ready AS ("
                " SELECT DISTINCT ON (d.organization_id, d.target_id) "
                " d.organization_id, d.target_id, d.version AS replay_target_version "
                " FROM target_definitions d "
                " WHERE (SELECT e.to_lifecycle FROM target_lifecycle_events e "
                "        WHERE e.organization_id = d.organization_id "
                "          AND e.target_id = d.target_id "
                "          AND e.target_version = d.version "
                "        ORDER BY e.id DESC LIMIT 1) = 'ready' "
                " ORDER BY d.organization_id, d.target_id, d.id DESC"
                ") "
                "SELECT c.organization_id, c.regression_case_id, c.case_version, "
                "c.finding_id, c.report_id, c.admission_disposition_id, c.target_id, "
                "c.source_target_version, c.attack_attempt, c.required_oracle_ids, "
                "c.planned_repetitions, d.contract_payload AS disposition, "
                "r.contract_payload AS report, latest.replay_target_version "
                "FROM regression_case_versions c "
                "JOIN latest_ready latest "
                "  ON latest.organization_id = c.organization_id "
                " AND latest.target_id = c.target_id "
                "JOIN regression_dispositions d "
                "  ON d.organization_id = c.organization_id "
                " AND d.disposition_id = c.admission_disposition_id "
                "JOIN vuln_reports r "
                "  ON r.organization_id = c.organization_id "
                " AND r.report_id = c.report_id "
                "LEFT JOIN regression_replay_plans p "
                "  ON p.organization_id = c.organization_id "
                " AND p.regression_case_id = c.regression_case_id "
                " AND p.target_id = c.target_id "
                " AND p.replay_target_version = latest.replay_target_version "
                "WHERE latest.replay_target_version <> c.source_target_version "
                "  AND p.replay_id IS NULL "
                "ORDER BY c.organization_id, c.target_id, c.regression_case_id, c.case_version"
            )
        ).mappings()
    ]


def _persist_plan(connection: Connection, row: dict[str, Any], plan: dict[str, Any]) -> bool:
    if plan["regression_case_id"] != row["regression_case_id"]:
        raise SchedulerUnavailable("regression_case_identity_mismatch")
    inserted = connection.execute(
        text(
            "INSERT INTO regression_replay_plans "
            "(organization_id, replay_id, regression_case_id, finding_id, report_id, "
            "disposition_id, target_id, source_target_version, replay_target_version, "
            "attack_sequence_sha256, contract_payload) VALUES "
            "(:organization_id, :replay_id, :regression_case_id, :finding_id, :report_id, "
            ":disposition_id, :target_id, :source_target_version, :replay_target_version, "
            ":attack_sequence_sha256, CAST(:contract_payload AS jsonb)) "
            "ON CONFLICT DO NOTHING RETURNING replay_id"
        ),
        {
            "organization_id": row["organization_id"],
            "replay_id": plan["replay_id"],
            "regression_case_id": plan["regression_case_id"],
            "finding_id": plan["finding_id"],
            "report_id": plan["report_id"],
            "disposition_id": row["admission_disposition_id"],
            "target_id": plan["target_id"],
            "source_target_version": plan["source_target_version"],
            "replay_target_version": plan["replay_target_version"],
            "attack_sequence_sha256": plan["attack_sequence_sha256"],
            "contract_payload": json.dumps(
                plan,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        },
    ).scalar_one_or_none()
    return inserted is not None


def plan_target_version_replays(engine: Engine) -> int:
    """Create all currently due, authorization-blocked target-version replay plans."""

    gate = RegressionReplayGate()
    created = 0
    with engine.begin() as connection:
        for row in _candidate_rows(connection):
            plan = gate.plan(
                disposition=row["disposition"],
                report=row["report"],
                attack_attempt=row["attack_attempt"],
                source_case_version=row["case_version"],
                target_id=row["target_id"],
                source_target_version=row["source_target_version"],
                replay_target_version=row["replay_target_version"],
                required_oracle_ids=row["required_oracle_ids"],
                trigger="target_version_changed",
                repetitions=row["planned_repetitions"],
            )
            created += int(_persist_plan(connection, row, plan))
    return created


def _heartbeat(
    engine: Engine,
    *,
    environment: str,
    availability: str,
    detail: str,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runtime_component_status "
                "(environment, component_id, name, kind, availability, detail) VALUES "
                "(:environment, 'scheduler', 'Regression scheduler', 'scheduler', "
                ":availability, :detail) "
                "ON CONFLICT (environment, component_id) DO UPDATE SET "
                "name = EXCLUDED.name, kind = EXCLUDED.kind, "
                "availability = EXCLUDED.availability, detail = EXCLUDED.detail, "
                "heartbeat_at = clock_timestamp()"
            ),
            {
                "environment": environment,
                "availability": availability,
                "detail": detail[:128],
            },
        )


class DurableScheduler:
    """One private, idempotent target-version planning loop."""

    def __init__(
        self,
        *,
        engine: Engine,
        environment: str,
        planner: Callable[[Engine], int] = plan_target_version_replays,
    ) -> None:
        if environment not in {"local", "staging", "production"}:
            raise SchedulerUnavailable("scheduler_environment_invalid")
        self.engine = engine
        self.environment = environment
        self.planner = planner

    def run_once(self) -> int:
        created = self.planner(self.engine)
        _heartbeat(
            self.engine,
            environment=self.environment,
            availability="operational and evidenced",
            detail=f"private scheduler healthy; {created} replay plan(s) created this cycle",
        )
        return created


def check_runtime(database_url: str | None = None) -> bool:
    """Check DB/schema/config readiness without binding a socket or contacting a target."""

    url = database_url if database_url is not None else os.environ.get("DATABASE_URL")
    environment = os.environ.get("AGENTFORGE_ENVIRONMENT")
    if not url or environment not in {"local", "staging", "production"}:
        return False
    try:
        return _schema_is_current(production_engine(url))
    except Exception:
        return False


def _poll_seconds() -> float:
    raw = os.environ.get("AGENTFORGE_SCHEDULER_POLL_SECONDS", str(_DEFAULT_POLL_SECONDS))
    try:
        value = float(raw)
    except ValueError as exc:
        raise SchedulerUnavailable("scheduler_poll_interval_invalid") from exc
    if not _MIN_POLL_SECONDS <= value <= _MAX_POLL_SECONDS:
        raise SchedulerUnavailable("scheduler_poll_interval_invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge-scheduler")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        return 0 if check_runtime() else 1

    database_url = os.environ.get("DATABASE_URL")
    environment = os.environ.get("AGENTFORGE_ENVIRONMENT")
    if not database_url or environment not in {"local", "staging", "production"}:
        print("scheduler unavailable: configuration is incomplete", file=sys.stderr)
        return 1
    try:
        scheduler = DurableScheduler(
            engine=production_engine(database_url),
            environment=environment,
        )
        poll_seconds = _poll_seconds()
    except Exception:
        print("scheduler unavailable: trusted composition failed", file=sys.stderr)
        return 1

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: stop.set())
    while not stop.is_set():
        try:
            scheduler.run_once()
        except Exception:
            with contextlib.suppress(Exception):
                _heartbeat(
                    scheduler.engine,
                    environment=scheduler.environment,
                    availability="evaluated and rejected",
                    detail="private scheduler cycle failed closed; no replay was dispatched",
                )
        if args.once:
            return 0
        stop.wait(poll_seconds)
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess/container smoke owns this path
    raise SystemExit(main())


__all__ = [
    "DurableScheduler",
    "SchedulerUnavailable",
    "check_runtime",
    "enqueue_due_work",
    "main",
    "plan_target_version_replays",
]
