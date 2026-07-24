"""Durable physical-work-unit admission and exact campaign reconciliation."""

from __future__ import annotations

import datetime
from dataclasses import dataclass

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, text

from agentforge.auth.permissions import CAMPAIGN_AUTHORIZE, CAMPAIGN_LAUNCH
from agentforge.auth.principal import Principal
from agentforge.config import Settings
from agentforge.control_plane.errors import AuthorizationDeniedError, RecordConflictError
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy.allowlist import Allowlist, AllowlistEntry
from agentforge.policy.gateway import (
    AbortError,
    PolicyGateway,
    RunPolicy,
    WorkUnitCoordinates,
)
from agentforge.storage.models import Base
from agentforge.storage.queue import JobRecord, LogicalQueue, PostgresJobQueue
from agentforge.target.base import TargetRequest, TargetResponse
from agentforge.target.catalog import TrustedTargetCatalog
from agentforge.target.spec import ExecutionProfile, SafetyCaps

_ORG = "org_WorkUnitFixture"
_CORPUS_HASH = "9" * 64
_EXACT_CORPUS_ID = "headshot-live-100-v1"
_LEASE = datetime.timedelta(minutes=5)


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _Accounting:
    per_call_usd = 0.01

    def __init__(self) -> None:
        self.spent_usd = 0.0

    def charge(self) -> None:
        self.spent_usd += self.per_call_usd


@dataclass(frozen=True)
class _RunFixture:
    store: ControlPlaneStore
    queue: PostgresJobQueue
    job: JobRecord
    run_id: str


def _principal(user: str, permission: str) -> Principal:
    return Principal(
        user_id=user,
        session_id=f"sess_{user.removeprefix('user_')}",
        organization_id=_ORG,
        organization_role="org:operator",
        organization_permissions=frozenset({permission}),
    )


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE campaign_work_unit_reservations, agent_executions, "
                "agent_configuration_versions, regression_dispositions, vuln_reports, "
                "campaign_run_summaries, finding_evidence_links, finding_decision_events, "
                "finding, verdict, attempt_result, audit_events, command_idempotency, "
                "campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _running_exact_run(
    engine: Engine,
    *,
    logical_count: int = 1,
    physical_count: int = 2,
) -> _RunFixture:
    _clean(engine)
    launcher = _principal("user_WorkUnitLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_WorkUnitApprover", CAMPAIGN_AUTHORIZE)
    store = ControlPlaneStore(engine, environment="staging")
    TrustedTargetCatalog.from_environment("staging").synchronize(
        store,
        organization_id=_ORG,
    )
    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=_EXACT_CORPUS_ID,
        corpus_hash=_CORPUS_HASH,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=logical_count,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
            logical_case_limit=logical_count,
            physical_request_limit=physical_count,
            target_retries_per_turn=0,
        ),
        run_nonce="work-unit-run-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="work-unit-request-0001",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="work-unit-approve-0001",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="work-unit-launch-0001",
    )
    queue = PostgresJobQueue(
        engine,
        supported_payload_versions={
            LogicalQueue.AGENT_WORK: {"campaign.execute": (1,)},
        },
    )
    job = queue.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="work-unit-worker-a",
        lease_duration=_LEASE,
    )
    assert job is not None
    store.append_campaign_state(run_id=run.run_id, state="running")
    return _RunFixture(store=store, queue=queue, job=job, run_id=run.run_id)


def _attempt(fixture: _RunFixture, *, ordinal: int = 0):
    return fixture.store.ensure_campaign_attempt(
        run_id=fixture.run_id,
        ordinal=ordinal,
        case_id=f"case-{ordinal}",
    )


def _reserve_and_observe(
    fixture: _RunFixture,
    attempt_id: str,
    *,
    turn_index: int,
    retry_index: int = 0,
) -> None:
    fixture.store.reserve_campaign_work_unit(
        job=fixture.job,
        attempt_id=attempt_id,
        turn_index=turn_index,
        retry_index=retry_index,
    )
    fixture.store.observe_campaign_work_unit(
        job=fixture.job,
        attempt_id=attempt_id,
        turn_index=turn_index,
        retry_index=retry_index,
        outcome="returned",
    )


def test_reservation_survives_restart_and_reclaim_and_blocks_ambiguous_replay(
    migrated_db: Engine,
) -> None:
    fixture = _running_exact_run(migrated_db)
    attempt = _attempt(fixture)
    fixture.store.reserve_campaign_work_unit(
        job=fixture.job,
        attempt_id=attempt.attempt_id,
        turn_index=0,
        retry_index=0,
    )

    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE jobs SET leased_at = clock_timestamp() - interval '2 seconds', "
                "last_heartbeat_at = clock_timestamp() - interval '2 seconds', "
                "lease_expires_at = clock_timestamp() - interval '1 second' "
                "WHERE job_id = :job_id"
            ),
            {"job_id": fixture.job.job_id},
        )
    assert fixture.queue.reap_expired().requeued_job_ids == (fixture.job.job_id,)
    reclaimed = fixture.queue.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="work-unit-worker-b",
        lease_duration=_LEASE,
    )
    assert reclaimed is not None and reclaimed.attempts == fixture.job.attempts + 1
    restarted_store = ControlPlaneStore(migrated_db, environment="staging")

    with pytest.raises(RecordConflictError, match="already reserved"):
        restarted_store.reserve_campaign_work_unit(
            job=reclaimed,
            attempt_id=attempt.attempt_id,
            turn_index=0,
            retry_index=0,
        )
    with pytest.raises(AuthorizationDeniedError, match="different queue claim"):
        restarted_store.observe_campaign_work_unit(
            job=reclaimed,
            attempt_id=attempt.attempt_id,
            turn_index=0,
            retry_index=0,
            outcome="returned",
        )
    with pytest.raises(RecordConflictError, match="unobserved"):
        restarted_store.complete_campaign_job(job=reclaimed, measured_cost=0.0)

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT job_attempt, worker_id, observed_at "
                    "FROM campaign_work_unit_reservations WHERE run_id = :run_id"
                ),
                {"run_id": fixture.run_id},
            )
            .mappings()
            .one()
        )
    assert row["job_attempt"] == 1
    assert row["worker_id"] == "work-unit-worker-a"
    assert row["observed_at"] is None


def test_duplicate_coordinate_is_rejected_even_after_observation(migrated_db: Engine) -> None:
    fixture = _running_exact_run(migrated_db)
    attempt = _attempt(fixture)
    _reserve_and_observe(fixture, attempt.attempt_id, turn_index=0)

    with pytest.raises(RecordConflictError, match="already reserved"):
        fixture.store.reserve_campaign_work_unit(
            job=fixture.job,
            attempt_id=attempt.attempt_id,
            turn_index=0,
            retry_index=0,
        )


def test_cap_plus_one_and_retry_plus_one_are_rejected_before_reservation(
    migrated_db: Engine,
) -> None:
    fixture = _running_exact_run(migrated_db, physical_count=2)
    attempt = _attempt(fixture)
    _reserve_and_observe(fixture, attempt.attempt_id, turn_index=0)
    _reserve_and_observe(fixture, attempt.attempt_id, turn_index=1)

    with pytest.raises(AuthorizationDeniedError, match="limit is already exhausted"):
        fixture.store.reserve_campaign_work_unit(
            job=fixture.job,
            attempt_id=attempt.attempt_id,
            turn_index=2,
            retry_index=0,
        )
    with pytest.raises(AuthorizationDeniedError, match="per-turn retry limit"):
        fixture.store.reserve_campaign_work_unit(
            job=fixture.job,
            attempt_id=attempt.attempt_id,
            turn_index=0,
            retry_index=1,
        )

    with migrated_db.connect() as connection:
        count = connection.execute(
            text("SELECT count(*) FROM campaign_work_unit_reservations WHERE run_id = :run_id"),
            {"run_id": fixture.run_id},
        ).scalar_one()
    assert count == 2


def test_interrupted_multi_step_attempt_is_not_a_logical_completion(
    migrated_db: Engine,
) -> None:
    fixture = _running_exact_run(migrated_db)
    attempt = _attempt(fixture)

    class _StopsAfterFirstTurn:
        name = "fake"
        turn_delivery = "sequential"

        def __init__(self) -> None:
            self.calls: list[TargetRequest] = []

        def send(self, request: TargetRequest) -> TargetResponse:
            self.calls.append(request)
            return TargetResponse(output="stopped", status=500, metadata={"adapter": "fake"})

    adapter = _StopsAfterFirstTurn()
    clock = _Clock()

    def reserve(coordinates: WorkUnitCoordinates) -> None:
        fixture.store.reserve_campaign_work_unit(
            job=fixture.job,
            attempt_id=coordinates.attempt_id,
            turn_index=coordinates.turn_index,
            retry_index=coordinates.retry_index,
        )

    def observe(coordinates: WorkUnitCoordinates, outcome: str) -> None:
        fixture.store.observe_campaign_work_unit(
            job=fixture.job,
            attempt_id=coordinates.attempt_id,
            turn_index=coordinates.turn_index,
            retry_index=coordinates.retry_index,
            outcome=outcome,
        )

    gateway = PolicyGateway(
        allowlist=Allowlist([AllowlistEntry(target_id="fake", adapter_name="fake")]),
        adapter=adapter,
        settings=Settings(environment="local"),
        clock=clock,
        accounting=_Accounting(),
        pre_physical_send_gate=reserve,
        post_physical_send_observer=observe,
    )
    policy = RunPolicy(
        budget_usd=1.0,
        max_attempts_per_run=1,
        target_requests_per_second=100.0,
        run_timeout_seconds=300.0,
        logical_case_limit=1,
        physical_request_limit=2,
        target_retries_per_turn=0,
    )
    attack = {
        "schema_version": "1",
        "case_ref": "case-0",
        "input_sequence": ["turn-one", "turn-two"],
        "category": "prompt_injection",
    }

    with pytest.raises(AbortError, match="before every authorized turn"):
        gateway.execute(attack, policy, attempt_id=attempt.attempt_id)
    assert len(adapter.calls) == 1
    assert gateway.completed_logical_cases == 0
    with pytest.raises(RecordConflictError, match="exact completion counts"):
        fixture.store.complete_campaign_job(
            job=fixture.job,
            measured_cost=0.01,
        )

    with migrated_db.connect() as connection:
        counts = (
            connection.execute(
                text(
                    "SELECT count(*) AS reserved, "
                    "count(*) FILTER (WHERE observed_at IS NOT NULL) AS observed "
                    "FROM campaign_work_unit_reservations WHERE run_id = :run_id"
                ),
                {"run_id": fixture.run_id},
            )
            .mappings()
            .one()
        )
        logical = connection.execute(
            text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run_id"),
            {"run_id": fixture.run_id},
        ).scalar_one()
    assert dict(counts) == {"reserved": 1, "observed": 1}
    assert logical == 0


def test_exact_completion_uses_durable_counts_not_process_local_counter(
    migrated_db: Engine,
) -> None:
    fixture = _running_exact_run(migrated_db)
    attempt = _attempt(fixture)
    _reserve_and_observe(fixture, attempt.attempt_id, turn_index=0)
    _reserve_and_observe(fixture, attempt.attempt_id, turn_index=1)
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO attempt_result "
                "(organization_id, campaign_run_id, attempt_id, content_hash, "
                "execution_profile, evidence_provenance) VALUES "
                "(:org, :run_id, :attempt_id, :hash, 'synthetic', 'synthetic_offline')"
            ),
            {
                "org": _ORG,
                "run_id": fixture.run_id,
                "attempt_id": attempt.attempt_id,
                "hash": "a" * 64,
            },
        )
        connection.execute(
            text(
                "INSERT INTO verdict "
                "(organization_id, campaign_run_id, attempt_id, state, confidence) VALUES "
                "(:org, :run_id, :attempt_id, 'NO_EXPLOIT_OBSERVED', 1.0)"
            ),
            {
                "org": _ORG,
                "run_id": fixture.run_id,
                "attempt_id": attempt.attempt_id,
            },
        )

    completed = fixture.store.complete_campaign_job(
        job=fixture.job,
        request_count=999,
        measured_cost=0.02,
    )
    assert completed.state == "complete"
    with migrated_db.connect() as connection:
        summary = (
            connection.execute(
                text(
                    "SELECT attempt_count, request_count FROM campaign_run_summaries "
                    "WHERE run_id = :run_id"
                ),
                {"run_id": fixture.run_id},
            )
            .mappings()
            .one()
        )
    assert dict(summary) == {"attempt_count": 1, "request_count": 2}


def test_work_unit_schema_matches_alembic_metadata(migrated_db: Engine) -> None:
    with migrated_db.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={"compare_server_default": True},
        )
        differences = compare_metadata(context, Base.metadata)
        primary_key = (
            connection.execute(
                text(
                    "SELECT a.attname FROM pg_index i "
                    "JOIN pg_class c ON c.oid = i.indrelid "
                    "JOIN unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true "
                    "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum "
                    "WHERE c.relname = 'campaign_work_unit_reservations' AND i.indisprimary "
                    "ORDER BY k.ord"
                )
            )
            .scalars()
            .all()
        )
        triggers = (
            connection.execute(
                text(
                    "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE c.relname = 'campaign_work_unit_reservations' AND NOT t.tgisinternal"
                )
            )
            .scalars()
            .all()
        )

    ledger_drift = [
        difference
        for difference in differences
        if "campaign_work_unit_reservations" in repr(difference)
    ]
    assert ledger_drift == []
    assert primary_key == ["run_id", "attempt_id", "turn_index", "retry_index"]
    assert triggers == ["trg_campaign_work_unit_reservations_guard"]
