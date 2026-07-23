"""Authoritative synthetic campaign through queue, Runner, Judge, and result repositories."""

from __future__ import annotations

import dataclasses
import datetime
import time
from types import SimpleNamespace
from typing import NamedTuple

import pytest
from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.permissions import CAMPAIGN_AUTHORIZE, CAMPAIGN_LAUNCH
from agentforge.auth.principal import Principal
from agentforge.campaign.corpus import load_mvp_corpus
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.runner import DispatchUnavailable, DurableCampaignRunner
from agentforge.storage.queue import JobRecord, LogicalQueue, PostgresJobQueue
from agentforge.target.catalog import TrustedTargetCatalog
from agentforge.target.spec import AuthMode, ExecutionProfile, SafetyCaps

ORG_ID = "org_RunnerFixture"
_LEASE = datetime.timedelta(minutes=10)


class _AdvancingClock:
    def __init__(self) -> None:
        self.value = time.time()

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _principal(user_id: str, permission: str) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=ORG_ID,
        organization_role="org:operator",
        organization_permissions=frozenset({permission}),
    )


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE campaign_run_summaries, finding_evidence_links, "
                "finding_decision_events, finding, verdict, attempt_result, audit_events, "
                "command_idempotency, campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _live_chat_prepared(
    *,
    auth_mode: AuthMode = AuthMode.SESSION,
    payload_profile: str = "copilot_chat",
) -> SimpleNamespace:
    """Minimal trusted composition input; it never constructs a client or opens a socket."""

    scope = SimpleNamespace(
        execution_profile=ExecutionProfile.LIVE,
        auth_mode=auth_mode,
    )
    policy = SimpleNamespace(
        request_timeout_seconds=30.0,
        redirect_policy="deny",
        response_size_limit_bytes=262_144,
        allowed_content_types=("application/json",),
        allow_private_destination=False,
        payload_profile=payload_profile,
    )
    return SimpleNamespace(
        authorized=SimpleNamespace(scope=scope),
        entry=SimpleNamespace(
            target=SimpleNamespace(base_url="https://copilot.example.test"),
            transport_policy=policy,
        ),
        surface=SimpleNamespace(method="POST", relative_path="chat"),
    )


def test_live_runner_composes_approved_bruno_chat_contract_without_network() -> None:
    runner = object.__new__(DurableCampaignRunner)

    adapter = runner._adapter(_live_chat_prepared())

    assert adapter.base_url == "https://copilot.example.test"
    assert adapter.relative_path == "chat"
    assert adapter.payload_profile == "copilot_chat"
    assert adapter.credential is None


def test_live_runner_refuses_chat_profile_without_session_bound_scope() -> None:
    runner = object.__new__(DurableCampaignRunner)

    with pytest.raises(DispatchUnavailable, match="copilot_chat_scope_invalid"):
        runner._adapter(_live_chat_prepared(auth_mode=AuthMode.BEARER))


def test_live_runner_refuses_catalog_profile_that_differs_from_approved_scope() -> None:
    runner = object.__new__(DurableCampaignRunner)

    with pytest.raises(DispatchUnavailable, match="payload_profile_scope_mismatch"):
        runner._adapter(_live_chat_prepared(payload_profile="openemr_turns"))


def test_synthetic_catalog_versions_the_fourteen_case_safety_contract() -> None:
    catalog = TrustedTargetCatalog.from_environment("staging")

    entry, surface = catalog.resolve(
        target_id="synthetic-copilot", surface_id="synthetic-chat"
    )

    assert entry.target.version == "1.1.0"
    assert entry.target.safety_caps.max_attempts_per_run == 14
    assert surface.version == "1.1.0"
    assert surface.target_version == entry.target.version


class _AuthorizedSyntheticRun(NamedTuple):
    launcher: Principal
    corpus: object
    catalog: TrustedTargetCatalog
    store: ControlPlaneStore
    run: object


def _authorize_synthetic_run(
    engine: Engine,
    *,
    target_requests_per_second: float = 100.0,
) -> _AuthorizedSyntheticRun:
    """Drive the full two-person control-plane handshake and enqueue one dispatchable job.

    This is the exact harness the happy-path test uses; the negative tests reuse it and
    then perturb a single precondition so the Runner refuses at network-free preflight.
    """

    _clean(engine)
    launcher = _principal("user_RunnerLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_RunnerApprover", CAMPAIGN_AUTHORIZE)
    corpus = load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    store = ControlPlaneStore(engine, environment="staging")
    catalog.synchronize(store, organization_id=ORG_ID)

    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=9,
            target_requests_per_second=target_requests_per_second,
            run_timeout_seconds=300.0,
        ),
        run_nonce="runner-negative-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
        idempotency_key="runner-negative-request-0001",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="runner-negative-approve-0001",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="runner-negative-launch-0001",
    )
    return _AuthorizedSyntheticRun(
        launcher=launcher, corpus=corpus, catalog=catalog, store=store, run=run
    )


def _claim_enqueued_job(runner: DurableCampaignRunner, *, worker_id: str) -> JobRecord:
    # Claim through the Runner's own queue, which trusts the ``campaign.execute`` schema
    # the launch step enqueues; a default-configured queue would reject that payload.
    job = runner.queue.claim(LogicalQueue.AGENT_WORK, worker_id=worker_id, lease_duration=_LEASE)
    assert job is not None
    return job


def _no_adapter_guard(runner: DurableCampaignRunner) -> list[bool]:
    """Trip a flag if adapter construction (the first live-path step) is ever reached."""

    constructed: list[bool] = []

    def _forbidden(prepared: object) -> object:  # pragma: no cover - must never run
        constructed.append(True)
        raise AssertionError("preflight refusal must precede adapter construction")

    runner._adapter = _forbidden  # type: ignore[method-assign]
    return constructed


def test_corpus_hash_drift_refuses_before_adapter_construction(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """The Runner independently rebinds the persisted scope's corpus hash to its own corpus.

    (The related "synthetic profile in production" gate at runner.py:293 is unreachable
    from a persisted run: the synthetic target is staging-bound, so a production-environment
    control plane refuses the scope at ``_build_scope_from_database`` (store.py:2015) — the
    run loads as ``authorization_not_dispatchable`` before the synthetic-profile check runs.
    That stronger environment gate subsumes it, so this test exercises a genuinely
    Runner-owned, otherwise-untested preflight blocker instead.)
    """

    authorized = _authorize_synthetic_run(migrated_db)
    # A corpus whose content hash no longer matches the authorized scope's corpus_hash,
    # while keeping the nine cases / three categories so only the hash gate trips.
    drifted_corpus = dataclasses.replace(authorized.corpus, content_hash="0" * 64)
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=drifted_corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    job = _claim_enqueued_job(runner, worker_id="runner-test")
    adapter_calls = _no_adapter_guard(runner)

    report, prepared = runner.preflight(job)

    assert "corpus_hash_mismatch" in report.blockers
    assert "corpus_not_complete" not in report.blockers
    assert report.ready is False
    assert prepared is None
    assert adapter_calls == []


def test_stale_runner_ownership_refuses_before_adapter_construction(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """A job whose lease token does not match the persisted row is not owned by this worker."""

    authorized = _authorize_synthetic_run(migrated_db)
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    job = _claim_enqueued_job(runner, worker_id="runner-test")
    # Forge a lease token so database-time ownership no longer resolves to this worker.
    tampered = dataclasses.replace(job, lease_token="not-the-real-lease-token")
    adapter_calls = _no_adapter_guard(runner)

    report, prepared = runner.preflight(tampered)

    assert "lease_not_owned" in report.blockers
    assert report.ready is False
    assert prepared is None
    assert adapter_calls == []


def test_two_person_control_violation_is_not_dispatchable(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """Same identity as launcher and approver cannot yield a dispatchable persisted run.

    The dedicated Runner blocker ``two_person_control_failed`` (runner.py:245) is
    defense-in-depth: the control plane refuses same-identity approval at
    ``decide_campaign_authorization`` (store.py:687) and again refuses to load such a run
    at ``load_run_for_execution`` (store.py:986), so it never persists a self-approved run
    to reach that later check. This test proves the store-level refusal blocks the request
    outright, and — because approval fails — no job is ever enqueued to dispatch.
    """

    _clean(migrated_db)
    single_identity = _principal("user_SelfApprover", CAMPAIGN_LAUNCH)
    single_identity = dataclasses.replace(
        single_identity,
        organization_permissions=frozenset({CAMPAIGN_LAUNCH, CAMPAIGN_AUTHORIZE}),
    )
    corpus = load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    store = ControlPlaneStore(migrated_db, environment="staging")
    catalog.synchronize(store, organization_id=ORG_ID)

    scope = store.build_scope(
        principal=single_identity,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=9,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
        ),
        run_nonce="runner-selfapprove-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=single_identity,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
        idempotency_key="runner-selfapprove-request-0001",
    )

    with pytest.raises(Exception) as excinfo:
        store.decide_campaign_authorization(
            principal=single_identity,
            request_id=request.request_id,
            decision="approved",
            idempotency_key="runner-selfapprove-approve-0001",
        )
    assert "own authorization request" in str(excinfo.value)

    # Approval was refused, so nothing was ever enqueued: there is no job to dispatch.
    queue = PostgresJobQueue(migrated_db)
    claimed = queue.claim(LogicalQueue.AGENT_WORK, worker_id="runner-test", lease_duration=_LEASE)
    assert claimed is None


def test_synthetic_campaign_executes_all_nine_cases_and_completes_atomically(
    migrated_db: Engine,
    tmp_path,
) -> None:
    _clean(migrated_db)
    launcher = _principal("user_RunnerLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_RunnerApprover", CAMPAIGN_AUTHORIZE)
    corpus = load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    store = ControlPlaneStore(migrated_db, environment="staging")
    catalog.synchronize(store, organization_id=ORG_ID)

    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=9,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
        ),
        run_nonce="runner-synthetic-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
        idempotency_key="runner-synthetic-request-0001",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="runner-synthetic-approve-0001",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="runner-synthetic-launch-0001",
    )

    clock = _AdvancingClock()
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=corpus,
        catalog=catalog,
        manifest_root=tmp_path,
        clock=clock,
        sleeper=clock.advance,
    )
    assert runner.run_once(worker_id="runner-test") is True

    with migrated_db.connect() as connection:
        state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id DESC LIMIT 1"
            ),
            {"run": run.run_id},
        ).scalar_one()
        evidence = connection.execute(
            text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        verdicts = connection.execute(
            text("SELECT count(*) FROM verdict WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        findings = connection.execute(
            text("SELECT count(*) FROM finding_evidence_links WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        summary = (
            connection.execute(
                text("SELECT * FROM campaign_run_summaries WHERE run_id = :run"),
                {"run": run.run_id},
            )
            .mappings()
            .one()
        )
        job_status = connection.execute(
            text("SELECT status FROM jobs WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()

    assert state == "complete"
    assert evidence == verdicts == 9
    assert findings == 2
    assert summary["attempt_count"] == summary["request_count"] == 9
    assert summary["execution_profile"] == "synthetic"
    assert summary["provenance"] == "synthetic_offline"
    assert job_status == "completed"

    backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        corpus=corpus,
    )
    findings_projection = backend.read("findings", launcher)
    coverage_projection = backend.read("coverage", launcher)
    events = backend.events(launcher, after_cursor=0, limit=100)
    assert findings_projection.state == "ready"
    assert len(findings_projection.data) == 2
    assert all(
        item["publication_status"] == "blocked_pending_human_approval"
        for item in findings_projection.data
    )
    assert coverage_projection.state == "ready"
    assert coverage_projection.data[0]["covered"] is True
    assert coverage_projection.data[0]["verified_attempt_count"] == 9
    assert any(event["type"] == "campaign.complete" for event in events.events)


def test_runner_throttles_from_response_completion_for_slow_target(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """A slow response must not consume the next request's completion-based rate interval."""

    authorized = _authorize_synthetic_run(
        migrated_db,
        target_requests_per_second=1.0,
    )
    clock = _AdvancingClock()
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
        clock=clock,
        sleeper=clock.advance,
    )

    build_adapter = runner._adapter

    def slow_adapter(prepared: object) -> object:
        adapter = build_adapter(prepared)  # type: ignore[arg-type]
        send = adapter.send

        def delayed_send(request: object) -> object:
            response = send(request)
            clock.advance(2.0)
            return response

        adapter.send = delayed_send
        return adapter

    runner._adapter = slow_adapter  # type: ignore[method-assign]
    record_outcome = runner.store.record_attempt_outcome

    def record_with_processing_time(**kwargs: object) -> str | None:
        result = record_outcome(**kwargs)  # type: ignore[arg-type]
        clock.advance(0.01)
        return result

    runner.store.record_attempt_outcome = record_with_processing_time  # type: ignore[method-assign]

    assert runner.run_once(worker_id="runner-rate-window-test") is True

    with migrated_db.connect() as connection:
        state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id DESC LIMIT 1"
            ),
            {"run": authorized.run.run_id},
        ).scalar_one()
        evidence = connection.execute(
            text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run"),
            {"run": authorized.run.run_id},
        ).scalar_one()

    assert state == "complete"
    assert evidence == 9
