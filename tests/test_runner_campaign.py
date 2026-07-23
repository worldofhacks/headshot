"""Authoritative synthetic campaign through queue, Runner, Judge, and result repositories."""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import time
from types import SimpleNamespace
from typing import NamedTuple

import pytest
from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.permissions import CAMPAIGN_AUTHORIZE, CAMPAIGN_LAUNCH
from agentforge.auth.principal import Principal
from agentforge.campaign.coordinator import CampaignAbort
from agentforge.campaign.corpus import load_full_scan_corpus, load_mvp_corpus
from agentforge.contracts import is_valid
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy.scoped_credentials import (
    CredentialResolutionError,
    SealedEnvironmentCredentialResolver,
    SessionLeaseMetadata,
)
from agentforge.runner import (
    DispatchUnavailable,
    DurableCampaignRunner,
    PreflightReport,
    _campaign_session_required_until,
)
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
                "TRUNCATE TABLE agent_executions, agent_configuration_versions, "
                "regression_dispositions, vuln_reports, "
                "campaign_run_summaries, finding_evidence_links, "
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

    entry, surface = catalog.resolve(target_id="synthetic-copilot", surface_id="synthetic-chat")

    assert entry.target.version == "1.1.0"
    assert entry.target.safety_caps.max_attempts_per_run == 14
    assert surface.version == "1.1.0"
    assert surface.target_version == entry.target.version


def test_session_window_is_bounded_by_authorization_and_run_timeout() -> None:
    started = datetime.datetime(2026, 7, 22, 18, 0, tzinfo=datetime.UTC)
    scope = SimpleNamespace(caps=SimpleNamespace(run_timeout_seconds=300.0))

    authorization_first = SimpleNamespace(
        scope=scope,
        expires_at=started + datetime.timedelta(seconds=120),
    )
    timeout_first = SimpleNamespace(
        scope=scope,
        expires_at=started + datetime.timedelta(seconds=900),
    )

    assert _campaign_session_required_until(
        authorization_first,
        now=started.timestamp(),
    ) == started + datetime.timedelta(seconds=120)
    assert _campaign_session_required_until(
        timeout_first,
        now=started.timestamp(),
    ) == started + datetime.timedelta(seconds=300)
    with pytest.raises(DispatchUnavailable, match="campaign_session_window_invalid"):
        _campaign_session_required_until(
            SimpleNamespace(scope=scope, expires_at=started),
            now=started.timestamp(),
        )


def test_runner_pins_and_releases_session_resources_on_campaign_abort() -> None:
    reference = "secretref://staging/openemr/session/generation-test"
    session_value = "synthetic-runner-session-0001"
    environment = {"OPENEMR_TEST_SESSION": session_value}
    started = datetime.datetime(2026, 7, 22, 18, 0, tzinfo=datetime.UTC)
    credentials = SealedEnvironmentCredentialResolver(
        {reference: "OPENEMR_TEST_SESSION"},
        environment=environment,
        session_metadata={
            reference: SessionLeaseMetadata(
                generation="generation-test",
                expires_at=started + datetime.timedelta(minutes=10),
                value_sha256=hashlib.sha256(session_value.encode()).hexdigest(),
            )
        },
    )
    prepared = SimpleNamespace(
        authorized=SimpleNamespace(
            scope=SimpleNamespace(
                credential_ref=reference,
                execution_profile=ExecutionProfile.LIVE,
                auth_mode=AuthMode.SESSION,
                caps=SimpleNamespace(run_timeout_seconds=300.0),
            ),
            expires_at=started + datetime.timedelta(minutes=8),
        )
    )

    class ClosableAdapter:
        def __init__(self) -> None:
            self.credential = None
            self.closed = False

        def close(self) -> None:
            self.credential = None
            self.closed = True

    adapter = ClosableAdapter()
    captured: list[object] = []
    runner = object.__new__(DurableCampaignRunner)
    runner.clock = SimpleNamespace(now=started.timestamp)
    runner.credentials = credentials
    runner.preflight = lambda _job: (PreflightReport(()), prepared)
    runner._adapter = lambda _prepared: adapter

    def fail_after_resolution(_job: object, _prepared: object, lease: object):
        live_adapter = runner._adapter(_prepared)
        runner._campaign_adapter = live_adapter
        first = lease.resolve(reference)
        environment["OPENEMR_TEST_SESSION"] = "synthetic-rotated-session"
        second = lease.resolve(reference)
        assert first is second
        live_adapter.credential = first
        captured.append(lease)
        raise CampaignAbort("synthetic abort", code="synthetic-abort")

    runner._execute_prepared = fail_after_resolution

    with pytest.raises(CampaignAbort, match="synthetic abort"):
        runner.execute_claimed(SimpleNamespace())

    lease = captured[0]
    assert lease.resolution_count == 1
    with pytest.raises(CredentialResolutionError, match="released"):
        lease.resolve(reference)
    assert adapter.closed is True
    assert adapter.credential is None


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
    full_scan: bool = False,
) -> _AuthorizedSyntheticRun:
    """Drive the full two-person control-plane handshake and enqueue one dispatchable job.

    This is the exact harness the happy-path test uses; the negative tests reuse it and
    then perturb a single precondition so the Runner refuses at network-free preflight.
    """

    _clean(engine)
    launcher = _principal("user_RunnerLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_RunnerApprover", CAMPAIGN_AUTHORIZE)
    corpus = load_full_scan_corpus() if full_scan else load_mvp_corpus()
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
            max_attempts_per_run=len(corpus.cases),
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


def test_directive_resolution_never_expands_a_sub_one_per_minute_rate_cap(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(
        migrated_db,
        target_requests_per_second=0.01,
    )
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    adapter_calls = _no_adapter_guard(runner)

    with pytest.raises(DispatchUnavailable, match="campaign_execution_failed"):
        runner.run_once(worker_id="runner-test")

    assert adapter_calls == []
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run"),
                {"run": authorized.run.run_id},
            ).scalar_one()
            == 0
        )


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
        attack_attempts = (
            connection.execute(
                text(
                    "SELECT ar.attack_attempt FROM campaign_attempts ca "
                    "JOIN attempt_result ar ON ar.organization_id = ca.organization_id "
                    "AND ar.campaign_run_id = ca.run_id AND ar.attempt_id = ca.attempt_id "
                    "WHERE ca.run_id = :run ORDER BY ca.ordinal"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
        verdicts = connection.execute(
            text("SELECT count(*) FROM verdict WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        findings = connection.execute(
            text("SELECT count(*) FROM finding_evidence_links WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        reports = (
            connection.execute(
                text(
                    "SELECT contract_payload FROM vuln_reports "
                    "WHERE campaign_run_id = :run ORDER BY report_id"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
        regression_dispositions = (
            connection.execute(
                text(
                    "SELECT contract_payload FROM regression_dispositions "
                    "WHERE campaign_run_id = :run ORDER BY disposition_id"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
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
        orchestration = connection.execute(
            text(
                "SELECT payload FROM audit_events WHERE organization_id = :org "
                "AND aggregate_id = :run AND event_type = 'campaign.orchestrated'"
            ),
            {"org": ORG_ID, "run": run.run_id},
        ).scalar_one()
        agent_executions = {
            row["agent_role"]: dict(row)
            for row in connection.execute(
                text(
                    "SELECT agent_role, count(*) AS executions, "
                    "count(*) FILTER (WHERE status = 'running') AS running, "
                    "count(*) FILTER (WHERE parent_execution_id IS NOT NULL) AS linked, "
                    "sum(measured_cost) AS measured_cost FROM agent_executions "
                    "WHERE campaign_run_id = :run GROUP BY agent_role"
                ),
                {"run": run.run_id},
            ).mappings()
        }

    assert state == "complete"
    assert evidence == verdicts == 9
    assert len(attack_attempts) == 9
    assert all(is_valid("attack_attempt", dict(attempt)) for attempt in attack_attempts)
    assert attack_attempts[0]["category"] == orchestration["directive"]["category"]
    assert findings == 2
    assert len(reports) == len(regression_dispositions) == findings
    assert all(is_valid("vuln_report", dict(report)) for report in reports)
    assert all(
        is_valid("regression_disposition", dict(disposition))
        for disposition in regression_dispositions
    )
    assert all(
        disposition["state"] == "pending_deterministic_reproduction"
        and disposition["admitted"] is False
        for disposition in regression_dispositions
    )
    assert summary["attempt_count"] == summary["request_count"] == 9
    assert summary["execution_profile"] == "synthetic"
    assert summary["provenance"] == "synthetic_offline"
    assert job_status == "completed"
    assert is_valid("campaign_directive", orchestration["directive"])
    assert len(orchestration["signal_sha256"]) == 64
    assert agent_executions["orchestrator"]["executions"] == 9
    assert agent_executions["red_team"]["executions"] == 9
    assert agent_executions["judge"]["executions"] == 9
    assert agent_executions["documentation"]["executions"] == findings
    assert all(row["running"] == 0 for row in agent_executions.values())
    assert agent_executions["judge"]["linked"] == 9
    assert all(float(row["measured_cost"]) == 0.0 for row in agent_executions.values())

    backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        corpus=corpus,
    )
    findings_projection = backend.read("findings", launcher)
    coverage_projection = backend.read("coverage", launcher)
    agents_projection = backend.read("agents", launcher)
    activity_projection = backend.read("agent_activity", launcher)
    traces_projection = backend.read("traces", launcher)
    costs_projection = backend.read("costs", launcher)
    events = backend.events(launcher, after_cursor=0, limit=100)
    assert findings_projection.state == "ready"
    assert len(findings_projection.data) == 2
    assert all(item["state"] == "documented" for item in findings_projection.data)
    assert all(
        item["publication_status"] == "blocked_pending_human_approval"
        for item in findings_projection.data
    )
    assert coverage_projection.state == "ready"
    assert coverage_projection.data[0]["covered"] is True
    assert coverage_projection.data[0]["verified_attempt_count"] == 9
    assert agents_projection.state == activity_projection.state == "ready"
    assert sum(row["execution_count"] for row in agents_projection.data) == 29
    assert len(activity_projection.data) == 29
    assert any(row["operation"] == "agent.judge" for row in traces_projection.data)
    assert any(row["provider"].startswith("agent:orchestrator:") for row in costs_projection.data)
    assert any(event["type"] == "campaign.complete" for event in events.events)


def test_full_scan_executes_all_reviewed_tool_candidates_with_lineage(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(migrated_db, full_scan=True)
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

    assert runner.run_once(worker_id="runner-full-scan-test") is True

    with migrated_db.connect() as connection:
        attempts = (
            connection.execute(
                text(
                    "SELECT source_tool, count(*) AS executions FROM campaign_attempts "
                    "WHERE run_id = :run GROUP BY source_tool ORDER BY source_tool"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )
        agents = (
            connection.execute(
                text(
                    "SELECT agent_role, count(*) AS executions FROM agent_executions "
                    "WHERE campaign_run_id = :run GROUP BY agent_role"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )

    counts = {row["source_tool"]: row["executions"] for row in attempts}
    assert sum(counts.values()) == 14
    assert counts == {None: 9, "garak": 1, "promptfoo": 1, "pyrit": 3}
    agent_counts = {row["agent_role"]: row["executions"] for row in agents}
    assert agent_counts["orchestrator"] == 14
    assert agent_counts["red_team"] == 14
    assert agent_counts["judge"] == 14

    tooling = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        corpus=authorized.corpus,
    ).read("tooling", authorized.launcher)
    tool_rows = {row["tool_id"]: row for row in tooling.data}
    assert tool_rows["garak"]["executed_attempt_count"] == 1
    assert tool_rows["promptfoo"]["executed_attempt_count"] == 1
    assert tool_rows["pyrit"]["executed_attempt_count"] == 3


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
