"""Authoritative synthetic campaign through queue, Runner, Judge, and result repositories."""

from __future__ import annotations

import datetime
import time

from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.permissions import CAMPAIGN_AUTHORIZE, CAMPAIGN_LAUNCH
from agentforge.auth.principal import Principal
from agentforge.campaign.corpus import load_mvp_corpus
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.runner import DurableCampaignRunner
from agentforge.target.catalog import TrustedTargetCatalog
from agentforge.target.spec import ExecutionProfile, SafetyCaps

ORG_ID = "org_RunnerFixture"


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
        target_version="1.0.0",
        surface_id="synthetic-chat",
        surface_version="1.0.0",
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
