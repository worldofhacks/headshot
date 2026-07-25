"""A finding approve/reject decision may carry a structured ``reason_code``.

The store (``record_finding_decision``) and the persisted ``FindingDecisionRecord`` already
support ``reason_code``; the gap is at the API boundary — ``FindingDecisionInput`` rejected the
field (strict model) and the command dispatcher never forwarded it. These tests pin the full
HTTP-body -> dispatcher -> store path so an approver can attach a structured reason to a decision.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine, event, text

from agentforge.api.backend import ApiConflict
from agentforge.api.postgres import PostgresApiBackend, _finding_histories
from agentforge.api.router import FindingDecisionInput
from agentforge.auth.permissions import FINDINGS_APPROVE
from agentforge.auth.principal import Principal
from agentforge.control_plane import AuthorizationDeniedError, ControlPlaneStore
from agentforge.policy.recorder import ExecutionRecorder

ORG_ID = "org_ReasonCodeFixture"
APPROVER_ID = "user_ReasonApprover"


def _approver(
    *,
    organization_id: str = ORG_ID,
    user_id: str = APPROVER_ID,
) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=organization_id,
        organization_role="org:approver",
        organization_permissions=frozenset((FINDINGS_APPROVE,)),
    )


def _seed_confirmed_finding(
    engine: Engine,
    *,
    organization_id: str = ORG_ID,
    launcher_user_id: str = "user_ReasonLauncher",
) -> str:
    """Insert an oracle/canary-confirmed finding with linked, integrity-verified evidence."""
    finding_id = f"finding-{uuid.uuid4().hex}"
    campaign_run_id = uuid.uuid4().hex
    attempt_id = uuid.uuid4().hex
    authorization_request_id = f"request-{uuid.uuid4().hex}"
    authorization_decision_id = f"decision-{uuid.uuid4().hex}"
    launcher_session_id = "sess_ReasonLauncher"
    evidence_fields = {
        "schema_version": "1",
        "campaign_run_id": campaign_run_id,
        "attempt_id": attempt_id,
        "campaign_id": "synthetic-fixture",
        "target_id": "synthetic-target",
        "target_version": "1.0.0",
        "attack_attempt": {"case_ref": "synthetic-case"},
        "request_transcript": {"request": ["synthetic input"]},
        "response_transcript": "synthetic canary response",
        "policy_decision_id": "fixture-policy-decision",
        "executed_at": "2026-07-21T12:00:00+00:00",
        "trace_id": None,
        "correlation_id": campaign_run_id,
        "recorder_identity": "recorder@1",
        "recorder_version": "1",
        "organization_id": organization_id,
        "surface_id": "synthetic-surface",
        "surface_version": "1.0.0",
        "authorization_scope_hash": "a" * 64,
        "execution_profile": "synthetic",
        "evidence_provenance": "synthetic_offline",
    }
    recorder = ExecutionRecorder()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request, :org, :scope_hash, '{}'::jsonb, :user, :session, "
                "clock_timestamp() + INTERVAL '10 minutes')"
            ),
            {
                "request": authorization_request_id,
                "org": organization_id,
                "scope_hash": "a" * 64,
                "user": launcher_user_id,
                "session": launcher_session_id,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "(:decision_id, :org, :request, :scope_hash, 'approved', "
                "'user_ReasonSeedApprover', 'sess_ReasonSeedApprover')"
            ),
            {
                "decision_id": authorization_decision_id,
                "org": organization_id,
                "request": authorization_request_id,
                "scope_hash": "a" * 64,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run, :org, :request, :scope_hash, :user, :session)"
            ),
            {
                "run": campaign_run_id,
                "org": organization_id,
                "request": authorization_request_id,
                "scope_hash": "a" * 64,
                "user": launcher_user_id,
                "session": launcher_session_id,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id, case_content_hash, "
                "category, severity, attack_class, owasp_mappings, fixture_provenance) VALUES "
                "(:org, :run, :attempt, 0, :case_id, :case_hash, 'access-control', 'high', "
                "'boundary', CAST(:mappings AS jsonb), CAST(:fixture AS jsonb))"
            ),
            {
                "org": organization_id,
                "run": campaign_run_id,
                "attempt": attempt_id,
                "case_id": f"case-{attempt_id}",
                "case_hash": "c" * 64,
                "mappings": (
                    '[{"framework":"OWASP Web","version":"2021",'
                    '"id":"A01","name":"Broken Access Control"}]'
                ),
                "fixture": '{"classification":"synthetic","contains_real_phi":false}',
            },
        )
        stored = recorder.record(evidence_fields, connection)
        verdict_id = connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "reason_codes, confirmation_source) VALUES "
                "('EXPLOIT_CONFIRMED', 1.0, :run, :attempt, :org, "
                "CAST('[\"canary_hit\"]' AS jsonb), 'canary') RETURNING id"
            ),
            {"run": campaign_run_id, "attempt": attempt_id, "org": organization_id},
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO finding "
                "(finding_id, organization_id, state, severity, category, target_version, "
                "source_kind, execution_profile) VALUES "
                "(:finding, :org, 'candidate', 'high', 'access-control', '1.0.0', "
                "'campaign', 'synthetic')"
            ),
            {"finding": finding_id, "org": organization_id},
        )
        connection.execute(
            text(
                "INSERT INTO finding_evidence_links "
                "(organization_id, finding_id, campaign_run_id, attempt_id, "
                "evidence_content_hash, verdict_id, provenance) VALUES "
                "(:org, :finding, :run, :attempt, :evidence_hash, :verdict_id, "
                "'synthetic_offline')"
            ),
            {
                "org": organization_id,
                "finding": finding_id,
                "run": campaign_run_id,
                "attempt": attempt_id,
                "evidence_hash": stored.content_hash,
                "verdict_id": verdict_id,
            },
        )
    return finding_id


def test_finding_decision_input_accepts_structured_reason_code() -> None:
    model = FindingDecisionInput(
        decision="rejected",
        rationale="Judge basis did not reproduce against the synthetic fixture.",
        reason_code="not_a_real_exploit",
    )
    assert model.reason_code == "not_a_real_exploit"


def test_finding_decision_input_accepts_approval_code() -> None:
    model = FindingDecisionInput(
        decision="approved",
        rationale="The durable verification chain was reviewed by the human approver.",
        reason_code="human_confirmed",
    )
    assert model.reason_code == "human_confirmed"


@pytest.mark.parametrize(
    ("decision", "reason_code"),
    (
        ("rejected", "Not A Valid Code!"),
        ("rejected", "human_confirmed"),
        ("approved", "not_a_real_exploit"),
    ),
)
def test_finding_decision_input_rejects_unknown_or_incompatible_reason_code(
    decision: str,
    reason_code: str,
) -> None:
    with pytest.raises(ValidationError):
        FindingDecisionInput(
            decision=decision,
            rationale="Not reproducible.",
            reason_code=reason_code,
        )


def test_finding_decision_input_requires_reason_code() -> None:
    with pytest.raises(ValidationError):
        FindingDecisionInput(
            decision="rejected",
            rationale="Not reproducible.",
        )


def test_finding_approval_denies_submitter_self_approval(migrated_db: Engine) -> None:
    finding_id = _seed_confirmed_finding(
        migrated_db,
        launcher_user_id=APPROVER_ID,
    )
    store = ControlPlaneStore(migrated_db, environment="staging")

    with pytest.raises(
        AuthorizationDeniedError,
        match="submitter cannot approve own finding",
    ):
        store.record_finding_decision(
            principal=_approver(),
            finding_id=finding_id,
            decision="approved",
            rationale="The submitter must not approve this finding.",
            reason_code="human_confirmed",
            idempotency_key="finding-self-approval-denied",
        )


def test_finding_approval_accepts_distinct_approver(migrated_db: Engine) -> None:
    finding_id = _seed_confirmed_finding(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")

    decision = store.record_finding_decision(
        principal=_approver(),
        finding_id=finding_id,
        decision="approved",
        rationale="A distinct human approver verified the retained evidence.",
        reason_code="human_confirmed",
        idempotency_key="finding-distinct-approval-succeeds",
    )

    assert decision.finding_id == finding_id
    assert decision.actor_user_id == APPROVER_ID
    assert decision.decision == "approved"


def test_finding_approval_rejects_missing_submitter_lineage(migrated_db: Engine) -> None:
    finding_id = f"finding-{uuid.uuid4().hex}"
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO finding "
                "(finding_id, organization_id, state, severity, category, target_version, "
                "source_kind, execution_profile) VALUES "
                "(:finding, :org, 'candidate', 'high', 'access-control', '1.0.0', "
                "'campaign', 'synthetic')"
            ),
            {"finding": finding_id, "org": ORG_ID},
        )
    store = ControlPlaneStore(migrated_db, environment="staging")

    with pytest.raises(
        AuthorizationDeniedError,
        match="approval lineage is unavailable",
    ):
        store.record_finding_decision(
            principal=_approver(),
            finding_id=finding_id,
            decision="approved",
            rationale="This must fail closed without immutable submitter lineage.",
            reason_code="human_confirmed",
            idempotency_key="finding-missing-lineage-denied",
        )


def test_backend_rejects_decision_incompatible_reason_code(migrated_db: Engine) -> None:
    finding_id = _seed_confirmed_finding(migrated_db)
    backend = PostgresApiBackend(migrated_db, environment="staging")

    with pytest.raises(ApiConflict):
        backend.command(
            "decide_finding",
            _approver(),
            {
                "decision": "approved",
                "rationale": "This approval cannot carry a rejection code.",
                "reason_code": "not_a_real_exploit",
            },
            idempotency_key="reason-code-mismatch-1",
            identifiers={"finding_id": finding_id},
        )


def test_decide_finding_command_forwards_reason_code(migrated_db: Engine) -> None:
    finding_id = _seed_confirmed_finding(migrated_db)
    backend = PostgresApiBackend(migrated_db, environment="staging")

    result = backend.command(
        "decide_finding",
        _approver(),
        {
            "decision": "rejected",
            "rationale": "Reproduction failed; oracle did not fire on re-run.",
            "reason_code": "not_a_real_exploit",
        },
        idempotency_key="reason-code-forward-1",
        identifiers={"finding_id": finding_id},
    )

    assert result.status == "completed"
    with migrated_db.connect() as connection:
        stored = (
            connection.execute(
                text(
                    "SELECT rationale, reason_code FROM finding_decision_events "
                    "WHERE finding_id = :finding"
                ),
                {"finding": finding_id},
            )
            .mappings()
            .one()
        )
    assert stored["rationale"] == "Reproduction failed; oracle did not fire on re-run."
    assert stored["reason_code"] == "not_a_real_exploit"


def test_finding_histories_are_batchable_bounded_and_include_reason_code(
    migrated_db: Engine,
) -> None:
    finding_id = _seed_confirmed_finding(migrated_db)
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO finding_decision_events "
                "(decision_id, organization_id, finding_id, decision, actor_user_id, "
                "actor_session_id, rationale, reason_code, created_at) "
                "SELECT 'historical-' || n, :org, :finding, 'rejected', :actor, :session, "
                "'historical rationale ' || n, 'not_a_real_exploit', "
                "TIMESTAMPTZ '2000-01-01T00:00:00Z' + n * INTERVAL '1 second' "
                "FROM generate_series(1, 55) AS n"
            ),
            {
                "org": ORG_ID,
                "finding": finding_id,
                "actor": APPROVER_ID,
                "session": "sess_ReasonApprover",
            },
        )
    with migrated_db.connect() as connection:
        histories = _finding_histories(
            connection,
            organization_id=ORG_ID,
            finding_ids={finding_id},
        )

    history = histories[finding_id]
    assert len(history) == 50
    assert history[0]["rationale"] == "historical rationale 6"
    assert history[-1]["rationale"] == "historical rationale 55"
    assert all(event["reason_code"] == "not_a_real_exploit" for event in history)


def test_findings_api_batches_multiple_histories_and_keeps_tenants_isolated(
    migrated_db: Engine,
) -> None:
    organization_a = "org_ReasonBatchA"
    organization_b = "org_ReasonBatchB"
    approver_a = _approver(
        organization_id=organization_a,
        user_id="user_ReasonBatchApproverA",
    )
    approver_b = _approver(
        organization_id=organization_b,
        user_id="user_ReasonBatchApproverB",
    )
    finding_a1 = _seed_confirmed_finding(
        migrated_db,
        organization_id=organization_a,
    )
    finding_a2 = _seed_confirmed_finding(
        migrated_db,
        organization_id=organization_a,
    )
    finding_b1 = _seed_confirmed_finding(
        migrated_db,
        organization_id=organization_b,
    )
    backend = PostgresApiBackend(migrated_db, environment="staging")
    backend.command(
        "decide_finding",
        approver_a,
        {
            "decision": "approved",
            "rationale": "Organization A reviewed and confirmed the first finding.",
            "reason_code": "human_confirmed",
        },
        idempotency_key="reason-batch-a1-approve",
        identifiers={"finding_id": finding_a1},
    )
    backend.command(
        "decide_finding",
        approver_a,
        {
            "decision": "rejected",
            "rationale": "Organization A found the second record insufficient.",
            "reason_code": "insufficient_evidence",
        },
        idempotency_key="reason-batch-a2-reject",
        identifiers={"finding_id": finding_a2},
    )
    backend.command(
        "decide_finding",
        approver_b,
        {
            "decision": "rejected",
            "rationale": "Organization B determined its finding was not an exploit.",
            "reason_code": "not_a_real_exploit",
        },
        idempotency_key="reason-batch-b1-reject",
        identifiers={"finding_id": finding_b1},
    )

    history_queries: list[str] = []

    def capture_history_query(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(str(statement).lower().split())
        if "from finding_decision_events" in normalized:
            history_queries.append(normalized)

    event.listen(migrated_db, "before_cursor_execute", capture_history_query)
    try:
        organization_a_result = backend.read("findings", approver_a)
    finally:
        event.remove(migrated_db, "before_cursor_execute", capture_history_query)
    organization_b_result = backend.read("findings", approver_b)

    assert len(history_queries) == 1
    assert organization_a_result.state == organization_b_result.state == "ready", (
        organization_a_result.reason_code,
        organization_b_result.reason_code,
    )
    organization_a_findings = {
        finding["finding_id"]: finding for finding in organization_a_result.data
    }
    organization_b_findings = {
        finding["finding_id"]: finding for finding in organization_b_result.data
    }
    assert set(organization_a_findings) == {finding_a1, finding_a2}
    assert set(organization_b_findings) == {finding_b1}
    assert finding_b1 not in organization_a_findings
    assert finding_a1 not in organization_b_findings
    assert organization_a_findings[finding_a1]["history"][0]["reason_code"] == ("human_confirmed")
    assert organization_a_findings[finding_a2]["history"][0]["reason_code"] == (
        "insufficient_evidence"
    )
    assert organization_b_findings[finding_b1]["history"][0]["reason_code"] == (
        "not_a_real_exploit"
    )
