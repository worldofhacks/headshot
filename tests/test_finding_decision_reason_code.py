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
from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend
from agentforge.api.router import FindingDecisionInput
from agentforge.auth.permissions import FINDINGS_APPROVE
from agentforge.auth.principal import Principal
from agentforge.policy.recorder import ExecutionRecorder

ORG_ID = "org_ReasonCodeFixture"
APPROVER_ID = "user_ReasonApprover"


def _approver() -> Principal:
    return Principal(
        user_id=APPROVER_ID,
        session_id="sess_ReasonApprover",
        organization_id=ORG_ID,
        organization_role="org:approver",
        organization_permissions=frozenset((FINDINGS_APPROVE,)),
    )


def _seed_confirmed_finding(engine: Engine) -> str:
    """Insert an oracle/canary-confirmed finding with linked, integrity-verified evidence."""
    finding_id = f"finding-{uuid.uuid4().hex}"
    campaign_run_id = uuid.uuid4().hex
    attempt_id = uuid.uuid4().hex
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
        "organization_id": ORG_ID,
        "surface_id": "synthetic-surface",
        "surface_version": "1.0.0",
        "authorization_scope_hash": "a" * 64,
        "execution_profile": "synthetic",
        "evidence_provenance": "synthetic_offline",
    }
    recorder = ExecutionRecorder()
    with engine.begin() as connection:
        stored = recorder.record(evidence_fields, connection)
        verdict_id = connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "reason_codes, confirmation_source) VALUES "
                "('EXPLOIT_CONFIRMED', 1.0, :run, :attempt, :org, "
                "CAST('[\"trusted_canary_hit\"]' AS jsonb), 'trusted_canary') RETURNING id"
            ),
            {"run": campaign_run_id, "attempt": attempt_id, "org": ORG_ID},
        ).scalar_one()
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
        connection.execute(
            text(
                "INSERT INTO finding_evidence_links "
                "(organization_id, finding_id, campaign_run_id, attempt_id, "
                "evidence_content_hash, verdict_id, provenance) VALUES "
                "(:org, :finding, :run, :attempt, :evidence_hash, :verdict_id, "
                "'synthetic_offline')"
            ),
            {
                "org": ORG_ID,
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


def test_finding_decision_input_rejects_malformed_reason_code() -> None:
    with pytest.raises(ValidationError):
        FindingDecisionInput(
            decision="rejected",
            rationale="Not reproducible.",
            reason_code="Not A Valid Code!",
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
        stored = connection.execute(
            text("SELECT reason_code FROM finding_decision_events WHERE finding_id = :finding"),
            {"finding": finding_id},
        ).scalar_one()
    assert stored == "not_a_real_exploit"
