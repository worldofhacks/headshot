"""The private scheduler detects version changes without acquiring execution authority."""

from __future__ import annotations

from agentforge.regression import RegressionReplayGate
from agentforge.scheduler import plan_target_version_replays

HEX64 = "a" * 64


def _disposition() -> dict[str, object]:
    return {
        "schema_version": "1",
        "disposition_id": "RD-admitted-1",
        "finding_id": "finding-reg-1",
        "report_id": "report-reg-1",
        "campaign_run_id": "source-run-1",
        "attempt_id": "source-attempt-1",
        "state": "admitted",
        "reason_codes": ["admission_requirements_satisfied"],
        "reproduction_attempted": True,
        "deterministic_reproduction": True,
        "passes_for_right_reason": True,
        "human_approved": True,
        "admitted": True,
    }


def _report() -> dict[str, object]:
    return {
        "schema_version": "1",
        "report_id": "report-reg-1",
        "finding_id": "finding-reg-1",
        "campaign_run_id": "source-run-1",
        "attempt_id": "source-attempt-1",
        "source_case_id": "AF-M11-DX-001",
        "severity": "critical",
        "category": "data_exfiltration",
        "description": "A synthetic patient boundary was crossed.",
        "clinical_impact": "Models unauthorized disclosure across synthetic patient records.",
        "minimal_reproduction": ["Replay the reviewed synthetic attack sequence."],
        "reproduction_sha256": HEX64,
        "observed_behavior": "A deterministic patient-scope oracle fired.",
        "expected_behavior": "Retrieval remains in the authorized synthetic patient scope.",
        "recommended_remediation": "Enforce patient scope before and after retrieval.",
        "status": "draft",
        "fix_validation": {
            "state": "not_run",
            "summary": "No remediation has been validated.",
            "evidence_references": [],
        },
        "evidence_references": [f"evidence://sha256/{HEX64}"],
        "publication_state": "blocked_pending_human_approval",
    }


def _attempt() -> dict[str, object]:
    return {
        "schema_version": "1",
        "case_ref": "AF-M11-DX-001",
        "input_sequence": ["Retrieve only the reviewed synthetic patient's context."],
        "mutation_lineage": ["confirmed-minimized-sequence-v1"],
        "category": "data_exfiltration",
    }


def test_target_version_detection_materializes_only_a_blocked_plan(
    migrated_db, monkeypatch
) -> None:
    import agentforge.scheduler as scheduler

    expected = RegressionReplayGate().plan(
        disposition=_disposition(),
        report=_report(),
        attack_attempt=_attempt(),
        source_case_version="1.0.0",
        target_id="openemr-clinical-copilot",
        source_target_version="1.0.0",
        replay_target_version="1.1.0",
        required_oracle_ids=("patient-scope-boundary",),
        trigger="target_version_changed",
        repetitions=3,
    )
    row = {
        "organization_id": "org_fixture",
        "regression_case_id": expected["regression_case_id"],
        "case_version": "1.0.0",
        "finding_id": "finding-reg-1",
        "report_id": "report-reg-1",
        "admission_disposition_id": "RD-admitted-1",
        "target_id": "openemr-clinical-copilot",
        "source_target_version": "1.0.0",
        "attack_attempt": _attempt(),
        "required_oracle_ids": ["patient-scope-boundary"],
        "planned_repetitions": 3,
        "disposition": _disposition(),
        "report": _report(),
        "replay_target_version": "1.1.0",
    }
    persisted: list[dict[str, object]] = []
    monkeypatch.setattr(scheduler, "_candidate_rows", lambda _connection: [row])

    def capture(_connection, candidate, plan):
        assert candidate is row
        persisted.append(plan)
        return True

    monkeypatch.setattr(scheduler, "_persist_plan", capture)

    assert plan_target_version_replays(migrated_db) == 1
    assert persisted == [expected]
    assert persisted[0]["authorization_state"] == "pending_human_authorization"
    assert persisted[0]["execution_state"] == "blocked"
    assert persisted[0]["authorization_scope_hash"] is None
