"""Confirmed findings cannot skip reproduction, approval, replay, or alert lineage."""

from __future__ import annotations

import copy

import pytest

from agentforge.agents.orchestrator import Orchestrator
from agentforge.regression import (
    RegressionAdmissionGate,
    RegressionLifecycle,
    RegressionLifecycleError,
    RegressionReplayGate,
    ReplayObservation,
)

HEX64 = "a" * 64


def _verdict() -> dict[str, object]:
    return {
        "schema_version": "1",
        "campaign_run_id": "source-run-1",
        "attempt_id": "source-attempt-1",
        "state": "EXPLOIT_CONFIRMED",
        "confidence": 1.0,
        "reason_codes": ["oracle_confirmed"],
        "confirmation_source": "oracle",
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
        "confirmation_status": "confirmed",
        "description": "A synthetic authorization boundary was crossed.",
        "clinical_impact": "Models an unauthorized synthetic-record disclosure.",
        "minimal_reproduction": ["Replay the reviewed synthetic sequence."],
        "reproduction_sha256": HEX64,
        "observed_behavior": "A deterministic scope oracle fired.",
        "expected_behavior": "Retrieval remains in the authorized synthetic scope.",
        "recommended_remediation": "Enforce scope before and after retrieval.",
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
        "input_sequence": ["Replay the reviewed synthetic boundary case."],
        "mutation_lineage": ["confirmed-minimized-sequence-v1"],
        "category": "data_exfiltration",
    }


def _observation(run_id: str, index: int, *, hit: bool) -> ReplayObservation:
    attempt_id = f"{run_id}-attempt-{index}"
    state = "EXPLOIT_CONFIRMED" if hit else "INDETERMINATE"
    verdict: dict[str, object] = {
        "schema_version": "1",
        "campaign_run_id": run_id,
        "attempt_id": attempt_id,
        "state": state,
        "confidence": 1.0 if hit else 0.0,
        "reason_codes": ["oracle_confirmed" if hit else "non_oracle_uncalibrated_indeterminate"],
    }
    if hit:
        verdict["confirmation_source"] = "oracle"
    return ReplayObservation(
        envelope={
            "schema_version": "1",
            "campaign_run_id": run_id,
            "attempt_id": attempt_id,
            "trusted": {
                "oracle_results": [
                    {
                        "id": "recorder-retrieval-scope-v1",
                        "provenance": "code",
                        "hit": hit,
                    }
                ],
                "canary_hits": [],
                "policy_decision": "authorized-regression-observation",
            },
            "hostile": {"trust": "hostile", "transcript": "synthetic observation"},
        },
        verdict=verdict,
        evidence_reference=f"evidence://sha256/{index:064x}",
    )


def _pending() -> dict[str, object]:
    return RegressionAdmissionGate().evaluate(
        verdict=_verdict(),
        finding_id="finding-reg-1",
        report_id="report-reg-1",
        reproduction_attempted=False,
        deterministic_reproduction=False,
        passes_for_right_reason=False,
        human_approved=False,
    )


def test_full_lifecycle_requires_reproduction_then_approval_and_emits_alert() -> None:
    lifecycle = RegressionLifecycle()
    reproduction_plan = lifecycle.plan_reproduction(
        pending_disposition=_pending(),
        report=_report(),
        attack_attempt=_attempt(),
        source_case_version="1.0.0",
        target_id="openemr-clinical-copilot",
        target_version="1.0.0",
        required_oracle_ids=("recorder-retrieval-scope-v1",),
        repetitions=2,
    )
    assert reproduction_plan["trigger"] == "deterministic_reproduction"
    assert reproduction_plan["execution_state"] == "blocked"
    assert reproduction_plan["authorization_state"] == "pending_human_authorization"

    reproduced = lifecycle.evaluate_reproduction(
        plan=reproduction_plan,
        campaign_run_id="authorized-reproduction-run",
        authorization_scope_hash="b" * 64,
        observations=tuple(
            _observation("authorized-reproduction-run", index, hit=True) for index in range(1, 3)
        ),
    )
    blocked = lifecycle.admission_after_reproduction(
        source_verdict=_verdict(),
        pending_disposition=_pending(),
        report=_report(),
        reproduction_plan=reproduction_plan,
        reproduction_result=reproduced,
        human_approval_verified=False,
    )
    assert blocked["state"] == "blocked_pending_human_approval"
    assert blocked["admitted"] is False

    admitted = lifecycle.admission_after_reproduction(
        source_verdict=_verdict(),
        pending_disposition=_pending(),
        report=_report(),
        reproduction_plan=reproduction_plan,
        reproduction_result=reproduced,
        human_approval_verified=True,
    )
    assert admitted["state"] == "admitted"
    assert admitted["admitted"] is True

    replay_plan = RegressionReplayGate().plan(
        disposition=admitted,
        report=_report(),
        attack_attempt=_attempt(),
        source_case_version="1.0.0",
        target_id="openemr-clinical-copilot",
        source_target_version="1.0.0",
        replay_target_version="1.1.0",
        required_oracle_ids=("recorder-retrieval-scope-v1",),
        trigger="target_version_changed",
        repetitions=2,
    )
    replay_result = RegressionReplayGate().evaluate(
        plan=replay_plan,
        campaign_run_id="authorized-replay-run",
        authorization_scope_hash="c" * 64,
        observations=tuple(
            _observation("authorized-replay-run", index, hit=True) for index in range(3, 5)
        ),
    )
    signal = lifecycle.reappearance_signal(
        report=_report(),
        replay_plan=replay_plan,
        replay_result=replay_result,
    )

    assert signal is not None
    assert signal["state"] == "regressed"
    decision = Orchestrator().decide(
        {
            "schema_version": "1",
            "campaign_run_id": "next-run",
            "target_ref": "openemr-clinical-copilot",
            "target_version": "1.1.0",
            "signal_provenance": "hash_verified_postgres",
            "coverage": [
                {
                    "category": "data_exfiltration",
                    "total_case_count": 1,
                    "verified_attempt_count": 1,
                    "deterministic_anchor_count": 1,
                }
            ],
            "findings": [],
            "regressions": [signal],
            "budget": {"cap_usd": 1.0, "spent_usd": 0.0},
            "queue": {"depth": 0, "backpressure_threshold": 2},
            "authorized_caps": {
                "budget_usd": 1.0,
                "rate_per_min": 1,
                "timeout_s": 30,
            },
            "low_signal_streak": 0,
            "previous_category": None,
        }
    )
    assert decision.priority_reason == "regression_reappearance"
    assert decision.regression_triggers == (replay_plan["regression_case_id"],)


def test_admission_rejects_a_reproduction_result_with_different_lineage() -> None:
    lifecycle = RegressionLifecycle()
    plan = lifecycle.plan_reproduction(
        pending_disposition=_pending(),
        report=_report(),
        attack_attempt=_attempt(),
        source_case_version="1.0.0",
        target_id="openemr-clinical-copilot",
        target_version="1.0.0",
        required_oracle_ids=("recorder-retrieval-scope-v1",),
        repetitions=2,
    )
    result = lifecycle.evaluate_reproduction(
        plan=plan,
        campaign_run_id="authorized-reproduction-run",
        authorization_scope_hash="b" * 64,
        observations=tuple(
            _observation("authorized-reproduction-run", index, hit=True) for index in range(1, 3)
        ),
    )
    forged = copy.deepcopy(result)
    forged["replay_id"] = "RR-" + "f" * 64

    with pytest.raises(RegressionLifecycleError, match="differs"):
        lifecycle.admission_after_reproduction(
            source_verdict=_verdict(),
            pending_disposition=_pending(),
            report=_report(),
            reproduction_plan=plan,
            reproduction_result=forged,
            human_approval_verified=True,
        )
