"""Orchestrator decisions use only verified signals and never expand authorized caps."""

from __future__ import annotations

import pytest

from agentforge.agents.orchestrator import (
    OrchestrationInputError,
    Orchestrator,
    OrchestratorHalt,
)
from agentforge.contracts import is_valid


def _snapshot(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1",
        "campaign_run_id": "run-orchestrator-1",
        "target_ref": "synthetic-copilot",
        "target_version": "1.0.0",
        "signal_provenance": "hash_verified_postgres",
        "coverage": [
            {
                "category": "prompt_injection",
                "total_case_count": 3,
                "verified_attempt_count": 3,
                "deterministic_anchor_count": 1,
            },
            {
                "category": "data_exfiltration",
                "total_case_count": 3,
                "verified_attempt_count": 1,
                "deterministic_anchor_count": 0,
            },
            {
                "category": "tool_misuse",
                "total_case_count": 3,
                "verified_attempt_count": 2,
                "deterministic_anchor_count": 1,
            },
        ],
        "findings": [],
        "regressions": [],
        "budget": {"cap_usd": 10.0, "spent_usd": 1.0},
        "queue": {"depth": 0, "backpressure_threshold": 20},
        "authorized_caps": {
            "budget_usd": 10.0,
            "rate_per_min": 30,
            "timeout_s": 300,
        },
        "low_signal_streak": 0,
        "previous_category": None,
    }
    payload.update(updates)
    return payload


def test_least_covered_unanchored_category_is_prioritized() -> None:
    decision = Orchestrator().decide(_snapshot())

    assert is_valid("campaign_directive", decision.directive)
    assert decision.directive["category"] == "data_exfiltration"
    assert decision.priority_reason == "coverage_gap"
    assert len(decision.signal_sha256) == 64


def test_open_critical_finding_overrides_ordinary_coverage_gap() -> None:
    snapshot = _snapshot(
        findings=[
            {
                "finding_id": "finding-critical-1",
                "category": "tool_misuse",
                "severity": "critical",
                "status": "documented",
                "evidence_verified": True,
            }
        ]
    )

    decision = Orchestrator().decide(snapshot)

    assert decision.directive["category"] == "tool_misuse"
    assert decision.priority_reason == "unresolved_critical_finding"


def test_failing_regression_has_highest_priority_and_emits_trigger() -> None:
    snapshot = _snapshot(
        regressions=[
            {
                "regression_id": "regression-1",
                "finding_id": "finding-1",
                "category": "prompt_injection",
                "severity": "high",
                "state": "failing",
                "evidence_verified": True,
            }
        ]
    )

    decision = Orchestrator().decide(snapshot)

    assert decision.priority_reason == "regression_reappearance"
    assert decision.directive["category"] == "prompt_injection"
    assert decision.regression_triggers == ("regression-1",)


def test_low_signal_streak_redirects_away_from_previous_category() -> None:
    decision = Orchestrator(low_signal_redirect_threshold=3).decide(
        _snapshot(low_signal_streak=3, previous_category="data_exfiltration")
    )

    assert decision.directive["category"] == "tool_misuse"
    assert decision.priority_reason == "low_signal_redirect"
    assert decision.directive["mutation_policy"] == "redirect_after_low_signal"


def test_budget_and_queue_breakers_halt_without_a_directive() -> None:
    with pytest.raises(OrchestratorHalt, match="budget_exhausted"):
        Orchestrator().decide(_snapshot(budget={"cap_usd": 10.0, "spent_usd": 10.0}))
    with pytest.raises(OrchestratorHalt, match="queue_backpressure"):
        Orchestrator().decide(_snapshot(queue={"depth": 20, "backpressure_threshold": 20}))


def test_unverified_or_internally_inconsistent_snapshot_fails_closed() -> None:
    with pytest.raises(OrchestrationInputError, match="contract"):
        Orchestrator().decide(_snapshot(signal_provenance="raw_span"))
    duplicated = _snapshot()
    duplicated["coverage"] = [
        duplicated["coverage"][0],  # type: ignore[index]
        duplicated["coverage"][0],  # type: ignore[index]
    ]
    with pytest.raises(OrchestrationInputError, match="duplicate"):
        Orchestrator().decide(duplicated)


def test_directive_caps_equal_the_authorized_snapshot_and_are_never_expanded() -> None:
    authorized = {"budget_usd": 2.5, "rate_per_min": 7, "timeout_s": 41}
    decision = Orchestrator().decide(
        _snapshot(
            budget={"cap_usd": 2.5, "spent_usd": 0.0},
            authorized_caps=authorized,
        )
    )

    assert decision.directive["caps"] == authorized
