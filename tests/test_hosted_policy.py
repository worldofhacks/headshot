"""Closed-registry tests for authorization-bound hosted generation policy."""

from __future__ import annotations

import pytest

from agentforge.agents.hosted_policy import (
    DEFAULT_HOSTED_GENERATION_POLICY,
    HostedGenerationPolicyError,
    resolve_hosted_generation_policy,
)


def test_registered_policy_round_trips_exact_bounds_and_role_triggers() -> None:
    policy = resolve_hosted_generation_policy(DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256)

    assert policy is DEFAULT_HOSTED_GENERATION_POLICY
    assert set(policy.call_bounds) == {
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    }
    assert [item.invocation_trigger for item in policy.roles] == [
        "each_selection_cycle",
        "each_generation_cycle",
        "each_evaluated_case",
        "each_confirmed_finding",
    ]


def test_policy_reserves_one_planner_generator_and_evaluator_call_per_case() -> None:
    required = DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(
        case_count=14,
        confirmed_finding_limit=3,
    )

    assert required == {
        "orchestrator": 14,
        "red_team": 14,
        "judge": 14,
        "documentation": 3,
    }


@pytest.mark.parametrize(
    ("case_count", "expected_total"),
    ((34, 38), (33, 37)),
)
def test_reviewed_replay_reservation_matches_bounded_runtime(
    case_count: int,
    expected_total: int,
) -> None:
    required = DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(
        case_count=case_count,
        confirmed_finding_limit=3,
        reviewed_replay=True,
    )

    assert required == {
        "orchestrator": 1,
        "red_team": 0,
        "judge": case_count,
        "documentation": 3,
    }
    assert sum(required.values()) == expected_total
    assert expected_total <= 56


@pytest.mark.parametrize("identity", ["f" * 64, "not-a-digest", ""])
def test_unregistered_or_invalid_policy_identity_fails_closed(identity: str) -> None:
    with pytest.raises(HostedGenerationPolicyError):
        resolve_hosted_generation_policy(identity)
