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
    orchestrator = policy.call_bounds["orchestrator"]
    assert orchestrator.output_tokens == 1_024
    assert {role: bounds.input_tokens for role, bounds in policy.call_bounds.items()} == {
        "orchestrator": 12_288,
        "red_team": 32_768,
        "judge": 32_768,
        "documentation": 12_288,
    }
    red_team = policy.call_bounds["red_team"]
    assert red_team.output_tokens == 8_192
    assert red_team.reasoning_tokens == 8_192
    # Raised from 60s after a live Chutes selection measured 32.4s — under 2x headroom meant an
    # ordinarily slower generation aborted the whole campaign. Matches the Judge's ceiling.
    assert red_team.timeout_seconds == 180.0


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
    ((34, 136), (33, 132)),
)
def test_four_hosted_roles_reserve_every_reviewed_case(
    case_count: int,
    expected_total: int,
) -> None:
    required = DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(
        case_count=case_count,
    )

    assert required == {
        "orchestrator": case_count,
        "red_team": case_count,
        "judge": case_count,
        "documentation": case_count,
    }
    assert sum(required.values()) == expected_total
    assert expected_total > 56


@pytest.mark.parametrize("identity", ["f" * 64, "not-a-digest", ""])
def test_unregistered_or_invalid_policy_identity_fails_closed(identity: str) -> None:
    with pytest.raises(HostedGenerationPolicyError):
        resolve_hosted_generation_policy(identity)
