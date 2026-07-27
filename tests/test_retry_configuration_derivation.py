"""The retry envelope is derived from the worst case, never chosen.

The platform previously bounded a role at 56 physical calls and a run at 136. Those are not round
numbers — they are 34 cases x 4 roles with no retry anywhere. So when one Gemini response failed
the Judge's schema in run 50da57b037d44b3c93a10e4c2edf61a8, the envelope had no room for a second
physical call regardless of what any configuration asked for.

Granting the Judge one retry moves the arithmetic to 34+34+68+34 = 170. These tests keep the
ceilings tied to that derivation, so a future workload or policy change that outgrows them fails
here rather than at preflight on a live run — and so nobody can quietly widen a ceiling without the
case count that justifies it.
"""

from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

from agentforge.agents.hosted import (
    HOSTED_MAX_GLOBAL_PHYSICAL_CALLS,
    HOSTED_MAX_LOGICAL_RETRIES,
    HOSTED_MAX_MEASURED_USD,
    HOSTED_MAX_PHYSICAL_CALLS,
    HOSTED_ROLE_MAX_MEASURED_USD,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.campaign.corpus import LIVE_100_BATCH_IDS, resolve_workload

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from derive_retry_configuration import check, derive  # type: ignore[import-not-found]  # noqa: E402

_BATCH_01 = LIVE_100_BATCH_IDS[0]


@pytest.fixture(scope="module")
def derivation():
    return derive(_BATCH_01)


def test_the_ceilings_are_exactly_the_largest_batch_worst_case(derivation) -> None:
    """68 and 170 are arithmetic, not preference."""

    case_count = len(resolve_workload(_BATCH_01).cases)
    assert case_count == 34

    judge = derivation["roles"]["judge"]
    assert judge["max_retries"] == 1
    assert judge["max_calls"] == case_count * 2 == 68
    assert HOSTED_MAX_PHYSICAL_CALLS == 68, "the per-role ceiling is the Judge's retried worst case"

    # orchestrator + red_team + judge(x2) + documentation
    assert derivation["global"]["max_calls"] == case_count * 5 == 170
    assert HOSTED_MAX_GLOBAL_PHYSICAL_CALLS == 170


def test_only_the_judge_is_granted_a_retry(derivation) -> None:
    """The Red Team must never re-generate: a second attempt would change the attack."""

    for role, values in derivation["roles"].items():
        expected = 1 if role == "judge" else 0
        assert values["max_retries"] == expected, role


def test_a_retry_cannot_exceed_the_platform_logical_limit(derivation) -> None:
    for values in derivation["roles"].values():
        assert values["max_retries"] <= HOSTED_MAX_LOGICAL_RETRIES


def test_the_derivation_fits_the_platform_envelope(derivation) -> None:
    """If this fails, the ceilings and the workload have drifted apart."""

    assert check(derivation) == []


def test_worst_case_spend_fits_with_headroom(derivation) -> None:
    worst = Decimal(derivation["global"]["worst_case_usd"])
    assert worst <= HOSTED_MAX_MEASURED_USD
    # The old $10 ceiling would NOT have held this workload — the raise was necessary, not padding.
    assert worst > Decimal("10")


def test_every_role_worst_case_fits_its_own_spend_cap(derivation) -> None:
    for role, values in derivation["roles"].items():
        assert Decimal(values["worst_case_usd"]) <= HOSTED_ROLE_MAX_MEASURED_USD[role], role


def test_token_totals_are_the_policy_bounds_times_the_physical_calls(derivation) -> None:
    """The cumulative caps must be the policy's own numbers, not independently chosen ones."""

    policy = DEFAULT_HOSTED_GENERATION_POLICY
    for role, values in derivation["roles"].items():
        bounds = policy.call_bounds[role]
        physical = values["max_calls"]
        assert values["max_input_tokens"] == bounds.input_tokens * physical
        assert values["max_output_tokens"] == bounds.output_tokens * physical
        assert values["max_reasoning_tokens"] == bounds.reasoning_tokens * physical


def test_the_derivation_is_bound_to_the_current_generation_policy(derivation) -> None:
    """A policy change must produce a different derivation, not a stale one."""

    assert derivation["generation_policy_sha256"] == DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256


def test_an_oversized_workload_is_refused_rather_than_rounded_up() -> None:
    """The check reports rather than silently widening — the whole point of deriving."""

    inflated = derive(_BATCH_01)
    inflated["global"]["max_calls"] = HOSTED_MAX_GLOBAL_PHYSICAL_CALLS + 1
    problems = check(inflated)
    assert problems
    assert any("global needs" in problem for problem in problems)


@pytest.mark.parametrize("batch_id", LIVE_100_BATCH_IDS)
def test_every_reviewed_batch_fits_the_raised_envelope(batch_id: str) -> None:
    """batch-01 is the largest, but 02 and 03 must fit too or the suite cannot complete."""

    assert check(derive(batch_id)) == []
