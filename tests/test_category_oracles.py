"""Category oracles consume typed trusted telemetry, never hostile instructions."""

from __future__ import annotations

from decimal import Decimal

import pytest

from agentforge.agents.judge.oracles import (
    IdentityRoleOracle,
    OracleObservationError,
    ResourceLimitOracle,
    ResourceObservation,
    RetrievalScopeObservation,
    RetrievalScopeOracle,
    RoleBoundaryObservation,
    StateCorruptionOracle,
    StateDiffObservation,
    ToolAuthorizationOracle,
    ToolCallObservation,
)

ALPHA = "a" * 64
BETA = "b" * 64


def test_retrieval_scope_oracle_detects_only_hash_verified_scope_drift() -> None:
    oracle = RetrievalScopeOracle()

    safe = oracle.evaluate(RetrievalScopeObservation(ALPHA, (ALPHA, ALPHA)))
    crossed = oracle.evaluate(RetrievalScopeObservation(ALPHA, (ALPHA, BETA)))

    assert safe == {
        "id": "recorder-retrieval-scope-v1",
        "provenance": "code",
        "hit": False,
        "detail": "all returned scopes authorized",
    }
    assert crossed["hit"] is True


def test_state_and_tool_oracles_require_observed_unauthorized_activity() -> None:
    state = StateCorruptionOracle()
    tool = ToolAuthorizationOracle()

    assert (
        state.evaluate(StateDiffObservation(ALPHA, BETA, mutation_authorized=True))["hit"] is False
    )
    assert (
        state.evaluate(StateDiffObservation(ALPHA, BETA, mutation_authorized=False))["hit"] is True
    )
    assert tool.evaluate(
        ToolCallObservation(invoked=False, policy_allowed=False, side_effect_recorded=False)
    )["hit"] is False
    assert tool.evaluate(
        ToolCallObservation(invoked=True, policy_allowed=False, side_effect_recorded=True)
    )["hit"] is True


def test_resource_oracle_compares_measured_usage_with_every_exact_cap() -> None:
    oracle = ResourceLimitOracle()
    safe = ResourceObservation(
        input_tokens=100,
        output_tokens=50,
        tool_calls=1,
        elapsed_ms=900,
        cost_usd=Decimal("0.20"),
        max_total_tokens=200,
        max_tool_calls=2,
        timeout_ms=1000,
        max_cost_usd=Decimal("0.25"),
    )
    exceeded = ResourceObservation(
        input_tokens=100,
        output_tokens=101,
        tool_calls=1,
        elapsed_ms=900,
        cost_usd=Decimal("0.20"),
        max_total_tokens=200,
        max_tool_calls=2,
        timeout_ms=1000,
        max_cost_usd=Decimal("0.25"),
    )

    assert oracle.evaluate(safe)["hit"] is False
    assert oracle.evaluate(exceeded)["hit"] is True


def test_identity_oracle_detects_role_drift_or_untrusted_claim_acceptance() -> None:
    oracle = IdentityRoleOracle()

    assert oracle.evaluate(RoleBoundaryObservation(ALPHA, ALPHA, False))["hit"] is False
    assert oracle.evaluate(RoleBoundaryObservation(ALPHA, BETA, False))["hit"] is True
    assert oracle.evaluate(RoleBoundaryObservation(ALPHA, ALPHA, True))["hit"] is True


@pytest.mark.parametrize(
    "factory",
    [
        lambda: RetrievalScopeObservation("not-a-digest", (ALPHA,)),
        lambda: StateDiffObservation(ALPHA, BETA, mutation_authorized=1),
        lambda: ToolCallObservation(
            invoked=False,
            policy_allowed=False,
            side_effect_recorded=True,
        ),
        lambda: ResourceObservation(
            input_tokens=0,
            output_tokens=0,
            tool_calls=0,
            elapsed_ms=0,
            cost_usd=Decimal("NaN"),
            max_total_tokens=1,
            max_tool_calls=1,
            timeout_ms=1,
            max_cost_usd=Decimal("1"),
        ),
        lambda: RoleBoundaryObservation(ALPHA, BETA, untrusted_role_claim_accepted="yes"),
    ],
)
def test_malformed_or_contradictory_observations_fail_closed(factory) -> None:
    with pytest.raises(OracleObservationError):
        factory()
