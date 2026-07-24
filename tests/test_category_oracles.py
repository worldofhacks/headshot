"""Category oracles consume typed trusted telemetry, never hostile instructions."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from agentforge.agents.judge.oracles import (
    CanaryOracle,
    IdentityRoleOracle,
    OracleObservationError,
    OracleRegistryError,
    ResourceLimitOracle,
    ResourceObservation,
    RetrievalScopeObservation,
    RetrievalScopeOracle,
    RoleBoundaryObservation,
    StateCorruptionOracle,
    StateDiffObservation,
    ToolAuthorizationOracle,
    ToolCallObservation,
    resolve_authored_oracle,
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
    assert (
        tool.evaluate(
            ToolCallObservation(invoked=False, policy_allowed=False, side_effect_recorded=False)
        )["hit"]
        is False
    )
    assert (
        tool.evaluate(
            ToolCallObservation(invoked=True, policy_allowed=False, side_effect_recorded=True)
        )["hit"]
        is True
    )


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


def test_every_deterministic_authored_id_resolves_to_its_reviewed_code_oracle() -> None:
    expected_implementations = {
        "offline-beta-disclosure-canary-v1": CanaryOracle,
        "offline-system-prompt-canary-v1": CanaryOracle,
        "recorder-forbidden-clinical-write-v1": ToolAuthorizationOracle,
        "recorder-identity-role-boundary-v1": IdentityRoleOracle,
        "recorder-patient-scope-oracle-v1": RetrievalScopeOracle,
        "recorder-resource-limits-v1": ResourceLimitOracle,
        "recorder-state-diff-v1": StateCorruptionOracle,
        "recorder-tool-call-cap-v1": ResourceLimitOracle,
        "recorder-tool-parameter-scope-v1": RetrievalScopeOracle,
    }
    observations = {
        IdentityRoleOracle: RoleBoundaryObservation(ALPHA, BETA, False),
        ResourceLimitOracle: ResourceObservation(
            input_tokens=100,
            output_tokens=101,
            tool_calls=1,
            elapsed_ms=900,
            cost_usd=Decimal("0.20"),
            max_total_tokens=200,
            max_tool_calls=2,
            timeout_ms=1000,
            max_cost_usd=Decimal("0.25"),
        ),
        RetrievalScopeOracle: RetrievalScopeObservation(ALPHA, (BETA,)),
        StateCorruptionOracle: StateDiffObservation(ALPHA, BETA, mutation_authorized=False),
        ToolAuthorizationOracle: ToolCallObservation(
            invoked=True,
            policy_allowed=False,
            side_effect_recorded=True,
        ),
    }
    root = Path(__file__).resolve().parents[1] / "evals"
    cases = [
        json.loads(path.read_text(encoding="utf-8"))
        for directory in ("seeds", "drafts")
        for path in sorted((root / directory).glob("*.json"))
    ]
    deterministic_cases = [
        case for case in cases if case["oracle_expectation"]["deterministic"] is True
    ]
    authored_ids = {case["oracle_expectation"]["oracle_id"] for case in deterministic_cases}
    assert authored_ids == set(expected_implementations)

    for case in deterministic_cases:
        expectation = case["oracle_expectation"]
        oracle_id = expectation["oracle_id"]
        registration = resolve_authored_oracle(oracle_id)

        assert registration.evaluator_type is expected_implementations[oracle_id]
        assert registration.category == case["category"]
        assert registration.expectation_kind == expectation["kind"]
        assert registration.availability == expectation["availability"]
        assert registration.runtime_wired is False

        if registration.evaluator_type is CanaryOracle:
            canary_ref = expectation["canary_ref"]
            assert registration.canary_refs == {canary_ref}
            evaluator = registration.build_evaluator(canary_ref=canary_ref)
            signal = evaluator.evaluate(f"trusted fixture response {canary_ref}")
            assert signal["id"] == canary_ref
        else:
            assert registration.canary_refs == set()
            evaluator = registration.build_evaluator()
            signal = evaluator.evaluate(observations[registration.evaluator_type])
            assert evaluator.id == oracle_id
            assert signal["id"] == oracle_id
            assert signal["provenance"] == "code"


def test_oracle_registry_rejects_unreviewed_ids() -> None:
    with pytest.raises(OracleRegistryError, match="not reviewed"):
        resolve_authored_oracle("caller-selected-oracle")
    with pytest.raises(OracleObservationError, match="reviewed alias"):
        RetrievalScopeOracle(oracle_id="caller-selected-oracle")
    with pytest.raises(OracleRegistryError, match="canary ref"):
        resolve_authored_oracle("offline-beta-disclosure-canary-v1").build_evaluator(
            canary_ref="SYNTH_CANARY_DIFFERENT"
        )
