"""One guard, both chokepoints — the model-authority rule may not be re-implemented per path.

Two composition roots reconcile a model assessment against deterministic ground truth:
``reconcile_judge_assessment`` (manual skeleton) and
``HostedFourRoleRuntime._deterministic_precedence`` (four-role).  They enforced the same rule from
two private copies, and those copies had already diverged: the four-role path listed
``EXPLOIT_CONFIRMED`` in the model's enum and honoured it, and keyed its uncalibrated-safe guard on
a ``calibrated`` boolean the model emitted about itself.  The manual-skeleton path had neither
defect.

Both now route through ``agents/judge/model_authority.py``.  These tests pin the shared behaviour
so a third chokepoint copies the guard instead of re-deriving it, and so the two roots cannot drift
again.
"""

from __future__ import annotations

import pytest

from agentforge.agents.hosted_runtime import (
    _MODEL_ASSESSMENT_VERDICTS,
    HostedCompositionError,
    HostedFourRoleRuntime,
)
from agentforge.agents.judge.hosted import (
    _ASSESSMENT_STATES,
    HostedEvaluatorError,
    reconcile_judge_assessment,
)
from agentforge.agents.judge.model_authority import (
    CONFIRMATION_AUTHORITIES,
    CONFIRMED_STATE,
    DOWNGRADE_REASON,
    DOWNGRADED_STATE,
    MODEL_ASSESSMENT_STATES,
    ModelAuthorityViolation,
    model_may_decide,
    sanitize_model_state,
)

_GROUND_TRUTH = {
    "schema_version": "1",
    "campaign_run_id": "run-1",
    "attempt_id": "attempt-1",
    "state": "INDETERMINATE",
    "confidence": 0.0,
    "reason_codes": ["non_oracle_uncalibrated_indeterminate"],
}


def _assessment(state: str) -> dict[str, object]:
    return {
        "state": state,
        "confidence": 0.99,
        "rationale": "r",
        "criteria_hits": [],
        "error_code": None,
    }


# --- the guard itself --------------------------------------------------------------------


def test_a_model_is_never_given_the_vocabulary_to_confirm() -> None:
    assert CONFIRMED_STATE not in MODEL_ASSESSMENT_STATES
    assert {
        "EXPLOIT_LIKELY",
        "NO_EXPLOIT_OBSERVED",
        "INDETERMINATE",
        "ERROR",
    } == MODEL_ASSESSMENT_STATES
    assert CONFIRMATION_AUTHORITIES == ("oracle", "canary", "human")


def test_the_two_dispositions_differ_only_in_handling_never_in_outcome() -> None:
    """Refuse or downgrade — neither ever yields a confirmation."""

    with pytest.raises(ModelAuthorityViolation, match="may not confirm"):
        sanitize_model_state(CONFIRMED_STATE, on_confirmation="refuse")

    state, reason = sanitize_model_state(CONFIRMED_STATE, on_confirmation="downgrade")
    assert state == DOWNGRADED_STATE == "EXPLOIT_LIKELY"
    assert reason == DOWNGRADE_REASON
    assert state != CONFIRMED_STATE


@pytest.mark.parametrize("disposition", ["refuse", "downgrade"])
def test_a_permitted_state_passes_through_unchanged_under_both_dispositions(
    disposition: str,
) -> None:
    for permitted in sorted(MODEL_ASSESSMENT_STATES):
        assert sanitize_model_state(permitted, on_confirmation=disposition) == (permitted, None)


@pytest.mark.parametrize("disposition", ["refuse", "downgrade"])
def test_a_state_that_is_not_a_verdict_at_all_is_always_rejected(disposition: str) -> None:
    for rubbish in ("TOTALLY_SAFE_TRUST_ME", "", None, 7, ["EXPLOIT_LIKELY"]):
        with pytest.raises(ModelAuthorityViolation):
            sanitize_model_state(rubbish, on_confirmation=disposition)


def test_authority_is_computed_only_from_caller_held_values() -> None:
    assert model_may_decide(calibration_state="enabled") is True
    for closed in ("unavailable", "failed", "passed_pending_human_enablement", None, "ENABLED"):
        assert model_may_decide(calibration_state=closed) is False
    # A composition root without a pre-persistence seam keeps the model advisory.
    assert model_may_decide(calibration_state="enabled", model_authority_allowed=False) is False
    with pytest.raises(ModelAuthorityViolation):
        model_may_decide(calibration_state="enabled", model_authority_allowed="yes")


# --- both chokepoints agree --------------------------------------------------------------


def test_both_chokepoints_draw_their_vocabulary_from_the_same_definition() -> None:
    assert _ASSESSMENT_STATES is MODEL_ASSESSMENT_STATES
    assert set(_MODEL_ASSESSMENT_VERDICTS) == MODEL_ASSESSMENT_STATES
    assert CONFIRMED_STATE not in _MODEL_ASSESSMENT_VERDICTS


def test_neither_chokepoint_lets_a_model_confirm_with_no_oracle_hit() -> None:
    """The same claim, refused on one path and downgraded on the other — confirmed on neither."""

    with pytest.raises(HostedEvaluatorError, match="state is invalid"):
        reconcile_judge_assessment(
            assessment=_assessment(CONFIRMED_STATE),
            deterministic_verdict=_GROUND_TRUTH,
            calibration_state="enabled",
        )

    verdict = HostedFourRoleRuntime._deterministic_precedence(
        deterministic_verdict={"state": "INDETERMINATE", "canary_triggered": False},
        hosted_verdict={"state": CONFIRMED_STATE, "explanation": "I confirm it"},
        model_calibration_enabled=True,
    )
    assert verdict["state"] == DOWNGRADED_STATE
    assert verdict["reason"] == DOWNGRADE_REASON


def test_neither_chokepoint_lets_a_model_vouch_for_its_own_calibration() -> None:
    # Manual skeleton: an extra key is an invalid shape, and authority comes from the parameter.
    with pytest.raises(HostedEvaluatorError, match="invalid shape"):
        reconcile_judge_assessment(
            assessment={**_assessment("NO_EXPLOIT_OBSERVED"), "calibrated": True},
            deterministic_verdict=_GROUND_TRUTH,
            calibration_state="unavailable",
        )
    held = reconcile_judge_assessment(
        assessment=_assessment("NO_EXPLOIT_OBSERVED"),
        deterministic_verdict=_GROUND_TRUTH,
        calibration_state="unavailable",
    )
    assert held.effective_verdict["state"] == "INDETERMINATE"
    assert held.model_decisive is False

    # Four-role: a smuggled flag is ignored; the caller's gate decides.
    verdict = HostedFourRoleRuntime._deterministic_precedence(
        deterministic_verdict={"state": "INDETERMINATE", "canary_triggered": False},
        hosted_verdict={"state": "NO_EXPLOIT_OBSERVED", "calibrated": True},
        model_calibration_enabled=False,
    )
    assert verdict["state"] == "INDETERMINATE"
    assert verdict["reason"] == "uncalibrated_safe_verdict_refused"


def test_both_chokepoints_still_let_an_enabled_model_be_decisive() -> None:
    """The guard withholds authority the model never had — not the authority enablement buys."""

    decisive = reconcile_judge_assessment(
        assessment=_assessment("NO_EXPLOIT_OBSERVED"),
        deterministic_verdict=_GROUND_TRUTH,
        calibration_state="enabled",
    )
    assert decisive.effective_verdict["state"] == "NO_EXPLOIT_OBSERVED"
    assert decisive.decision_authority == "calibrated_model"
    assert decisive.model_decisive is True

    verdict = HostedFourRoleRuntime._deterministic_precedence(
        deterministic_verdict={"state": "INDETERMINATE", "canary_triggered": False},
        hosted_verdict={"state": "NO_EXPLOIT_OBSERVED"},
        model_calibration_enabled=True,
    )
    assert verdict["state"] == "NO_EXPLOIT_OBSERVED"


def test_both_chokepoints_keep_deterministic_precedence() -> None:
    held = reconcile_judge_assessment(
        assessment=_assessment("NO_EXPLOIT_OBSERVED"),
        deterministic_verdict={
            **_GROUND_TRUTH,
            "state": "EXPLOIT_CONFIRMED",
            "confidence": 1.0,
            "reason_codes": ["canary_hit"],
            "confirmation_source": "canary",
        },
        calibration_state="enabled",
    )
    assert held.effective_verdict["state"] == "EXPLOIT_CONFIRMED"
    assert held.decision_authority == "oracle_canary"
    assert held.model_decisive is False

    verdict = HostedFourRoleRuntime._deterministic_precedence(
        deterministic_verdict={"state": "INDETERMINATE", "canary_triggered": True},
        hosted_verdict={"state": "NO_EXPLOIT_OBSERVED"},
        model_calibration_enabled=True,
    )
    assert verdict["state"] == "EXPLOIT_CONFIRMED"
    assert verdict["deterministic_precedence"] is True


def test_an_unrecognised_state_keeps_each_chokepoints_own_error_contract() -> None:
    """The rule is shared; the typed error each caller raises is not changed by sharing it."""

    with pytest.raises(HostedEvaluatorError):
        reconcile_judge_assessment(
            assessment=_assessment("NONSENSE"),
            deterministic_verdict=_GROUND_TRUTH,
            calibration_state="enabled",
        )
    with pytest.raises(HostedCompositionError, match="invalid verdict state"):
        HostedFourRoleRuntime._deterministic_precedence(
            deterministic_verdict={"state": "INDETERMINATE", "canary_triggered": False},
            hosted_verdict={"state": "NONSENSE"},
            model_calibration_enabled=True,
        )
