"""An enabled model Judge must not be able to confirm an exploit, or to clear one.

``HostedFourRoleRuntime`` is the four-role composition an enabled model Judge runs inside.  Two
authorities were being read out of the model's own response there:

* its verdict enum included ``EXPLOIT_CONFIRMED``, and ``_deterministic_precedence`` passed that
  straight through when no oracle or canary had fired.  ``run_attempt`` then drafts a
  vulnerability report for any ``EXPLOIT_CONFIRMED``/``EXPLOIT_LIKELY`` verdict, so a model that
  claimed a confirmation produced documentation for a finding with no evidence behind it; and
* the guard that refuses an uncalibrated ``NO_EXPLOIT_OBSERVED`` was keyed on a ``calibrated``
  boolean the *model* emitted, so a model asserting its own calibration could clear a case.

Both are now decided in code.  These tests pin that, at the reconciliation function and at the
schema the model is given.
"""

from __future__ import annotations

import pytest

from agentforge.agents.hosted_runtime import (
    _MODEL_ASSESSMENT_VERDICTS,
    HostedCompositionError,
    HostedFourRoleRuntime,
)

_NO_ORACLE = {"state": "INDETERMINATE", "canary_triggered": False}


def _reconcile(hosted: dict[str, object], *, enabled: bool = True) -> dict[str, object]:
    return HostedFourRoleRuntime._deterministic_precedence(
        deterministic_verdict=_NO_ORACLE,
        hosted_verdict=hosted,
        model_calibration_enabled=enabled,
    )


def test_the_model_is_never_given_the_vocabulary_to_confirm() -> None:
    assert "EXPLOIT_CONFIRMED" not in _MODEL_ASSESSMENT_VERDICTS
    assert set(_MODEL_ASSESSMENT_VERDICTS) == {
        "EXPLOIT_LIKELY",
        "NO_EXPLOIT_OBSERVED",
        "INDETERMINATE",
        "ERROR",
    }


def test_a_model_claimed_confirmation_is_downgraded_not_passed_through() -> None:
    """Defense in depth: even off-schema, a model confirmation never becomes a confirmation."""

    verdict = _reconcile({"state": "EXPLOIT_CONFIRMED", "explanation": "I confirm it"})

    assert verdict["state"] == "EXPLOIT_LIKELY"
    assert verdict["reason"] == "model_confirmation_refused"
    assert verdict["deterministic_precedence"] is False


def test_a_model_cannot_vouch_for_its_own_calibration_to_clear_a_case() -> None:
    hosted = {"state": "NO_EXPLOIT_OBSERVED", "explanation": "looks fine", "calibrated": True}

    verdict = _reconcile(hosted, enabled=False)

    assert verdict["state"] == "INDETERMINATE"
    assert verdict["reason"] == "uncalibrated_safe_verdict_refused"


def test_an_enabled_model_may_still_return_a_decisive_assessment() -> None:
    """Enablement is not neutered — this is exactly what enabling buys."""

    assert _reconcile({"state": "NO_EXPLOIT_OBSERVED"}, enabled=True)["state"] == (
        "NO_EXPLOIT_OBSERVED"
    )
    assert _reconcile({"state": "EXPLOIT_LIKELY"}, enabled=True)["state"] == "EXPLOIT_LIKELY"
    assert _reconcile({"state": "INDETERMINATE"}, enabled=True)["state"] == "INDETERMINATE"


def test_a_deterministic_hit_still_wins_over_any_model_output() -> None:
    verdict = HostedFourRoleRuntime._deterministic_precedence(
        deterministic_verdict={"state": "INDETERMINATE", "canary_triggered": True},
        hosted_verdict={"state": "NO_EXPLOIT_OBSERVED", "explanation": "nothing here"},
        model_calibration_enabled=True,
    )

    assert verdict["state"] == "EXPLOIT_CONFIRMED"
    assert verdict["deterministic_precedence"] is True


def test_an_unrecognised_state_is_still_a_composition_error() -> None:
    with pytest.raises(HostedCompositionError, match="invalid verdict state"):
        _reconcile({"state": "TOTALLY_SAFE_TRUST_ME"})
