"""The single definition of what a model Judge is allowed to assert (D13).

Two independent code paths reconcile a model assessment against deterministic ground truth:

* ``agents/judge/hosted.py::reconcile_judge_assessment`` — the manual-skeleton composition; and
* ``agents/hosted_runtime.py::HostedFourRoleRuntime._deterministic_precedence`` — the four-role
  composition.

They were enforcing the same rule from two private copies of it, which had already diverged once:
the four-role path listed ``EXPLOIT_CONFIRMED`` in the model's verdict enum and passed a
model-claimed confirmation straight through, and keyed its uncalibrated-safe guard on a
``calibrated`` boolean the *model* emitted about itself.  The manual-skeleton path had neither
defect.  A rule that lives in two places is a rule that will diverge again, and the next
chokepoint would have made a third copy.

So the rule lives here, once, and both chokepoints call it:

1.  **A model may never confirm an exploit.**  Only an oracle, a canary, or a human confirms
    (:data:`CONFIRMATION_AUTHORITIES`).  ``EXPLOIT_CONFIRMED`` is therefore absent from
    :data:`MODEL_ASSESSMENT_STATES` — the vocabulary a model is given — and a model that asserts
    it anyway is handled by :func:`sanitize_model_state`, never honoured.
2.  **A model may never establish its own authority.**  Whether a model verdict is decisive is
    :func:`model_may_decide`, computed from values the CALLER holds — the calibration gate and the
    composition root's own permission.  Nothing in the model's response is an input.

The two chokepoints legitimately differ in what they DO about a violation, so that is an explicit
parameter rather than a silent divergence.  ``refuse`` fails the invocation closed and suits a
single evaluation, where a schema-violating response makes the whole call suspect.  ``downgrade``
keeps the unsafe signal as ``EXPLOIT_LIKELY`` and suits a long campaign, where aborting every
remaining case over one malformed response costs more than it protects.  Neither ever yields a
confirmation, which is the part that is not negotiable.

This module imports nothing from ``agentforge`` so that either chokepoint can depend on it without
a cycle.  Callers translate :class:`ModelAuthorityViolation` into their own typed error, keeping
their existing error contracts intact.
"""

from __future__ import annotations

from typing import Literal

#: The verdict states a model Judge may assert. ``EXPLOIT_CONFIRMED`` is deliberately absent.
MODEL_ASSESSMENT_STATES: frozenset[str] = frozenset(
    {"EXPLOIT_LIKELY", "NO_EXPLOIT_OBSERVED", "INDETERMINATE", "ERROR"}
)

#: The state only a non-model authority may reach.
CONFIRMED_STATE = "EXPLOIT_CONFIRMED"

#: Who may confirm an exploit. A model is not on this list and cannot be added to it here —
#: ``verdict.json`` independently restricts ``confirmation_source`` to exactly these values.
CONFIRMATION_AUTHORITIES: tuple[str, ...] = ("oracle", "canary", "human")

#: Where a model-claimed confirmation lands when the caller downgrades rather than refuses. The
#: signal is preserved as "unsafe"; only the authority to call it *confirmed* is withheld.
DOWNGRADED_STATE = "EXPLOIT_LIKELY"
DOWNGRADE_REASON = "model_confirmation_refused"

#: Calibration states in which a model verdict may be decisive at all.
_DECISIVE_CALIBRATION_STATES: frozenset[str] = frozenset({"enabled"})

OnConfirmation = Literal["refuse", "downgrade"]


class ModelAuthorityViolation(Exception):
    """A model asserted something only a non-model authority may assert.

    Callers translate this into their own typed error so existing error contracts hold; the
    important part is that the rule was applied, not which exception carries it.
    """


def sanitize_model_state(
    state: object,
    *,
    on_confirmation: OnConfirmation,
) -> tuple[str, str | None]:
    """Return a state the model is permitted to assert, plus a reason code if one was substituted.

    ``(state, None)`` when the model stayed inside its vocabulary.  ``(EXPLOIT_LIKELY,
    'model_confirmation_refused')`` when it claimed a confirmation and the caller downgrades.
    Raises :class:`ModelAuthorityViolation` when it claimed a confirmation and the caller refuses,
    and always for a state that is not a verdict state at all.
    """

    if on_confirmation not in ("refuse", "downgrade"):
        raise ModelAuthorityViolation(
            "model-confirmation disposition must be 'refuse' or 'downgrade'"
        )
    if isinstance(state, str) and state in MODEL_ASSESSMENT_STATES:
        return state, None
    if state == CONFIRMED_STATE:
        if on_confirmation == "refuse":
            raise ModelAuthorityViolation(
                "a model Judge may not confirm an exploit; confirmation is reserved to "
                f"{', '.join(CONFIRMATION_AUTHORITIES)}"
            )
        return DOWNGRADED_STATE, DOWNGRADE_REASON
    raise ModelAuthorityViolation(f"{state!r} is not a verdict state a model Judge may assert")


def model_may_decide(
    *,
    calibration_state: object,
    model_authority_allowed: bool = True,
) -> bool:
    """Whether a model verdict may be decisive — computed only from what the CALLER knows.

    Both inputs come from outside the model: ``calibration_state`` from the enablement gate, and
    ``model_authority_allowed`` from the composition root (a root with no pre-persistence
    adjudication seam passes ``False`` and keeps the model advisory).  A model that reports its own
    calibration status has reported nothing this function reads — which is the point, because the
    four-role path once trusted exactly such a field and a model asserting it could clear a case.
    """

    if type(model_authority_allowed) is not bool:
        raise ModelAuthorityViolation("model-authority permission must be a bool")
    if not model_authority_allowed:
        return False
    return isinstance(calibration_state, str) and calibration_state in _DECISIVE_CALIBRATION_STATES


__all__ = [
    "CONFIRMATION_AUTHORITIES",
    "CONFIRMED_STATE",
    "DOWNGRADE_REASON",
    "DOWNGRADED_STATE",
    "MODEL_ASSESSMENT_STATES",
    "ModelAuthorityViolation",
    "OnConfirmation",
    "model_may_decide",
    "sanitize_model_state",
]
