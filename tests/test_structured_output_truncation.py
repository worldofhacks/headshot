"""A truncated generation is reported as truncation, not as malformed JSON.

Live incident, campaign 8f44953bdd10 (batch-01, 34 cases). Three cases adjudicated normally, then
the fourth died and took the whole run with it:

    CampaignAbort[red_team_proposal_failed]
      <- HostedStructuredOutputInvalid[invalid_structured_output]
        <- HostedProviderError[hosted-provider-unavailable]
          <- TypeError

The durable ``provider_call_events`` rows explain it. Successful Red Team calls on that run emitted
3677, 3720 and 3676 output tokens. The failing one emitted **16383** — one below 16384, which is
exactly the role's output ceiling (8192 output + 8192 reasoning) — and ran for 295 seconds. The
model ran away, hit the cap, and OpenRouter returned ``content: null``.

``json.loads(None)`` raises ``TypeError``. The broad ``except Exception`` in ``_structured_output``
rewrote that into a generic "failed validation", which the call site then labelled
``invalid_structured_output``. So the one error an operator could actually see pointed at a schema
or prompt bug that did not exist, while the real cause — a generation that exhausted its budget —
appeared nowhere.

These tests pin the accurate classification. They deliberately do NOT change retry or isolation
behaviour: ``HostedStructuredOutputTruncated`` is a *subclass* of ``HostedStructuredOutputInvalid``,
so every existing ``isinstance`` check keeps working and truncation stays exactly as retryable and
as isolatable as any other formatting failure.
"""

from __future__ import annotations

import json

import pytest

from agentforge.providers.openrouter import (
    HostedProviderError,
    HostedStructuredOutputInvalid,
    HostedStructuredOutputTruncated,
    _StructuredOutputAbsent,
)

_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def _payload(content, *, finish_reason="stop"):
    return {"choices": [{"finish_reason": finish_reason, "message": {"content": content}}]}


def _structured_output(payload):
    from agentforge.providers.openrouter import OpenRouterTransport

    return OpenRouterTransport._structured_output(payload, _SCHEMA)


# ---------------------------------------------------------------------------------------
# The exact incident shape.
# ---------------------------------------------------------------------------------------


def test_null_content_raises_absent_rather_than_a_bare_typeerror() -> None:
    """json.loads(None) would raise TypeError; the broad handler would then mislabel it."""

    with pytest.raises(_StructuredOutputAbsent) as caught:
        _structured_output(_payload(None, finish_reason="length"))

    assert caught.value.finish_reason == "length"
    assert not isinstance(caught.value, TypeError)


def test_the_provider_finish_reason_is_carried_so_the_cause_is_visible() -> None:
    for reason in ("length", "content_filter", None):
        with pytest.raises(_StructuredOutputAbsent) as caught:
            _structured_output(_payload(None, finish_reason=reason))
        assert caught.value.finish_reason == (str(reason) if reason is not None else None)


def test_a_missing_content_key_is_treated_the_same_as_an_explicit_null() -> None:
    with pytest.raises(_StructuredOutputAbsent):
        _structured_output({"choices": [{"finish_reason": "length", "message": {}}]})


# ---------------------------------------------------------------------------------------
# Truncation keeps the retry and isolation it already earned.
# ---------------------------------------------------------------------------------------


def test_truncated_is_a_subclass_so_every_isinstance_check_still_holds() -> None:
    """This is the whole reason it is a subclass and not a sibling type."""

    assert issubclass(HostedStructuredOutputTruncated, HostedStructuredOutputInvalid)


def test_truncation_has_its_own_code_so_the_console_names_the_real_fault() -> None:
    assert HostedStructuredOutputTruncated.code == "structured_output_truncated"
    assert HostedStructuredOutputInvalid.code == "invalid_structured_output"
    assert HostedStructuredOutputTruncated.code != HostedStructuredOutputInvalid.code


# ---------------------------------------------------------------------------------------
# Nothing else changed.
# ---------------------------------------------------------------------------------------


def test_genuinely_malformed_json_is_still_a_plain_validation_failure() -> None:
    """Truncation must not swallow the real malformed-output case."""

    with pytest.raises(HostedProviderError) as caught:
        _structured_output(_payload("{not json"))

    assert not isinstance(caught.value, _StructuredOutputAbsent)


def test_schema_violating_but_well_formed_json_is_unchanged() -> None:
    with pytest.raises(HostedProviderError) as caught:
        _structured_output(_payload(json.dumps({"wrong_key": 1})))

    assert not isinstance(caught.value, _StructuredOutputAbsent)


def test_a_valid_response_still_decodes() -> None:
    assert _structured_output(_payload(json.dumps({"answer": "ok"}))) == {"answer": "ok"}


def test_a_malformed_envelope_falls_through_to_the_existing_handler() -> None:
    """The absence probe must never itself become a new failure mode."""

    for broken in ({}, {"choices": []}, {"choices": [{}]}, {"choices": [{"message": "x"}]}):
        with pytest.raises(HostedProviderError):
            _structured_output(broken)
