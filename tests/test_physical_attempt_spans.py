"""Per-attempt Langfuse spans: visible retries, correlatable ids, and cost counted once.

Two gaps closed here, both found by querying Langfuse remotely rather than by reading code.

First, ``attempt_id`` was arriving as ``***REDACTED***``. Nothing was wrong with the sanitizer's
intent — ``looks_like_provider_key`` treats any lowercase-hex string of 40+ characters as a
Together-style key, and a 64-hex attempt id is exactly that shape. The value was a false positive,
so Langfuse could only correlate by campaign and never by case.

Second, one aggregate ``*.runtime`` generation per logical execution cannot show that a call was
retried. The physical attempts were durable in PostgreSQL but invisible in the trace.

The risk in fixing the second is double-counting: if a child span carries usage or cost, Langfuse
adds it to the aggregate the parent already reported. These tests pin that it does not.
"""

from __future__ import annotations

from typing import Any

from agentforge.telemetry.outbound import (
    _labelled_attempt_id,
    _LangfuseBridge,
    _physical_attempt_metadata,
    _sanitize,
)


class _Observation:
    """Minimal stand-in for a Langfuse observation handle."""

    def __init__(self, name: str, kind: str, metadata: dict | None = None) -> None:
        self.name = name
        self.kind = kind
        self.metadata = metadata or {}
        self.children: list[_Observation] = []
        self.ended = False
        self.id = f"obs-{name}"

    def start_observation(self, *, as_type: str, name: str, **kwargs: Any) -> _Observation:
        child = _Observation(name, as_type, kwargs.get("metadata"))
        self.children.append(child)
        return child

    def end(self) -> None:
        self.ended = True


def _record(sequence: int, status: str = "succeeded", **overrides: Any) -> dict:
    base = {
        "physical_sequence": sequence,
        "status": status,
        "returned_model": "google/gemini-2.5-pro",
        "upstream_provider": "Google",
        "provider_request_id": f"gen-{sequence}",
        "input_tokens": 531,
        "output_tokens": 100,
        "reasoning_tokens": 12,
        "measured_cost_usd": "0.00878375",
        "cost_measurement_state": "measured",
        "duration_ms": "7183.0",
        "error_code": None,
    }
    base.update(overrides)
    return base


def _state() -> tuple[_Observation, _Observation, str, str]:
    agent = _Observation("agent.judge", "agent")
    generation = agent.start_observation(as_type="generation", name="agent.judge.runtime")
    return agent, generation, "provider_measured", agent.id


# ---------------------------------------------------------------------------------------
# Parentage.
# ---------------------------------------------------------------------------------------


def test_each_physical_attempt_is_a_child_of_the_agent_runtime() -> None:
    agent, generation, _cs, _oid = state = _state()

    emitted = _LangfuseBridge().record_physical_attempts(
        state, [_physical_attempt_metadata(_record(1))]
    )

    assert emitted == 1
    # Parented under the runtime generation, NOT under the agent root or the trace.
    assert [c.name for c in generation.children] == ["provider.attempt.1"]
    assert [c.name for c in agent.children] == ["agent.judge.runtime"]


def test_spans_are_ended_so_they_are_not_left_open() -> None:
    _agent, generation, _cs, _oid = state = _state()

    _LangfuseBridge().record_physical_attempts(state, [_physical_attempt_metadata(_record(1))])

    assert all(child.ended for child in generation.children)


def test_no_state_means_no_spans_and_no_error() -> None:
    assert _LangfuseBridge().record_physical_attempts(None, [_record(1)]) == 0


def test_no_attempts_means_no_spans() -> None:
    _agent, generation, _cs, _oid = state = _state()
    assert _LangfuseBridge().record_physical_attempts(state, []) == 0
    assert generation.children == []


# ---------------------------------------------------------------------------------------
# Retries become visible — the whole point.
# ---------------------------------------------------------------------------------------


def test_a_retried_call_produces_two_ordered_sibling_spans() -> None:
    """An aggregate generation cannot show this; the child spans can."""

    _agent, generation, _cs, _oid = state = _state()

    emitted = _LangfuseBridge().record_physical_attempts(
        state,
        [
            _physical_attempt_metadata(
                _record(1, status="invalid_output", error_code="invalid_structured_output")
            ),
            _physical_attempt_metadata(_record(2)),
        ],
    )

    assert emitted == 2
    assert [c.name for c in generation.children] == ["provider.attempt.1", "provider.attempt.2"]
    assert generation.children[0].metadata["attempt.status"] == "invalid_output"
    assert generation.children[0].metadata["attempt.error_code"] == "invalid_structured_output"
    assert generation.children[1].metadata["attempt.status"] == "succeeded"


def test_each_span_carries_role_relevant_identity_and_measurements() -> None:
    metadata = _physical_attempt_metadata(_record(1))

    assert metadata["attempt.physical_sequence"] == "1"
    assert metadata["attempt.returned_model"] == "google/gemini-2.5-pro"
    assert metadata["attempt.upstream_provider"] == "Google"
    assert metadata["attempt.provider_request_id"] == "gen-1"
    assert metadata["attempt.input_tokens"] == "531"
    assert metadata["attempt.output_tokens"] == "100"
    assert metadata["attempt.measured_cost_usd"] == "0.00878375"
    assert metadata["attempt.duration_ms"] == "7183.0"
    assert metadata["attempt.cost_measurement_state"] == "measured"


# ---------------------------------------------------------------------------------------
# Cost is reported once, on the aggregate.
# ---------------------------------------------------------------------------------------


def test_a_span_carries_no_billable_usage_or_cost_fields() -> None:
    """Langfuse sums usage/cost from observations. A child carrying them double-counts."""

    _agent, generation, _cs, _oid = state = _state()
    _LangfuseBridge().record_physical_attempts(state, [_physical_attempt_metadata(_record(1))])
    span = generation.children[0]

    # The SDK is only ever handed `metadata` — never usage, cost_details or model.
    assert set(span.metadata) <= {
        "attempt.physical_sequence",
        "attempt.status",
        "attempt.returned_model",
        "attempt.upstream_provider",
        "attempt.provider_request_id",
        "attempt.input_tokens",
        "attempt.output_tokens",
        "attempt.reasoning_tokens",
        "attempt.measured_cost_usd",
        "attempt.cost_measurement_state",
        "attempt.duration_ms",
        "attempt.error_code",
    }
    # Measurements are strings, so they cannot be summed as numeric usage.
    for key in ("attempt.input_tokens", "attempt.output_tokens", "attempt.measured_cost_usd"):
        assert isinstance(span.metadata[key], str)


def test_spans_are_metadata_only_with_no_prompt_or_response() -> None:
    metadata = _physical_attempt_metadata(_record(1))
    joined = " ".join(f"{k}{v}" for k, v in metadata.items()).lower()
    for forbidden in ("prompt", "message", "content", "response_body", "transcript"):
        assert forbidden not in joined


# ---------------------------------------------------------------------------------------
# The attempt id survives the sanitizer, and real secrets still do not.
# ---------------------------------------------------------------------------------------


def test_a_bare_attempt_id_would_be_redacted_but_the_labelled_one_survives() -> None:
    raw = "5460d1f0817745aabdae50c4" + "0" * 40  # 64 lowercase hex, like a real attempt id

    assert _sanitize(raw, ()) == "***REDACTED***", "the false positive this fix exists for"
    assert _sanitize(_labelled_attempt_id(raw), ()) == f"attempt:{raw}"


def test_labelling_is_idempotent_and_none_safe() -> None:
    assert _labelled_attempt_id(None) is None
    once = _labelled_attempt_id("abc")
    assert _labelled_attempt_id(once) == once == "attempt:abc"


def test_real_secrets_are_still_redacted_after_the_change() -> None:
    """Loosening one false positive must not loosen the control."""

    for secret in (
        "sk-ant-0123456789abcdefghij",
        "sk-or-v1-0123456789abcdefghij",
        "sk-proj-0123456789abcdefghij",
        "Authorization: Bearer abcdefghijklmnopqrstuvwx",
        "cookie: session=abcdefghijklmnopqrst",
        "api_key = abcdefghijklmnopqrstuvwx",
    ):
        assert "REDACTED" in _sanitize(secret, ()), secret


def test_labelling_cannot_be_used_to_smuggle_a_provider_key() -> None:
    """A key prefixed with the label is still caught by the pattern rules."""

    smuggled = _labelled_attempt_id("sk-ant-0123456789abcdefghij")
    assert "REDACTED" in _sanitize(smuggled, ())
