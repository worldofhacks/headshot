"""Schema-invalid model output is the ONE retryable provider failure — and nothing else is.

Run 50da57b037d44b3c93a10e4c2edf61a8 died on case 12 of 34 because Gemini returned HTTP 200 with
correct identity, route and measured usage, but a body that failed the Judge's JSON Schema. That
raised ``HostedProviderResponseError`` — the same type used for ledger-settlement failures — so the
single handler at the retry seam could not tell "the model formatted its answer badly" apart from
"this call breached an authorized cap", and refused to retry either. One malformed response ended a
34-case campaign.

Splitting the two apart is only safe if the retryable set stays exactly one member wide. These
tests pin both halves: the schema case retries and accounts for both physical calls, and every
other measured failure still terminates on the first send. A retry must also never reach the
target — it is a model round-trip, not an attack turn.
"""

from __future__ import annotations

import json
from decimal import Decimal

import httpx
import pytest

from agentforge.providers.openrouter import (
    HostedBudgetExceeded,
    HostedProviderError,
    HostedProviderResponseError,
    HostedRetryAdmissionRefused,
    HostedSettlementAccountingInvalid,
    HostedSettlementBudgetExceeded,
    HostedSettlementFailed,
    HostedStructuredOutputInvalid,
    OpenRouterTransport,
)
from agentforge.secrets import Secret
from test_openrouter_transport import (  # type: ignore[import-not-found]
    _configuration,
    _digest,
    _messages,
    _provider_context,
    _ProviderRecorder,
    _success,
)

_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string"}},
    "required": ["verdict"],
    "additionalProperties": False,
}


def _transport(
    responses: list[httpx.Response],
    recorder: _ProviderRecorder | None = None,
) -> tuple[OpenRouterTransport, _ProviderRecorder, list[httpx.Request]]:
    """A transport whose mock returns ``responses`` in order, recording every outbound request."""

    sent: list[httpx.Request] = []
    remaining = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if not remaining:
            raise AssertionError("transport sent more physical requests than the test authorized")
        return remaining.pop(0)

    recorder = recorder or _ProviderRecorder()
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=recorder,
    )
    return transport, recorder, sent


def _invoke(transport: OpenRouterTransport):
    return transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema=_VERDICT_SCHEMA,
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(_configuration()),
    )


def _body(content: str) -> dict:
    payload = _success().json()
    payload["choices"][0]["message"]["content"] = content
    return payload


def _invalid() -> httpx.Response:
    return httpx.Response(200, json=_body('{"unexpected":true}'))


def _valid() -> httpx.Response:
    return httpx.Response(200, json=_body(json.dumps({"verdict": "NO_EXPLOIT_OBSERVED"})))


# --------------------------------------------------------------------------------------
# The retryable case.
# --------------------------------------------------------------------------------------


def test_invalid_output_then_success_returns_the_valid_answer() -> None:
    transport, recorder, sent = _transport([_invalid(), _valid()])

    result = _invoke(transport)

    assert result.output == {"verdict": "NO_EXPLOIT_OBSERVED"}
    assert len(sent) == 2, "exactly one retry"
    assert [i.physical_sequence for i in recorder.invocations] == [1, 2]
    assert [e.status for e in recorder.events] == ["invalid_output", "succeeded"]


def test_the_failed_attempt_keeps_its_measured_identity_tokens_and_cost() -> None:
    """A retry must not erase the evidence that the first call happened and was charged."""

    transport, recorder, _sent = _transport([_invalid(), _valid()])

    _invoke(transport)

    failed = recorder.events[0]
    assert failed.status == "invalid_output"
    assert failed.physical_sequence == 1
    assert failed.returned_model == "google/gemini-2.5-pro"
    assert failed.upstream_provider == "Google"
    assert failed.provider_request_id
    assert failed.input_tokens == 30
    assert failed.output_tokens == 5
    assert failed.reasoning_tokens == 5
    assert failed.cost_measurement_state == "measured"
    assert failed.measured_cost_usd == Decimal("0.000065")


def test_retry_is_a_new_physical_call_under_the_same_logical_execution() -> None:
    transport, recorder, _sent = _transport([_invalid(), _valid()])

    _invoke(transport)

    first, second = recorder.invocations
    assert first.logical_execution_id == second.logical_execution_id
    assert first.campaign_attempt_id == second.campaign_attempt_id
    assert first.invocation_id != second.invocation_id
    assert (first.physical_sequence, second.physical_sequence) == (1, 2)


def test_logical_totals_include_both_measured_physical_calls() -> None:
    transport, _recorder, _sent = _transport([_invalid(), _valid()])

    result = _invoke(transport)

    assert result.physical_attempts == 2
    # Both calls were genuinely charged, so both must appear in the ledger.
    assert transport.ledger.snapshot.measured_usd == Decimal("0.00013")


def test_two_invalid_outputs_exhaust_the_retry_and_keep_the_typed_cause() -> None:
    transport, recorder, sent = _transport([_invalid(), _invalid()])

    with pytest.raises(HostedStructuredOutputInvalid) as raised:
        _invoke(transport)

    assert raised.value.code == "invalid_structured_output"
    assert len(sent) == 2, "the authorized retry is used exactly once, not repeatedly"
    assert [e.status for e in recorder.events] == ["invalid_output", "invalid_output"]
    assert [i.physical_sequence for i in recorder.invocations] == [1, 2]
    assert raised.value.observed_result.physical_attempts == 2


def test_exhaustion_does_not_collapse_into_a_generic_provider_error() -> None:
    """The operator must still see invalid_structured_output, not hosted-provider-unavailable."""

    transport, _recorder, _sent = _transport([_invalid(), _invalid()])

    with pytest.raises(HostedProviderError) as raised:
        _invoke(transport)

    assert isinstance(raised.value, HostedStructuredOutputInvalid)
    assert raised.value.code == "invalid_structured_output"
    assert "hosted-provider-unavailable" not in str(raised.value)


def test_a_provider_retry_never_produces_a_target_request() -> None:
    """Every request the transport makes goes to the provider host, never the target."""

    transport, _recorder, sent = _transport([_invalid(), _valid()])

    _invoke(transport)

    assert len(sent) == 2
    for request in sent:
        assert request.url.host == "openrouter.ai", request.url


def test_a_retry_blocked_by_the_call_cap_is_fatal_and_keeps_measurements() -> None:
    """Exhausted authority must stay campaign-fatal even though a format fault prompted the retry.

    Two things have to be true at once. Attempt 1 really was sent, measured and charged, so its
    tokens and cost must survive on the logical row. But the reason the run stopped is that its
    authorized envelope ran out — a fact about the whole campaign — so this must NOT arrive as the
    case-isolatable structured-output type, or the Runner would swallow budget exhaustion as a
    per-case formatting nuisance and keep going.
    """

    import dataclasses

    base = _configuration()
    # Exactly one call of authority: attempt 1 consumes it, attempt 2's reservation is refused.
    roles = tuple(
        dataclasses.replace(role, limits=dataclasses.replace(role.limits, max_calls=1))
        for role in base.roles
    )
    configuration = dataclasses.replace(
        base,
        roles=roles,
        global_limits=dataclasses.replace(base.global_limits, max_calls=1),
    )
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return _invalid()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedRetryAdmissionRefused) as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema=_VERDICT_SCHEMA,
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.code == "retry-admission-refused"
    # Campaign-fatal, NOT case-isolatable: the Runner's per-case handler must not catch this.
    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    # Attempt 1's measurements survive rather than being replaced by a measurement-free
    # reservation error.
    assert raised.value.observed_result.measured_cost_usd == Decimal("0.000065")
    # The cap breach is still visible, just not as the headline cause.
    assert isinstance(raised.value.__cause__, HostedBudgetExceeded)
    assert len(sent) == 1, "the refused retry must not reach the provider"


def _one_call_configuration():
    """A configuration whose call authority is exhausted by attempt 1."""

    import dataclasses

    base = _configuration()
    roles = tuple(
        dataclasses.replace(role, limits=dataclasses.replace(role.limits, max_calls=1))
        for role in base.roles
    )
    return dataclasses.replace(
        base,
        roles=roles,
        global_limits=dataclasses.replace(base.global_limits, max_calls=1),
    )


def _invoke_with(configuration, transport):
    return transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema=_VERDICT_SCHEMA,
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
    )


def test_a_retry_blocked_by_credential_loss_keeps_attempt_one_measurements() -> None:
    """Credential resolution runs before the send, so failing there consumes no authority."""

    configuration = _configuration()
    sent: list[httpx.Request] = []
    calls = {"n": 0}

    def credentials(_reference: str) -> Secret:
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("credential rotated away mid-campaign")
        return Secret("test-provider-value")

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return _invalid()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=credentials,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedRetryAdmissionRefused) as raised:
        _invoke_with(configuration, transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert raised.value.observed_result.measured_cost_usd == Decimal("0.000065")
    assert len(sent) == 1


def test_a_retry_blocked_by_lineage_failure_keeps_attempt_one_measurements() -> None:
    """The lineage recorder is the last gate before a retry is sent."""

    class _FailsSecondBegin(_ProviderRecorder):
        def begin_physical_attempt(self, logical_context, sequence):  # type: ignore[override]
            if sequence > 1:
                raise HostedProviderError("provider lineage is unavailable")
            return super().begin_physical_attempt(logical_context, sequence)

    configuration = _configuration()
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return _invalid()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_FailsSecondBegin(),
    )

    with pytest.raises(HostedRetryAdmissionRefused) as raised:
        _invoke_with(configuration, transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert raised.value.observed_result.measured_cost_usd == Decimal("0.000065")
    assert len(sent) == 1


def test_a_first_attempt_refusal_is_unchanged_and_carries_no_observed_result() -> None:
    """With nothing measured yet there is nothing to preserve; the original error passes through."""

    configuration = _configuration()

    def refuse(_reference: str) -> Secret:
        raise RuntimeError("credential unavailable")

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=refuse,
        client=httpx.Client(transport=httpx.MockTransport(lambda _r: _valid())),
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedProviderError) as raised:
        _invoke_with(configuration, transport)

    assert not isinstance(raised.value, HostedRetryAdmissionRefused)
    assert not isinstance(raised.value, HostedProviderResponseError)


# --------------------------------------------------------------------------------------
# Settlement failures are typed: a governed ceiling is not accounting corruption.
# --------------------------------------------------------------------------------------


def test_settlement_cost_cap_raises_the_budget_subtype() -> None:
    payload = _body(json.dumps({"verdict": "NO_EXPLOIT_OBSERVED"}))
    payload["usage"]["cost"] = 99.0
    transport, _recorder, sent = _transport([httpx.Response(200, json=payload)])

    with pytest.raises(HostedSettlementFailed) as raised:
        _invoke(transport)

    assert isinstance(raised.value, HostedSettlementBudgetExceeded)
    assert not isinstance(raised.value, HostedSettlementAccountingInvalid)
    assert isinstance(raised.value.__cause__, HostedBudgetExceeded)
    # A settlement failure is never a retryable formatting fault.
    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert len(sent) == 1


def test_the_two_settlement_subtypes_are_mutually_exclusive() -> None:
    assert issubclass(HostedSettlementBudgetExceeded, HostedSettlementFailed)
    assert issubclass(HostedSettlementAccountingInvalid, HostedSettlementFailed)
    assert not issubclass(HostedSettlementBudgetExceeded, HostedSettlementAccountingInvalid)
    assert not issubclass(HostedSettlementAccountingInvalid, HostedSettlementBudgetExceeded)
    # Both remain observable as charged responses, so their measurements are never lost.
    assert issubclass(HostedSettlementFailed, HostedProviderResponseError)


def test_no_authority_failure_is_ever_case_isolatable() -> None:
    """The Runner isolates exactly one type; every authority failure must fall outside it."""

    for authority_failure in (
        HostedRetryAdmissionRefused,
        HostedSettlementFailed,
        HostedSettlementBudgetExceeded,
        HostedSettlementAccountingInvalid,
        HostedBudgetExceeded,
    ):
        assert not issubclass(authority_failure, HostedStructuredOutputInvalid), authority_failure


# --------------------------------------------------------------------------------------
# Everything else still terminates on the first physical send.
# --------------------------------------------------------------------------------------


def test_model_substitution_never_retries() -> None:
    payload = _body(json.dumps({"verdict": "NO_EXPLOIT_OBSERVED"}))
    payload["model"] = "anthropic/claude-opus-4.8"
    transport, _recorder, sent = _transport([httpx.Response(200, json=payload)])

    with pytest.raises(HostedProviderResponseError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert len(sent) == 1, "a substituted model must not be sent a second time"


def test_unauthorized_route_never_retries() -> None:
    payload = _body(json.dumps({"verdict": "NO_EXPLOIT_OBSERVED"}))
    # The served upstream is read from the router metadata, not a top-level field.
    payload["openrouter_metadata"]["endpoints"]["available"][0]["provider"] = "Together"
    transport, _recorder, sent = _transport([httpx.Response(200, json=payload)])

    with pytest.raises(HostedProviderError, match="unauthorized provider route") as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert len(sent) == 1


def test_invalid_usage_accounting_never_retries() -> None:
    """Reasoning tokens outside the completion total is a measurement fault, not a format fault."""

    payload = _body(json.dumps({"verdict": "NO_EXPLOIT_OBSERVED"}))
    payload["usage"]["completion_tokens_details"]["reasoning_tokens"] = 999
    transport, _recorder, sent = _transport([httpx.Response(200, json=payload)])

    with pytest.raises(HostedProviderError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert len(sent) == 1


def test_a_duplicate_object_key_is_refused_not_retried() -> None:
    """Ambiguous output is a smuggling channel, not a formatting slip.

    A repeated key validates against the FIRST value while ``json.loads`` keeps the LAST, so the
    screened payload is not the stored payload. Retrying would re-offer that channel to an
    untrusted generator, so this must stay a terminal refusal even though it is, superficially,
    "the model returned bad JSON".
    """

    duplicate = '{"verdict": "NO_EXPLOIT_OBSERVED", "verdict": "EXPLOIT_CONFIRMED"}'
    transport, _recorder, sent = _transport([httpx.Response(200, json=_body(duplicate))])

    with pytest.raises(HostedProviderResponseError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert raised.value.code == "provider-structured-output-ambiguous"
    assert len(sent) == 1, "an ambiguous response must never be sent again"


def test_terminal_http_error_never_retries_as_structured_output() -> None:
    transport, _recorder, sent = _transport([httpx.Response(400, json={"error": "bad"})])

    with pytest.raises(HostedProviderError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert len(sent) == 1


def test_unknown_outcome_never_retries() -> None:
    """A response the transport cannot classify must fail closed on the first send."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("something the transport does not model")

    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedProviderError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)


def test_credential_failure_never_retries() -> None:
    configuration = _configuration()
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        sent.append(request)
        return _valid()

    def refuse(_reference: str) -> Secret:
        raise RuntimeError("credential unavailable")

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=refuse,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedProviderError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert sent == [], "no physical send may occur without a credential"


def test_budget_exhaustion_never_retries() -> None:
    """Settlement is checked before schema validation, so a cap breach cannot reach the retry."""

    from agentforge.providers.openrouter import HostedBudgetExceeded

    payload = _body(json.dumps({"verdict": "NO_EXPLOIT_OBSERVED"}))
    payload["usage"]["cost"] = 99.0
    transport, _recorder, sent = _transport([httpx.Response(200, json=payload)])

    with pytest.raises(HostedProviderError) as raised:
        _invoke(transport)

    assert not isinstance(raised.value, HostedStructuredOutputInvalid)
    assert isinstance(raised.value, HostedBudgetExceeded | HostedProviderResponseError)
    assert len(sent) == 1


def test_zero_authorized_retries_means_one_physical_call() -> None:
    """The deployed configuration had max_retries=0; the split must not invent authority."""

    import dataclasses

    base = _configuration()
    roles = tuple(
        dataclasses.replace(role, limits=dataclasses.replace(role.limits, max_retries=0))
        for role in base.roles
    )
    configuration = dataclasses.replace(
        base,
        roles=roles,
        global_limits=dataclasses.replace(base.global_limits, max_retries=0),
    )
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return _invalid()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedStructuredOutputInvalid):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema=_VERDICT_SCHEMA,
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert len(sent) == 1, "retry authority must come from configuration, never from the code path"
