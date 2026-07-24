"""Offline tests for strict routing, retry, structured output, and shared accounting."""

from __future__ import annotations

import hashlib
from decimal import Decimal

import httpx
import pytest

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.providers.openrouter import (
    HostedBudgetExceeded,
    HostedProviderError,
    HostedProviderResponseError,
    HostedUsageLedger,
    OpenRouterTransport,
)
from agentforge.secrets import Secret

_MODELS = {
    "orchestrator": ("anthropic/claude-opus-4.8", "anthropic", 9),
    "red_team": ("qwen/qwen3.5-397b-a17b", "together", 19),
    "judge": ("google/gemini-2.5-pro", "google-vertex", 19),
    "documentation": ("openai/gpt-5.4", "openai", 9),
}
_USD_CAPS = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _configuration() -> HostedConfigurationSet:
    roles = tuple(
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=model,
            upstream_provider=upstream,
            credential_reference=f"secretref://production/openrouter/{role}/generation-1",
            prompt_sha256=hosted_prompt(role).prompt_sha256,
            policy_sha256=_digest(f"{role}:policy"),
            prices=TokenPrices(
                input_usd_per_million_tokens=Decimal("1"),
                output_usd_per_million_tokens=Decimal("2"),
                reasoning_usd_per_million_tokens=Decimal("3"),
            ),
            limits=HostedLimits(
                max_calls=calls,
                max_input_tokens=100_000,
                max_output_tokens=100_000,
                max_reasoning_tokens=100_000,
                max_usd=_USD_CAPS[role],
                max_retries=1,
                max_requests_per_second=Decimal("0.5"),
                max_concurrency=1,
            ),
        )
        for role, (model, upstream, calls) in _MODELS.items()
    )
    return HostedConfigurationSet(
        roles=roles,
        global_limits=HostedLimits(
            max_calls=56,
            max_input_tokens=400_000,
            max_output_tokens=400_000,
            max_reasoning_tokens=400_000,
            max_usd=Decimal("5"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _success(request_id: str = "gen-1") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": request_id,
            "model": "google/gemini-2.5-pro",
            "openrouter_metadata": {
                "requested": "google/gemini-2.5-pro",
                "endpoints": {
                    "available": [
                        {
                            "provider": "Google",
                            "model": "google/gemini-2.5-pro",
                            "selected": True,
                            "additive_future_field": "ignored",
                        }
                    ]
                },
                "additive_future_field": {"ignored": True},
            },
            "choices": [{"message": {"content": '{"verdict":"NO_EXPLOIT_OBSERVED"}'}}],
            "usage": {
                "prompt_tokens": 30,
                "completion_tokens": 10,
                "completion_tokens_details": {"reasoning_tokens": 5},
                "cost": 0.000065,
            },
        },
    )


def test_transport_disables_fallback_and_verifies_usage_and_identity() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _success()

    client = httpx.Client(transport=httpx.MockTransport(handler))
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )
    result = transport.invoke(
        role="judge",
        messages=({"role": "system", "content": "Return a verdict."},),
        output_schema={
            "type": "object",
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
            "additionalProperties": False,
        },
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
    )

    payload = __import__("json").loads(seen[0].content)
    assert seen[0].headers["X-OpenRouter-Metadata"] == "enabled"
    assert payload["model"] == "google/gemini-2.5-pro"
    assert "models" not in payload
    assert "max_tokens" not in payload
    assert payload["max_completion_tokens"] == 70
    assert payload["provider"] == {
        "only": ["google-vertex"],
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "max_price": {"prompt": 1.0, "completion": 2.0, "request": 0},
    }
    assert payload["reasoning"] == {"max_tokens": 20}
    assert payload["response_format"]["json_schema"]["strict"] is True
    assert result.request_id == "gen-1"
    assert result.requested_model == result.returned_model
    assert result.upstream_provider == "Google"
    assert result.output_tokens == 5
    assert result.reasoning_tokens == 5
    assert result.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.physical_calls == 1
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert "test-provider-value" not in repr(result)


def test_transport_permits_only_one_retry_and_counts_both_physical_calls() -> None:
    responses = iter(
        [
            httpx.Response(503, headers={"Retry-After": "0"}),
            _success("gen-after-retry"),
        ]
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda _request: next(responses)))
    sleeps: list[float] = []
    monotonic_values = iter((0.0, 0.0, 2.0))
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        sleeper=sleeps.append,
        monotonic=lambda: next(monotonic_values),
    )

    result = transport.invoke(
        role="judge",
        messages=({"role": "user", "content": "Judge."},),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
    )

    assert result.physical_attempts == 2
    assert transport.ledger.snapshot.physical_calls == 2
    assert transport.ledger.snapshot.unresolved_exposure_usd > 0
    assert sleeps == [2.0]


def test_retry_exhaustion_exposes_consumed_physical_attempts_without_inventing_usage() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(503, headers={"Retry-After": "0"})
        )
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        sleeper=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )

    with pytest.raises(HostedProviderError, match="authorized retry") as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    assert raised.value.physical_attempts == 2
    assert transport.ledger.snapshot.physical_calls == 2
    assert transport.ledger.snapshot.measured_usd == 0


def test_transport_refuses_a_substituted_model_but_carries_the_observation_out() -> None:
    """A served model that is not the authorized one must leave the transport as evidence.

    This is the only path that can actually observe a substitution. Raising before the
    observation is built would destroy the record here, below everything downstream.
    """

    payload = _success().json()
    # A coherent substitution: the provider says it served a different model and its router
    # metadata agrees, while "requested" still records what we actually asked for.
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    failure = raised.value
    assert failure.code == "provider-model-substituted"
    assert failure.physical_attempts == 1
    observed = failure.observed_result
    # Both identities survive, and they are distinguishable.
    assert observed.requested_model == "google/gemini-2.5-pro"
    assert observed.returned_model == "google/gemini-flash"
    assert observed.request_id == "gen-1"
    assert observed.upstream_provider == "Google"
    # The refused call was still billed, so its usage is settled rather than left dangling.
    assert observed.measured_cost_usd > 0
    assert transport.ledger.snapshot.measured_usd == observed.measured_cost_usd


@pytest.mark.parametrize(
    ("mutate", "label"),
    (
        (lambda usage: usage.update({"completion_tokens": 400}), "usage overruns the reservation"),
        (lambda usage: usage.update({"cost": 9.5}), "cost breaches the role cap"),
    ),
)
def test_a_substituted_call_still_surrenders_its_observation_when_settle_fails(
    mutate: object,
    label: str,
) -> None:
    """settle() raises on provider-controlled input, and that must not swallow the evidence.

    The request pins max_price to the AUTHORIZED model's price, so a router that serves a
    different model is exactly the case that breaches the cap. If that path lost the observation,
    a substitution would be indistinguishable from an ordinary budget refusal.
    """

    payload = _success().json()
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    assert callable(mutate)
    mutate(payload["usage"])
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert observed.requested_model == "google/gemini-2.5-pro"
    assert observed.returned_model == "google/gemini-flash", label


def test_an_unusable_served_model_is_recorded_as_a_substitution_not_discarded() -> None:
    """An absent or unusable served model must still leave a record.

    Refusing it is right; treating it as a reason to throw away the identity, the request id and
    the billed cost would let the provider erase a substitution by returning junk.
    """

    payload = _success().json()
    payload["model"] = None
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert raised.value.code == "provider-model-substituted"
    assert observed.requested_model == "google/gemini-2.5-pro"
    assert observed.returned_model.startswith("unsafe-provider-text-")


@pytest.mark.parametrize(
    ("mutate", "label"),
    (
        (
            lambda payload: payload["openrouter_metadata"]["endpoints"]["available"].append(
                {"provider": "Google", "model": "google/gemini-2.5-pro", "selected": True}
            ),
            "two selected endpoints",
        ),
        (
            lambda payload: payload["openrouter_metadata"].__setitem__("endpoints", None),
            "endpoint list unreadable",
        ),
        (
            lambda payload: payload.__setitem__("openrouter_metadata", None),
            "router metadata absent",
        ),
        (
            lambda payload: payload["openrouter_metadata"].__setitem__("requested", "  other  "),
            "router echoes a different request",
        ),
        (
            lambda payload: payload["openrouter_metadata"]["endpoints"]["available"][0].update(
                {"provider": ""}
            ),
            "endpoint provider empty",
        ),
        (
            lambda payload: payload["openrouter_metadata"]["endpoints"]["available"][0].update(
                {"model": 42}
            ),
            "endpoint model not a string",
        ),
    ),
)
def test_unreadable_router_metadata_is_refused_but_never_erases_the_record(
    mutate: object,
    label: str,
) -> None:
    """Router metadata is entirely provider-controlled, so it must not be a delete switch.

    Each of these once raised before the observation existed, so a genuine substitution plus one
    malformed metadata field lost the served identity, the typed code and the billed charge
    together — the same defect as a padded model name, in a field the earlier fix did not reach.
    """

    payload = _success().json()
    payload["model"] = "google/gemini-flash"
    assert callable(mutate)
    mutate(payload)
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert raised.value.code == "provider-model-substituted", label
    assert observed.requested_model == "google/gemini-2.5-pro"
    # The billed charge survives, and every stored string is one the store will accept.
    assert observed.measured_cost_usd > 0
    for value, maximum in (
        (observed.returned_model, 160),
        (observed.upstream_provider, 64),
        (observed.request_id, 256),
    ):
        assert value and value == value.strip() and len(value) <= maximum, label


def test_charged_invalid_output_exposes_exact_observed_usage() -> None:
    payload = _success().json()
    payload["choices"][0]["message"]["content"] = '{"unexpected":true}'
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(
        HostedProviderResponseError,
        match="measured usage was observed",
    ) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={
                "type": "object",
                "properties": {"verdict": {"type": "string"}},
                "required": ["verdict"],
                "additionalProperties": False,
            },
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert observed.output == {}
    assert observed.returned_model == "google/gemini-2.5-pro"
    assert observed.upstream_provider == "Google"
    assert observed.input_tokens == 30
    assert observed.output_tokens == 5
    assert observed.reasoning_tokens == 5
    assert observed.measured_cost_usd == Decimal("0.000065")
    assert observed.physical_attempts == 1
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")


def test_transport_rejects_reasoning_outside_completion_total() -> None:
    payload = _success().json()
    payload["usage"]["completion_tokens_details"]["reasoning_tokens"] = 11
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderError, match="reasoning token accounting"):
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )


def test_shared_ledger_hard_stops_at_fifty_six_physical_calls() -> None:
    configuration = _configuration()
    ledger = HostedUsageLedger(configuration)
    for role, (_model, _provider, count) in _MODELS.items():
        for _ in range(count):
            reservation = ledger.reserve(
                role,  # type: ignore[arg-type]
                input_tokens=0,
                output_tokens=0,
                reasoning_tokens=0,
            )
            ledger.settle(
                reservation,
                measured_cost=Decimal(0),
                input_tokens=0,
                output_tokens=0,
                reasoning_tokens=0,
            )

    assert ledger.snapshot.physical_calls == 56
    with pytest.raises(HostedBudgetExceeded):
        ledger.reserve(
            "orchestrator",
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )


def test_shared_ledger_restores_durable_usage_before_new_reservations() -> None:
    ledger = HostedUsageLedger(_configuration())
    ledger.restore(
        "judge",
        physical_calls=18,
        measured_usd=Decimal("3.5"),
        input_tokens=50,
        output_tokens=25,
        reasoning_tokens=10,
    )

    reservation = ledger.reserve(
        "judge",
        input_tokens=100,
        output_tokens=50,
        reasoning_tokens=20,
    )
    ledger.settle(
        reservation,
        measured_cost=Decimal("0.1"),
        input_tokens=40,
        output_tokens=20,
        reasoning_tokens=5,
    )

    assert ledger.snapshot.physical_calls == 19
    assert ledger.snapshot.measured_usd == Decimal("3.6")
    with pytest.raises(HostedProviderError, match="more than once"):
        ledger.restore(
            "judge",
            physical_calls=1,
            measured_usd=Decimal("0"),
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )


def test_shared_ledger_refuses_persisted_usage_over_a_role_subcap() -> None:
    ledger = HostedUsageLedger(_configuration())

    with pytest.raises(HostedBudgetExceeded, match="persisted hosted usage"):
        ledger.restore(
            "documentation",
            physical_calls=1,
            measured_usd=Decimal("1.01"),
            input_tokens=1,
            output_tokens=1,
            reasoning_tokens=1,
        )


@pytest.mark.parametrize(
    ("hostile", "label"),
    (
        ("  google/gemini-flash  ", "padded name the control-plane store would reject"),
        ("google/gemini-flash\nevil=1", "interior newline bound for the audit log"),
        ("sk-or-v1-abcdefghijklmnop", "a name shaped like a provider key"),
        ("google/gemini-flash" + "x" * 200, "a name longer than the column"),
    ),
)
def test_a_provider_cannot_erase_its_substitution_by_choosing_the_name(
    hostile: str,
    label: str,
) -> None:
    """The served model is provider-chosen, so it must never be usable as a delete switch.

    Each of these previously destroyed the record somewhere downstream — the runtime lineage
    guard, or the control-plane store, whose rules disagreed with each other.
    """

    payload = _success().json()
    payload["model"] = hostile
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = hostile
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert raised.value.code == "provider-model-substituted", label
    # Normalized to something every downstream validator accepts, and still a substitution.
    assert observed.returned_model == observed.returned_model.strip()
    assert len(observed.returned_model) <= 160
    assert observed.returned_model != observed.requested_model
    assert hostile not in observed.returned_model
    # The billed usage is still settled and carried.
    assert observed.measured_cost_usd > 0


def test_a_hostile_upstream_provider_name_cannot_erase_the_record() -> None:
    """The same switch existed on upstream_provider, which had no length bound at all."""

    payload = _success().json()
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["provider"] = "G" * 76
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert len(observed.upstream_provider) <= 64
    assert observed.returned_model == "google/gemini-flash"


@pytest.mark.parametrize(
    ("cost", "label"),
    (
        ("NaN", "not a number"),
        ("Infinity", "infinite"),
        (-1, "negative"),
        (None, "null"),
        ("abc", "not numeric"),
        ({"amount": 1}, "wrong type"),
        ("1E+400", "beyond the column's magnitude"),
        ("0.0000000000001", "finer than the column's quantum"),
    ),
)
def test_an_unusable_cost_never_erases_the_observation(cost: object, label: str) -> None:
    """Cost is provider-chosen, so it must not be able to refuse the whole record either.

    It is not one of the seven columns agent_execution_hosted_measurement_tuple binds together,
    and the schema models an unusable amount as cost_measurement_state='invalid' with a NULL
    value — so the identity and usage that WERE observed must survive it.
    """

    payload = _success().json()
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    payload["usage"]["cost"] = cost
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderResponseError) as raised:
        transport.invoke(
            role="judge",
            messages=({"role": "user", "content": "Judge."},),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    observed = raised.value.observed_result
    assert raised.value.code == "provider-model-substituted", label
    assert observed.returned_model == "google/gemini-flash", label
    assert observed.input_tokens == 30 and observed.output_tokens == 5
    # Unknown, never a fabricated zero.
    assert observed.measured_cost_usd is None, label


def test_a_sub_quantum_cost_is_unknown_rather_than_rounded_to_zero() -> None:
    """A charge finer than NUMERIC(20, 12) is a real amount, not a free call.

    Rounding it down would record the fabricated zero the unknown-cost invariant exists to
    forbid, and an honest response must not strand its execution either.
    """

    payload = _success().json()
    payload["usage"]["cost"] = "0.0000000000001"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    result = transport.invoke(
        role="judge",
        messages=({"role": "user", "content": "Judge."},),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
    )

    # The honest call still succeeds, and its cost is unknown rather than zero.
    assert result.returned_model == "google/gemini-2.5-pro"
    assert result.measured_cost_usd is None
