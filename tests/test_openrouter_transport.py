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
from agentforge.providers.openrouter import (
    HostedBudgetExceeded,
    HostedProviderError,
    HostedUsageLedger,
    OpenRouterTransport,
)
from agentforge.secrets import Secret

_MODELS = {
    "orchestrator": ("anthropic/claude-opus-4.8", "Anthropic", 8),
    "red_team": ("qwen/qwen3.5-397b-a17b", "Together", 21),
    "judge": ("google/gemini-2.5-pro", "Google", 21),
    "documentation": ("openai/gpt-5.4", "OpenAI", 6),
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
            prompt_sha256=_digest(f"{role}:prompt"),
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
                max_usd=Decimal("5"),
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
            "provider": "Google",
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
    assert payload["model"] == "google/gemini-2.5-pro"
    assert "models" not in payload
    assert payload["provider"] == {
        "only": ["Google"],
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


def test_transport_fails_closed_on_model_or_provider_substitution() -> None:
    response = _success()
    payload = response.json()
    payload["model"] = "google/gemini-flash"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    transport = OpenRouterTransport(
        configuration=_configuration(),
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
    )

    with pytest.raises(HostedProviderError, match="different model"):
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
