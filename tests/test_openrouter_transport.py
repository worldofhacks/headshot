"""Offline tests for strict routing, retry, structured output, and shared accounting."""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.prompts import load_prompt_registry
from agentforge.providers.lineage import (
    ProviderInvocationContextV1,
    ProviderLogicalContextV1,
    ProviderTerminalEventV1,
    served_provider_matches_configured,
)
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


def _prompt(role: str):
    return next(record for record in load_prompt_registry() if record.role == role)


_USD_CAPS = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}
_PROMPTS = {record.role: record for record in load_prompt_registry()}
_TEST_INPUT_TOKEN_BOUND = 10_000


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _messages(
    *,
    role: str = "judge",
    user: str = "Judge.",
) -> tuple[dict[str, str], ...]:
    return (
        {
            "role": "system",
            "content": _prompt(role).content,  # type: ignore[arg-type]
        },
        {"role": "user", "content": user},
    )


def _configuration() -> HostedConfigurationSet:
    roles = tuple(
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=model,
            upstream_provider=upstream,
            completion_token_parameter="max_completion_tokens",
            credential_reference=f"secretref://production/openrouter/{role}/generation-1",
            prompt_sha256=_PROMPTS[role].sha256,
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


def _provider_context(
    configuration: HostedConfigurationSet,
    role_name: str = "judge",
) -> ProviderLogicalContextV1:
    role = next(item for item in configuration.roles if item.role == role_name)
    return ProviderLogicalContextV1(
        organization_id="org_lineage",
        campaign_run_id="run_lineage",
        campaign_attempt_id=None,
        logical_execution_id="execution_lineage",
        parent_execution_id=None,
        agent_role=role.role,
        requested_model=role.model_id,
        configured_upstream=role.upstream_provider,
        prompt_version=_prompt(role.role).version,
        prompt_sha256=_prompt(role.role).sha256,
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role.configuration_sha256,
        generation_policy_sha256=_digest("generation-policy"),
    )


class _ProviderRecorder:
    def __init__(self) -> None:
        self.invocations: list[ProviderInvocationContextV1] = []
        self.events: list[ProviderTerminalEventV1] = []

    def begin_physical_attempt(
        self,
        logical_context: ProviderLogicalContextV1,
        sequence: int,
    ) -> ProviderInvocationContextV1:
        invocation_id = _digest(
            f"{logical_context.organization_id}:{logical_context.logical_execution_id}:{sequence}"
        )
        invocation = ProviderInvocationContextV1(
            invocation_id=invocation_id,
            organization_id=logical_context.organization_id,
            campaign_run_id=logical_context.campaign_run_id,
            campaign_attempt_id=logical_context.campaign_attempt_id,
            logical_execution_id=logical_context.logical_execution_id,
            parent_execution_id=logical_context.parent_execution_id,
            agent_role=logical_context.agent_role,
            physical_sequence=sequence,
            idempotency_key=f"provider-call:{invocation_id}",
            requested_model=logical_context.requested_model,
            configured_upstream=logical_context.configured_upstream,
            prompt_version=logical_context.prompt_version,
            prompt_sha256=logical_context.prompt_sha256,
            configuration_set_sha256=logical_context.configuration_set_sha256,
            role_configuration_sha256=logical_context.role_configuration_sha256,
            generation_policy_sha256=logical_context.generation_policy_sha256,
            started_at=datetime.datetime.now(datetime.UTC),
        )
        self.invocations.append(invocation)
        return invocation

    def finish_physical_attempt(
        self,
        invocation: ProviderInvocationContextV1,
        event: ProviderTerminalEventV1,
    ) -> ProviderTerminalEventV1:
        assert event.invocation_id == invocation.invocation_id
        self.events.append(event)
        return event


class _AttemptObserver:
    def __init__(
        self,
        recorder: _ProviderRecorder,
        *,
        fail_start: bool = False,
        fail_finish: bool = False,
    ) -> None:
        self.recorder = recorder
        self.fail_start = fail_start
        self.fail_finish = fail_finish
        self.started: list[ProviderInvocationContextV1] = []
        self.finished: list[tuple[ProviderInvocationContextV1, ProviderTerminalEventV1]] = []

    def begin_provider_attempt(self, invocation: ProviderInvocationContextV1) -> None:
        self.started.append(invocation)
        if self.fail_start:
            raise RuntimeError("synthetic observer start failure")

    def finish_provider_attempt(
        self,
        invocation: ProviderInvocationContextV1,
        event: ProviderTerminalEventV1,
    ) -> None:
        # Projection completion is ordered after the append-only recorder.
        assert self.recorder.events[-1] == event
        self.finished.append((invocation, event))
        if self.fail_finish:
            raise RuntimeError("synthetic observer completion failure")


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


@pytest.mark.parametrize(
    "messages",
    (
        ({"role": "system", "content": "mutated system authority"},),
        (
            {"role": "system", "content": _prompt("judge").content},
            {"role": "system", "content": _prompt("judge").content},
        ),
    ),
)
def test_transport_rejects_mutated_prompt_before_any_side_effect(
    messages: tuple[dict[str, str], ...],
) -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    credential_calls = 0
    network_calls = 0

    def credential(_reference: str) -> Secret:
        nonlocal credential_calls
        credential_calls += 1
        return Secret("test-provider-value")

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=credential,
        client=httpx.Client(transport=httpx.MockTransport(send)),
        lineage_recorder=recorder,
    )
    with pytest.raises(HostedProviderError, match="immutable prompt authority"):
        transport.invoke(
            role="judge",
            messages=messages,
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert credential_calls == network_calls == 0
    assert recorder.invocations == recorder.events == []
    assert transport.ledger.snapshot.physical_calls == 0


def test_transport_rejects_wrong_prompt_version_before_any_side_effect() -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    context = replace(
        _provider_context(configuration),
        prompt_version="untrusted-version",
    )
    credential_calls = 0

    def credential(_reference: str) -> Secret:
        nonlocal credential_calls
        credential_calls += 1
        return Secret("test-provider-value")

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=credential,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: pytest.fail("wrong prompt version reached network")
            )
        ),
        lineage_recorder=recorder,
    )
    with pytest.raises(HostedProviderError, match="differs from authorization"):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=context,
        )
    assert credential_calls == 0
    assert recorder.invocations == recorder.events == []
    assert transport.ledger.snapshot.physical_calls == 0


def test_transport_rejects_encoded_input_above_authorized_bound_before_any_side_effect() -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    observer = _AttemptObserver(recorder)
    ledger = HostedUsageLedger(configuration)
    messages = _messages(user="Authorization-bound input.")
    conservative_bound = OpenRouterTransport._conservative_input_token_bound(messages)
    credential_calls = 0
    network_calls = 0

    def credential(_reference: str) -> Secret:
        nonlocal credential_calls
        credential_calls += 1
        return Secret("test-provider-value")

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=credential,
        client=httpx.Client(transport=httpx.MockTransport(send)),
        ledger=ledger,
        lineage_recorder=recorder,
        attempt_observer=observer,
    )

    with pytest.raises(HostedProviderError, match="authorization-bound input token ceiling"):
        transport.invoke(
            role="judge",
            messages=messages,
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=conservative_bound - 1,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert credential_calls == 0
    assert network_calls == 0
    assert ledger.snapshot.physical_calls == 0
    assert ledger.snapshot.measured_usd == 0
    assert ledger.snapshot.unresolved_exposure_usd == 0
    assert recorder.invocations == recorder.events == []
    assert observer.started == observer.finished == []


def test_ledger_rejects_unrepresentable_reservation_as_typed_provider_error() -> None:
    configuration = _configuration()
    hostile_price = Decimal("0." + ("1" * 300))
    judge = next(role for role in configuration.roles if role.role == "judge")
    hostile_judge = replace(
        judge,
        prices=TokenPrices(
            input_usd_per_million_tokens=hostile_price,
            output_usd_per_million_tokens=Decimal("2"),
            reasoning_usd_per_million_tokens=Decimal("3"),
        ),
    )
    configuration = replace(
        configuration,
        roles=tuple(
            hostile_judge if role.role == "judge" else role for role in configuration.roles
        ),
    )
    ledger = HostedUsageLedger(configuration)

    with pytest.raises(HostedProviderError, match="cannot be represented exactly"):
        ledger.reserve(
            "judge",
            input_tokens=1,
            output_tokens=0,
            reasoning_tokens=0,
        )

    assert ledger.snapshot.physical_calls == 0
    assert ledger.snapshot.measured_usd == 0
    assert ledger.snapshot.unresolved_exposure_usd == 0


@pytest.mark.parametrize("authorization_headroom", (0, 1))
def test_transport_accepts_encoded_input_at_or_below_authorized_bound(
    authorization_headroom: int,
) -> None:
    configuration = _configuration()
    messages = _messages(user="Authorization-bound input.")
    conservative_bound = OpenRouterTransport._conservative_input_token_bound(messages)
    credential_calls = 0
    network_calls = 0

    def credential(_reference: str) -> Secret:
        nonlocal credential_calls
        credential_calls += 1
        return Secret("test-provider-value")

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=credential,
        client=httpx.Client(transport=httpx.MockTransport(send)),
    )

    result = transport.invoke(
        role="judge",
        messages=messages,
        output_schema={
            "type": "object",
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
            "additionalProperties": False,
        },
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=conservative_bound + authorization_headroom,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
    )

    assert result.request_id == "gen-1"
    assert credential_calls == 1
    assert network_calls == 1
    assert transport.ledger.snapshot.physical_calls == 1


@pytest.mark.parametrize(
    ("configured", "served", "expected"),
    (
        ("atlas-cloud", "AtlasCloud", True),
        ("atlas-cloud/fp8", "AtlasCloud", True),
        ("amazon-bedrock/eu-west-1", "Amazon Bedrock", True),
        ("azure/eu", "Azure", True),
        ("atlas-cloud", "Together", False),
    ),
)
def test_served_provider_normalization_includes_atlas_cloud(
    configured: str,
    served: str,
    expected: bool,
) -> None:
    assert served_provider_matches_configured(configured, served) is expected


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
        messages=_messages(user="Return a verdict."),
        output_schema={
            "type": "object",
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
            "additionalProperties": False,
        },
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
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


def test_transport_sends_only_hash_bound_max_tokens_parameter() -> None:
    configuration = _configuration()
    judge = next(role for role in configuration.roles if role.role == "judge")
    max_tokens_judge = replace(judge, completion_token_parameter="max_tokens")
    configuration = replace(
        configuration,
        roles=tuple(
            max_tokens_judge if role.role == "judge" else role for role in configuration.roles
        ),
    )
    seen: list[httpx.Request] = []
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: seen.append(request) or _success())
        ),
    )

    transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
    )

    payload = __import__("json").loads(seen[0].content)
    assert payload["max_tokens"] == 70
    assert "max_completion_tokens" not in payload


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
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
    )

    assert result.physical_attempts == 2
    assert transport.ledger.snapshot.physical_calls == 2
    assert transport.ledger.snapshot.unresolved_exposure_usd > 0
    assert sleeps == [2.0]


def test_transport_records_each_actual_send_and_retry_as_physical_facts() -> None:
    responses = iter(
        [
            httpx.Response(503, headers={"Retry-After": "0"}),
            _success("gen-lineage-after-retry"),
        ]
    )
    configuration = _configuration()
    recorder = _ProviderRecorder()
    monotonic_values = iter((0.0, 0.0, 2.0))
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(lambda _request: next(responses))),
        lineage_recorder=recorder,
        sleeper=lambda _seconds: None,
        monotonic=lambda: next(monotonic_values),
    )

    result = transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
    )

    assert result.physical_attempts == 2
    assert [item.physical_sequence for item in recorder.invocations] == [1, 2]
    assert [item.campaign_attempt_id for item in recorder.invocations] == [None, None]
    assert [item.status for item in recorder.events] == [
        "retryable_failure",
        "succeeded",
    ]
    assert [item.cost_measurement_state for item in recorder.events] == [
        "not_observed",
        "measured",
    ]
    assert recorder.events[1].measured_cost_usd == Decimal("0.000065")


def test_attempt_observer_tracks_success_and_retry_in_physical_order() -> None:
    responses = iter(
        [
            httpx.Response(503, headers={"Retry-After": "0"}),
            _success("gen-observed-after-retry"),
        ]
    )
    configuration = _configuration()
    recorder = _ProviderRecorder()
    observer = _AttemptObserver(recorder)
    monotonic_values = iter((0.0, 0.0, 2.0))
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(lambda _request: next(responses))),
        lineage_recorder=recorder,
        attempt_observer=observer,
        sleeper=lambda _seconds: None,
        monotonic=lambda: next(monotonic_values),
    )

    result = transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
    )

    assert result.physical_attempts == 2
    assert [item.physical_sequence for item in observer.started] == [1, 2]
    assert [item[1].status for item in observer.finished] == [
        "retryable_failure",
        "succeeded",
    ]


def test_attempt_observer_start_failure_prevents_http_and_retry() -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    observer = _AttemptObserver(recorder, fail_start=True)
    network_calls = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(send)),
        lineage_recorder=recorder,
        attempt_observer=observer,
    )
    with pytest.raises(HostedProviderError, match="observation could not start") as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 1
    assert network_calls == 0
    assert len(recorder.invocations) == 1
    assert [event.status for event in recorder.events] == ["terminal_failure"]
    assert len(observer.started) == 1
    assert observer.finished == []


def test_attempt_observer_completion_failure_after_send_never_retries() -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    observer = _AttemptObserver(recorder, fail_finish=True)
    network_calls = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(send)),
        lineage_recorder=recorder,
        attempt_observer=observer,
    )
    with pytest.raises(HostedProviderError, match="observation could not complete") as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 1
    assert network_calls == 1
    assert [event.status for event in recorder.events] == ["succeeded"]
    assert len(observer.finished) == 1


def test_q_generator_with_a_recorder_refuses_before_network_without_logical_context() -> None:
    seen: list[httpx.Request] = []
    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: seen.append(request) or _success())
        ),
        lineage_recorder=recorder,
    )

    with pytest.raises(HostedProviderError, match="lineage context"):
        transport.invoke(
            role="red_team",
            messages=_messages(
                role="red_team",
                user="Generate a synthetic attack.",
            ),
            output_schema={"type": "object"},
            schema_name="generated_attack",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    assert seen == []
    assert recorder.invocations == []
    assert recorder.events == []


def test_unrepresentable_provider_cost_is_invalid_not_rounded() -> None:
    payload = _success().json()
    payload["usage"]["cost"] = "0.0000000000001"
    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
        ),
        lineage_recorder=recorder,
    )

    with pytest.raises(HostedProviderError, match="storage precision"):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert len(recorder.events) == 1
    assert recorder.events[0].status == "invalid_usage"
    assert recorder.events[0].cost_measurement_state == "invalid"
    assert recorder.events[0].measured_cost_usd is None


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
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )

    assert raised.value.physical_attempts == 2
    assert transport.ledger.snapshot.physical_calls == 2
    assert transport.ledger.snapshot.measured_usd == 0


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

    with pytest.raises(HostedProviderError, match="different model") as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )
    assert raised.value.physical_attempts == 1


def test_transport_records_served_provider_substitution_as_invalid_output() -> None:
    payload = _success().json()
    payload["openrouter_metadata"]["endpoints"]["available"][0]["provider"] = "Together"
    configuration = _configuration()
    recorder = _ProviderRecorder()
    observer = _AttemptObserver(recorder)
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
        ),
        lineage_recorder=recorder,
        attempt_observer=observer,
    )

    with pytest.raises(HostedProviderError, match="unauthorized provider route") as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 1
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "invalid_output"
    assert event.upstream_provider == "Together"
    assert event.returned_model == "google/gemini-2.5-pro"
    assert event.provider_request_id == "gen-1"
    assert event.cost_measurement_state == "measured"
    assert event.measured_cost_usd == Decimal("0.000065")
    assert [item[1].status for item in observer.finished] == ["invalid_output"]


def test_retry_then_pacing_failure_preserves_durable_attempt_count() -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    clock_calls = 0

    def monotonic() -> float:
        nonlocal clock_calls
        clock_calls += 1
        if clock_calls == 1:
            return 0.0
        raise RuntimeError("synthetic clock failure")

    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(503, headers={"Retry-After": "0"})
            )
        ),
        lineage_recorder=recorder,
        monotonic=monotonic,
    )

    with pytest.raises(HostedProviderError, match="pacing failed") as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 1
    assert [event.status for event in recorder.events] == ["retryable_failure"]


def test_retry_then_credential_failure_preserves_durable_attempt_count() -> None:
    configuration = _configuration()
    recorder = _ProviderRecorder()
    ledger = HostedUsageLedger(configuration)
    credential_calls = 0

    def credential_resolver(_reference: str) -> Secret:
        nonlocal credential_calls
        credential_calls += 1
        if credential_calls == 1:
            return Secret("test-provider-value")
        raise RuntimeError("synthetic credential resolution failure")

    monotonic_values = iter((0.0, 2.0))
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=credential_resolver,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(503, headers={"Retry-After": "0"})
            )
        ),
        lineage_recorder=recorder,
        ledger=ledger,
        monotonic=lambda: next(monotonic_values),
    )

    with pytest.raises(HostedProviderError, match="credential reference is unavailable") as raised:
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 1
    assert [event.status for event in recorder.events] == ["retryable_failure"]
    assert ledger.snapshot.physical_calls == 1


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (
            lambda payload: payload["openrouter_metadata"]["endpoints"]["available"].append(
                {
                    "provider": "Google",
                    "model": "google/gemini-2.5-pro",
                    "selected": True,
                }
            ),
            "unique selected endpoint",
        ),
        (
            lambda payload: payload["openrouter_metadata"]["endpoints"]["available"][0].update(
                {"model": "google/gemini-flash"}
            ),
            "different endpoint model",
        ),
    ),
)
def test_transport_requires_one_exact_selected_router_endpoint(
    mutate: object,
    message: str,
) -> None:
    payload = _success().json()
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

    with pytest.raises(HostedProviderError, match=message):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
        )


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
            messages=_messages(),
            output_schema={
                "type": "object",
                "properties": {"verdict": {"type": "string"}},
                "required": ["verdict"],
                "additionalProperties": False,
            },
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
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
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=_TEST_INPUT_TOKEN_BOUND,
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
