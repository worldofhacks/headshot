"""Offline tests for strict routing, retry, structured output, and shared accounting."""

from __future__ import annotations

import datetime
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
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
    normalize_provider_observation,
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
_USD_CAPS = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}
_PROMPTS = {record.role: record for record in load_prompt_registry()}


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
            "content": _PROMPTS[role].content,  # type: ignore[arg-type]
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
        prompt_version=_PROMPTS[role.role].version,
        prompt_sha256=_PROMPTS[role.role].sha256,
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


class _FailingBeginRecorder(_ProviderRecorder):
    def begin_physical_attempt(
        self,
        logical_context: ProviderLogicalContextV1,
        sequence: int,
    ) -> ProviderInvocationContextV1:
        raise RuntimeError("synthetic durable reservation failure")


class _WrongReceiptRecorder(_ProviderRecorder):
    def __init__(self, field_name: str, value: object) -> None:
        super().__init__()
        self._field_name = field_name
        self._value = value

    def begin_physical_attempt(
        self,
        logical_context: ProviderLogicalContextV1,
        sequence: int,
    ) -> ProviderInvocationContextV1:
        invocation = super().begin_physical_attempt(logical_context, sequence)
        return replace(invocation, **{self._field_name: self._value})


def test_transport_cannot_be_constructed_without_physical_lineage_recorder() -> None:
    network_calls = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    with pytest.raises(TypeError, match="lineage_recorder"):
        OpenRouterTransport(  # type: ignore[call-arg]
            configuration=_configuration(),
            credential_resolver=lambda _reference: Secret("test-provider-value"),
            client=httpx.Client(transport=httpx.MockTransport(send)),
        )
    assert network_calls == 0


def test_invalid_recorder_is_rejected_before_default_client_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_allocations = 0

    def allocate_client(*_args: object, **_kwargs: object) -> httpx.Client:
        nonlocal client_allocations
        client_allocations += 1
        pytest.fail("invalid composition allocated a default HTTP client")

    monkeypatch.setattr(httpx, "Client", allocate_client)
    with pytest.raises(TypeError, match="lineage recorder"):
        OpenRouterTransport(
            configuration=_configuration(),
            credential_resolver=lambda _reference: Secret("test-provider-value"),
            lineage_recorder=object(),  # type: ignore[arg-type]
        )
    assert client_allocations == 0


@pytest.mark.parametrize(
    "hostile_identity",
    (
        "Bear" + "er " + "abcdefghijklmnop",
        "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456",
        "github_" + "pat_" + "abcdefghijklmnopqrstuvwxyz123456",
        "gl" + "pat-abcdefghijklmnopqrstuvwxyz123456",
        "AK" + "IAABCDEFGHIJKLMNOP",
        "AI" + "za" + "abcdefghijklmnopqrstuvwxyz123456",
        "ya" + "29." + "abcdefghijklmnopqrstuvwxyz123456",
        "xo" + "xb-" + "1234567890-abcdefghijklmnop",
        "postgresql:" + "//user:" + "password@" + "host/db",
    ),
)
def test_provider_identity_credentials_are_digested_not_persisted(
    hostile_identity: str,
) -> None:
    normalized, valid = normalize_provider_observation(
        hostile_identity,
        field_name="provider_request_id",
        maximum=256,
    )

    assert valid is False
    assert normalized.startswith("unsafe-provider-text-")
    assert hostile_identity not in normalized


@pytest.mark.parametrize(
    "safe_identity",
    (
        "google/gemini-2.5-pro",
        "Google Vertex",
        "gen-01HFABC_123",
        "openai/gpt-5.4",
    ),
)
def test_safe_provider_identity_round_trips_without_normalization(
    safe_identity: str,
) -> None:
    normalized, valid = normalize_provider_observation(
        safe_identity,
        field_name="provider_request_id",
        maximum=256,
    )

    assert valid is True
    assert normalized == safe_identity


def test_transport_does_not_send_when_physical_reservation_fails() -> None:
    network_calls = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(send)),
        lineage_recorder=_FailingBeginRecorder(),
    )

    with pytest.raises(HostedProviderError, match="could not be durably reserved"):
        _invoke_judge(transport)

    assert network_calls == 0


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    (
        ("organization_id", "org_other"),
        ("campaign_run_id", "run_other"),
        ("campaign_attempt_id", "attempt_other"),
        ("logical_execution_id", "execution_other"),
        ("parent_execution_id", "execution_parent"),
        ("agent_role", "red_team"),
        ("requested_model", "openai/gpt-5.4"),
        ("configured_upstream", "openai"),
        ("prompt_version", "v-other"),
        ("prompt_sha256", _digest("other-prompt")),
        ("configuration_set_sha256", _digest("other-configuration")),
        ("role_configuration_sha256", _digest("other-role")),
        ("generation_policy_sha256", _digest("other-policy")),
    ),
)
def test_transport_rejects_wrong_physical_receipt_before_network(
    field_name: str,
    wrong_value: object,
) -> None:
    network_calls = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return _success()

    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(send)),
        lineage_recorder=_WrongReceiptRecorder(field_name, wrong_value),
    )

    with pytest.raises(HostedProviderError, match="invalid identity"):
        _invoke_judge(transport)

    assert network_calls == 0


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


def _invoke_judge(transport: OpenRouterTransport) -> object:
    configuration = _configuration()
    return transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
    )


@pytest.mark.parametrize(
    "messages",
    (
        ({"role": "system", "content": "mutated system authority"},),
        (
            {"role": "system", "content": _PROMPTS["judge"].content},
            {"role": "system", "content": _PROMPTS["judge"].content},
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


@pytest.mark.parametrize(
    ("configured", "served", "expected"),
    (
        ("atlas-cloud", "AtlasCloud", True),
        ("atlas-cloud/fp8", "AtlasCloud", True),
        ("atlas-cloud", "Together", False),
        ("digitalocean", "DigitalOcean", True),
        ("digitalocean", "Together", False),
    ),
)
def test_served_provider_normalization_includes_authorized_routes(
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
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=_ProviderRecorder(),
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
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
    )

    payload = __import__("json").loads(seen[0].content)
    assert seen[0].headers["X-OpenRouter-Metadata"] == "enabled"
    assert payload["model"] == "google/gemini-2.5-pro"
    assert "models" not in payload
    # The completion cap must be sent as `max_tokens`. `provider.require_parameters` is true, and
    # OpenRouter endpoints advertise `max_tokens` (never `max_completion_tokens`) in
    # `supported_parameters` — sending the latter matches no endpoint and fails routing with 404.
    assert "max_completion_tokens" not in payload
    assert payload["max_tokens"] == 70
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


def test_red_team_request_and_reservation_stay_at_4096_while_accounting_accepts_overage() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "id": "gen-red-team-overage",
                "model": "qwen/qwen3.5-397b-a17b",
                "openrouter_metadata": {
                    "requested": "qwen/qwen3.5-397b-a17b",
                    "endpoints": {
                        "available": [
                            {
                                "provider": "Together",
                                "model": "qwen/qwen3.5-397b-a17b",
                                "selected": True,
                            }
                        ]
                    },
                },
                "choices": [{"message": {"content": '{"case_ref":"case-1"}'}}],
                "usage": {
                    "prompt_tokens": 303,
                    "completion_tokens": 5_120,
                    "completion_tokens_details": {"reasoning_tokens": 4_846},
                    "cost": 0.012660655,
                },
            },
        )

    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=_ProviderRecorder(),
    )

    result = transport.invoke(
        role="red_team",
        messages=_messages(role="red_team", user="Select one exact case."),
        output_schema={
            "type": "object",
            "properties": {"case_ref": {"type": "string", "enum": ["case-1"]}},
            "required": ["case_ref"],
            "additionalProperties": False,
        },
        schema_name="red_team_reviewed_case_selection",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=4_096,
        max_output_tokens=1_024,
        max_reasoning_tokens=4_096,
        timeout_seconds=60,
        provider_context=_provider_context(configuration, "red_team"),
    )

    payload = __import__("json").loads(seen[0].content)
    assert payload["max_tokens"] == 5_120
    assert payload["reasoning"] == {"max_tokens": 4_096}
    assert result.output == {"case_ref": "case-1"}
    assert result.output_tokens == 274
    assert result.reasoning_tokens == 4_846


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
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=_ProviderRecorder(),
        sleeper=sleeps.append,
        monotonic=lambda: next(monotonic_values),
    )

    result = transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
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
        input_tokens_upper_bound=100,
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
            input_tokens_upper_bound=100,
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
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert len(recorder.events) == 1
    assert recorder.events[0].status == "invalid_usage"
    assert recorder.events[0].cost_measurement_state == "invalid"
    assert recorder.events[0].measured_cost_usd is None
    assert recorder.events[0].input_tokens == 30
    assert recorder.events[0].output_tokens == 5
    assert recorder.events[0].reasoning_tokens == 5


def test_retry_exhaustion_exposes_consumed_physical_attempts_without_inventing_usage() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(503, headers={"Retry-After": "0"})
        )
    )
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=_ProviderRecorder(),
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
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 2
    assert transport.ledger.snapshot.physical_calls == 2
    assert transport.ledger.snapshot.measured_usd == 0


def test_transport_records_and_settles_coherent_model_substitution() -> None:
    response = _success()
    payload = response.json()
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=recorder,
    )

    with pytest.raises(
        HostedProviderResponseError,
        match="other than the authorized one",
    ) as raised:
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
            provider_context=_provider_context(configuration),
        )
    assert raised.value.physical_attempts == 1
    assert raised.value.code == "provider-model-substituted"
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "model_mismatch"
    assert event.error_code == "returned_model_mismatch"
    assert event.returned_model == "google/gemini-flash"
    assert event.upstream_provider == "Google"
    assert event.provider_request_id == "gen-1"
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


@pytest.mark.parametrize(
    ("role_name", "selected_provider", "selected_model"),
    (
        (
            "orchestrator",
            "Anthropic",
            "anthropic/claude-4.8-opus-20260528",
        ),
        (
            "red_team",
            "Together",
            "qwen/qwen3.5-397b-a17b-20260216",
        ),
        (
            "documentation",
            "OpenAI",
            "openai/gpt-5.4-20260305",
        ),
    ),
)
def test_transport_accepts_reviewed_provider_canonical_endpoint_model(
    role_name: str,
    selected_provider: str,
    selected_model: str,
) -> None:
    configuration = _configuration()
    role = next(item for item in configuration.roles if item.role == role_name)
    payload = _success().json()
    payload["model"] = role.model_id
    payload["openrouter_metadata"]["requested"] = role.model_id
    endpoint = payload["openrouter_metadata"]["endpoints"]["available"][0]
    endpoint["provider"] = selected_provider
    endpoint["model"] = selected_model
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
        ),
        lineage_recorder=recorder,
    )

    result = transport.invoke(
        role=role.role,
        messages=_messages(role=role_name),
        output_schema={"type": "object"},
        schema_name=f"{role_name}_output",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration, role_name),
    )

    assert result.returned_model == role.model_id
    assert result.upstream_provider == selected_provider
    assert recorder.events[0].status == "succeeded"


def test_transport_rejects_unreviewed_provider_canonical_endpoint_model() -> None:
    payload = _success().json()
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = (
        "google/gemini-2.5-pro-unreviewed"
    )
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

    with pytest.raises(HostedProviderError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == "provider-identity-invalid"
    assert recorder.events[0].status == "identity_invalid"


def test_transport_records_served_provider_substitution_as_invalid_output() -> None:
    payload = _success().json()
    payload["openrouter_metadata"]["endpoints"]["available"][0]["provider"] = "Together"
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

    with pytest.raises(HostedProviderError, match="unauthorized provider route") as raised:
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
            provider_context=_provider_context(configuration),
        )

    assert raised.value.physical_attempts == 1
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "route_unauthorized"
    assert event.error_code == "provider_route_unauthorized"
    assert event.upstream_provider == "Together"
    assert event.returned_model == "google/gemini-2.5-pro"
    assert event.provider_request_id == "gen-1"
    assert event.cost_measurement_state == "measured"
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


@pytest.mark.parametrize(
    "malformed_model",
    (
        None,
        "google/gemini-2.5-pro ",
        "google/gemini-2.5-pro\n",
        "sk-or-" + ("a" * 32),
        "unsafe-provider-text-" + ("a" * 32),
        "m" * 193,
    ),
)
def test_malformed_returned_model_is_digested_recorded_and_charged(
    malformed_model: object,
) -> None:
    payload = _success().json()
    payload["model"] = malformed_model
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

    with pytest.raises(HostedProviderError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == "provider-identity-invalid"
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "identity_invalid"
    assert event.error_code == "provider_identity_invalid"
    assert event.returned_model.startswith("unsafe-provider-text-")
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


@pytest.mark.parametrize(
    "malformed_request_id",
    (
        None,
        "",
        " gen-1",
        "gen-1\n",
        "sk-or-" + ("b" * 32),
        "unsafe-provider-text-" + ("b" * 32),
        "r" * 257,
    ),
)
def test_malformed_request_id_is_digested_recorded_and_charged(
    malformed_request_id: object,
) -> None:
    payload = _success().json()
    payload["id"] = malformed_request_id
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

    with pytest.raises(HostedProviderError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == "provider-identity-invalid"
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "identity_invalid"
    assert event.error_code == "provider_identity_invalid"
    assert event.provider_request_id.startswith("unsafe-provider-text-")
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


@pytest.mark.parametrize(
    ("malformed_upstream", "expected_code"),
    (
        (None, "provider-identity-invalid"),
        ("", "provider-identity-invalid"),
        (" Google", "provider-identity-invalid"),
        ("Google\n", "provider-identity-invalid"),
        ("sk-or-" + ("c" * 32), "provider-identity-invalid"),
        ("unsafe-provider-text-" + ("c" * 32), "provider-identity-invalid"),
        ("u" * 129, "provider-identity-invalid"),
        ("Together", "provider-route-unauthorized"),
    ),
)
def test_malformed_or_unauthorized_upstream_is_recorded_and_charged(
    malformed_upstream: object,
    expected_code: str,
) -> None:
    payload = _success().json()
    payload["openrouter_metadata"]["endpoints"]["available"][0]["provider"] = malformed_upstream
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

    with pytest.raises(HostedProviderError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == expected_code
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == (
        "route_unauthorized"
        if expected_code == "provider-route-unauthorized"
        else "identity_invalid"
    )
    assert event.error_code == (
        "provider_route_unauthorized"
        if expected_code == "provider-route-unauthorized"
        else "provider_identity_invalid"
    )
    if malformed_upstream == "Together":
        assert event.upstream_provider == "Together"
    else:
        assert event.upstream_provider.startswith("unsafe-provider-text-")
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


def test_malformed_router_requested_identity_is_recorded_and_charged() -> None:
    payload = _success().json()
    payload["openrouter_metadata"]["requested"] = "google/gemini-2.5-pro "
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

    with pytest.raises(HostedProviderError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == "provider-identity-invalid"
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "identity_invalid"
    assert event.error_code == "provider_identity_invalid"
    assert event.upstream_provider == "Google"
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


def test_model_substitution_wins_after_measured_cost_overrun_is_reconciled() -> None:
    payload = _success().json()
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    payload["usage"]["cost"] = "4.1"
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

    with pytest.raises(HostedProviderResponseError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == "provider-model-substituted"
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "model_mismatch"
    assert event.measured_cost_usd == Decimal("4.100000000000")
    assert transport.ledger.snapshot.measured_usd == Decimal("4.100000000000")
    assert transport.ledger.snapshot.unresolved_exposure_usd == 0


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
            input_tokens_upper_bound=100,
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
            input_tokens_upper_bound=100,
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
            "invalid provider identity",
        ),
        (
            lambda payload: payload["openrouter_metadata"]["endpoints"]["available"][0].update(
                {"model": "google/gemini-flash"}
            ),
            "invalid provider identity",
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
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedProviderError, match=message):
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
            provider_context=_provider_context(configuration),
        )


def test_charged_invalid_output_exposes_exact_observed_usage() -> None:
    payload = _success().json()
    payload["choices"][0]["message"]["content"] = '{"unexpected":true}'
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=_ProviderRecorder(),
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
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
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
    configuration = _configuration()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=client,
        lineage_recorder=_ProviderRecorder(),
    )

    with pytest.raises(HostedProviderError, match="reasoning token accounting"):
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
            provider_context=_provider_context(configuration),
        )


@pytest.mark.parametrize(
    ("mutate_usage", "expected_tokens"),
    (
        (
            lambda usage: usage.update({"prompt_tokens": 2_147_483_648}),
            (None, 5, 5),
        ),
        (
            lambda usage: usage.update({"completion_tokens": 2_147_483_648}),
            (30, None, 5),
        ),
        (
            lambda usage: usage["completion_tokens_details"].update(
                {"reasoning_tokens": 2_147_483_648}
            ),
            (30, None, None),
        ),
    ),
)
def test_unstorable_provider_token_count_records_one_invalid_usage_event(
    mutate_usage: object,
    expected_tokens: tuple[int | None, int | None, int | None],
) -> None:
    payload = _success().json()
    assert callable(mutate_usage)
    mutate_usage(payload["usage"])
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

    with pytest.raises(HostedProviderError, match="token accounting"):
        _invoke_judge(transport)

    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "invalid_usage"
    assert event.error_code == "invalid_provider_usage"
    assert event.returned_model == "google/gemini-2.5-pro"
    assert event.upstream_provider == "Google"
    assert event.provider_request_id == "gen-1"
    assert (event.input_tokens, event.output_tokens, event.reasoning_tokens) == expected_tokens
    assert event.cost_measurement_state == "partial"
    assert event.measured_cost_usd == Decimal("0.000065")
    assert transport.ledger.snapshot.measured_usd == 0
    assert transport.ledger.snapshot.unresolved_exposure_usd > 0


def test_model_substitution_precedes_invalid_usage_without_losing_identity() -> None:
    payload = _success().json()
    payload["model"] = "google/gemini-flash"
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = "google/gemini-flash"
    payload["usage"]["cost"] = "not-a-cost"
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

    with pytest.raises(HostedProviderError) as raised:
        _invoke_judge(transport)

    assert raised.value.code == "provider-model-substituted"
    assert len(recorder.invocations) == len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "model_mismatch"
    assert event.returned_model == "google/gemini-flash"
    assert event.upstream_provider == "Google"
    assert event.provider_request_id == "gen-1"
    assert event.cost_measurement_state == "invalid"
    assert event.measured_cost_usd is None
    assert (event.input_tokens, event.output_tokens, event.reasoning_tokens) == (30, 5, 5)


def test_present_non_object_token_details_are_not_laundered_to_zero_reasoning() -> None:
    payload = _success().json()
    payload["usage"]["completion_tokens_details"] = "not-an-object"
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

    with pytest.raises(HostedProviderError, match="token accounting"):
        _invoke_judge(transport)

    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event.status == "invalid_usage"
    assert event.input_tokens == 30
    assert event.output_tokens is None
    assert event.reasoning_tokens is None
    assert event.cost_measurement_state == "partial"
    assert event.measured_cost_usd == Decimal("0.000065")


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


def test_shared_ledger_reservation_is_single_use() -> None:
    ledger = HostedUsageLedger(_configuration())
    reservation = ledger.reserve(
        "judge",
        input_tokens=100,
        output_tokens=50,
        reasoning_tokens=20,
    )
    ledger.settle(
        reservation,
        measured_cost=Decimal("0.1"),
        input_tokens=30,
        output_tokens=5,
        reasoning_tokens=5,
    )
    settled = ledger.snapshot

    with pytest.raises(HostedProviderError, match="already settled"):
        ledger.settle(
            reservation,
            measured_cost=Decimal("0.1"),
            input_tokens=30,
            output_tokens=5,
            reasoning_tokens=5,
        )

    assert ledger.snapshot == settled


def test_shared_ledger_rejects_foreign_reservation_without_mutation() -> None:
    first = HostedUsageLedger(_configuration())
    second = HostedUsageLedger(_configuration())
    reservation = first.reserve(
        "judge",
        input_tokens=100,
        output_tokens=50,
        reasoning_tokens=20,
    )
    first_before = first.snapshot
    second_before = second.snapshot

    with pytest.raises(HostedProviderError, match="reservation is invalid"):
        second.settle(
            reservation,
            measured_cost=Decimal("0.1"),
            input_tokens=30,
            output_tokens=5,
            reasoning_tokens=5,
        )

    assert first.snapshot == first_before
    assert second.snapshot == second_before


def test_shared_ledger_concurrent_double_settlement_has_one_winner() -> None:
    ledger = HostedUsageLedger(_configuration())
    reservation = ledger.reserve(
        "judge",
        input_tokens=100,
        output_tokens=50,
        reasoning_tokens=20,
    )
    barrier = threading.Barrier(2)

    def settle_once() -> str:
        barrier.wait()
        try:
            ledger.settle(
                reservation,
                measured_cost=Decimal("0.1"),
                input_tokens=30,
                output_tokens=5,
                reasoning_tokens=5,
            )
        except HostedProviderError:
            return "rejected"
        return "settled"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = (executor.submit(settle_once), executor.submit(settle_once))
        results = sorted(future.result() for future in outcomes)

    assert results == ["rejected", "settled"]
    assert ledger.snapshot.physical_calls == 1
    assert ledger.snapshot.measured_usd == Decimal("0.1")
    assert ledger.snapshot.unresolved_exposure_usd == 0


def test_shared_ledger_accepts_per_call_overrun_below_aggregate_caps() -> None:
    ledger = HostedUsageLedger(_configuration())
    reservation = ledger.reserve(
        "judge",
        input_tokens=100,
        output_tokens=50,
        reasoning_tokens=20,
    )

    ledger.settle(
        reservation,
        measured_cost=Decimal("0.1"),
        input_tokens=101,
        output_tokens=51,
        reasoning_tokens=21,
    )
    reconciled = ledger.snapshot
    assert reconciled.measured_usd == Decimal("0.1")
    assert reconciled.unresolved_exposure_usd == 0

    with pytest.raises(HostedProviderError, match="already settled"):
        ledger.settle(
            reservation,
            measured_cost=Decimal("0.1"),
            input_tokens=101,
            output_tokens=51,
            reasoning_tokens=21,
        )

    assert ledger.snapshot == reconciled


def test_shared_ledger_true_aggregate_overrun_is_consumed_and_rejected() -> None:
    ledger = HostedUsageLedger(_configuration())
    reservation = ledger.reserve(
        "judge",
        input_tokens=100,
        output_tokens=50,
        reasoning_tokens=20,
    )

    with pytest.raises(HostedBudgetExceeded, match="token cap"):
        ledger.settle(
            reservation,
            measured_cost=Decimal("0.1"),
            input_tokens=100_001,
            output_tokens=5,
            reasoning_tokens=5,
        )
    reconciled = ledger.snapshot
    assert reconciled.measured_usd == Decimal("0.1")
    assert reconciled.unresolved_exposure_usd == 0

    with pytest.raises(HostedProviderError, match="already settled"):
        ledger.settle(
            reservation,
            measured_cost=Decimal("0.1"),
            input_tokens=100_001,
            output_tokens=5,
            reasoning_tokens=5,
        )

    assert ledger.snapshot == reconciled
