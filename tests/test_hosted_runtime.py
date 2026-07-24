"""Network-free four-role composition and deterministic-Judge precedence tests."""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any

import pytest

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.agents.hosted_runtime import (
    HostedCallBounds,
    HostedCompositionError,
    HostedFourRoleRuntime,
)
from agentforge.providers.openrouter import OpenRouterResult
from agentforge.target.spec import HostedRunBinding


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _configuration() -> HostedConfigurationSet:
    values = {
        "orchestrator": ("anthropic/claude-opus-4.8", "Anthropic", 8),
        "red_team": ("qwen/qwen3.5-397b-a17b", "Together", 21),
        "judge": ("google/gemini-2.5-pro", "Google", 21),
        "documentation": ("openai/gpt-5.4", "OpenAI", 6),
    }
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=model,
                upstream_provider=provider,
                credential_reference=f"secretref://production/openrouter/{role}/generation-1",
                prompt_sha256=hosted_prompt(role).prompt_sha256,
                policy_sha256=_digest(f"{role}:policy"),
                prices=TokenPrices(Decimal("1"), Decimal("2"), Decimal("3")),
                limits=HostedLimits(
                    max_calls=calls,
                    max_input_tokens=10000,
                    max_output_tokens=10000,
                    max_reasoning_tokens=10000,
                    max_usd=Decimal("5"),
                    max_retries=1,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
            for role, (model, provider, calls) in values.items()
        ),
        global_limits=HostedLimits(
            max_calls=56,
            max_input_tokens=40000,
            max_output_tokens=40000,
            max_reasoning_tokens=40000,
            max_usd=Decimal("5"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


class _FakeTransport:
    def __init__(
        self,
        configuration: HostedConfigurationSet,
        outputs: dict[str, dict[str, Any]],
    ) -> None:
        self.configuration = configuration
        self.outputs = outputs
        self.calls: list[str] = []
        self.invocations: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> OpenRouterResult:
        role = kwargs["role"]
        self.calls.append(role)
        self.invocations.append(dict(kwargs))
        configuration = next(item for item in self.configuration.roles if item.role == role)
        return OpenRouterResult(
            output=self.outputs[role],
            requested_model=configuration.model_id,
            returned_model=configuration.model_id,
            upstream_provider=configuration.upstream_provider,
            request_id=f"provider-request-{role}",
            input_tokens=10,
            output_tokens=5,
            reasoning_tokens=2,
            measured_cost_usd=Decimal("0.01"),
            configuration_sha256=self.configuration.configuration_sha256,
            role_configuration_sha256=configuration.configuration_sha256,
            generation_policy_sha256=kwargs["generation_policy_sha256"],
            physical_attempts=1,
        )


def _outputs(*, judge_state: str = "NO_EXPLOIT_OBSERVED") -> dict[str, dict[str, Any]]:
    return {
        "orchestrator": {"case_ref": "case-1", "directive": "Exercise the bound case."},
        "red_team": {
            "schema_version": "1",
            "case_ref": "case-1",
            "input_sequence": ["Use only synthetic fixture data."],
            "category": "prompt_injection",
            "attack_class": "boundary",
            "owasp_mappings": ["LLM01:2025", "A03:2021"],
        },
        "judge": {
            "state": judge_state,
            "explanation": "Hosted assessment.",
            "calibrated": True,
        },
        "documentation": {
            "title": "Synthetic finding",
            "summary": "A bounded synthetic finding.",
            "severity": "high",
            "reproduction_steps": ["Replay the exact synthetic case."],
        },
    }


def _runtime(
    *,
    outputs: dict[str, dict[str, Any]],
    target: Any,
    recorded: list[Any],
    deterministic_verdict: dict[str, Any] | None = None,
) -> tuple[HostedFourRoleRuntime, _FakeTransport]:
    configuration = _configuration()
    transport = _FakeTransport(configuration, outputs)
    authorization = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_digest("generation-policy"),
        session_generation="generation-1",
        provider_model_call_limit=56,
        provider_model_spend_limit_usd="5",
        provider_max_retries=1,
        provider_max_concurrency=1,
        provider_timeout_seconds=10,
    )
    runtime = HostedFourRoleRuntime(
        configuration=configuration,
        transport=transport,
        authorization=authorization,
        call_bounds={role.role: HostedCallBounds(100, 50, 25, 10) for role in configuration.roles},
        policy_gateway_dispatch=target,
        deterministic_judge=lambda _attempt, _evidence: (
            deterministic_verdict or {"state": "NO_EXPLOIT_OBSERVED"}
        ),
        lineage_recorder=recorded.append,
    )
    return runtime, transport


def test_runtime_refuses_configuration_not_bound_by_campaign_authorization() -> None:
    configuration = _configuration()
    transport = _FakeTransport(configuration, _outputs())
    authorization = HostedRunBinding(
        configuration_set_sha256="f" * 64,
        generation_policy_sha256=_digest("generation-policy"),
        session_generation="generation-1",
        provider_model_call_limit=56,
        provider_model_spend_limit_usd="5",
        provider_max_retries=1,
        provider_max_concurrency=1,
        provider_timeout_seconds=10,
    )

    with pytest.raises(HostedCompositionError, match="campaign authorization"):
        HostedFourRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=authorization,
            call_bounds={
                role.role: HostedCallBounds(100, 50, 25, 10) for role in configuration.roles
            },
            policy_gateway_dispatch=lambda _attempt: {},
            deterministic_judge=lambda _attempt, _evidence: {"state": "NO_EXPLOIT_OBSERVED"},
        )


def test_confirmed_deterministic_exploit_cannot_be_laundered_safe_and_docs_stay_draft() -> None:
    target_calls: list[dict[str, Any]] = []
    recorded: list[Any] = []
    runtime, transport = _runtime(
        outputs=_outputs(judge_state="NO_EXPLOIT_OBSERVED"),
        target=lambda attempt: (
            target_calls.append(dict(attempt)) or {"status_code": 200, "canary_observed": True}
        ),
        recorded=recorded,
        deterministic_verdict={
            "state": "EXPLOIT_CONFIRMED",
            "canary_triggered": True,
            "oracle": "synthetic-canary",
        },
    )

    outcome = runtime.run_attempt(authorized_case={"case_id": "case-1"})

    assert transport.calls == ["orchestrator", "red_team", "judge", "documentation"]
    assert len(target_calls) == 1
    assert outcome.verdict["state"] == "EXPLOIT_CONFIRMED"
    assert outcome.verdict["deterministic_precedence"] is True
    assert outcome.documentation_draft is not None
    assert outcome.documentation_draft["draft_unpublished"] is True
    assert outcome.documentation_draft["publication_status"] == "blocked_pending_human_approval"
    assert len(outcome.lineage) == len(recorded) == 4
    assert outcome.lineage[1].parent_request_id == "provider-request-orchestrator"
    assert outcome.lineage[2].parent_request_id == "provider-request-red_team"
    assert all(item.requested_model == item.returned_model for item in outcome.lineage)


def test_runtime_sends_the_exact_registry_prompt_as_the_system_message() -> None:
    runtime, transport = _runtime(
        outputs=_outputs(judge_state="EXPLOIT_LIKELY"),
        target=lambda _attempt: {"status_code": 200},
        recorded=[],
    )

    runtime.run_attempt(authorized_case={"case_id": "case-1"})

    assert transport.calls == ["orchestrator", "red_team", "judge", "documentation"]
    for invocation in transport.invocations:
        role = invocation["role"]
        prompt = hosted_prompt(role)
        messages = invocation["messages"]
        assert messages[0] == {
            "role": "system",
            "content": prompt.system_prompt,
        }
        assert messages[1]["role"] == "user"
        configured = next(item for item in transport.configuration.roles if item.role == role)
        assert configured.prompt_sha256 == prompt.prompt_sha256


def test_deterministic_error_remains_error_and_skips_documentation() -> None:
    runtime, transport = _runtime(
        outputs=_outputs(judge_state="EXPLOIT_LIKELY"),
        target=lambda _attempt: {"status_code": 500},
        recorded=[],
        deterministic_verdict={"state": "ERROR", "reason": "oracle unavailable"},
    )

    outcome = runtime.run_attempt(authorized_case={"case_id": "case-1"})

    assert outcome.verdict["state"] == "ERROR"
    assert outcome.documentation_draft is None
    assert transport.calls == ["orchestrator", "red_team", "judge"]


def test_case_identity_drift_is_refused_before_policy_gateway_dispatch() -> None:
    outputs = _outputs()
    outputs["red_team"]["case_ref"] = "case-other"
    target_calls: list[dict[str, Any]] = []
    runtime, _transport = _runtime(
        outputs=outputs,
        target=lambda attempt: target_calls.append(dict(attempt)) or {},
        recorded=[],
    )

    with pytest.raises(HostedCompositionError, match="authorized case"):
        runtime.run_attempt(authorized_case={"case_id": "case-1"})
    assert target_calls == []
