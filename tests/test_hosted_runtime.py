"""Network-free four-role composition and deterministic-Judge precedence tests."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_runtime import (
    HostedCallBounds,
    HostedCompositionError,
    HostedFourRoleRuntime,
    HostedRoleRuntime,
    hosted_judge_identity,
)
from agentforge.agents.judge import CalibrationGate
from agentforge.agents.prompts import load_prompt_registry
from agentforge.providers.lineage import ProviderLogicalContextV1
from agentforge.providers.openrouter import HostedUsageEnvelope, OpenRouterResult
from agentforge.target.spec import HostedRunBinding

_GROUND_TRUTH = Path(__file__).resolve().parents[1] / "evals" / "ground-truth"
_PROMPTS = {record.role: record for record in load_prompt_registry()}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _configuration() -> HostedConfigurationSet:
    values = {
        "orchestrator": ("anthropic/claude-opus-4.8", "anthropic", 9),
        "red_team": ("qwen/qwen3.5-397b-a17b", "together", 19),
        "judge": ("google/gemini-2.5-pro", "google-vertex", 19),
        "documentation": ("openai/gpt-5.4", "openai", 9),
    }
    usd_caps = {
        "orchestrator": Decimal("1.5"),
        "red_team": Decimal("1"),
        "judge": Decimal("4"),
        "documentation": Decimal("1"),
    }
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=model,
                upstream_provider=provider,
                credential_reference=f"secretref://production/openrouter/{role}/generation-1",
                prompt_sha256=_PROMPTS[role].sha256,
                policy_sha256=_digest(f"{role}:policy"),
                prices=TokenPrices(Decimal("1"), Decimal("2"), Decimal("3")),
                limits=HostedLimits(
                    max_calls=calls,
                    max_input_tokens=10000,
                    max_output_tokens=10000,
                    max_reasoning_tokens=10000,
                    max_usd=usd_caps[role],
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
        self.usage_envelope_sha256: str | None = None

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


class _FakeExecutionLifecycle:
    def __init__(self, recorded: list[Any] | None = None) -> None:
        self.recorded = recorded if recorded is not None else []
        self.starts: list[dict[str, Any]] = []
        self.finishes: list[dict[str, Any]] = []

    def start(self, **values: Any) -> str:
        self.starts.append(dict(values))
        return f"execution-{values['role']}"

    def finish(self, **values: Any) -> None:
        self.finishes.append(dict(values))
        if values["status"] == "succeeded":
            self.recorded.append(values["lineage"])

    def provider_context(self, **values: Any) -> ProviderLogicalContextV1:
        start = next(
            item for item in self.starts if f"execution-{item['role']}" == values["execution_id"]
        )
        return ProviderLogicalContextV1(
            organization_id="org-hosted-runtime",
            campaign_run_id="run-hosted-runtime",
            campaign_attempt_id=None,
            logical_execution_id=values["execution_id"],
            parent_execution_id=start["parent_execution_id"],
            agent_role=start["role"],
            requested_model=start["model"],
            configured_upstream=start["upstream_provider"],
            prompt_version=values["prompt_version"],
            prompt_sha256=values["prompt_sha256"],
            configuration_set_sha256=start["configuration_sha256"],
            role_configuration_sha256=start["role_configuration_sha256"],
            generation_policy_sha256=start["generation_policy_sha256"],
        )


def _contained_usage_envelope(
    configuration: HostedConfigurationSet,
) -> HostedUsageEnvelope:
    return HostedUsageEnvelope(
        role_limits={
            role.role: HostedLimits(
                max_calls=1,
                max_input_tokens=100,
                max_output_tokens=50,
                max_reasoning_tokens=25,
                max_usd=role.limits.max_usd,
                max_retries=0,
                max_requests_per_second=Decimal("0.5"),
                max_concurrency=1,
            )
            for role in configuration.roles
        },
        global_limits=HostedLimits(
            max_calls=4,
            max_input_tokens=400,
            max_output_tokens=200,
            max_reasoning_tokens=100,
            max_usd=Decimal("5"),
            max_retries=0,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
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
        },
        "documentation": {
            "title": "Synthetic finding",
            "summary": "A bounded synthetic finding.",
            "severity": "high",
            "reproduction_steps": ["Replay the exact synthetic case."],
        },
    }


class _ExpectedVerdictEvaluator:
    def __init__(self, slices: list[dict[str, Any]]) -> None:
        self._expected = {
            label["label_id"]: copy.deepcopy(label["expected_verdict"])
            for item in slices
            for label in item["labels"]
        }

    def evaluate(
        self,
        envelope: dict[str, Any],
        *,
        integrity_ok: bool = True,
    ) -> dict[str, Any]:
        assert integrity_ok is True
        return copy.deepcopy(self._expected[envelope["trusted"]["ground_truth_ref"]])


@lru_cache(maxsize=1)
def _enabled_judge_calibration() -> dict[str, Any]:
    """Create a real passing calibration for this network-free runtime test fixture."""

    slices = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(_GROUND_TRUTH.glob("*.json"))
    ]
    identity = hosted_judge_identity(_configuration())
    gate = CalibrationGate(evaluator=_ExpectedVerdictEvaluator(slices))
    result = gate.evaluate(slices=slices, identity=identity)
    return gate.human_enable(
        result,
        current_identity=identity,
        approver_ref="test-human-reviewer",
    )


def _runtime(
    *,
    outputs: dict[str, dict[str, Any]],
    target: Any,
    recorded: list[Any],
    deterministic_verdict: dict[str, Any] | None = None,
    lifecycle: _FakeExecutionLifecycle | None = None,
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
        execution_lifecycle=lifecycle or _FakeExecutionLifecycle(recorded),
        judge_calibration=_enabled_judge_calibration(),
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
            execution_lifecycle=_FakeExecutionLifecycle(),
        )


def test_role_runtime_accepts_only_a_transport_enforced_contained_sub_envelope() -> None:
    configuration = _configuration()
    envelope = _contained_usage_envelope(configuration)
    transport = _FakeTransport(configuration, _outputs())
    authorization = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_digest("generation-policy"),
        session_generation="acceptance-1",
        provider_model_call_limit=4,
        provider_model_spend_limit_usd="5",
        provider_max_retries=0,
        provider_max_concurrency=1,
        provider_timeout_seconds=10,
    )
    call_bounds = {role.role: HostedCallBounds(100, 50, 25, 10) for role in configuration.roles}

    with pytest.raises(HostedCompositionError, match="transport does not enforce"):
        HostedRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=authorization,
            call_bounds=call_bounds,
            execution_lifecycle=_FakeExecutionLifecycle(),
            usage_envelope=envelope,
        )

    transport.usage_envelope_sha256 = envelope.envelope_sha256
    HostedRoleRuntime(
        configuration=configuration,
        transport=transport,
        authorization=authorization,
        call_bounds=call_bounds,
        execution_lifecycle=_FakeExecutionLifecycle(),
        usage_envelope=envelope,
    )

    oversized = HostedUsageEnvelope(
        role_limits=envelope.role_limits,
        global_limits=replace(envelope.global_limits, max_calls=57),
    )
    transport.usage_envelope_sha256 = oversized.envelope_sha256
    with pytest.raises(HostedCompositionError, match="sub-envelope exceeds"):
        HostedRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=replace(authorization, provider_model_call_limit=57),
            call_bounds=call_bounds,
            execution_lifecycle=_FakeExecutionLifecycle(),
            usage_envelope=oversized,
        )


def test_runtime_refuses_model_judge_without_exact_human_enabled_calibration() -> None:
    configuration = _configuration()
    transport = _FakeTransport(configuration, _outputs())
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

    with pytest.raises(HostedCompositionError, match="calibration gate is closed"):
        HostedFourRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=authorization,
            call_bounds={
                role.role: HostedCallBounds(100, 50, 25, 10) for role in configuration.roles
            },
            policy_gateway_dispatch=lambda _attempt: {},
            deterministic_judge=lambda _attempt, _evidence: {"state": "NO_EXPLOIT_OBSERVED"},
            execution_lifecycle=_FakeExecutionLifecycle(),
        )

    assert transport.calls == []


def test_runtime_refuses_hosted_provider_without_mandatory_execution_lifecycle() -> None:
    configuration = _configuration()
    transport = _FakeTransport(configuration, _outputs())
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

    with pytest.raises(HostedCompositionError, match="dependency is unavailable"):
        HostedFourRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=authorization,
            call_bounds={
                role.role: HostedCallBounds(100, 50, 25, 10) for role in configuration.roles
            },
            policy_gateway_dispatch=lambda _attempt: {},
            deterministic_judge=lambda _attempt, _evidence: {"state": "NO_EXPLOIT_OBSERVED"},
            execution_lifecycle=None,  # type: ignore[arg-type]
            judge_calibration=_enabled_judge_calibration(),
        )

    assert transport.calls == []


def test_provider_failure_is_terminally_recorded_before_it_propagates() -> None:
    class FailingTransport(_FakeTransport):
        def invoke(self, **kwargs: Any) -> OpenRouterResult:
            if kwargs["role"] == "red_team":
                self.calls.append("red_team")
                raise RuntimeError("bounded provider failure")
            return super().invoke(**kwargs)

    configuration = _configuration()
    transport = FailingTransport(configuration, _outputs())
    lifecycle = _FakeExecutionLifecycle()
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
        policy_gateway_dispatch=lambda _attempt: {},
        deterministic_judge=lambda _attempt, _evidence: {"state": "NO_EXPLOIT_OBSERVED"},
        execution_lifecycle=lifecycle,
        judge_calibration=_enabled_judge_calibration(),
    )

    with pytest.raises(RuntimeError, match="bounded provider failure"):
        runtime.run_attempt(authorized_case={"case_id": "case-1"})

    assert [event["role"] for event in lifecycle.starts] == ["orchestrator", "red_team"]
    assert [event["status"] for event in lifecycle.finishes] == ["succeeded", "failed"]
    assert lifecycle.finishes[-1]["error_code"] == "hosted-agent-failed"


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
    assert outcome.lineage[1].parent_execution_id == "execution-orchestrator"
    assert outcome.lineage[2].parent_request_id == "provider-request-red_team"
    assert outcome.lineage[2].parent_execution_id == "execution-red_team"
    assert all(item.requested_model == item.returned_model for item in outcome.lineage)


def test_runtime_sends_the_exact_registry_prompt_as_the_system_message() -> None:
    lifecycle = _FakeExecutionLifecycle()
    runtime, transport = _runtime(
        outputs=_outputs(judge_state="EXPLOIT_LIKELY"),
        target=lambda _attempt: {"status_code": 200},
        recorded=[],
        lifecycle=lifecycle,
    )

    runtime.run_attempt(authorized_case={"case_id": "case-1"})

    assert transport.calls == ["orchestrator", "red_team", "judge", "documentation"]
    for invocation in transport.invocations:
        role = invocation["role"]
        prompt = _PROMPTS[role]
        messages = invocation["messages"]
        assert messages[0] == {
            "role": "system",
            "content": prompt.content,
        }
        assert messages[1]["role"] == "user"
        configured = next(item for item in transport.configuration.roles if item.role == role)
        assert configured.prompt_sha256 == prompt.sha256
        started = next(item for item in lifecycle.starts if item["role"] == role)
        assert started["system_prompt_version"] == prompt.version
        assert started["system_prompt_sha256"] == prompt.sha256
        assert started["system_prompt_content"] == prompt.content
        assert started["provider_messages"] == messages


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


class _RefusingLifecycle(_FakeExecutionLifecycle):
    """A lifecycle that refuses exactly what the real store refuses."""

    def __init__(self, recorded: list[Any] | None = None, *, refuse_lineage: bool = False) -> None:
        super().__init__(recorded)
        self._refuse_lineage = refuse_lineage
        self.attempts: list[dict[str, Any]] = []

    def finish(self, **values: Any) -> None:
        self.attempts.append(dict(values))
        if values["status"] == "succeeded":
            raise RuntimeError("hosted agent output contains credential material")
        if self._refuse_lineage and values.get("lineage") is not None:
            raise RuntimeError("hosted token accounting is out of range")
        super().finish(**values)


def test_a_refused_success_still_closes_the_execution() -> None:
    """Producing text that looks like a credential is the Red Team's job, not a reason to dangle.

    The store screens agent output for credential material and refuses it. If that refusal simply
    propagated, an honest in-contract Red Team response would leave its row 'running' forever with
    no terminal record and no audit event — the platform disabling itself the first time an attack
    works.
    """

    recorded: list[Any] = []
    lifecycle = _RefusingLifecycle(recorded)
    runtime, _transport = _runtime(
        outputs=_outputs(),
        target=lambda _attempt: {"status_code": 200},
        recorded=recorded,
        lifecycle=lifecycle,
    )

    with pytest.raises(HostedCompositionError):
        runtime.run_attempt(authorized_case={"case_id": "case-1"})

    # Nothing was accepted as a success, but the execution IS closed.
    assert recorded == []
    closed = [item for item in lifecycle.finishes if item["status"] == "failed"]
    assert closed, "a refused success must still terminalize the execution"
    # And the observation that was refused is still offered on the closing record.
    assert closed[0]["lineage"] is not None
    assert closed[0]["lineage"].returned_model == "anthropic/claude-opus-4.8"


def test_a_terminalization_the_store_refuses_degrades_instead_of_dangling() -> None:
    """When even the observation is unstorable, close the row with the smallest record that fits.

    A provider token count beyond the column's range makes the rich terminal write fail. Losing
    the observation is acceptable; leaving the execution open is not, because the runner has
    already dropped its context and nothing can ever close it.
    """

    recorded: list[Any] = []
    lifecycle = _RefusingLifecycle(recorded, refuse_lineage=True)
    runtime, _transport = _runtime(
        outputs=_outputs(),
        target=lambda _attempt: {"status_code": 200},
        recorded=recorded,
        lifecycle=lifecycle,
    )

    with pytest.raises(HostedCompositionError):
        runtime.run_attempt(authorized_case={"case_id": "case-1"})

    # It tried with the observation, was refused, and fell back to a record that fits.
    with_lineage = [
        item
        for item in lifecycle.attempts
        if item["status"] == "failed" and item.get("lineage") is not None
    ]
    without_lineage = [
        item
        for item in lifecycle.attempts
        if item["status"] == "failed" and item.get("lineage") is None
    ]
    assert with_lineage, "the observation must be offered before it is given up"
    assert without_lineage, "a refused observation must not leave the execution open"
    assert without_lineage[0]["error_code"]
