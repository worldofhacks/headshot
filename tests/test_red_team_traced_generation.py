"""RED tests for the traced hosted Red Team generation (qwen as the fourth live agent).

The two-stage loop's GENERATION is the Red Team's LLM work. It must route through the SAME
OpenRouter transport as the other three roles and emit through the SAME execution lifecycle
(start -> invoke -> HostedExecutionLineage -> finish) so it lands in agent_executions with the
identical trace/cost/lineage shape (agent_role='red_team', returned_model, tokens, measured_cost,
parent_execution_id, provider_request_id). No divergent SDK client, no untraced generation.

Offline: the transport + lifecycle are injected fakes; the socket is patched to raise, proving the
provider never opens its own network exit.
"""

from __future__ import annotations

import json
import socket
from decimal import Decimal

import pytest

from agentforge.agents.hosted_runtime import HostedCallBounds, HostedExecutionLineage
from agentforge.agents.red_team.hosted_generation import (
    RED_TEAM_SUBCAP_CEILING_USD,
    RedTeamRoleIdentity,
    TracedHostedRedTeamProvider,
    TracedRedTeamGenerationError,
    build_generation_messages,
    require_red_team_subcap,
    variants_output_schema,
)
from agentforge.agents.red_team.providers import ProviderExhaustedError
from agentforge.providers.openrouter import (
    HostedBudgetExceeded,
    HostedProviderError,
    OpenRouterResult,
)

SEED = {
    "case_ref": "AF-M11-PI-001",
    "input_sequence": ["seed turn one"],
    "category": "prompt_injection",
}
ROLE = RedTeamRoleIdentity(
    provider="openrouter",
    model="qwen/qwen3.5-397b-a17b",
    upstream_provider="deepinfra",
    role_configuration_sha256="a" * 64,
)
CONFIG_SHA = "b" * 64
POLICY_SHA = "c" * 64
BOUNDS = HostedCallBounds(
    input_tokens=2048, output_tokens=1024, reasoning_tokens=512, timeout_seconds=30.0
)


def _result(variants: list[str], **over) -> OpenRouterResult:
    base = dict(
        output={"variants": variants},
        requested_model=ROLE.model,
        returned_model=ROLE.model,
        upstream_provider=ROLE.upstream_provider,
        request_id="or-req-123",
        input_tokens=120,
        output_tokens=64,
        reasoning_tokens=8,
        measured_cost_usd=Decimal("0.0031"),
        configuration_sha256=CONFIG_SHA,
        role_configuration_sha256=ROLE.role_configuration_sha256,
        generation_policy_sha256=POLICY_SHA,
        physical_attempts=1,
    )
    base.update(over)
    return OpenRouterResult(**base)


class _FakeTransport:
    def __init__(self, *, result: OpenRouterResult | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls: list[dict] = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class _FakeLifecycle:
    def __init__(self, execution_id: str = "exec-rt-1"):
        self._execution_id = execution_id
        self.started: list[dict] = []
        self.finished: list[dict] = []

    def start(self, **kwargs) -> str:
        self.started.append(kwargs)
        return self._execution_id

    def finish(self, **kwargs) -> None:
        self.finished.append(kwargs)


def _provider(transport, lifecycle, *, parent="exec-orchestrator-9"):
    return TracedHostedRedTeamProvider(
        transport=transport,
        lifecycle=lifecycle,
        role_identity=ROLE,
        configuration_sha256=CONFIG_SHA,
        generation_policy_sha256=POLICY_SHA,
        call_bounds=BOUNDS,
        parent_execution_id=parent,
    )


def test_generation_starts_a_red_team_execution_with_the_parent_lineage() -> None:
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    lifecycle = _FakeLifecycle()
    _provider(transport, lifecycle).generate(SEED, count=2, category="prompt_injection")

    start = lifecycle.started[0]
    assert start["role"] == "red_team"
    assert start["parent_execution_id"] == "exec-orchestrator-9"
    assert start["provider"] == "openrouter"
    assert start["model"] == "qwen/qwen3.5-397b-a17b"
    assert start["generation_policy_sha256"] == POLICY_SHA
    assert start["judge_calibration_id"] is None


def test_generation_routes_through_the_transport_as_the_red_team_role() -> None:
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    _provider(transport, _FakeLifecycle()).generate(SEED, count=2, category="prompt_injection")

    call = transport.calls[0]
    assert call["role"] == "red_team"
    assert call["generation_policy_sha256"] == POLICY_SHA
    assert call["max_output_tokens"] == BOUNDS.output_tokens
    # The structured-output schema pins exactly `count` variants.
    schema = call["output_schema"]
    assert schema["properties"]["variants"]["minItems"] == 2
    assert schema["additionalProperties"] is False


def test_finish_emits_the_identical_lineage_shape() -> None:
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    lifecycle = _FakeLifecycle()
    _provider(transport, lifecycle).generate(SEED, count=2, category="prompt_injection")

    finish = lifecycle.finished[0]
    assert finish["status"] == "succeeded"
    assert finish["error_code"] is None
    lineage = finish["lineage"]
    assert isinstance(lineage, HostedExecutionLineage)
    assert lineage.role == "red_team"
    assert lineage.parent_execution_id == "exec-orchestrator-9"
    assert lineage.returned_model == "qwen/qwen3.5-397b-a17b"
    assert lineage.provider_request_id == "or-req-123"
    assert lineage.input_tokens == 120 and lineage.output_tokens == 64
    assert lineage.reasoning_tokens == 8
    assert lineage.measured_cost_usd == "0.0031"


def test_generation_returns_proposed_input_variants_only() -> None:
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    variants = _provider(transport, _FakeLifecycle()).generate(
        SEED, count=2, category="prompt_injection"
    )
    assert variants == [
        {"input_sequence": ["seed turn one", "cont-a"]},
        {"input_sequence": ["seed turn one", "cont-b"]},
    ]
    # Untrusted generator: proposed input only — never a credential, content_hash, or verdict.
    for variant in variants:
        assert set(variant) == {"input_sequence"}


def test_budget_refusal_is_recorded_failed_then_reraised() -> None:
    transport = _FakeTransport(error=HostedBudgetExceeded("role measured-spend cap exhausted"))
    lifecycle = _FakeLifecycle()
    with pytest.raises(HostedBudgetExceeded):
        _provider(transport, lifecycle).generate(SEED, count=2, category="prompt_injection")
    finish = lifecycle.finished[0]
    assert finish["status"] == "failed"
    assert finish["error_code"] == "hosted-budget-exceeded"
    assert finish["lineage"] is None


def test_provider_error_is_recorded_failed_then_reraised() -> None:
    transport = _FakeTransport(error=HostedProviderError("upstream unavailable"))
    lifecycle = _FakeLifecycle()
    with pytest.raises(HostedProviderError):
        _provider(transport, lifecycle).generate(SEED, count=1, category="prompt_injection")
    assert lifecycle.finished[0]["status"] == "failed"
    assert lifecycle.finished[0]["error_code"] == "hosted-provider-unavailable"


def test_finish_failure_on_success_path_is_a_typed_terminal_record_error() -> None:
    # If the terminal SUCCESS finish itself fails, the generation must not be returned as if it were
    # durably recorded. Surface a typed terminal-record error (mirrors the four-role runtime
    # success-finish guard, hosted_runtime.py:359-372) so a lost durable/Langfuse record is loud and
    # the red_team execution fails uniformly with the other three roles.
    transport = _FakeTransport(result=_result(["cont-a"]))
    lifecycle = _FinishRaisingLifecycle()
    with pytest.raises(TracedRedTeamGenerationError, match="terminally recorded"):
        _provider(transport, lifecycle).generate(SEED, count=1, category="prompt_injection")
    # The success finish was attempted (status=succeeded) before the terminal-record error surfaced.
    assert lifecycle.finished[0]["status"] == "succeeded"


def test_lineage_threads_the_parent_request_id_for_the_uniform_four_agent_chain() -> None:
    # The other three roles thread the parent's provider request id into their lineage
    # (hosted_runtime.py:345 — red_team's parent_request_id is the orchestrator's request id). The
    # traced red_team lineage must carry it identically so the four-agent request chain is uniform,
    # not silently dropped to None.
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    lifecycle = _FakeLifecycle()
    provider = TracedHostedRedTeamProvider(
        transport=transport,
        lifecycle=lifecycle,
        role_identity=ROLE,
        configuration_sha256=CONFIG_SHA,
        generation_policy_sha256=POLICY_SHA,
        call_bounds=BOUNDS,
        parent_execution_id="exec-orchestrator-9",
        parent_request_id="or-req-orchestrator",
    )
    provider.generate(SEED, count=2, category="prompt_injection")
    lineage = lifecycle.finished[0]["lineage"]
    assert lineage.parent_request_id == "or-req-orchestrator"
    assert lineage.parent_execution_id == "exec-orchestrator-9"


def test_generation_refuses_when_lifecycle_returns_no_execution_identity() -> None:
    # A missing execution identity means the generation could never be traced/recorded. Refuse
    # LOUDLY and BEFORE the qwen call — never emit an untraceable, cost-incurring generation.
    transport = _FakeTransport(result=_result(["cont-a"]))
    lifecycle = _FakeLifecycle(execution_id="")
    with pytest.raises(TracedRedTeamGenerationError, match="identity"):
        _provider(transport, lifecycle).generate(SEED, count=1, category="prompt_injection")
    assert transport.calls == [], "no qwen call may be made without a recordable execution identity"


class _FinishRaisingLifecycle(_FakeLifecycle):
    """A lifecycle whose terminal ``finish`` itself fails — the durable record could not write."""

    def finish(self, **kwargs) -> None:
        super().finish(**kwargs)
        raise RuntimeError("durable finish write failed")


def test_finish_failure_on_error_path_does_not_mask_the_original_provider_error() -> None:
    # If the terminal failed-finish ITSELF raises, the original provider error must not be silently
    # replaced by the lifecycle write error. Mirrors the four-role runtime guard
    # (hosted_runtime.py:413-426): raise a typed terminal-record error whose __cause__ preserves the
    # ROOT provider failure, so the incident stays diagnosable across all four agents uniformly.
    transport = _FakeTransport(error=HostedProviderError("upstream unavailable"))
    lifecycle = _FinishRaisingLifecycle()
    with pytest.raises(TracedRedTeamGenerationError) as excinfo:
        _provider(transport, lifecycle).generate(SEED, count=1, category="prompt_injection")
    assert isinstance(excinfo.value.__cause__, HostedProviderError)
    assert excinfo.value.__cause__.code == "hosted-provider-unavailable"
    # The failed finish was attempted (not skipped) before the terminal-record error surfaced.
    assert lifecycle.finished[0]["status"] == "failed"


def test_short_generation_fails_loudly() -> None:
    # The model returned fewer usable variants than requested -> loud, not a silent short return.
    transport = _FakeTransport(result=_result(["only-one"]))
    with pytest.raises(ProviderExhaustedError):
        _provider(transport, _FakeLifecycle()).generate(SEED, count=3, category="prompt_injection")


def test_short_generation_closes_the_started_execution_never_dangling() -> None:
    # A short/exhausted generation happens AFTER a successful (cost-incurring) transport call, so
    # the red_team execution has already been STARTED. It must still be FINISHED (status=failed) —
    # never left dangling as a perpetually-"running" agent_execution that pollutes the uniform
    # four-agent lineage. The loud ProviderExhaustedError still propagates.
    transport = _FakeTransport(result=_result(["only-one"]))
    lifecycle = _FakeLifecycle()
    with pytest.raises(ProviderExhaustedError):
        _provider(transport, lifecycle).generate(SEED, count=3, category="prompt_injection")
    assert len(lifecycle.started) == 1
    assert len(lifecycle.finished) == 1, "the started execution must be finished, not dangling"
    finish = lifecycle.finished[0]
    assert finish["status"] == "failed"
    assert finish["error_code"]  # a non-empty typed error code the recorder can persist
    # The observation SURVIVES the failure. This assertion used to require the opposite, and that
    # was the defect: discarding the lineage makes the store derive cost_measurement_state=
    # 'not_observed', which asserts no provider call was made — for a call that was made, billed,
    # and whose request id was in hand. A short generation is unusable CONTENT, never a free call.
    lineage = finish["lineage"]
    assert lineage is not None
    assert lineage.provider_request_id == "or-req-123"
    assert lineage.measured_cost_usd == "0.0031"
    assert lineage.physical_attempts == 1


def test_traced_provider_is_a_drop_in_for_the_two_stage_mutate_loop() -> None:
    # The two-stage loop's mutate() calls provider.generate — so a real scan's generation step is a
    # live, traced qwen invocation, and mutate() wraps the variants into lineage-tagged attempts.
    from agentforge.agents.red_team.mutation import mutate

    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    lifecycle = _FakeLifecycle()
    provider = _provider(transport, lifecycle)
    attempt = {
        "case_ref": "AF-M11-PI-001",
        "input_sequence": ["seed turn one"],
        "category": "prompt_injection",
        "mutation_lineage": [],
    }
    coverage = {"prompt_injection": 0, "data_exfiltration": 5, "tool_misuse": 3}
    variants = mutate(attempt, coverage=coverage, count=2, provider=provider)

    assert transport.calls[0]["role"] == "red_team", "generation is a live red_team invocation"
    assert lifecycle.finished[0]["status"] == "succeeded", "the generation was traced end to end"
    assert len(variants) == 2
    assert all(v["case_ref"].startswith("AF-M11-PI-001~m") for v in variants)
    assert all("mutation_lineage" in v for v in variants)


class _StubLimits:
    def __init__(self, max_usd: Decimal, max_calls: int = 8):
        self.max_usd = max_usd
        self.max_calls = max_calls


class _StubRole:
    def __init__(self, role: str, max_usd: Decimal):
        self.role = role
        self.limits = _StubLimits(max_usd)


class _StubConfig:
    def __init__(self, red_team_max_usd: Decimal):
        self.roles = (
            _StubRole("orchestrator", Decimal("2")),
            _StubRole("red_team", red_team_max_usd),
            _StubRole("judge", Decimal("2")),
            _StubRole("documentation", Decimal("2")),
        )


def test_require_red_team_subcap_accepts_a_cap_at_or_below_one_dollar() -> None:
    assert Decimal("1") == RED_TEAM_SUBCAP_CEILING_USD
    # ≤ $1 passes and returns the effective subcap for surfacing.
    assert require_red_team_subcap(_StubConfig(Decimal("1"))) == Decimal("1")
    assert require_red_team_subcap(_StubConfig(Decimal("0.50"))) == Decimal("0.50")


def test_require_red_team_subcap_rejects_a_cap_above_one_dollar() -> None:
    with pytest.raises(TracedRedTeamGenerationError, match="subcap"):
        require_red_team_subcap(_StubConfig(Decimal("1.5")))


def test_require_red_team_subcap_rejects_a_nonpositive_cap_with_a_clear_reason() -> None:
    # A zero/negative subcap is not "over the ceiling" — it is an invalid, unusable cap. The refusal
    # must say so plainly (a security-critical cost control must be diagnosable), not mislabel it as
    # exceeding the ceiling.
    with pytest.raises(TracedRedTeamGenerationError, match="positive"):
        require_red_team_subcap(_StubConfig(Decimal("0")))
    with pytest.raises(TracedRedTeamGenerationError, match="positive"):
        require_red_team_subcap(_StubConfig(Decimal("-0.10")))


def test_require_red_team_subcap_is_free_of_binary_float_drift() -> None:
    # A float-typed cap must not smuggle binary representation drift into a $-denominated cost cap:
    # Decimal(0.10) is 0.1000000000000000055..., which would make an intended $0.10 cap fractionally
    # wrong. Coercion through str keeps the cap exactly the decimal the operator authorized.
    assert require_red_team_subcap(_StubConfig(0.10)) == Decimal("0.10")


def test_generate_traced_returns_cost_and_token_metadata_for_the_recorder() -> None:
    # The composition root (runner) records via the store seam and needs measured_cost + tokens.
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    result = _provider(transport, _FakeLifecycle()).generate_traced(
        SEED, count=2, category="prompt_injection"
    )
    assert result.variants == [
        {"input_sequence": ["seed turn one", "cont-a"]},
        {"input_sequence": ["seed turn one", "cont-b"]},
    ]
    assert result.returned_model == "qwen/qwen3.5-397b-a17b"
    assert result.provider_request_id == "or-req-123"
    assert result.input_tokens == 120 and result.output_tokens == 64
    assert result.reasoning_tokens == 8
    assert result.measured_cost_usd == "0.0031"
    assert result.upstream_provider == "deepinfra"
    # It routed through the transport as the red_team role (ledger-capped), no self-recording here.
    assert transport.calls[0]["role"] == "red_team"


def test_generate_traced_propagates_typed_budget_refusal_without_self_recording() -> None:
    # generate_traced() is the store-seam path: the composition root (runner) owns start/finish of
    # the red_team execution. So a typed budget refusal must propagate UNCHANGED — with its `.code`
    # intact so the runner can map it to the execution's error_code — and the provider must NOT
    # touch the lifecycle itself (no double-recording).
    transport = _FakeTransport(error=HostedBudgetExceeded("role measured-spend cap exhausted"))
    lifecycle = _FakeLifecycle()
    with pytest.raises(HostedBudgetExceeded) as excinfo:
        _provider(transport, lifecycle).generate_traced(SEED, count=2, category="prompt_injection")
    assert excinfo.value.code == "hosted-budget-exceeded"
    assert lifecycle.started == [] and lifecycle.finished == []


def test_generate_traced_surfaces_short_generation_to_the_composition_root() -> None:
    # A short/exhausted generation surfaces loudly (ProviderExhaustedError) so the composition root
    # records the failed execution; generate_traced neither swallows it nor self-records.
    transport = _FakeTransport(result=_result(["only-one"]))
    lifecycle = _FakeLifecycle()
    with pytest.raises(ProviderExhaustedError):
        _provider(transport, lifecycle).generate_traced(SEED, count=3, category="prompt_injection")
    assert lifecycle.started == [] and lifecycle.finished == []


def test_all_four_call_bounds_are_transmitted_to_the_transport() -> None:
    # The shared ledger caps cost via the bounds passed to the transport. All four must flow (not
    # just max_output_tokens) so the Red Team generation stays inside the kill switch.
    transport = _FakeTransport(result=_result(["cont-a", "cont-b"]))
    _provider(transport, _FakeLifecycle()).generate(SEED, count=2, category="prompt_injection")
    call = transport.calls[0]
    assert call["input_tokens_upper_bound"] == BOUNDS.input_tokens
    assert call["max_output_tokens"] == BOUNDS.output_tokens
    assert call["max_reasoning_tokens"] == BOUNDS.reasoning_tokens
    assert call["timeout_seconds"] == BOUNDS.timeout_seconds


def test_variants_output_schema_pins_exactly_count_and_rejects_out_of_bounds() -> None:
    schema = variants_output_schema(3)
    variants = schema["properties"]["variants"]
    assert variants["minItems"] == 3 and variants["maxItems"] == 3
    assert variants["items"] == {"type": "string", "minLength": 1}
    assert schema["additionalProperties"] is False
    for bad in (0, -1, 17, True):
        with pytest.raises(TracedRedTeamGenerationError, match="out of bounds"):
            variants_output_schema(bad)


def test_generation_messages_are_untrusted_proposed_input_only_no_secret() -> None:
    # The prompt must instruct the UNTRUSTED generator to emit proposed input only (never a verdict
    # or credential), carry the seed's own turns as context, and request EXACTLY `count` variants as
    # strict JSON. No secret/credential/session id may ride in the prompt.
    system, user = build_generation_messages(SEED, 2, "prompt_injection")
    assert system["role"] == "system" and user["role"] == "user"
    assert "UNTRUSTED" in system["content"]
    assert "exactly 2" in system["content"]
    assert "never a verdict, credential" in system["content"]
    payload = json.loads(user["content"])
    assert payload == {
        "category": "prompt_injection",
        "count": 2,
        "seed_case_ref": SEED["case_ref"],
        "seed_turns": SEED["input_sequence"],
    }


def test_untyped_transport_failure_records_the_typed_fallback_error_code() -> None:
    # A provider failure with no `.code` (an unexpected error) must still close the execution with a
    # typed fallback code, never an empty/None error_code, so the recorder always has a reason.
    transport = _FakeTransport(error=RuntimeError("unexpected upstream shape"))
    lifecycle = _FakeLifecycle()
    with pytest.raises(RuntimeError):
        _provider(transport, lifecycle).generate(SEED, count=1, category="prompt_injection")
    finish = lifecycle.finished[0]
    assert finish["status"] == "failed"
    assert finish["error_code"] == "red-team-generation-failed"


def test_construction_refuses_an_uncallable_transport_or_lifecycle() -> None:
    with pytest.raises(TracedRedTeamGenerationError, match="transport"):
        TracedHostedRedTeamProvider(
            transport=object(),
            lifecycle=_FakeLifecycle(),
            role_identity=ROLE,
            configuration_sha256=CONFIG_SHA,
            generation_policy_sha256=POLICY_SHA,
            call_bounds=BOUNDS,
        )
    with pytest.raises(TracedRedTeamGenerationError, match="lifecycle"):
        TracedHostedRedTeamProvider(
            transport=_FakeTransport(result=_result(["x"])),
            lifecycle=object(),
            role_identity=ROLE,
            configuration_sha256=CONFIG_SHA,
            generation_policy_sha256=POLICY_SHA,
            call_bounds=BOUNDS,
        )


def test_provider_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket, "socket", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network"))
    )
    transport = _FakeTransport(result=_result(["cont-a"]))
    variants = _provider(transport, _FakeLifecycle()).generate(
        SEED, count=1, category="prompt_injection"
    )
    assert variants == [{"input_sequence": ["seed turn one", "cont-a"]}]
