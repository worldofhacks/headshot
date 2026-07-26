"""Target-free authority and cap tests for the four-role live acceptance command."""

from __future__ import annotations

import ast
import inspect

import pytest

import agentforge.agent_acceptance as acceptance
from agentforge.agents.hosted_runtime import HostedCompositionError, HostedExecutionLineage
from agentforge.agents.prompts import load_prompt_registry
from agentforge.agents.red_team.hosted_generation import build_generation_messages
from agentforge.policy.scoped_credentials import CredentialResolutionError


def test_acceptance_generation_policy_covers_the_staged_four_role_set() -> None:
    generation_policy = acceptance.acceptance_generation_policy()

    assert set(generation_policy.call_bounds) == {
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    }
    assert {
        role: bounds.input_tokens for role, bounds in generation_policy.call_bounds.items()
    } == {
        "orchestrator": 32_768,
        "red_team": 32_768,
        "judge": 32_768,
        "documentation": 32_768,
    }
    assert generation_policy.call_bounds["red_team"].output_tokens == 8_192
    assert generation_policy.call_bounds["red_team"].reasoning_tokens == 8_192
    assert generation_policy.call_bounds["judge"].reasoning_tokens == 1_024
    assert generation_policy.call_bounds["documentation"].timeout_seconds == 120.0
    assert acceptance._ACCEPTANCE_SIGNAL_PROVENANCE == "hash_verified_postgres"


def test_red_team_acceptance_input_cap_contains_the_exact_conservative_request_bound() -> None:
    red_team_prompt = next(prompt for prompt in load_prompt_registry() if prompt.role == "red_team")
    messages = build_generation_messages(
        {
            "case_ref": "synthetic-acceptance-seed",
            "input_sequence": ["Synthetic acceptance seed; propose one test-only continuation."],
        },
        1,
        "prompt_injection",
        prompt_version=red_team_prompt.version,
        prompt_sha256=red_team_prompt.sha256,
    )
    conservative_bound = acceptance.OpenRouterTransport._conservative_input_token_bound(messages)
    authorized_bound = (
        acceptance.acceptance_generation_policy().call_bounds["red_team"].input_tokens
    )

    assert 4_096 < conservative_bound <= authorized_bound


def test_acceptance_evidence_uses_only_vetted_trusted_signal_mappings() -> None:
    envelope = acceptance._acceptance_evidence_envelope(
        run_id="AR-synthetic-test",
        attempt_id="a" * 64,
    )

    assert envelope["trusted"]["canary_hits"] == [
        {
            "id": "acceptance-canary-marker",
            "provenance": "code",
            "hit": True,
            "detail": "The package-owned synthetic marker was observed.",
        }
    ]


def test_acceptance_refuses_a_release_without_the_canonical_provider_writer() -> None:
    acceptance._require_canonical_provider_writer()
    assert (
        "lineage_recorder" in inspect.signature(acceptance.OpenRouterTransport.__init__).parameters
    )
    assert "provider_context" in inspect.signature(acceptance.OpenRouterTransport.invoke).parameters
    assert acceptance.OpenRouterTransport.LINEAGE_RECORDER_CONTRACT == "provider-call-final-v1"


def test_acceptance_preflight_requires_every_sealed_binding_and_langfuse_authentication() -> None:
    class Resolver:
        def __init__(self, *, missing: str | None = None) -> None:
            self.missing = missing
            self.resolved: list[str] = []

        def resolve(self, reference: str):
            self.resolved.append(reference)
            return None if reference == self.missing else object()

    class Telemetry:
        def __init__(self, *, ready: bool) -> None:
            self.ready = ready
            self.checks = 0

        def hosted_observability_ready(self) -> bool:
            self.checks += 1
            return self.ready

    references = (
        "secretref://acceptance/orchestrator",
        "secretref://acceptance/red-team",
        "secretref://acceptance/judge",
        "secretref://acceptance/documentation",
    )
    missing = Resolver(missing=references[1])
    with pytest.raises(CredentialResolutionError):
        acceptance._require_acceptance_dependencies(
            credential_references=references,
            resolver=missing,  # type: ignore[arg-type]
            telemetry=Telemetry(ready=True),  # type: ignore[arg-type]
        )

    resolver = Resolver()
    telemetry = Telemetry(ready=False)
    with pytest.raises(Exception, match="Langfuse authentication is unavailable"):
        acceptance._require_acceptance_dependencies(
            credential_references=references,
            resolver=resolver,  # type: ignore[arg-type]
            telemetry=telemetry,  # type: ignore[arg-type]
        )
    assert resolver.resolved == list(references)
    assert telemetry.checks == 1


def test_acceptance_lifecycle_projects_complete_provider_lineage() -> None:
    class Store:
        terminal: dict[str, object] | None = None

        def start_acceptance_agent_execution(self, **_values: object) -> str:
            return "execution-orchestrator"

        def finish_hosted_agent_execution(self, **values: object) -> None:
            self.terminal = values

    class Telemetry:
        def begin_agent(self, **_values: object) -> bool:
            return True

        def finish_agent(self, **_values: object) -> None:
            return None

        def flush(self) -> None:
            return None

    store = Store()
    lifecycle = acceptance._AcceptanceLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=Telemetry(),  # type: ignore[arg-type]
        run_id="AR-test",
        attempt_id="a" * 64,
        calibration_id=f"JC-{'b' * 64}",
        deterministic_verdict={"state": "EXPLOIT_CONFIRMED"},
    )
    execution_id = lifecycle.start(
        role="orchestrator",
        parent_execution_id=None,
        input_payload={"synthetic": True},
        provider="openrouter",
        model="anthropic/claude-opus-4.8",
        upstream_provider="amazon-bedrock/eu-west-1",
        configuration_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        judge_calibration_id=None,
    )
    lineage = HostedExecutionLineage(
        execution_id=execution_id,
        parent_execution_id=None,
        role="orchestrator",
        parent_request_id=None,
        requested_model="anthropic/claude-opus-4.8",
        returned_model="anthropic/claude-opus-4.8",
        upstream_provider="Amazon Bedrock",
        provider_request_id="provider-request",
        input_tokens=10,
        output_tokens=5,
        reasoning_tokens=2,
        measured_cost_usd="0.0123",
        configuration_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        physical_attempts=1,
    )

    lifecycle.finish(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"selected": "synthetic"},
        lineage=lineage,
        error_code=None,
    )

    assert store.terminal is not None
    for key, expected in {
        "returned_model": lineage.returned_model,
        "upstream_provider": lineage.upstream_provider,
        "provider_request_id": lineage.provider_request_id,
        "input_tokens": lineage.input_tokens,
        "output_tokens": lineage.output_tokens,
        "reasoning_tokens": lineage.reasoning_tokens,
        "measured_cost_usd": lineage.measured_cost_usd,
        "configuration_set_sha256": lineage.configuration_sha256,
        "role_configuration_sha256": lineage.role_configuration_sha256,
        "generation_policy_sha256": lineage.generation_policy_sha256,
        "physical_attempts": lineage.physical_attempts,
    }.items():
        assert store.terminal[key] == expected


def test_acceptance_lifecycle_keeps_context_until_invalid_red_team_output_is_failed() -> None:
    class Store:
        terminals: list[dict[str, object]]

        def __init__(self) -> None:
            self.terminals = []

        def start_acceptance_agent_execution(self, **_values: object) -> str:
            return "execution-red-team"

        def finish_hosted_agent_execution(self, **values: object) -> None:
            self.terminals.append(values)

    class Telemetry:
        def begin_agent(self, **_values: object) -> bool:
            return True

        def finish_agent(self, **_values: object) -> None:
            return None

        def flush(self) -> None:
            return None

    store = Store()
    lifecycle = acceptance._AcceptanceLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=Telemetry(),  # type: ignore[arg-type]
        run_id="AR-red-team-validation",
        attempt_id="a" * 64,
        calibration_id=f"JC-{'b' * 64}",
        deterministic_verdict={"state": "EXPLOIT_CONFIRMED"},
    )
    execution_id = lifecycle.start(
        role="red_team",
        parent_execution_id="execution-orchestrator",
        input_payload={"synthetic": True},
        provider="openrouter",
        model="qwen/qwen3.5-397b-a17b",
        upstream_provider="atlas-cloud",
        configuration_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        judge_calibration_id=None,
    )
    lineage = HostedExecutionLineage(
        execution_id=execution_id,
        parent_execution_id="execution-orchestrator",
        role="red_team",
        parent_request_id="provider-request-orchestrator",
        requested_model="qwen/qwen3.5-397b-a17b",
        returned_model="qwen/qwen3.5-397b-a17b",
        upstream_provider="AtlasCloud",
        provider_request_id="provider-request-red-team",
        input_tokens=10,
        output_tokens=5,
        reasoning_tokens=2,
        measured_cost_usd="0.0123",
        configuration_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        physical_attempts=1,
    )

    with pytest.raises(HostedCompositionError, match="not durably quarantined"):
        lifecycle.finish(
            execution_id=execution_id,
            status="succeeded",
            output_payload={
                "generated_output_sha256": "g" * 64,
                "generated_variant_count": 1,
                "generated_output_disposition": "quarantined_not_dispatched",
                "target_call_limit": 0,
            },
            lineage=lineage,
            error_code=None,
        )
    assert store.terminals == []

    lifecycle.finish(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        lineage=None,
        error_code="red-team-output-invalid",
    )
    assert store.terminals[0]["status"] == "failed"


def test_acceptance_lifecycle_can_retry_a_failed_terminal_write() -> None:
    class Store:
        finish_calls = 0

        def start_acceptance_agent_execution(self, **_values: object) -> str:
            return "execution-orchestrator"

        def finish_hosted_agent_execution(self, **_values: object) -> None:
            self.finish_calls += 1
            if self.finish_calls == 1:
                raise RuntimeError("synthetic storage outage")

    class Telemetry:
        def begin_agent(self, **_values: object) -> bool:
            return True

        def finish_agent(self, **_values: object) -> None:
            return None

        def flush(self) -> None:
            return None

    store = Store()
    lifecycle = acceptance._AcceptanceLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=Telemetry(),  # type: ignore[arg-type]
        run_id="AR-terminal-retry",
        attempt_id="a" * 64,
        calibration_id=f"JC-{'b' * 64}",
        deterministic_verdict={"state": "EXPLOIT_CONFIRMED"},
    )
    execution_id = lifecycle.start(
        role="orchestrator",
        parent_execution_id=None,
        input_payload={"synthetic": True},
        provider="openrouter",
        model="anthropic/claude-opus-4.8",
        upstream_provider="anthropic",
        configuration_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        judge_calibration_id=None,
    )
    lineage = HostedExecutionLineage(
        execution_id=execution_id,
        parent_execution_id=None,
        role="orchestrator",
        parent_request_id=None,
        requested_model="anthropic/claude-opus-4.8",
        returned_model="anthropic/claude-opus-4.8",
        upstream_provider="Anthropic",
        provider_request_id="provider-request",
        input_tokens=10,
        output_tokens=5,
        reasoning_tokens=2,
        measured_cost_usd="0.0123",
        configuration_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        physical_attempts=1,
    )
    finish = {
        "execution_id": execution_id,
        "status": "succeeded",
        "output_payload": {"selected": "synthetic"},
        "lineage": lineage,
        "error_code": None,
    }

    with pytest.raises(RuntimeError, match="storage outage"):
        lifecycle.finish(**finish)
    lifecycle.finish(**finish)
    assert store.finish_calls == 2


def test_acceptance_authority_allows_each_hosted_role_once_and_forbids_target_calls() -> None:
    limits = acceptance.acceptance_limits()

    assert limits["schema_version"] == "2"
    assert limits["network_scope"] == "openrouter_langfuse_only"
    assert limits["target_call_limit"] == 0
    assert limits["allowed_roles"] == [
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    ]
    assert limits["role_call_caps"] == {
        "orchestrator": 1,
        "red_team": 1,
        "judge": 1,
        "documentation": 1,
    }
    assert limits["role_usd_caps"]["red_team"] == "1"
    assert limits["global_call_cap"] == 4


def test_acceptance_module_has_no_scanner_or_target_dispatch_import() -> None:
    tree = ast.parse(inspect.getsource(acceptance))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )

    forbidden = (
        "agentforge.security_tools",
        "agentforge.campaign.coordinator",
        "agentforge.policy.gateway",
        "agentforge.target.openemr_adapter",
        "agentforge.target.cassette_adapter",
    )
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in imported
        for prefix in forbidden
    )
