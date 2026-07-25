"""Target-free authority and cap tests for the three-role live acceptance command."""

from __future__ import annotations

import ast
import inspect

import pytest

import agentforge.agent_acceptance as acceptance
from agentforge.agents.hosted_runtime import HostedExecutionLineage
from agentforge.policy.scoped_credentials import CredentialResolutionError


def test_acceptance_generation_policy_covers_the_staged_four_role_set() -> None:
    generation_policy = acceptance.acceptance_generation_policy()

    assert set(generation_policy.call_bounds) == {
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    }
    assert generation_policy.call_bounds["orchestrator"].input_tokens == 8_192
    assert generation_policy.call_bounds["red_team"].output_tokens == 512
    assert generation_policy.call_bounds["judge"].reasoning_tokens == 1_024
    assert generation_policy.call_bounds["documentation"].timeout_seconds == 120.0


def test_acceptance_refuses_a_release_without_the_canonical_provider_writer() -> None:
    try:
        acceptance._require_canonical_provider_writer()
    except Exception as exc:
        assert "provider-lineage writer is unavailable" in str(exc)
    else:
        assert (
            "lineage_recorder"
            in inspect.signature(acceptance.OpenRouterTransport.__init__).parameters
        )
        assert (
            "provider_context"
            in inspect.signature(acceptance.OpenRouterTransport.invoke).parameters
        )


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


def test_acceptance_authority_forbids_generator_and_target_calls() -> None:
    limits = acceptance.acceptance_limits()

    assert limits["network_scope"] == "openrouter_langfuse_only"
    assert limits["target_call_limit"] == 0
    assert limits["allowed_roles"] == [
        "orchestrator",
        "judge",
        "documentation",
    ]
    assert "red_team" not in limits["role_call_caps"]
    assert limits["global_call_cap"] == 3


def test_acceptance_module_has_no_generator_scanner_or_target_dispatch_import() -> None:
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
        "agentforge.agents.red_team",
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
