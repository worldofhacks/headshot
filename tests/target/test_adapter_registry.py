from __future__ import annotations

import socket
from dataclasses import replace

import pytest

from agentforge.target.adapter_registry import (
    AdapterRegistry,
    AdapterRegistryError,
    AdapterResolutionError,
)
from agentforge.target.base import TargetAdapter, TargetRequest, TargetResponse
from agentforge.target.registry import ResolvedTargetSurface, TargetRegistry
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    AuthorizationScope,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)


class BoundAdapter(TargetAdapter):
    name = "shared-json"

    def __init__(self, target_id: str) -> None:
        self.target_id = target_id

    def send(self, request: TargetRequest) -> TargetResponse:
        return TargetResponse(output=f"{self.target_id}:{len(request.turns)}")


class WrongAdapter(BoundAdapter):
    name = "wrong-json"


def _caps() -> SafetyCaps:
    return SafetyCaps(10.0, 20, 2.0, 60.0)


def _registered_scope(
    target_id: str,
    host: str,
    *,
    adapter_kind: str = "shared-json",
    registry: TargetRegistry | None = None,
) -> tuple[TargetRegistry, AuthorizationScope]:
    target = TargetDefinition(
        target_id=target_id,
        name=f"Service {target_id}",
        version="1.0.0",
        adapter_kind=adapter_kind,
        environment=TargetEnvironment.STAGING,
        base_url=f"https://{host}/api",
        allowlisted_hosts=(host,),
        auth_mode=AuthMode.NONE,
        credential_ref=None,
        synthetic_data_only=True,
        synthetic_data_attestation_ref=f"attestation://fixtures/{target_id}",
        canary_refs=(),
        oracle_refs=(f"oracle://policy/{target_id}",),
        safety_caps=_caps(),
    )
    surface = AttackSurfaceDefinition(
        surface_id=f"surface-{target_id}",
        version="1.0.0",
        target_id=target_id,
        target_version=target.version,
        kind=SurfaceKind.RESPONSES,
        protocol="https",
        method="POST",
        relative_path="v1/responses",
        trust_boundary="untrusted-input-to-model",
        authentication_required=False,
        risk=RiskLevel.HIGH,
        owasp_mappings=(
            OwaspMapping("OWASP Web", "2021", "A03", "Injection"),
            OwaspMapping("OWASP LLM", "2025", "LLM01", "Prompt Injection"),
        ),
        oracle_refs=(f"oracle://surface/{target_id}",),
        enabled=True,
    )
    registry = registry or TargetRegistry()
    registry.register_target(target)
    registry.register_surface(surface)
    registry.transition_target(target_id, target.version, TargetLifecycle.VALIDATING)
    ready = registry.transition_target(target_id, target.version, TargetLifecycle.READY)
    scope = AuthorizationScope.for_definitions(
        target=ready,
        surface=surface,
        corpus_hash="c" * 64,
        caps=_caps(),
        run_nonce=f"run-{target_id}-0001",
    )
    return registry, scope


def test_two_targets_resolve_through_one_trusted_adapter_factory() -> None:
    registry = TargetRegistry()
    _, alpha_scope = _registered_scope("target-alpha", "alpha.example.test", registry=registry)
    _, beta_scope = _registered_scope("target-beta", "beta.example.test", registry=registry)
    adapters = AdapterRegistry(
        registry,
        {"shared-json": lambda resolved: BoundAdapter(resolved.target.target_id)},
    )

    alpha = adapters.resolve(alpha_scope)
    beta = adapters.resolve(beta_scope)

    assert isinstance(alpha, BoundAdapter)
    assert isinstance(beta, BoundAdapter)
    assert alpha.target_id == "target-alpha"
    assert beta.target_id == "target-beta"


def test_unknown_adapter_kind_has_no_fallback() -> None:
    registry, scope = _registered_scope(
        "target-alpha",
        "alpha.example.test",
        adapter_kind="unregistered-json",
    )
    adapters = AdapterRegistry(registry, {"shared-json": lambda resolved: BoundAdapter("unused")})

    with pytest.raises(AdapterResolutionError, match="not registered"):
        adapters.resolve(scope)


def test_factory_result_must_match_the_trusted_adapter_kind() -> None:
    registry, scope = _registered_scope("target-alpha", "alpha.example.test")
    adapters = AdapterRegistry(registry, {"shared-json": lambda resolved: WrongAdapter("unused")})

    with pytest.raises(AdapterResolutionError, match="mismatched adapter"):
        adapters.resolve(scope)


def test_factory_must_return_a_target_adapter() -> None:
    registry, scope = _registered_scope("target-alpha", "alpha.example.test")
    adapters = AdapterRegistry(registry, {"shared-json": lambda resolved: object()})

    with pytest.raises(AdapterResolutionError, match="TargetAdapter"):
        adapters.resolve(scope)


def test_untrusted_payload_cannot_select_an_adapter() -> None:
    registry, _scope = _registered_scope("target-alpha", "alpha.example.test")
    adapters = AdapterRegistry(registry, {"shared-json": lambda resolved: BoundAdapter("unused")})

    with pytest.raises(AdapterResolutionError, match="authorization scope"):
        adapters.resolve(  # type: ignore[arg-type]
            {
                "adapter_kind": "shared-json",
                "base_url": "https://other.example.test",
                "credential_ref": "secretref://staging/other",
            }
        )


def test_forged_resolved_snapshot_cannot_reach_a_factory() -> None:
    registry, scope = _registered_scope("target-alpha", "alpha.example.test")
    resolved = registry.resolve(scope)
    forged = ResolvedTargetSurface(
        target=replace(resolved.target, adapter_kind="other-json"),
        surface=resolved.surface,
        authorization_scope=replace(scope, adapter_kind="other-json"),
    )
    factory_called = False

    def factory(_resolved: ResolvedTargetSurface) -> BoundAdapter:
        nonlocal factory_called
        factory_called = True
        return BoundAdapter("unused")

    adapters = AdapterRegistry(registry, {"shared-json": factory})

    with pytest.raises(AdapterResolutionError, match="authorization scope"):
        adapters.resolve(forged)  # type: ignore[arg-type]
    assert factory_called is False


@pytest.mark.parametrize("kind", ["*", "default", "fallback"])
def test_wildcard_or_fallback_factory_keys_are_rejected(kind: str) -> None:
    registry, _scope = _registered_scope("target-alpha", "alpha.example.test")
    with pytest.raises(AdapterRegistryError):
        AdapterRegistry(registry, {kind: lambda resolved: BoundAdapter("unused")})


def test_factory_configuration_is_copied_and_resolution_opens_no_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, scope = _registered_scope("target-alpha", "alpha.example.test")
    factories = {"shared-json": lambda resolved: BoundAdapter(resolved.target.target_id)}
    adapters = AdapterRegistry(registry, factories)
    factories["late-json"] = lambda resolved: BoundAdapter("late")

    def no_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("adapter resolution attempted network access")

    monkeypatch.setattr(socket, "socket", no_socket)
    adapter = adapters.resolve(scope)

    assert adapter.name == "shared-json"
    assert adapters.kinds == ("shared-json",)
