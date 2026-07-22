from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from agentforge.target.registry import (
    AuthorizationScopeMismatch,
    RegistrationError,
    SurfaceUnavailableError,
    TargetNotFoundError,
    TargetNotReadyError,
    TargetRegistry,
    TargetUnavailableError,
    VersionMismatchError,
)
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


def _caps(*, budget: float = 10.0) -> SafetyCaps:
    return SafetyCaps(
        budget_usd=budget,
        max_attempts_per_run=20,
        target_requests_per_second=2.0,
        run_timeout_seconds=60.0,
    )


def _target(
    target_id: str,
    host: str,
    *,
    version: str = "1.0.0",
    adapter_kind: str = "shared-json",
    auth_mode: AuthMode = AuthMode.NONE,
    credential_ref: str | None = None,
) -> TargetDefinition:
    return TargetDefinition(
        target_id=target_id,
        name=f"Service {target_id}",
        version=version,
        adapter_kind=adapter_kind,
        environment=TargetEnvironment.STAGING,
        base_url=f"https://{host}/api",
        allowlisted_hosts=(host,),
        auth_mode=auth_mode,
        credential_ref=credential_ref,
        synthetic_data_only=True,
        synthetic_data_attestation_ref=f"attestation://fixtures/{target_id}-{version}",
        canary_refs=(),
        oracle_refs=(f"oracle://policy/{target_id}-{version}",),
        safety_caps=_caps(),
    )


def _surface(
    target: TargetDefinition,
    surface_id: str,
    *,
    version: str = "1.0.0",
    relative_path: str = "v1/messages",
    enabled: bool = True,
) -> AttackSurfaceDefinition:
    return AttackSurfaceDefinition(
        surface_id=surface_id,
        version=version,
        target_id=target.target_id,
        target_version=target.version,
        kind=SurfaceKind.MESSAGES,
        protocol="https",
        method="POST",
        relative_path=relative_path,
        trust_boundary="untrusted-input-to-model",
        authentication_required=target.auth_mode is not AuthMode.NONE,
        risk=RiskLevel.HIGH,
        owasp_mappings=(
            OwaspMapping("OWASP Web", "2021", "A03", "Injection"),
            OwaspMapping("OWASP LLM", "2025", "LLM01", "Prompt Injection"),
        ),
        oracle_refs=(f"oracle://surface/{surface_id}-{version}",),
        enabled=enabled,
    )


def _ready_registry(target: TargetDefinition, *surfaces: AttackSurfaceDefinition) -> TargetRegistry:
    registry = TargetRegistry()
    registry.register_target(target)
    for surface in surfaces:
        registry.register_surface(surface)
    registry.transition_target(target.target_id, target.version, TargetLifecycle.VALIDATING)
    registry.transition_target(target.target_id, target.version, TargetLifecycle.READY)
    return registry


def _scope(target: TargetDefinition, surface: AttackSurfaceDefinition) -> AuthorizationScope:
    return AuthorizationScope.for_definitions(
        target=target,
        surface=surface,
        corpus_hash="b" * 64,
        caps=_caps(),
        run_nonce="run-nonce-000002",
    )


def test_two_unrelated_targets_can_share_one_adapter_kind() -> None:
    alpha = _target("target-alpha", "alpha.example.test")
    beta = _target("target-beta", "beta.example.test")
    alpha_surface = _surface(alpha, "surface-alpha")
    beta_surface = _surface(beta, "surface-beta")
    registry = TargetRegistry()

    for target, surface in ((alpha, alpha_surface), (beta, beta_surface)):
        registry.register_target(target)
        registry.register_surface(surface)
        registry.transition_target(target.target_id, target.version, TargetLifecycle.VALIDATING)
        registry.transition_target(target.target_id, target.version, TargetLifecycle.READY)

    assert registry.resolve(_scope(alpha, alpha_surface)).target.adapter_kind == "shared-json"
    assert registry.resolve(_scope(beta, beta_surface)).target.adapter_kind == "shared-json"


def test_one_target_has_multiple_immutable_versioned_surfaces() -> None:
    target = _target("target-alpha", "alpha.example.test")
    first = _surface(target, "surface-messages", version="1.0.0")
    second = _surface(
        target,
        "surface-messages",
        version="2.0.0",
        relative_path="v2/messages",
    )
    files = _surface(target, "surface-files", relative_path="v1/files")
    registry = _ready_registry(target, first, second, files)

    assert registry.surface_history(target.target_id, first.surface_id) == (first, second)
    assert registry.get_surface(target.target_id, first.surface_id, "1.0.0") is first
    assert registry.get_surface(target.target_id, first.surface_id, "2.0.0") is second
    with pytest.raises(FrozenInstanceError):
        first.relative_path = "changed"  # type: ignore[misc]


def test_target_revision_preserves_prior_version_and_identity() -> None:
    first = _target("target-alpha", "alpha.example.test")
    second = first.revise(version="2.0.0", name="Revised service")
    registry = TargetRegistry()
    registry.register_target(first)
    registry.register_target(second)

    assert registry.target_history(first.target_id) == (first, second)
    assert registry.get_target(first.target_id, "1.0.0") is first
    assert registry.get_target(first.target_id).version == "2.0.0"
    assert second.target_id == first.target_id


def test_lifecycle_transitions_do_not_overwrite_registered_version_history() -> None:
    target = _target("target-alpha", "alpha.example.test")
    registry = TargetRegistry()
    registry.register_target(target)

    registry.transition_target(target.target_id, target.version, TargetLifecycle.VALIDATING)
    ready = registry.transition_target(target.target_id, target.version, TargetLifecycle.READY)

    assert registry.target_history(target.target_id) == (target,)
    assert registry.target_history(target.target_id)[0] is target
    assert target.lifecycle is TargetLifecycle.DRAFT
    assert registry.get_target(target.target_id, target.version) == ready
    assert registry.target_lifecycle_history(target.target_id, target.version) == (
        TargetLifecycle.DRAFT,
        TargetLifecycle.VALIDATING,
        TargetLifecycle.READY,
    )


def test_duplicate_versions_cannot_overwrite_registry_history() -> None:
    target = _target("target-alpha", "alpha.example.test")
    surface = _surface(target, "surface-alpha")
    registry = TargetRegistry()
    registry.register_target(target)
    registry.register_surface(surface)

    with pytest.raises(RegistrationError, match="already registered"):
        registry.register_target(target)
    with pytest.raises(RegistrationError, match="already registered"):
        registry.register_surface(surface)


@pytest.mark.parametrize(
    "change",
    [
        {"target_id": "target-beta"},
        {"surface_id": "surface-other"},
        {"exact_host": "other.example.test"},
        {"adapter_kind": "other-json"},
        {"target_version": "9.0.0"},
        {"surface_version": "9.0.0"},
        {"relative_path": "v1/other"},
        {
            "auth_mode": AuthMode.BEARER,
            "credential_ref": "secretref://staging/other",
            "explicit_no_auth": False,
        },
        {"protocol": "adapter-native"},
        {"method": "PUT"},
    ],
)
def test_cross_target_surface_host_adapter_and_version_substitution_is_rejected(
    change: dict[str, object],
) -> None:
    target = _target("target-alpha", "alpha.example.test")
    surface = _surface(target, "surface-alpha")
    registry = _ready_registry(target, surface)
    altered = replace(_scope(target, surface), **change)

    with pytest.raises((AuthorizationScopeMismatch, TargetNotFoundError, VersionMismatchError)):
        registry.resolve(altered)


def test_credential_and_caps_substitution_is_rejected() -> None:
    target = _target(
        "target-alpha",
        "alpha.example.test",
        auth_mode=AuthMode.BEARER,
        credential_ref="secretref://staging/target-alpha",
    )
    surface = _surface(target, "surface-alpha")
    registry = _ready_registry(target, surface)
    scope = _scope(target, surface)

    with pytest.raises(AuthorizationScopeMismatch):
        registry.resolve(replace(scope, credential_ref="secretref://staging/target-beta"))
    with pytest.raises(AuthorizationScopeMismatch):
        registry.resolve(replace(scope, caps=_caps(budget=11.0)))


def test_unknown_unready_disabled_and_archived_targets_fail_closed() -> None:
    target = _target("target-alpha", "alpha.example.test")
    surface = _surface(target, "surface-alpha")
    registry = TargetRegistry()

    with pytest.raises(TargetNotFoundError):
        registry.resolve(_scope(target, surface))

    registry.register_target(target)
    registry.register_surface(surface)
    with pytest.raises(TargetNotReadyError):
        registry.resolve(_scope(target, surface))

    validating = registry.transition_target(
        target.target_id, target.version, TargetLifecycle.VALIDATING
    )
    with pytest.raises(TargetNotReadyError):
        registry.resolve(_scope(validating, surface))

    ready = registry.transition_target(target.target_id, target.version, TargetLifecycle.READY)
    registry.resolve(_scope(ready, surface))

    disabled = registry.transition_target(
        target.target_id, target.version, TargetLifecycle.DISABLED
    )
    with pytest.raises(TargetUnavailableError):
        registry.resolve(_scope(disabled, surface))

    archived = registry.transition_target(
        target.target_id, target.version, TargetLifecycle.ARCHIVED
    )
    with pytest.raises(TargetUnavailableError):
        registry.resolve(_scope(archived, surface))


def test_disabled_surface_and_auth_mismatch_fail_closed() -> None:
    target = _target("target-alpha", "alpha.example.test")
    disabled = _surface(target, "surface-disabled", enabled=False)
    registry = _ready_registry(target, disabled)

    ready = target.transition(TargetLifecycle.VALIDATING).transition(TargetLifecycle.READY)
    with pytest.raises(SurfaceUnavailableError):
        registry.resolve(_scope(ready, disabled))

    bad_surface = replace(disabled, surface_id="surface-bad", authentication_required=True)
    other_registry = TargetRegistry()
    other_registry.register_target(target)
    with pytest.raises(RegistrationError, match="authentication"):
        other_registry.register_surface(bad_surface)


def test_surface_registration_is_refused_after_target_validation_starts() -> None:
    target = _target("target-alpha", "alpha.example.test")
    registry = TargetRegistry()
    registry.register_target(target)
    registry.transition_target(target.target_id, target.version, TargetLifecycle.VALIDATING)

    with pytest.raises(RegistrationError, match="draft"):
        registry.register_surface(_surface(target, "surface-late"))

    registry.transition_target(target.target_id, target.version, TargetLifecycle.READY)
    with pytest.raises(RegistrationError, match="draft"):
        registry.register_surface(_surface(target, "surface-unvalidated"))


def test_surface_cannot_be_rebound_to_another_target() -> None:
    alpha = _target("target-alpha", "alpha.example.test")
    beta = _target("target-beta", "beta.example.test")
    registry = TargetRegistry()
    registry.register_target(alpha)
    registry.register_target(beta)
    registry.register_surface(_surface(alpha, "surface-shared"))

    with pytest.raises(RegistrationError, match="immutable target"):
        registry.register_surface(_surface(beta, "surface-shared", version="2.0.0"))
