from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    AuthorizationScope,
    DefinitionError,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)


def _caps() -> SafetyCaps:
    return SafetyCaps(
        budget_usd=10.0,
        max_attempts_per_run=20,
        target_requests_per_second=2.0,
        run_timeout_seconds=60.0,
    )


def _target(
    *,
    auth_mode: AuthMode = AuthMode.NONE,
    credential_ref: str | None = None,
) -> TargetDefinition:
    return TargetDefinition(
        target_id="target-alpha",
        name="Alpha service",
        version="1.0.0",
        adapter_kind="shared-json",
        environment=TargetEnvironment.STAGING,
        base_url="https://alpha.example.test/api",
        allowlisted_hosts=("alpha.example.test",),
        auth_mode=auth_mode,
        credential_ref=credential_ref,
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://fixtures/alpha-v1",
        canary_refs=(),
        oracle_refs=("oracle://policy/alpha-v1",),
        safety_caps=_caps(),
    )


def _surface(**overrides: object) -> AttackSurfaceDefinition:
    values: dict[str, object] = {
        "surface_id": "surface-chat",
        "version": "1.0.0",
        "target_id": "target-alpha",
        "target_version": "1.0.0",
        "kind": SurfaceKind.CHAT,
        "protocol": "https",
        "method": "POST",
        "relative_path": "v1/chat",
        "trust_boundary": "untrusted-input-to-model",
        "authentication_required": False,
        "risk": RiskLevel.HIGH,
        "owasp_mappings": (
            OwaspMapping("OWASP Web", "2021", "A03", "Injection"),
            OwaspMapping("OWASP LLM", "2025", "LLM01", "Prompt Injection"),
        ),
        "oracle_refs": ("oracle://surface/chat-v1",),
        "enabled": True,
    }
    values.update(overrides)
    return AttackSurfaceDefinition(**values)  # type: ignore[arg-type]


def test_target_id_is_immutable_and_revision_preserves_it() -> None:
    original = _target()

    with pytest.raises(FrozenInstanceError):
        original.target_id = "target-beta"  # type: ignore[misc]

    revised = original.revise(version="2.0.0", name="Alpha service v2")
    assert revised.target_id == original.target_id
    assert revised.name == "Alpha service v2"
    assert revised.version == "2.0.0"
    assert revised.lifecycle is TargetLifecycle.DRAFT
    assert original.version == "1.0.0"


@pytest.mark.parametrize("auth_mode", [AuthMode.BEARER, AuthMode.SESSION, AuthMode.OAUTH])
def test_authenticated_modes_require_a_credential_reference(auth_mode: AuthMode) -> None:
    with pytest.raises(DefinitionError, match="credential reference"):
        _target(auth_mode=auth_mode)

    target = _target(
        auth_mode=auth_mode,
        credential_ref=f"secretref://staging/{auth_mode.value}/target-alpha",
    )
    assert target.credential_ref is not None
    assert target.explicit_no_auth is False


def test_no_auth_forbids_a_credential_reference() -> None:
    target = _target()
    assert target.explicit_no_auth is True

    with pytest.raises(DefinitionError, match="must not carry"):
        _target(auth_mode=AuthMode.NONE, credential_ref="secretref://staging/unused")


@pytest.mark.parametrize(
    "credential_ref",
    [
        "inline-value",
        "https://vault.example.test/item",
        "secretref://",
        "secretref://../item",
        "secretref://staging/%2e%2e/other",
        "secretref://staging/folder%2Fother",
        r"secretref://staging/folder\other",
        "secretref://staging//other",
        "secretref://staging/other/",
        "secretref://staging/./other",
    ],
)
def test_credential_reference_must_be_an_opaque_secret_reference(
    credential_ref: str,
) -> None:
    with pytest.raises(DefinitionError, match="credential reference"):
        _target(auth_mode=AuthMode.BEARER, credential_ref=credential_ref)


def test_synthetic_attestation_is_mandatory() -> None:
    with pytest.raises(DefinitionError, match="synthetic"):
        replace(_target(), synthetic_data_only=False)
    with pytest.raises(DefinitionError, match="attestation"):
        replace(_target(), synthetic_data_attestation_ref="")


def test_lifecycle_allows_only_adjacent_forward_transitions() -> None:
    draft = _target()
    with pytest.raises(DefinitionError, match="lifecycle transition"):
        draft.transition(TargetLifecycle.READY)

    validating = draft.transition(TargetLifecycle.VALIDATING)
    ready = validating.transition(TargetLifecycle.READY)
    disabled = ready.transition(TargetLifecycle.DISABLED)
    archived = disabled.transition(TargetLifecycle.ARCHIVED)

    with pytest.raises(DefinitionError, match="lifecycle transition"):
        ready.transition(TargetLifecycle.VALIDATING)
    with pytest.raises(DefinitionError, match="lifecycle transition"):
        archived.transition(TargetLifecycle.DRAFT)


@pytest.mark.parametrize(
    "base_url,allowed_hosts",
    [
        ("http://alpha.example.test", ("alpha.example.test",)),
        ("https://user@alpha.example.test", ("alpha.example.test",)),
        ("https://alpha.example.test?q=1", ("alpha.example.test",)),
        ("https://alpha.example.test#fragment", ("alpha.example.test",)),
        ("https://alpha.example.test", ("beta.example.test",)),
        ("https://alpha.example.test/%2525252e%2525252e/admin", ("alpha.example.test",)),
        ("https://alpha.example.test:0443/api", ("alpha.example.test:443",)),
        ("https://alpha.example.test:/api", ("alpha.example.test",)),
    ],
)
def test_target_requires_an_exact_allowlisted_https_base_url(
    base_url: str, allowed_hosts: tuple[str, ...]
) -> None:
    with pytest.raises(DefinitionError):
        TargetDefinition(
            target_id="target-alpha",
            name="Alpha service",
            version="1.0.0",
            adapter_kind="shared-json",
            environment=TargetEnvironment.STAGING,
            base_url=base_url,
            allowlisted_hosts=allowed_hosts,
            auth_mode=AuthMode.NONE,
            credential_ref=None,
            synthetic_data_only=True,
            synthetic_data_attestation_ref="attestation://fixtures/alpha-v1",
            canary_refs=(),
            oracle_refs=("oracle://policy/alpha-v1",),
            safety_caps=_caps(),
        )


@pytest.mark.parametrize(
    "field", ["budget_usd", "target_requests_per_second", "run_timeout_seconds"]
)
@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), True])
def test_safety_caps_reject_non_positive_or_non_finite_values(field: str, value: object) -> None:
    values: dict[str, object] = {
        "budget_usd": 10.0,
        "max_attempts_per_run": 20,
        "target_requests_per_second": 2.0,
        "run_timeout_seconds": 60.0,
    }
    values[field] = value
    with pytest.raises(DefinitionError):
        SafetyCaps(**values)  # type: ignore[arg-type]


def test_surface_kind_set_is_explicit_and_complete() -> None:
    assert {kind.value for kind in SurfaceKind} == {
        "chat",
        "completion",
        "responses",
        "messages",
        "tool",
        "rag",
        "memory",
        "file",
        "action",
        "custom",
    }


@pytest.mark.parametrize(
    "relative_path",
    [
        "/v1/chat",
        "//other.example.test/v1/chat",
        "https://other.example.test/v1/chat",
        "../admin",
        "v1/../admin",
        "v1/%2e%2e/admin",
        r"..\admin",
        r"\\other.example.test\v1\chat",
        "v1/chat?next=https://other.example.test",
        "v1/chat#override",
    ],
)
def test_surface_rejects_absolute_traversal_and_host_override_paths(
    relative_path: str,
) -> None:
    with pytest.raises(DefinitionError, match="relative path"):
        _surface(relative_path=relative_path)


def test_authorization_scope_is_canonical_and_credential_free_for_no_auth() -> None:
    target = _target()
    surface = _surface()
    scope = AuthorizationScope.for_definitions(
        target=target,
        surface=surface,
        corpus_hash="a" * 64,
        caps=_caps(),
        run_nonce="run-nonce-000001",
    )

    payload = scope.canonical_payload()
    assert payload == {
        "target_id": "target-alpha",
        "target_version": "1.0.0",
        "surface_id": "surface-chat",
        "surface_version": "1.0.0",
        "adapter_kind": "shared-json",
        "environment": "staging",
        "exact_host": "alpha.example.test",
        "auth_mode": "none",
        "credential_ref": None,
        "explicit_no_auth": True,
        "protocol": "https",
        "method": "POST",
        "relative_path": "v1/chat",
        "corpus_hash": "a" * 64,
        "caps": {
            "budget_usd": 10.0,
            "max_attempts_per_run": 20,
            "target_requests_per_second": 2.0,
            "run_timeout_seconds": 60.0,
        },
        "run_nonce": "run-nonce-000001",
    }


def test_scope_hash_binds_corpus_caps_and_run_nonce() -> None:
    target = _target()
    surface = _surface()
    scope = AuthorizationScope.for_definitions(
        target=target,
        surface=surface,
        corpus_hash="a" * 64,
        caps=_caps(),
        run_nonce="run-nonce-000001",
    )

    variants = (
        replace(scope, corpus_hash="d" * 64),
        replace(scope, caps=replace(_caps(), budget_usd=9.0)),
        replace(scope, run_nonce="run-nonce-000009"),
    )
    assert all(variant.scope_hash() != scope.scope_hash() for variant in variants)
