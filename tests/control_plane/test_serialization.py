from __future__ import annotations

import pytest

from agentforge.control_plane.serialization import scope_from_payload
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
)


def _scope() -> AuthorizationScope:
    caps = SafetyCaps(
        budget_usd=2.0,
        max_attempts_per_run=3,
        target_requests_per_second=0.5,
        run_timeout_seconds=60.0,
    )
    target = TargetDefinition(
        target_id="target-alpha",
        name="Alpha service",
        version="1.0.0",
        adapter_kind="shared-json",
        environment=TargetEnvironment.STAGING,
        base_url="https://alpha.example.test/api",
        allowlisted_hosts=("alpha.example.test",),
        auth_mode=AuthMode.NONE,
        credential_ref=None,
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://fixtures/alpha-v1",
        canary_refs=(),
        oracle_refs=("oracle://policy/alpha-v1",),
        safety_caps=caps,
    )
    surface = AttackSurfaceDefinition(
        surface_id="surface-chat",
        version="1.0.0",
        target_id=target.target_id,
        target_version=target.version,
        kind=SurfaceKind.CHAT,
        protocol="https",
        method="POST",
        relative_path="v1/chat",
        trust_boundary="untrusted-input-to-model",
        authentication_required=False,
        risk=RiskLevel.HIGH,
        owasp_mappings=(OwaspMapping("OWASP Web", "2021", "A03", "Injection"),),
        oracle_refs=("oracle://surface/chat-v1",),
        enabled=True,
    )
    return AuthorizationScope.for_definitions(
        target=target,
        surface=surface,
        corpus_hash="a" * 64,
        caps=caps,
        run_nonce="run-nonce-000001",
    )


def test_scope_target_policy_bindings_round_trip_canonically() -> None:
    scope = _scope()

    restored = scope_from_payload(scope.canonical_payload())

    assert restored == scope
    assert restored.scope_hash() == scope.scope_hash()


@pytest.mark.parametrize(
    "missing",
    (
        "allowlisted_hosts",
        "synthetic_data_only",
        "synthetic_data_attestation_ref",
    ),
)
def test_scope_deserialization_refuses_legacy_payload_missing_target_policy_binding(
    missing: str,
) -> None:
    payload = _scope().canonical_payload()
    del payload[missing]

    with pytest.raises(DefinitionError, match="missing trusted target-policy bindings"):
        scope_from_payload(payload)


def test_scope_deserialization_refuses_noncanonical_or_false_target_policy_bindings() -> None:
    tuple_hosts = _scope().canonical_payload()
    tuple_hosts["allowlisted_hosts"] = ("alpha.example.test",)
    with pytest.raises(DefinitionError, match="canonical list"):
        scope_from_payload(tuple_hosts)

    false_assertion = _scope().canonical_payload()
    false_assertion["synthetic_data_only"] = False
    with pytest.raises(DefinitionError, match="synthetic data only"):
        scope_from_payload(false_assertion)
