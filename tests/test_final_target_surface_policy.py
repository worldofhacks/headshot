"""T-F16a RED contract for immutable, surface-specific target policy.

The partial final-target implementation selects request profiles at target/path level.  These
tests instead exercise the trusted serialized boundary: every v2 surface owns one complete policy,
the policy has an independently reproducible SHA-256, and that policy/hash travel in the
authorization scope before registry resolution.  No adapter, credential resolver, fixture reader,
or network client is used here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from agentforge.control_plane.serialization import (
    scope_from_payload,
    surface_from_payload,
    surface_payload,
    target_from_payload,
)
from agentforge.target.adapter_registry import AdapterRegistry
from agentforge.target.catalog import TargetCatalogError, TrustedTargetCatalog
from agentforge.target.registry import (
    AuthorizationScopeMismatch,
    SurfaceUnavailableError,
    TargetRegistry,
    VersionMismatchError,
)
from agentforge.target.spec import AuthorizationScope, DefinitionError, TargetLifecycle

JsonObject = dict[str, Any]
PolicyMutation = Callable[[JsonObject], None]

_CATALOG_ENV = "AGENTFORGE_LIVE_TARGET_CATALOG_JSON"
_WEEK1_TARGET_ID = "clinical-copilot-week1"
_WEEK2_TARGET_ID = "clinical-copilot-week2"
_TARGET_VERSION = "2.0.0"
_DOCUMENT_CANDIDATE_VERSION = "2.1.0"
_WEEK1_CREDENTIAL_REF = "secretref://production/clinical-copilot-week1/session/generation-20260724a"
_WEEK2_CREDENTIAL_REF = "secretref://production/clinical-copilot-week2/session/generation-20260724a"
_CREDENTIAL_REF = _WEEK2_CREDENTIAL_REF
_CORPUS_HASH = "a" * 64
_RUN_NONCE = "run-t-f16a-000001"
_PARTIAL_TARGET_WIDE_PROFILES = [
    "copilot_chat",
    "copilot_public_get",
    "copilot_evidence_search",
    "copilot_document_upload",
    "copilot_document_read",
]
_POLICY_KEYS = {
    "schema",
    "schema_version",
    "adapter_profile",
    "auth_mode",
    "credential_ref",
    "explicit_no_auth",
    "redirect_policy",
    "response_size_limit_bytes",
    "request_timeout_seconds",
    "tls_required",
    "operation_templates",
    "maximum_logical_operations",
    "physical_request_limit",
    "fixture_descriptors",
}
_OPERATION_KEYS = {
    "operation_class",
    "method",
    "relative_path",
    "request_content_type",
    "response_content_types",
    "credential_placement",
    "credential_field_name",
    "retry_count",
    "maximum_logical_operations",
}
_FIXTURE_KEYS = {
    "opaque_ref",
    "sha256",
    "byte_length",
    "media_type",
    "doc_type",
    "workflow_id",
}

_LAB_FIXTURE = {
    "opaque_ref": "fixture://clinical-copilot/week2/clean-pdf-20260724",
    "sha256": "145f3d50a1f807429d5b0ddc459bf649c00a5b8f64736982132fab14a7574969",
    "byte_length": 753,
    "media_type": "application/pdf",
    "doc_type": "lab_pdf",
    "workflow_id": "lab-extraction-v1",
}
_INTAKE_FIXTURE = {
    "opaque_ref": "fixture://clinical-copilot/week2/intake-full-valid-pdf-20260724",
    "sha256": "406c8eb63e0675b6ffa2c04d5bde687de14eff997be3bac6960fb3c3753c45bd",
    "byte_length": 2146,
    "media_type": "application/pdf",
    "doc_type": "intake_form",
    "workflow_id": "intake-idempotency-v1",
}


def _canonical_sha256(payload: JsonObject) -> str:
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _operation(
    operation_class: str,
    method: str,
    relative_path: str,
    *,
    request_content_type: str | None,
    response_content_types: list[str],
    credential_placement: str,
    credential_field_name: str | None,
    retry_count: int,
    maximum_logical_operations: int = 1,
) -> JsonObject:
    return {
        "operation_class": operation_class,
        "method": method,
        "relative_path": relative_path,
        "request_content_type": request_content_type,
        "response_content_types": response_content_types,
        "credential_placement": credential_placement,
        "credential_field_name": credential_field_name,
        "retry_count": retry_count,
        "maximum_logical_operations": maximum_logical_operations,
    }


def _policy(
    adapter_profile: str,
    operations: list[JsonObject],
    *,
    auth_mode: str = "session",
    credential_ref: str | None = _CREDENTIAL_REF,
    explicit_no_auth: bool = False,
    fixture_descriptors: list[JsonObject] | None = None,
    response_size_limit_bytes: int = 262_144,
) -> JsonObject:
    maximum_logical_operations = sum(
        operation["maximum_logical_operations"] for operation in operations
    )
    physical_request_limit = sum(
        operation["maximum_logical_operations"] * (operation["retry_count"] + 1)
        for operation in operations
    )
    return {
        "schema": "agentforge.target-surface-policy",
        "schema_version": 2,
        "adapter_profile": adapter_profile,
        "auth_mode": auth_mode,
        "credential_ref": credential_ref,
        "explicit_no_auth": explicit_no_auth,
        "redirect_policy": "deny",
        "response_size_limit_bytes": response_size_limit_bytes,
        "request_timeout_seconds": 30.0,
        "tls_required": True,
        "operation_templates": operations,
        "maximum_logical_operations": maximum_logical_operations,
        "physical_request_limit": physical_request_limit,
        "fixture_descriptors": fixture_descriptors or [],
    }


def _chat_policy(*, credential_ref: str = _WEEK2_CREDENTIAL_REF) -> JsonObject:
    return _policy(
        "copilot_chat",
        [
            _operation(
                "chat",
                "POST",
                "chat",
                request_content_type="application/json",
                response_content_types=["application/json"],
                credential_placement="json",
                credential_field_name="session_id",
                retry_count=0,
            )
        ],
        credential_ref=credential_ref,
    )


def _ui_policy(
    *,
    relative_path: str = "week2",
    credential_ref: str = _WEEK2_CREDENTIAL_REF,
) -> JsonObject:
    return _policy(
        "copilot_public_get",
        [
            _operation(
                "ui_shell",
                "GET",
                relative_path,
                request_content_type=None,
                response_content_types=["text/html"],
                credential_placement="query",
                credential_field_name="sid",
                retry_count=0,
            )
        ],
        credential_ref=credential_ref,
    )


def _evidence_policy() -> JsonObject:
    return _policy(
        "copilot_evidence_search",
        [
            _operation(
                "evidence_search",
                "POST",
                "evidence/search",
                request_content_type="application/json",
                response_content_types=["application/json"],
                credential_placement="none",
                credential_field_name=None,
                retry_count=0,
            )
        ],
        auth_mode="none",
        credential_ref=None,
        explicit_no_auth=True,
    )


def _lab_policy() -> JsonObject:
    return _policy(
        "copilot_document_workflow",
        [
            _operation(
                "upload",
                "POST",
                "documents",
                request_content_type="multipart/form-data",
                response_content_types=["application/json"],
                credential_placement="multipart",
                credential_field_name="session_id",
                retry_count=0,
            ),
            _operation(
                "status_poll",
                "GET",
                "documents/{document_id}/status",
                request_content_type=None,
                response_content_types=["application/json"],
                credential_placement="query",
                credential_field_name="session_id",
                retry_count=1,
                maximum_logical_operations=30,
            ),
            _operation(
                "report",
                "GET",
                "documents/{document_id}/extraction-report",
                request_content_type=None,
                response_content_types=["application/json"],
                credential_placement="query",
                credential_field_name="session_id",
                retry_count=1,
            ),
            _operation(
                "preview",
                "GET",
                "documents/{document_id}/pages/{page}",
                request_content_type=None,
                response_content_types=["image/png"],
                credential_placement="query",
                credential_field_name="session_id",
                retry_count=1,
            ),
            _operation(
                "readback",
                "GET",
                "documents/{document_id}/readback-verification",
                request_content_type=None,
                response_content_types=["application/json"],
                credential_placement="query",
                credential_field_name="session_id",
                retry_count=1,
            ),
        ],
        fixture_descriptors=[deepcopy(_LAB_FIXTURE)],
        response_size_limit_bytes=10_485_760,
    )


def _intake_policy() -> JsonObject:
    return _policy(
        "copilot_document_workflow",
        [
            _operation(
                "upload",
                "POST",
                "documents",
                request_content_type="multipart/form-data",
                response_content_types=["application/json"],
                credential_placement="multipart",
                credential_field_name="session_id",
                retry_count=0,
            ),
            _operation(
                "duplicate_check",
                "POST",
                "documents",
                request_content_type="multipart/form-data",
                response_content_types=["application/json"],
                credential_placement="multipart",
                credential_field_name="session_id",
                retry_count=0,
            ),
        ],
        fixture_descriptors=[deepcopy(_INTAKE_FIXTURE)],
        response_size_limit_bytes=10_485_760,
    )


def _surface(
    surface_id: str,
    *,
    kind: str,
    method: str,
    relative_path: str,
    authentication_required: bool,
    policy: JsonObject,
    target_id: str = _WEEK2_TARGET_ID,
    version: str = _TARGET_VERSION,
    enabled: bool = True,
) -> JsonObject:
    return {
        "surface_id": surface_id,
        "version": version,
        "target_id": target_id,
        "target_version": version,
        "kind": kind,
        "protocol": "https",
        "method": method,
        "relative_path": relative_path,
        "trust_boundary": (
            "authenticated-session" if authentication_required else "anonymous-guideline-retrieval"
        ),
        "authentication_required": authentication_required,
        "risk": "critical" if kind in {"chat", "file"} else "high",
        "owasp_mappings": [
            {
                "framework": "OWASP Web",
                "version": "2021",
                "id": "A03",
                "name": "Injection",
            },
            {
                "framework": "OWASP LLM",
                "version": "2025",
                "id": "LLM01",
                "name": "Prompt Injection",
            },
        ],
        "oracle_refs": ["oracle://agentforge/copilot-surface-v2"],
        "enabled": enabled,
        "surface_policy": policy,
        "surface_policy_sha256": _canonical_sha256(policy),
    }


def _surface_payloads(
    *,
    version: str = _TARGET_VERSION,
    documents_enabled: bool = False,
) -> dict[str, JsonObject]:
    return {
        "chat": _surface(
            "clinical-copilot-week2-chat",
            kind="chat",
            method="POST",
            relative_path="chat",
            authentication_required=True,
            policy=_chat_policy(),
            version=version,
        ),
        "ui": _surface(
            "clinical-copilot-week2-ui",
            kind="custom",
            method="GET",
            relative_path="week2",
            authentication_required=True,
            policy=_ui_policy(),
            version=version,
        ),
        "evidence": _surface(
            "clinical-copilot-week2-evidence",
            kind="rag",
            method="POST",
            relative_path="evidence/search",
            authentication_required=False,
            policy=_evidence_policy(),
            version=version,
        ),
        "lab": _surface(
            "clinical-copilot-week2-lab",
            kind="file",
            method="POST",
            relative_path="documents",
            authentication_required=True,
            policy=_lab_policy(),
            version=version,
            enabled=documents_enabled,
        ),
        "intake": _surface(
            "clinical-copilot-week2-intake",
            kind="file",
            method="POST",
            relative_path="documents",
            authentication_required=True,
            policy=_intake_policy(),
            version=version,
            enabled=documents_enabled,
        ),
    }


def _week1_surface_payloads(*, version: str = _TARGET_VERSION) -> dict[str, JsonObject]:
    return {
        "chat": _surface(
            "clinical-copilot-week1-chat",
            kind="chat",
            method="POST",
            relative_path="chat",
            authentication_required=True,
            policy=_chat_policy(credential_ref=_WEEK1_CREDENTIAL_REF),
            target_id=_WEEK1_TARGET_ID,
            version=version,
        ),
        "ui": _surface(
            "clinical-copilot-week1-ui",
            kind="custom",
            method="GET",
            relative_path="app",
            authentication_required=True,
            policy=_ui_policy(
                relative_path="app",
                credential_ref=_WEEK1_CREDENTIAL_REF,
            ),
            target_id=_WEEK1_TARGET_ID,
            version=version,
        ),
        "evidence": _surface(
            "clinical-copilot-week1-evidence",
            kind="rag",
            method="POST",
            relative_path="evidence/search",
            authentication_required=False,
            policy=_evidence_policy(),
            target_id=_WEEK1_TARGET_ID,
            version=version,
        ),
    }


def _target_payload(
    *,
    target_id: str = _WEEK2_TARGET_ID,
    version: str = _TARGET_VERSION,
) -> JsonObject:
    week = "1" if target_id == _WEEK1_TARGET_ID else "2"
    credential_ref = (
        _WEEK1_CREDENTIAL_REF if target_id == _WEEK1_TARGET_ID else _WEEK2_CREDENTIAL_REF
    )
    return {
        "target_id": target_id,
        "name": f"Clinical Co-Pilot Week {week}",
        "version": version,
        "adapter_kind": "openemr",
        "environment": "production",
        "base_url": "https://copilot.example.test",
        "allowlisted_hosts": ["copilot.example.test"],
        "auth_mode": "session",
        "credential_ref": credential_ref,
        "synthetic_data_only": True,
        "synthetic_data_attestation_ref": f"attestation://agentforge/synthetic-week{week}-v2",
        "canary_refs": ["oracle://agentforge/SYNTH_CANARY_PATIENT_BETA_8C1E"],
        "oracle_refs": ["oracle://agentforge/copilot-chat-refusal-oracle-v1"],
        "safety_caps": {
            "budget_usd": 1.0,
            "max_attempts_per_run": 100,
            "target_requests_per_second": 0.5,
            "run_timeout_seconds": 1800.0,
            "logical_case_limit": 100,
            "physical_request_limit": 100,
            "target_retries_per_turn": 1,
        },
        "lifecycle": "draft",
    }


def _v2_entry(
    *,
    target_id: str = _WEEK2_TARGET_ID,
    version: str = _TARGET_VERSION,
    documents_enabled: bool = False,
) -> JsonObject:
    surfaces = (
        _week1_surface_payloads(version=version)
        if target_id == _WEEK1_TARGET_ID
        else _surface_payloads(version=version, documents_enabled=documents_enabled)
    )
    return {
        "target": _target_payload(target_id=target_id, version=version),
        "surfaces": list(surfaces.values()),
        "ownership_authorization_ref": (
            "authorization://agentforge/headshot-owner-synthetic-2026-07-24"
        ),
    }


def _v2_entries() -> list[JsonObject]:
    return [
        _v2_entry(target_id=_WEEK1_TARGET_ID),
        _v2_entry(target_id=_WEEK2_TARGET_ID),
    ]


def _parse_canonical_surface(payload: JsonObject) -> Any:
    try:
        parsed = surface_from_payload(deepcopy(payload))
    except Exception as exc:  # noqa: BLE001 - turn absent v2 support into intentional RED
        pytest.fail(f"canonical per-surface policy is not implemented: {exc!r}")
    assert surface_payload(parsed) == payload
    return parsed


def _load_canonical_catalog(
    monkeypatch: pytest.MonkeyPatch,
    entries: JsonObject | list[JsonObject] | None = None,
) -> TrustedTargetCatalog:
    if entries is None:
        payload = _v2_entries()
    elif isinstance(entries, list):
        payload = entries
    else:
        payload = [entries]
    monkeypatch.setenv(_CATALOG_ENV, json.dumps(payload))
    try:
        return TrustedTargetCatalog.from_environment("production")
    except Exception as exc:  # noqa: BLE001 - turn absent v2 support into intentional RED
        pytest.fail(f"canonical multi-surface policy catalog is not implemented: {exc!r}")


def _target_and_surfaces(
    *,
    target_id: str = _WEEK2_TARGET_ID,
    version: str = _TARGET_VERSION,
    documents_enabled: bool = False,
) -> tuple[Any, dict[str, Any]]:
    target = target_from_payload(_target_payload(target_id=target_id, version=version))
    payloads = (
        _week1_surface_payloads(version=version)
        if target_id == _WEEK1_TARGET_ID
        else _surface_payloads(version=version, documents_enabled=documents_enabled)
    )
    surfaces = {name: _parse_canonical_surface(payload) for name, payload in payloads.items()}
    return target, surfaces


def _document_candidate() -> tuple[Any, dict[str, Any]]:
    return _target_and_surfaces(
        version=_DOCUMENT_CANDIDATE_VERSION,
        documents_enabled=True,
    )


def _scope(target: Any, surface: Any) -> AuthorizationScope:
    try:
        return AuthorizationScope.for_definitions(
            target=target,
            surface=surface,
            corpus_hash=_CORPUS_HASH,
            caps=target.safety_caps,
            run_nonce=_RUN_NONCE,
        )
    except Exception as exc:  # noqa: BLE001 - turn absent v2 support into intentional RED
        pytest.fail(f"canonical surface policy is absent from authorization scope: {exc!r}")


def _ready_registry(target: Any, surfaces: list[Any]) -> TargetRegistry:
    registry = TargetRegistry()
    try:
        registry.register_target(target)
        for surface in surfaces:
            registry.register_surface(surface)
        registry.transition_target(target.target_id, target.version, TargetLifecycle.VALIDATING)
        registry.transition_target(target.target_id, target.version, TargetLifecycle.READY)
    except Exception as exc:  # noqa: BLE001 - turn absent v2 support into intentional RED
        pytest.fail(f"surface-specific registry policy is not implemented: {exc!r}")
    return registry


def _resolve_with_side_effect_boundaries(
    *,
    registry: TargetRegistry,
    adapters: AdapterRegistry,
    scope: AuthorizationScope,
    credential_resolver: Callable[[str | None], None],
    fixture_resolver: Callable[[JsonObject], None],
) -> None:
    resolved = registry.resolve(scope)
    credential_resolver(resolved.authorization_scope.credential_ref)
    for descriptor in surface_payload(resolved.surface)["surface_policy"]["fixture_descriptors"]:
        fixture_resolver(descriptor)
    adapters.resolve(scope)


def _rehash_surface(payload: JsonObject, mutation: PolicyMutation) -> JsonObject:
    changed = deepcopy(payload)
    mutation(changed["surface_policy"])
    changed["surface_policy_sha256"] = _canonical_sha256(changed["surface_policy"])
    return changed


def _set_operation_value(
    operation_index: int,
    field: str,
    value: Any,
) -> PolicyMutation:
    def mutate(policy: JsonObject) -> None:
        policy["operation_templates"][operation_index][field] = value

    return mutate


def _set_retry_and_rederive(operation_index: int, retry_count: int) -> PolicyMutation:
    def mutate(policy: JsonObject) -> None:
        policy["operation_templates"][operation_index]["retry_count"] = retry_count
        policy["maximum_logical_operations"] = sum(
            operation["maximum_logical_operations"] for operation in policy["operation_templates"]
        )
        policy["physical_request_limit"] = sum(
            operation["maximum_logical_operations"] * (operation["retry_count"] + 1)
            for operation in policy["operation_templates"]
        )

    return mutate


def _legacy_chat_entry(*, mixed_profiles: bool) -> JsonObject:
    target = _target_payload(version="1.0.0")
    target["target_id"] = "legacy-copilot"
    target["name"] = "Legacy single-profile Co-Pilot"
    target["credential_ref"] = "secretref://production/legacy-copilot/session/generation-v1"
    target["safety_caps"] = {
        "budget_usd": 1.0,
        "max_attempts_per_run": 2,
        "target_requests_per_second": 0.5,
        "run_timeout_seconds": 30.0,
    }
    chat = deepcopy(_surface_payloads()["chat"])
    for field in ("surface_policy", "surface_policy_sha256"):
        chat.pop(field)
    chat.update(
        {
            "surface_id": "legacy-copilot-chat",
            "version": "1.0.0",
            "target_id": "legacy-copilot",
            "target_version": "1.0.0",
        }
    )
    surfaces = [chat]
    policy: JsonObject = {
        "allowed_methods": ["POST"],
        "write_upload_allowed": False,
        "allowed_write_resource_refs": [],
        "redirect_policy": "deny",
        "response_size_limit_bytes": 262_144,
        "allowed_content_types": ["application/json"],
        "request_timeout_seconds": 30.0,
        "tls_required": True,
        "allow_private_destination": False,
        "payload_profile": "copilot_chat",
    }
    if mixed_profiles:
        policy["payload_profiles"] = deepcopy(_PARTIAL_TARGET_WIDE_PROFILES)
    return {
        "target": target,
        "surfaces": surfaces,
        "transport_policy": policy,
        "ownership_authorization_ref": "authorization://agentforge/legacy-v1",
    }


def _v1_week2_chat_definitions() -> tuple[Any, Any]:
    target_payload = _target_payload(version="1.0.0")
    surface_payload_v1 = deepcopy(_surface_payloads()["chat"])
    surface_payload_v1["version"] = "1.0.0"
    surface_payload_v1["target_version"] = "1.0.0"
    surface_payload_v1.pop("surface_policy")
    surface_payload_v1.pop("surface_policy_sha256")
    return (
        target_from_payload(target_payload),
        surface_from_payload(surface_payload_v1),
    )


# spec(T-F16a:AC-1)
def test_spec_t_f16a_ac_1_catalog_resolves_one_complete_policy_per_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = _load_canonical_catalog(monkeypatch)
    expected_by_target = {
        _WEEK1_TARGET_ID: _week1_surface_payloads(),
        _WEEK2_TARGET_ID: _surface_payloads(),
    }
    assert sum(len(surfaces) for surfaces in expected_by_target.values()) == 8

    for target_id, expected_surfaces in expected_by_target.items():
        parsed_surfaces = []
        target = target_from_payload(_target_payload(target_id=target_id))
        for surface_name, expected_payload in expected_surfaces.items():
            entry, surface = catalog.resolve(
                target_id=target_id,
                surface_id=expected_payload["surface_id"],
            )
            parsed_surfaces.append(surface)
            serialized = surface_payload(surface)
            policy = serialized["surface_policy"]
            assert entry.target.target_id == target_id
            assert set(policy) == _POLICY_KEYS
            assert policy == expected_payload["surface_policy"]
            assert serialized["surface_policy_sha256"] == _canonical_sha256(policy)
            assert all(
                set(operation) == _OPERATION_KEYS for operation in policy["operation_templates"]
            )
            assert policy["maximum_logical_operations"] == sum(
                operation["maximum_logical_operations"]
                for operation in policy["operation_templates"]
            )
            assert policy["physical_request_limit"] == sum(
                operation["maximum_logical_operations"] * (operation["retry_count"] + 1)
                for operation in policy["operation_templates"]
            )
            if target_id == _WEEK1_TARGET_ID and surface_name == "ui":
                assert serialized["relative_path"] == "app"
                assert policy["operation_templates"][0]["relative_path"] == "app"
                assert policy["operation_templates"][0]["credential_field_name"] == "sid"

        registry = _ready_registry(target, parsed_surfaces)
        for surface_name, surface in zip(expected_surfaces, parsed_surfaces, strict=True):
            scope = _scope(target, surface)
            if target_id == _WEEK2_TARGET_ID and surface_name in {"lab", "intake"}:
                with pytest.raises(SurfaceUnavailableError):
                    registry.resolve(scope)
            else:
                assert registry.resolve(scope).authorization_scope == scope

    candidate_catalog = _load_canonical_catalog(
        monkeypatch,
        _v2_entry(
            version=_DOCUMENT_CANDIDATE_VERSION,
            documents_enabled=True,
        ),
    )
    candidate_target = target_from_payload(_target_payload(version=_DOCUMENT_CANDIDATE_VERSION))
    candidate_surfaces = []
    candidate_scopes = {}
    for name, payload in _surface_payloads(
        version=_DOCUMENT_CANDIDATE_VERSION,
        documents_enabled=True,
    ).items():
        _, surface = candidate_catalog.resolve(
            target_id=_WEEK2_TARGET_ID,
            surface_id=payload["surface_id"],
        )
        candidate_surfaces.append(surface)
        candidate_scopes[name] = _scope(candidate_target, surface)

    candidate_registry = _ready_registry(candidate_target, candidate_surfaces)
    for name in ("lab", "intake"):
        assert candidate_registry.resolve(candidate_scopes[name]).surface.enabled is True

    v2_target, v2_surfaces = _target_and_surfaces()
    assert (
        _scope(v2_target, v2_surfaces["lab"]).scope_hash() != candidate_scopes["lab"].scope_hash()
    )


@pytest.mark.parametrize("version", ["2.0.1", "2.2.0", "3.0.0"])
# spec(T-F16a:AC-1,AC-6)
def test_spec_t_f16a_exact_activation_versions_refuse_document_workflow_bypass(
    monkeypatch: pytest.MonkeyPatch,
    version: str,
) -> None:
    monkeypatch.setenv(
        _CATALOG_ENV,
        json.dumps([_v2_entry(version=version, documents_enabled=True)]),
    )

    with pytest.raises(TargetCatalogError, match="exact approved activation"):
        TrustedTargetCatalog.from_environment("production")


@pytest.mark.parametrize("surface_version", ["1.0.0", "2.0.1", "3.0.0"])
# spec(T-F16a:AC-1,AC-6)
def test_spec_t_f16a_exact_activation_surface_versions_cannot_drift(
    monkeypatch: pytest.MonkeyPatch,
    surface_version: str,
) -> None:
    entry = _v2_entry()
    entry["surfaces"][0]["version"] = surface_version
    monkeypatch.setenv(_CATALOG_ENV, json.dumps([entry]))

    with pytest.raises(TargetCatalogError, match="surface policy version must match"):
        TrustedTargetCatalog.from_environment("production")


# spec(T-F16a:AC-1,AC-6)
def test_spec_t_f16a_document_activation_requires_exact_2_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        _CATALOG_ENV,
        json.dumps([_v2_entry(version="2.0.0", documents_enabled=True)]),
    )
    with pytest.raises(TargetCatalogError, match="v2.0.0 document surfaces must remain disabled"):
        TrustedTargetCatalog.from_environment("production")

    candidate = _load_canonical_catalog(
        monkeypatch,
        _v2_entry(version="2.1.0", documents_enabled=True),
    )
    _, lab = candidate.resolve(
        target_id=_WEEK2_TARGET_ID,
        surface_id="clinical-copilot-week2-lab",
    )
    assert lab.enabled is True


# spec(T-F16a:AC-1)
def test_spec_t_f16a_ac_1_caller_supplied_policy_hash_must_match_canonical_bytes() -> None:
    canonical = _surface_payloads()["chat"]
    _parse_canonical_surface(canonical)
    forged = deepcopy(canonical)
    forged["surface_policy_sha256"] = "0" * 64

    with pytest.raises(DefinitionError):
        surface_from_payload(forged)


@pytest.mark.parametrize("invalid_shape", ["missing", "duplicate", "target-wide"])
# spec(T-F16a:AC-1)
def test_spec_t_f16a_ac_1_missing_duplicate_or_target_wide_policy_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    invalid_shape: str,
) -> None:
    _load_canonical_catalog(monkeypatch)
    entry = _v2_entry()

    if invalid_shape == "missing":
        entry["surfaces"][1].pop("surface_policy")
        entry["surfaces"][1].pop("surface_policy_sha256")
    elif invalid_shape == "duplicate":
        entry["surfaces"].append(deepcopy(entry["surfaces"][0]))
    else:
        entry["transport_policy"] = {
            "allowed_methods": ["GET", "POST"],
            "write_upload_allowed": False,
            "allowed_write_resource_refs": [],
            "redirect_policy": "deny",
            "response_size_limit_bytes": 262_144,
            "allowed_content_types": ["application/json", "text/html"],
            "request_timeout_seconds": 30.0,
            "tls_required": True,
            "allow_private_destination": False,
            "payload_profile": "copilot_chat",
            "payload_profiles": ["copilot_chat", "copilot_public_get"],
        }

    monkeypatch.setenv(_CATALOG_ENV, json.dumps([entry]))
    with pytest.raises(TargetCatalogError):
        TrustedTargetCatalog.from_environment("production")


# spec(T-F16a:AC-2)
def test_spec_t_f16a_ac_2_exact_surface_credential_key_table_is_canonical() -> None:
    payloads = _surface_payloads()
    expected = {
        "chat": [("json", "session_id")],
        "ui": [("query", "sid")],
        "evidence": [("none", None)],
        "lab": [
            ("multipart", "session_id"),
            ("query", "session_id"),
            ("query", "session_id"),
            ("query", "session_id"),
            ("query", "session_id"),
        ],
        "intake": [("multipart", "session_id"), ("multipart", "session_id")],
    }

    for name, expected_credentials in expected.items():
        surface = _parse_canonical_surface(payloads[name])
        policy = surface_payload(surface)["surface_policy"]
        actual = [
            (operation["credential_placement"], operation["credential_field_name"])
            for operation in policy["operation_templates"]
        ]
        assert actual == expected_credentials
        if name == "evidence":
            assert policy["auth_mode"] == "none"
            assert policy["explicit_no_auth"] is True
            assert policy["credential_ref"] is None
        else:
            assert policy["auth_mode"] == "session"
            assert policy["explicit_no_auth"] is False
            assert policy["credential_ref"] == _CREDENTIAL_REF


@pytest.mark.parametrize(
    ("surface_name", "mutation"),
    [
        ("ui", _set_operation_value(0, "credential_field_name", "session_id")),
        ("ui", _set_operation_value(0, "credential_placement", "json")),
        ("ui", _set_operation_value(0, "credential_placement", "header")),
        ("ui", _set_operation_value(0, "credential_placement", "cookie")),
        ("ui", _set_operation_value(0, "credential_placement", "body")),
        ("ui", _set_operation_value(0, "credential_field_name", None)),
        ("chat", _set_operation_value(0, "credential_placement", "query")),
        ("chat", _set_operation_value(0, "credential_placement", "header")),
        ("chat", _set_operation_value(0, "credential_field_name", None)),
        ("lab", _set_operation_value(0, "credential_placement", "json")),
        ("lab", _set_operation_value(0, "credential_field_name", None)),
        ("lab", _set_operation_value(0, "credential_field_name", "sid")),
        ("lab", _set_operation_value(1, "credential_placement", "cookie")),
        ("lab", _set_operation_value(1, "credential_field_name", None)),
        ("evidence", _set_operation_value(0, "credential_placement", "query")),
        ("evidence", _set_operation_value(0, "credential_field_name", "session_id")),
    ],
)
# spec(T-F16a:AC-2,AC-5)
def test_spec_t_f16a_ac_2_hostile_credential_placement_changes_hash_and_cannot_resolve(
    surface_name: str,
    mutation: PolicyMutation,
) -> None:
    if surface_name in {"lab", "intake"}:
        target, surfaces = _document_candidate()
    else:
        target, surfaces = _target_and_surfaces()
    canonical_surface = surfaces[surface_name]
    registry = _ready_registry(target, [canonical_surface])
    canonical_payload = surface_payload(canonical_surface)
    hostile_payload = _rehash_surface(canonical_payload, mutation)

    assert hostile_payload["surface_policy_sha256"] != canonical_payload["surface_policy_sha256"]
    try:
        hostile_surface = surface_from_payload(hostile_payload)
    except DefinitionError:
        return

    hostile_scope = _scope(target, hostile_surface)
    with pytest.raises(AuthorizationScopeMismatch):
        registry.resolve(hostile_scope)


@pytest.mark.parametrize(
    ("case", "mutation"),
    [
        ("auth-mode", lambda policy: policy.update({"auth_mode": "session"})),
        ("explicit-no-auth", lambda policy: policy.update({"explicit_no_auth": False})),
        (
            "credential-ref",
            lambda policy: policy.update({"credential_ref": _WEEK2_CREDENTIAL_REF}),
        ),
        (
            "combined-authenticated-downgrade",
            lambda policy: policy.update(
                {
                    "auth_mode": "session",
                    "explicit_no_auth": False,
                    "credential_ref": _WEEK2_CREDENTIAL_REF,
                }
            ),
        ),
    ],
)
# spec(T-F16a:AC-2,AC-5)
def test_spec_t_f16a_ac_2_evidence_auth_triad_drift_is_refused_before_credentials(
    case: str,
    mutation: PolicyMutation,
) -> None:
    del case
    target, surfaces = _target_and_surfaces()
    evidence = surfaces["evidence"]
    registry = _ready_registry(target, [evidence])
    canonical = surface_payload(evidence)
    hostile = _rehash_surface(canonical, mutation)
    credential_calls = 0

    def credential_resolver(_: str | None) -> None:
        nonlocal credential_calls
        credential_calls += 1

    def resolve_with_credential(scope: AuthorizationScope) -> None:
        resolved = registry.resolve(scope)
        credential_resolver(resolved.authorization_scope.credential_ref)

    with pytest.raises((DefinitionError, AuthorizationScopeMismatch)):
        hostile_surface = surface_from_payload(hostile)
        resolve_with_credential(_scope(target, hostile_surface))
    assert credential_calls == 0


# spec(T-F16a:AC-2,AC-5)
def test_spec_t_f16a_ac_2_evidence_scope_never_inherits_target_authentication() -> None:
    target, surfaces = _target_and_surfaces()
    evidence = surfaces["evidence"]
    registry = _ready_registry(target, [evidence])
    scope = _scope(target, evidence)

    assert target.credential_ref == _CREDENTIAL_REF
    assert scope.auth_mode.value == "none"
    assert scope.explicit_no_auth is True
    assert scope.credential_ref is None
    assert scope.canonical_payload()["surface_policy"]["credential_ref"] is None
    resolved = registry.resolve(scope)
    assert resolved.authorization_scope.credential_ref is None


# spec(T-F16a:AC-3)
def test_spec_t_f16a_ac_3_complete_fixture_descriptor_is_exact_and_hash_bound() -> None:
    for surface_name, expected_descriptor in (
        ("lab", _LAB_FIXTURE),
        ("intake", _INTAKE_FIXTURE),
    ):
        surface = _parse_canonical_surface(_surface_payloads()[surface_name])
        serialized = surface_payload(surface)
        policy = serialized["surface_policy"]
        assert policy["fixture_descriptors"] == [expected_descriptor]
        assert set(policy["fixture_descriptors"][0]) == _FIXTURE_KEYS
        assert serialized["surface_policy_sha256"] == _canonical_sha256(policy)


@pytest.mark.parametrize("surface_name", ["lab", "intake"])
@pytest.mark.parametrize("field", sorted(_FIXTURE_KEYS))
# spec(T-F16a:AC-3)
def test_spec_t_f16a_ac_3_every_fixture_field_is_required_per_document_surface(
    surface_name: str,
    field: str,
) -> None:
    canonical = _surface_payloads(
        version=_DOCUMENT_CANDIDATE_VERSION,
        documents_enabled=True,
    )[surface_name]
    hostile = _rehash_surface(
        canonical,
        lambda policy: policy["fixture_descriptors"][0].pop(field),
    )

    with pytest.raises(DefinitionError):
        surface_from_payload(hostile)


@pytest.mark.parametrize(
    ("case", "mutation"),
    [
        (
            "incomplete",
            lambda policy: policy["fixture_descriptors"][0].pop("workflow_id"),
        ),
        (
            "extra-key",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"path": "/private/owner/fixture.pdf"}
            ),
        ),
        (
            "absolute-path",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"opaque_ref": "/private/owner/fixture.pdf"}
            ),
        ),
        (
            "file-url",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"opaque_ref": "file:///private/owner/fixture.pdf"}
            ),
        ),
        (
            "relative-path",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"opaque_ref": "fixtures/clean-pdf-20260724.pdf"}
            ),
        ),
        (
            "traversal",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"opaque_ref": "fixture://clinical-copilot/week2/../../private/fixture.pdf"}
            ),
        ),
        (
            "mutable-url",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"opaque_ref": "https://fixtures.example.test/latest.pdf"}
            ),
        ),
        (
            "query-locator",
            lambda policy: policy["fixture_descriptors"][0].update(
                {
                    "opaque_ref": (
                        "fixture://clinical-copilot/week2/clean-pdf-20260724?version=latest"
                    )
                }
            ),
        ),
        (
            "duplicate-ref",
            lambda policy: policy["fixture_descriptors"].append(
                deepcopy(policy["fixture_descriptors"][0])
            ),
        ),
        (
            "bad-digest",
            lambda policy: policy["fixture_descriptors"][0].update({"sha256": "A" * 64}),
        ),
        (
            "zero-length",
            lambda policy: policy["fixture_descriptors"][0].update({"byte_length": 0}),
        ),
        (
            "missing-media-type",
            lambda policy: policy["fixture_descriptors"][0].update({"media_type": ""}),
        ),
        (
            "missing-doc-type",
            lambda policy: policy["fixture_descriptors"][0].update({"doc_type": ""}),
        ),
        (
            "missing-workflow",
            lambda policy: policy["fixture_descriptors"][0].update({"workflow_id": ""}),
        ),
        (
            "upload-without-fixture",
            lambda policy: policy.update({"fixture_descriptors": []}),
        ),
    ],
)
# spec(T-F16a:AC-3)
def test_spec_t_f16a_ac_3_incomplete_mutable_or_duplicate_fixture_is_refused(
    case: str,
    mutation: PolicyMutation,
) -> None:
    del case  # The parametrized id is useful in pytest's RED report.
    canonical = _surface_payloads()["lab"]
    _parse_canonical_surface(canonical)
    hostile = _rehash_surface(canonical, mutation)

    with pytest.raises(DefinitionError):
        surface_from_payload(hostile)


# spec(T-F16a:AC-3)
def test_spec_t_f16a_ac_3_duplicate_opaque_ref_across_surfaces_is_catalog_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _v2_entry(
        version=_DOCUMENT_CANDIDATE_VERSION,
        documents_enabled=True,
    )
    _load_canonical_catalog(monkeypatch, deepcopy(control))

    entry = deepcopy(control)
    lab, intake = entry["surfaces"][-2:]
    intake["surface_policy"]["fixture_descriptors"][0]["opaque_ref"] = lab["surface_policy"][
        "fixture_descriptors"
    ][0]["opaque_ref"]
    intake["surface_policy_sha256"] = _canonical_sha256(intake["surface_policy"])
    monkeypatch.setenv(_CATALOG_ENV, json.dumps([entry]))

    with pytest.raises(TargetCatalogError):
        TrustedTargetCatalog.from_environment("production")


# spec(T-F16a:AC-4)
def test_spec_t_f16a_ac_4_retry_inclusive_physical_maximum_is_derived_exactly() -> None:
    lab = surface_payload(_parse_canonical_surface(_surface_payloads()["lab"]))["surface_policy"]
    intake = surface_payload(_parse_canonical_surface(_surface_payloads()["intake"]))[
        "surface_policy"
    ]
    retries = {
        operation["operation_class"]: operation["retry_count"]
        for operation in lab["operation_templates"]
    }

    assert retries == {
        "upload": 0,
        "status_poll": 1,
        "report": 1,
        "preview": 1,
        "readback": 1,
    }
    assert lab["maximum_logical_operations"] == 34
    assert lab["physical_request_limit"] == 67
    assert intake["maximum_logical_operations"] == 2
    assert intake["physical_request_limit"] == 2


@pytest.mark.parametrize("invalid", [-1, True, "unbounded", float("inf"), float("nan")])
# spec(T-F16a:AC-4)
def test_spec_t_f16a_ac_4_invalid_retry_scalar_is_refused(invalid: Any) -> None:
    mutation = _set_operation_value(0, "retry_count", invalid)
    canonical = _surface_payloads()["lab"]
    _parse_canonical_surface(canonical)
    try:
        hostile = _rehash_surface(canonical, mutation)
    except (TypeError, ValueError):
        hostile = deepcopy(canonical)
        mutation(hostile["surface_policy"])
        hostile["surface_policy_sha256"] = "0" * 64

    with pytest.raises(DefinitionError):
        surface_from_payload(hostile)


@pytest.mark.parametrize(
    ("surface_name", "operation_index", "retry_count"),
    [
        ("lab", 0, 1),
        ("lab", 1, 2),
        ("lab", 2, 2),
        ("lab", 3, 2),
        ("lab", 4, 2),
        ("intake", 0, 1),
        ("intake", 1, 1),
    ],
    ids=[
        "lab-upload",
        "lab-status-poll",
        "lab-report-read",
        "lab-preview-read",
        "lab-document-readback",
        "intake-upload",
        "intake-duplicate-check",
    ],
)
# spec(T-F16a:AC-4)
def test_spec_t_f16a_ac_4_document_operation_retry_ceiling_is_specific(
    surface_name: str,
    operation_index: int,
    retry_count: int,
) -> None:
    canonical = _surface_payloads(
        version=_DOCUMENT_CANDIDATE_VERSION,
        documents_enabled=True,
    )[surface_name]
    _parse_canonical_surface(canonical)
    hostile = _rehash_surface(
        canonical,
        _set_retry_and_rederive(operation_index, retry_count),
    )

    with pytest.raises(DefinitionError):
        surface_from_payload(hostile)


@pytest.mark.parametrize(
    ("level", "field", "value"),
    [
        ("operation", "maximum_logical_operations", True),
        ("operation", "maximum_logical_operations", -1),
        ("operation", "maximum_logical_operations", float("inf")),
        ("operation", "maximum_logical_operations", float("nan")),
        ("operation", "maximum_logical_operations", "unbounded"),
        ("operation-understated", "maximum_logical_operations", 29),
        ("operation-overstated", "maximum_logical_operations", 31),
        ("top-logical", "maximum_logical_operations", True),
        ("top-logical", "maximum_logical_operations", -1),
        ("top-logical", "maximum_logical_operations", float("inf")),
        ("top-logical", "maximum_logical_operations", float("nan")),
        ("top-logical", "maximum_logical_operations", "unbounded"),
        ("top-logical-understated", "maximum_logical_operations", 33),
        ("top-logical-overstated", "maximum_logical_operations", 35),
        ("top-physical", "physical_request_limit", True),
        ("top-physical", "physical_request_limit", -1),
        ("top-physical", "physical_request_limit", float("inf")),
        ("top-physical", "physical_request_limit", float("nan")),
        ("top-physical", "physical_request_limit", "unbounded"),
        ("top-physical-understated", "physical_request_limit", 66),
        ("top-physical-overstated", "physical_request_limit", 68),
    ],
)
# spec(T-F16a:AC-4)
def test_spec_t_f16a_ac_4_invalid_or_inexact_logical_and_physical_maxima_are_refused(
    level: str,
    field: str,
    value: Any,
) -> None:
    canonical = _surface_payloads()["lab"]

    def mutate(policy: JsonObject) -> None:
        if level.startswith("operation"):
            policy["operation_templates"][1][field] = value
        else:
            policy[field] = value

    _parse_canonical_surface(canonical)
    try:
        hostile = _rehash_surface(canonical, mutate)
    except ValueError:
        hostile = deepcopy(canonical)
        mutate(hostile["surface_policy"])
        hostile["surface_policy_sha256"] = "0" * 64

    with pytest.raises(DefinitionError):
        surface_from_payload(hostile)


# spec(T-F16a:AC-4)
def test_spec_t_f16a_ac_4_generic_non_document_retry_two_has_exact_arithmetic() -> None:
    policy = _policy(
        "copilot_public_get",
        [
            _operation(
                "generic_read",
                "GET",
                "week2",
                request_content_type=None,
                response_content_types=["application/json"],
                credential_placement="query",
                credential_field_name="sid",
                retry_count=2,
                maximum_logical_operations=4,
            )
        ],
    )
    surface = _surface(
        "clinical-copilot-week2-generic-read-control",
        kind="custom",
        method="GET",
        relative_path="week2",
        authentication_required=True,
        policy=policy,
    )
    parsed = _parse_canonical_surface(surface)
    serialized_policy = surface_payload(parsed)["surface_policy"]

    assert serialized_policy["operation_templates"][0]["retry_count"] == 2
    assert serialized_policy["maximum_logical_operations"] == 4
    assert serialized_policy["physical_request_limit"] == 12


# spec(T-F16a:AC-1,AC-5)
def test_spec_t_f16a_ac_5_scope_binds_exact_policy_and_independent_canonical_hash() -> None:
    target, surfaces = _document_candidate()
    scope = _scope(target, surfaces["lab"])
    payload = scope.canonical_payload()
    policy = _lab_policy()

    assert payload["surface_policy"] == policy
    assert payload["surface_policy_sha256"] == _canonical_sha256(policy)
    assert scope.scope_hash() == _canonical_sha256(payload)

    changed_policy = deepcopy(policy)
    changed_policy["operation_templates"][1]["retry_count"] = 0
    changed_payload = deepcopy(payload)
    changed_payload["surface_policy"] = changed_policy
    changed_payload["surface_policy_sha256"] = _canonical_sha256(changed_policy)
    assert _canonical_sha256(changed_payload) != scope.scope_hash()


@pytest.mark.parametrize(
    ("drift_fact", "mutation"),
    [
        ("method", _set_operation_value(2, "method", "POST")),
        (
            "path",
            _set_operation_value(
                2,
                "relative_path",
                "documents/{document_id}/extraction-report-v2",
            ),
        ),
        (
            "adapter-profile",
            lambda policy: policy.update({"adapter_profile": "copilot_document_read"}),
        ),
        ("retry", _set_retry_and_rederive(2, 0)),
        (
            "fixture",
            lambda policy: policy["fixture_descriptors"][0].update(
                {"workflow_id": "lab-extraction-v2"}
            ),
        ),
        (
            "credential",
            lambda policy: policy.update(
                {
                    "credential_ref": (
                        "secretref://production/clinical-copilot-week2/session/generation-hostile"
                    )
                }
            ),
        ),
    ],
)
# spec(T-F16a:AC-5)
def test_spec_t_f16a_ac_5_each_policy_drift_fails_before_independent_side_effects(
    drift_fact: str,
    mutation: PolicyMutation,
) -> None:
    del drift_fact
    target, surfaces = _document_candidate()
    registry = _ready_registry(target, [surfaces["lab"]])
    canonical = surface_payload(surfaces["lab"])
    hostile = _rehash_surface(canonical, mutation)
    side_effects = {"adapter": 0, "credential": 0, "fixture": 0}

    def adapter_construction_probe(_: Any) -> object:
        side_effects["adapter"] += 1
        return object()

    def credential_resolution_probe(_: str | None) -> None:
        side_effects["credential"] += 1

    def fixture_resolution_probe(_: JsonObject) -> None:
        side_effects["fixture"] += 1

    try:
        hostile_surface = surface_from_payload(hostile)
        scope = AuthorizationScope.for_definitions(
            target=target,
            surface=hostile_surface,
            corpus_hash=_CORPUS_HASH,
            caps=target.safety_caps,
            run_nonce=_RUN_NONCE,
        )
    except DefinitionError:
        assert side_effects == {"adapter": 0, "credential": 0, "fixture": 0}
        return

    adapters = AdapterRegistry(registry, {"openemr": adapter_construction_probe})

    with pytest.raises(AuthorizationScopeMismatch):
        _resolve_with_side_effect_boundaries(
            registry=registry,
            adapters=adapters,
            scope=scope,
            credential_resolver=credential_resolution_probe,
            fixture_resolver=fixture_resolution_probe,
        )
    assert side_effects == {"adapter": 0, "credential": 0, "fixture": 0}


@pytest.mark.parametrize("fallback", ["target-auth", "path"])
# spec(T-F16a:AC-5,AC-6)
def test_spec_t_f16a_ac_5_v2_scope_cannot_use_target_auth_or_path_fallback(
    fallback: str,
) -> None:
    target, surfaces = _target_and_surfaces()
    scope_payload = _scope(target, surfaces["evidence"]).canonical_payload()

    for omitted in ("surface_policy", "surface_policy_sha256"):
        downgraded = deepcopy(scope_payload)
        downgraded.pop(omitted)
        with pytest.raises(DefinitionError):
            scope_from_payload(downgraded)

    downgraded = deepcopy(scope_payload)
    if fallback == "target-auth":
        downgraded["auth_mode"] = target.auth_mode.value
        downgraded["credential_ref"] = target.credential_ref
        downgraded["explicit_no_auth"] = target.explicit_no_auth
    else:
        downgraded["relative_path"] = "chat"

    with pytest.raises((DefinitionError, AuthorizationScopeMismatch)):
        candidate = scope_from_payload(downgraded)
        _ready_registry(target, [surfaces["evidence"]]).resolve(candidate)


# spec(T-F16a:AC-6)
def test_spec_t_f16a_ac_6_legacy_single_profile_stays_valid_but_mixed_profile_set_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _legacy_chat_entry(mixed_profiles=False)
    monkeypatch.delenv(_CATALOG_ENV, raising=False)
    local = TrustedTargetCatalog.from_environment("local")
    synthetic_entry, synthetic_surface = local.resolve(
        target_id="synthetic-copilot",
        surface_id="synthetic-chat",
    )
    assert synthetic_entry.transport_policy.payload_profiles == ("openemr_turns",)
    assert synthetic_surface.relative_path == "apis/default/api/copilot/message"

    monkeypatch.setenv(_CATALOG_ENV, json.dumps([control]))
    legacy = TrustedTargetCatalog.from_environment("production")
    entry, surface = legacy.resolve(
        target_id="legacy-copilot",
        surface_id="legacy-copilot-chat",
    )
    assert entry.transport_policy.payload_profile == "copilot_chat"
    assert surface.relative_path == "chat"

    partial_target_wide = _legacy_chat_entry(mixed_profiles=True)
    assert partial_target_wide["target"] == control["target"]
    assert partial_target_wide["surfaces"] == control["surfaces"]
    assert partial_target_wide["transport_policy"] == {
        **control["transport_policy"],
        "payload_profiles": _PARTIAL_TARGET_WIDE_PROFILES,
    }
    monkeypatch.setenv(_CATALOG_ENV, json.dumps([partial_target_wide]))
    with pytest.raises(
        TargetCatalogError,
        match="(?i)(ambig|target-wide|surface-specific|per-surface)",
    ):
        TrustedTargetCatalog.from_environment("production")


# spec(T-F16a:AC-6)
def test_spec_t_f16a_ac_6_legacy_single_profile_may_retain_only_disabled_staging_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _legacy_chat_entry(mixed_profiles=False)
    staged_evidence = deepcopy(control["surfaces"][0])
    staged_evidence.update(
        {
            "surface_id": "legacy-copilot-evidence",
            "kind": "rag",
            "relative_path": "evidence/search",
            "trust_boundary": "anonymous-guideline-retrieval",
            "authentication_required": False,
            "enabled": False,
        }
    )
    control["surfaces"].append(staged_evidence)
    monkeypatch.setenv(_CATALOG_ENV, json.dumps([control]))

    catalog = TrustedTargetCatalog.from_environment("production")
    _, staged = catalog.resolve(
        target_id="legacy-copilot",
        surface_id="legacy-copilot-evidence",
    )
    assert staged.enabled is False

    staged_evidence["enabled"] = True
    monkeypatch.setenv(_CATALOG_ENV, json.dumps([control]))
    with pytest.raises(TargetCatalogError, match="one enabled single-profile surface"):
        TrustedTargetCatalog.from_environment("production")


# spec(T-F16a:AC-6)
def test_spec_t_f16a_ac_6_old_v1_approval_cannot_authorize_v2_policy_hash() -> None:
    old_target, old_surface = _v1_week2_chat_definitions()
    old_scope = AuthorizationScope.for_definitions(
        target=old_target,
        surface=old_surface,
        corpus_hash=_CORPUS_HASH,
        caps=old_target.safety_caps,
        run_nonce=_RUN_NONCE,
    )
    new_target, new_surfaces = _target_and_surfaces()
    new_scope = _scope(new_target, new_surfaces["chat"])
    registry = _ready_registry(new_target, [new_surfaces["chat"]])

    assert old_scope.target_id == new_scope.target_id
    assert old_scope.surface_id == new_scope.surface_id
    assert old_scope.scope_hash() != new_scope.scope_hash()
    with pytest.raises(VersionMismatchError):
        registry.resolve(old_scope)
    assert registry.resolve(new_scope).authorization_scope == new_scope


# spec(T-F16a:AC-6)
def test_spec_t_f16a_ac_6_migration_declares_hash_break_invalidation_staging_and_rollback() -> None:
    migration = Path("docs/migrations/final-target-surface-policy-v2.md")
    assert migration.is_file(), "the v2 surface-policy migration note is missing"
    text = migration.read_text(encoding="utf-8").lower()
    normalized = " ".join(text.split())

    for heading in (
        "## hash break",
        "## old approval invalidation",
        "## staged activation",
        "## rollback",
        "## legacy compatibility",
    ):
        assert heading in text
    for changed_hash_input in (
        "surface_policy",
        "surface_policy_sha256",
        "scope_hash",
    ):
        assert changed_hash_input in text

    assert "1.0.0 -> 2.0.0 -> 2.1.0" in normalized
    assert "1.0.0 approvals cannot authorize 2.0.0" in normalized
    assert "2.0.0" in normalized and "document surfaces remain disabled" in normalized
    assert "2.1.0" in normalized and "document surfaces" in normalized
    assert normalized.index("2.0.0") < normalized.index("2.1.0")
    assert "rollback to 2.0.0" in normalized
    assert "disable document surfaces" in normalized
    assert "legacy single-profile" in normalized
