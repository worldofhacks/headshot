"""Canonical serialization for immutable PR7 target and authorization values."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthorizationScope,
    DefinitionError,
    FixtureDescriptor,
    HostedRunBinding,
    OwaspMapping,
    SafetyCaps,
    SurfaceOperationTemplate,
    SurfacePolicy,
    TargetDefinition,
)

_SURFACE_POLICY_KEYS = {
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
_OPERATION_TEMPLATE_KEYS = {
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
_FIXTURE_DESCRIPTOR_KEYS = {
    "opaque_ref",
    "sha256",
    "byte_length",
    "media_type",
    "doc_type",
    "workflow_id",
}


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def content_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _require_exact_mapping(
    value: object,
    expected_keys: set[str],
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise DefinitionError(f"{field} must contain exactly its canonical fields")
    return dict(value)


def _operation_from_payload(payload: object) -> SurfaceOperationTemplate:
    values = _require_exact_mapping(
        payload,
        _OPERATION_TEMPLATE_KEYS,
        "surface policy operation template",
    )
    response_types = values["response_content_types"]
    if not isinstance(response_types, list):
        raise DefinitionError("operation response_content_types must be a JSON list")
    values["response_content_types"] = tuple(response_types)
    try:
        return SurfaceOperationTemplate(**values)
    except TypeError as exc:
        raise DefinitionError("surface policy operation template is invalid") from exc


def _fixture_from_payload(payload: object) -> FixtureDescriptor:
    values = _require_exact_mapping(
        payload,
        _FIXTURE_DESCRIPTOR_KEYS,
        "surface policy fixture descriptor",
    )
    try:
        return FixtureDescriptor(**values)
    except TypeError as exc:
        raise DefinitionError("surface policy fixture descriptor is invalid") from exc


def surface_policy_from_payload(payload: object) -> SurfacePolicy:
    """Decode the exact schema-v2 policy shape with no ignored extension fields."""

    values = _require_exact_mapping(
        payload,
        _SURFACE_POLICY_KEYS,
        "surface_policy",
    )
    operation_payloads = values["operation_templates"]
    fixture_payloads = values["fixture_descriptors"]
    if not isinstance(operation_payloads, list) or not isinstance(fixture_payloads, list):
        raise DefinitionError("surface policy operations and fixtures must be JSON lists")
    values["operation_templates"] = tuple(
        _operation_from_payload(operation) for operation in operation_payloads
    )
    values["fixture_descriptors"] = tuple(
        _fixture_from_payload(descriptor) for descriptor in fixture_payloads
    )
    try:
        return SurfacePolicy(**values)
    except TypeError as exc:
        raise DefinitionError("surface_policy is invalid") from exc


def surface_policy_payload(policy: SurfacePolicy) -> dict[str, Any]:
    if not isinstance(policy, SurfacePolicy):
        raise DefinitionError("surface policy serialization requires a SurfacePolicy")
    return policy.canonical_payload()


def target_payload(target: TargetDefinition) -> dict[str, Any]:
    return {
        "target_id": target.target_id,
        "name": target.name,
        "version": target.version,
        "adapter_kind": target.adapter_kind,
        "environment": target.environment.value,
        "base_url": target.base_url,
        "allowlisted_hosts": list(target.allowlisted_hosts),
        "auth_mode": target.auth_mode.value,
        "credential_ref": target.credential_ref,
        "synthetic_data_only": target.synthetic_data_only,
        "synthetic_data_attestation_ref": target.synthetic_data_attestation_ref,
        "canary_refs": list(target.canary_refs),
        "oracle_refs": list(target.oracle_refs),
        "safety_caps": target.safety_caps.canonical_payload(),
        "lifecycle": target.lifecycle.value,
    }


def target_from_payload(payload: dict[str, Any]) -> TargetDefinition:
    values = dict(payload)
    values["allowlisted_hosts"] = tuple(values["allowlisted_hosts"])
    values["canary_refs"] = tuple(values["canary_refs"])
    values["oracle_refs"] = tuple(values["oracle_refs"])
    values["safety_caps"] = SafetyCaps(**values["safety_caps"])
    return TargetDefinition(**values)


def surface_payload(surface: AttackSurfaceDefinition) -> dict[str, Any]:
    payload = {
        "surface_id": surface.surface_id,
        "version": surface.version,
        "target_id": surface.target_id,
        "target_version": surface.target_version,
        "kind": surface.kind.value,
        "protocol": surface.protocol,
        "method": surface.method,
        "relative_path": surface.relative_path,
        "trust_boundary": surface.trust_boundary,
        "authentication_required": surface.authentication_required,
        "risk": surface.risk.value,
        "owasp_mappings": [mapping.canonical_payload() for mapping in surface.owasp_mappings],
        "oracle_refs": list(surface.oracle_refs),
        "enabled": surface.enabled,
    }
    if surface.surface_policy is not None:
        payload["surface_policy"] = surface_policy_payload(surface.surface_policy)
        payload["surface_policy_sha256"] = surface.surface_policy_sha256
    return payload


def surface_from_payload(payload: dict[str, Any]) -> AttackSurfaceDefinition:
    values = dict(payload)
    has_policy = "surface_policy" in values
    has_policy_hash = "surface_policy_sha256" in values
    if has_policy != has_policy_hash:
        raise DefinitionError("surface policy and surface_policy_sha256 must be supplied together")
    try:
        values["oracle_refs"] = tuple(values["oracle_refs"])
        values["owasp_mappings"] = tuple(
            OwaspMapping(
                framework=mapping["framework"],
                version=mapping["version"],
                identifier=mapping["id"],
                name=mapping["name"],
            )
            for mapping in values["owasp_mappings"]
        )
        if has_policy:
            values["surface_policy"] = surface_policy_from_payload(values["surface_policy"])
        return AttackSurfaceDefinition(**values)
    except DefinitionError:
        raise
    except (KeyError, TypeError) as exc:
        raise DefinitionError("attack surface payload is invalid") from exc


def scope_from_payload(payload: dict[str, Any]) -> AuthorizationScope:
    values = dict(payload)
    # Pre-0006 requests intentionally decode as the legacy live profile. Their recomputed
    # canonical hash includes the new fields and therefore cannot pass an old stored hash.
    values.setdefault("corpus_id", "m11-seed-corpus-v1")
    values.setdefault("execution_profile", "live")
    has_policy = "surface_policy" in values
    has_policy_hash = "surface_policy_sha256" in values
    if has_policy != has_policy_hash:
        raise DefinitionError(
            "scope surface policy and surface_policy_sha256 must be supplied together"
        )
    try:
        values["caps"] = SafetyCaps(**values["caps"])
        if values.get("hosted_run") is not None:
            values["hosted_run"] = HostedRunBinding(**values["hosted_run"])
        if has_policy:
            values["surface_policy"] = surface_policy_from_payload(values["surface_policy"])
        return AuthorizationScope(**values)
    except DefinitionError:
        raise
    except (KeyError, TypeError) as exc:
        raise DefinitionError("authorization scope payload is invalid") from exc


__all__ = [
    "canonical_json",
    "content_hash",
    "scope_from_payload",
    "surface_from_payload",
    "surface_policy_from_payload",
    "surface_policy_payload",
    "surface_payload",
    "target_from_payload",
    "target_payload",
]
