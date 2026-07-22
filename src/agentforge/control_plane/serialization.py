"""Canonical serialization for immutable PR7 target and authorization values."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthorizationScope,
    OwaspMapping,
    SafetyCaps,
    TargetDefinition,
)


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
    return {
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


def surface_from_payload(payload: dict[str, Any]) -> AttackSurfaceDefinition:
    values = dict(payload)
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
    return AttackSurfaceDefinition(**values)


def scope_from_payload(payload: dict[str, Any]) -> AuthorizationScope:
    values = dict(payload)
    # Pre-0006 requests intentionally decode as the legacy live profile. Their recomputed
    # canonical hash includes the new fields and therefore cannot pass an old stored hash.
    values.setdefault("corpus_id", "m11-seed-corpus-v1")
    values.setdefault("execution_profile", "live")
    values["caps"] = SafetyCaps(**values["caps"])
    return AuthorizationScope(**values)


__all__ = [
    "canonical_json",
    "content_hash",
    "scope_from_payload",
    "surface_from_payload",
    "surface_payload",
    "target_from_payload",
    "target_payload",
]
