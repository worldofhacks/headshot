"""Trusted server-side target catalog; browser input can never create dispatch authority."""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass

from agentforge.auth.permissions import TARGETS_MANAGE
from agentforge.auth.principal import Principal
from agentforge.control_plane.serialization import surface_from_payload, target_from_payload
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)

SYNTHETIC_TARGET_ID = "synthetic-copilot"
SYNTHETIC_SURFACE_ID = "synthetic-chat"


class TargetCatalogError(RuntimeError):
    """Trusted catalog configuration is absent or invalid."""


@dataclass(frozen=True, slots=True)
class TransportPolicy:
    """Closed transport controls reviewed with a server-owned catalog entry."""

    allowed_methods: tuple[str, ...]
    write_upload_allowed: bool
    allowed_write_resource_refs: tuple[str, ...]
    redirect_policy: str
    response_size_limit_bytes: int
    allowed_content_types: tuple[str, ...]
    request_timeout_seconds: float
    tls_required: bool
    allow_private_destination: bool

    def __post_init__(self) -> None:
        if not self.allowed_methods or any(
            method not in {"GET", "POST"} for method in self.allowed_methods
        ):
            raise TargetCatalogError("transport policy method set is invalid")
        if not isinstance(self.write_upload_allowed, bool):
            raise TargetCatalogError("transport write policy is invalid")
        if not isinstance(self.allowed_write_resource_refs, tuple):
            raise TargetCatalogError("transport write resource policy is invalid")
        if self.write_upload_allowed and not self.allowed_write_resource_refs:
            raise TargetCatalogError("write-enabled policy requires exact resource references")
        if not self.write_upload_allowed and self.allowed_write_resource_refs:
            raise TargetCatalogError("write-disabled policy cannot carry write resources")
        if self.redirect_policy != "deny":
            raise TargetCatalogError("redirects must be denied for the MVP live adapter")
        if (
            isinstance(self.response_size_limit_bytes, bool)
            or not isinstance(self.response_size_limit_bytes, int)
            or not 1 <= self.response_size_limit_bytes <= 10_485_760
        ):
            raise TargetCatalogError("response size policy is invalid")
        if not self.allowed_content_types or any(
            not isinstance(value, str) or not value or "/" not in value
            for value in self.allowed_content_types
        ):
            raise TargetCatalogError("response content-type policy is invalid")
        if (
            isinstance(self.request_timeout_seconds, bool)
            or not isinstance(self.request_timeout_seconds, (int, float))
            or not math.isfinite(float(self.request_timeout_seconds))
            or not 0 < float(self.request_timeout_seconds) <= 120
        ):
            raise TargetCatalogError("request timeout policy is invalid")
        if self.tls_required is not True:
            raise TargetCatalogError("TLS verification must be required")
        if not isinstance(self.allow_private_destination, bool):
            raise TargetCatalogError("private-destination policy is invalid")


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    target: TargetDefinition
    surfaces: tuple[AttackSurfaceDefinition, ...]
    transport_policy: TransportPolicy
    ownership_authorization_ref: str

    def __post_init__(self) -> None:
        if not self.ownership_authorization_ref.startswith("authorization://"):
            raise TargetCatalogError("target ownership/testing authorization is not recorded")
        surface_methods = {surface.method for surface in self.surfaces}
        if not surface_methods.issubset(set(self.transport_policy.allowed_methods)):
            raise TargetCatalogError("surface method is outside the transport policy")


class TrustedTargetCatalog:
    """Immutable validated targets plus their exact approved surface definitions."""

    def __init__(self, entries: tuple[CatalogEntry, ...]):
        if len({entry.target.target_id for entry in entries}) != len(entries):
            raise TargetCatalogError("trusted target catalog contains a duplicate target")
        self.entries = entries

    @classmethod
    def from_environment(cls, environment: str) -> TrustedTargetCatalog:
        try:
            selected = TargetEnvironment(environment)
        except ValueError as exc:
            raise TargetCatalogError("target catalog environment is invalid") from exc
        entries: list[CatalogEntry] = []
        if selected in {TargetEnvironment.LOCAL, TargetEnvironment.STAGING}:
            entries.append(_synthetic_entry(selected))

        raw = os.environ.get("AGENTFORGE_LIVE_TARGET_CATALOG_JSON", "").strip()
        if raw:
            try:
                configured = json.loads(raw)
            except ValueError as exc:
                raise TargetCatalogError("live target catalog JSON is invalid") from exc
            if not isinstance(configured, list):
                raise TargetCatalogError("live target catalog must be a list")
            for item in configured:
                if not isinstance(item, dict) or set(item) != {
                    "target",
                    "surfaces",
                    "transport_policy",
                    "ownership_authorization_ref",
                }:
                    raise TargetCatalogError("live target catalog entry is invalid")
                target = target_from_payload(dict(item["target"]))
                if target.environment is not selected or target.adapter_kind != "openemr":
                    raise TargetCatalogError("live target catalog environment or adapter differs")
                surfaces = tuple(surface_from_payload(dict(value)) for value in item["surfaces"])
                if not surfaces:
                    raise TargetCatalogError("live target catalog requires an exact surface")
                policy_payload = item["transport_policy"]
                if not isinstance(policy_payload, dict):
                    raise TargetCatalogError("live target transport policy is invalid")
                policy_values = dict(policy_payload)
                policy_values["allowed_methods"] = tuple(policy_values["allowed_methods"])
                policy_values["allowed_write_resource_refs"] = tuple(
                    policy_values["allowed_write_resource_refs"]
                )
                policy_values["allowed_content_types"] = tuple(
                    policy_values["allowed_content_types"]
                )
                entries.append(
                    CatalogEntry(
                        target=target,
                        surfaces=surfaces,
                        transport_policy=TransportPolicy(**policy_values),
                        ownership_authorization_ref=str(item["ownership_authorization_ref"]),
                    )
                )
        return cls(tuple(entries))

    def resolve(
        self, *, target_id: str, surface_id: str
    ) -> tuple[CatalogEntry, AttackSurfaceDefinition]:
        matches = [entry for entry in self.entries if entry.target.target_id == target_id]
        if len(matches) != 1:
            raise TargetCatalogError("approved target is absent or ambiguous in the server catalog")
        surfaces = [surface for surface in matches[0].surfaces if surface.surface_id == surface_id]
        if len(surfaces) != 1:
            raise TargetCatalogError(
                "approved surface is absent or ambiguous in the server catalog"
            )
        return matches[0], surfaces[0]

    def synchronize(self, store: ControlPlaneStore, *, organization_id: str) -> None:
        principal = Principal(
            user_id="user_systemcatalog",
            session_id="sess_systemcatalog",
            organization_id=organization_id,
            organization_role="org:system",
            organization_permissions=frozenset({TARGETS_MANAGE}),
        )
        for entry in self.entries:
            prefix = f"catalog-{entry.target.target_id}-{entry.target.version}".replace(".", "-")
            store.register_target(
                principal=principal,
                target=entry.target,
                idempotency_key=f"{prefix}-target",
            )
            for surface in entry.surfaces:
                store.register_surface(
                    principal=principal,
                    surface=surface,
                    idempotency_key=f"{prefix}-surface-{surface.surface_id}",
                )
            for lifecycle in (TargetLifecycle.VALIDATING, TargetLifecycle.READY):
                store.transition_target(
                    principal=principal,
                    target_id=entry.target.target_id,
                    version=entry.target.version,
                    lifecycle=lifecycle,
                    idempotency_key=f"{prefix}-lifecycle-{lifecycle.value}",
                )


def _synthetic_entry(environment: TargetEnvironment) -> CatalogEntry:
    target = TargetDefinition(
        target_id=SYNTHETIC_TARGET_ID,
        name="Deterministic offline Clinical Co-Pilot rehearsal",
        version="1.0.0",
        adapter_kind="openemr",
        environment=environment,
        base_url="https://synthetic.invalid",
        allowlisted_hosts=("synthetic.invalid",),
        auth_mode=AuthMode.NONE,
        credential_ref=None,
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://agentforge/synthetic-clinical-context-v1",
        canary_refs=(
            "oracle://agentforge/SYNTH_CANARY_PATIENT_BETA_8C1E",
            "oracle://agentforge/SYNTH_CANARY_SYSTEM_PROMPT_4D2B",
        ),
        oracle_refs=("oracle://agentforge/deterministic-cassette-v1",),
        safety_caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=9,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
        ),
    )
    surface = AttackSurfaceDefinition(
        surface_id=SYNTHETIC_SURFACE_ID,
        version="1.0.0",
        target_id=target.target_id,
        target_version=target.version,
        kind=SurfaceKind.CHAT,
        protocol="https",
        method="POST",
        relative_path="apis/default/api/copilot/message",
        trust_boundary="offline-cassette",
        authentication_required=False,
        risk=RiskLevel.HIGH,
        owasp_mappings=(
            OwaspMapping("OWASP Web", "2021", "A03", "Injection"),
            OwaspMapping("OWASP LLM", "2025", "LLM01", "Prompt Injection"),
        ),
        oracle_refs=("oracle://agentforge/deterministic-cassette-v1",),
        enabled=True,
    )
    return CatalogEntry(
        target=target,
        surfaces=(surface,),
        transport_policy=TransportPolicy(
            allowed_methods=("POST",),
            write_upload_allowed=False,
            allowed_write_resource_refs=(),
            redirect_policy="deny",
            response_size_limit_bytes=262_144,
            allowed_content_types=("application/json", "text/plain"),
            request_timeout_seconds=5.0,
            tls_required=True,
            # synthetic.invalid is intentionally non-routable and the cassette opens no socket.
            allow_private_destination=False,
        ),
        ownership_authorization_ref="authorization://agentforge/offline-cassette-v1",
    )


__all__ = [
    "CatalogEntry",
    "SYNTHETIC_SURFACE_ID",
    "SYNTHETIC_TARGET_ID",
    "TransportPolicy",
    "TargetCatalogError",
    "TrustedTargetCatalog",
]
