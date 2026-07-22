"""Explicit v1 read contracts for authoritative console projections.

Only models backed by the integrated PostgreSQL schema are decoded as ready today. Models
whose repositories are still absent document the v1 boundary without manufacturing rows;
their endpoints return a typed ``unavailable`` envelope until those repositories exist.
"""

from __future__ import annotations

import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class _ReadModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrincipalReadModel(_ReadModel):
    user_id: str
    session_id: str
    organization_id: str
    organization_role: str
    organization_permissions: tuple[str, ...]


class SafetyCapsReadModel(_ReadModel):
    budget_usd: float
    max_attempts_per_run: int
    target_requests_per_second: float
    run_timeout_seconds: float


class SafeAuthorizationScopeReadModel(_ReadModel):
    """Reviewable operation scope. Credential references are deliberately absent."""

    target_id: str
    target_version: str
    surface_id: str
    surface_version: str
    adapter_kind: str
    environment: str
    exact_host: str
    auth_mode: str
    explicit_no_auth: bool
    auth_posture: str
    protocol: str
    method: str
    relative_path: str
    endpoint: str
    corpus_id: str
    corpus_hash: str
    caps: SafetyCapsReadModel
    run_nonce: str
    execution_profile: Literal["synthetic", "live"]


class CampaignReadModel(SafeAuthorizationScopeReadModel):
    run_id: str
    authorization_request_id: str
    scope_hash: str
    launcher_user_id: str
    state: Literal["queued", "running", "complete", "aborted", "failed"]
    attempt_count: int | None = Field(default=None, ge=0)
    created_at: datetime.datetime


class AttemptReadModel(_ReadModel):
    attempt_id: str
    ordinal: int = Field(ge=0)
    case_id: str
    content_hash: str | None = None
    executed_at: datetime.datetime | None = None
    trace_id: str | None = None
    verdict: str | None = None
    confidence: float | None = None
    execution_profile: Literal["synthetic", "live"] | None = None
    evidence_provenance: (
        Literal["synthetic_offline", "live_target", "scan_only", "simulated"] | None
    ) = None
    created_at: datetime.datetime


class EvidenceReadModel(_ReadModel):
    campaign_run_id: str
    attempt_id: str
    target_id: str | None = None
    target_version: str | None = None
    surface_id: str | None = None
    surface_version: str | None = None
    attack_attempt: dict[str, Any] | None = None
    request_transcript: dict[str, Any] | None = None
    response_transcript: str | None = None
    policy_decision_id: str | None = None
    executed_at: datetime.datetime | None = None
    trace_id: str | None = None
    content_hash: str
    verdict: str | None = None
    confidence: float | None = None
    execution_profile: Literal["synthetic", "live"] | None = None
    evidence_provenance: (
        Literal["synthetic_offline", "live_target", "scan_only", "simulated"] | None
    ) = None


class ApprovalReadModel(SafeAuthorizationScopeReadModel):
    request_id: str
    scope_hash: str
    launcher_user_id: str
    expires_at: datetime.datetime
    created_at: datetime.datetime
    status: Literal["pending", "approved", "rejected"]
    decision: Literal["approved", "rejected"] | None = None
    approver_user_id: str | None = None
    decided_at: datetime.datetime | None = None


class SurfaceReadModel(_ReadModel):
    surface_id: str
    version: str
    target_version: str
    content_hash: str
    kind: str
    protocol: str
    method: str
    relative_path: str
    trust_boundary: str
    authentication_required: bool
    risk: str
    owasp_mappings: list[dict[str, Any]]
    oracle_refs: list[str]
    enabled: bool
    created_at: datetime.datetime


class CampaignTemplateReadModel(_ReadModel):
    target_id: str
    target_version: str
    surface_id: str
    surface_version: str
    corpus_id: str
    corpus_hash: str
    execution_profile: Literal["synthetic", "live"]
    maximum_caps: SafetyCapsReadModel


class TargetReadModel(_ReadModel):
    target_id: str
    version: str
    content_hash: str
    name: str
    adapter_kind: str
    environment: str
    base_url: str
    auth_mode: str
    credential_configured: bool
    synthetic_data_only: bool
    safety_caps: SafetyCapsReadModel
    lifecycle: str
    allowed_lifecycle_transitions: list[str]
    surfaces: list[SurfaceReadModel]
    campaign_template: CampaignTemplateReadModel | None = None
    created_at: datetime.datetime


class AuditReadModel(_ReadModel):
    cursor: int = Field(ge=1)
    event_type: str
    aggregate_type: str
    aggregate_id: str
    actor_user_id: str | None = None
    payload: dict[str, Any]
    created_at: datetime.datetime


# Contracts reserved for repositories that currently return ``unavailable``.
class FindingHistoryReadModel(_ReadModel):
    decision: str
    actor_user_id: str
    rationale: str
    created_at: datetime.datetime


class FindingReadModel(_ReadModel):
    finding_id: str
    state: str
    severity: str
    category: str
    target_version: str
    publication_status: str
    evidence_integrity: str
    source_kind: str
    execution_profile: Literal["synthetic", "live"]
    evidence_provenance: str
    campaign_run_id: str | None
    attempt_id: str | None
    evidence_content_hash: str
    history: tuple[FindingHistoryReadModel, ...]


class CoverageReadModel(_ReadModel):
    target_version: str
    verified_attempt_count: int = Field(ge=0)
    total_case_count: int = Field(ge=0)
    category_count: int = Field(ge=0)
    execution_profile: Literal["synthetic", "live"]
    evidence_provenance: str
    classifications: tuple[str, ...]
    owasp_web: tuple[str, ...]
    owasp_llm: tuple[str, ...]
    verdict_counts: dict[str, int]
    covered: bool
    as_of: datetime.datetime


class ResilienceReadModel(_ReadModel):
    regression_id: str
    version: str
    status: str
    recorded_at: datetime.datetime


class TraceReadModel(_ReadModel):
    request_id: str | None
    trace_id: str
    campaign_id: str
    attempt_id: str | None
    operation: str
    provider: str
    method: str | None
    destination_host: str | None
    relative_path: str | None
    status: str
    status_code: int | None
    error_code: str | None
    started_at: datetime.datetime
    finished_at: datetime.datetime | None
    duration_ms: float = Field(ge=0)
    request_bytes: int = Field(ge=0)
    response_bytes: int | None = Field(default=None, ge=0)
    measured_cost: float = Field(ge=0)
    currency: str
    langfuse_status: str


class CostReadModel(_ReadModel):
    accounting_id: str
    campaign_id: str
    provider: str
    measured_cost: float = Field(ge=0)
    currency: str
    request_count: int = Field(ge=0)
    attempt_count: int = Field(ge=0)
    confirmed_finding_count: int = Field(ge=0)
    average_cost_per_request: float = Field(ge=0)
    budget_usd: float | None = Field(default=None, ge=0)
    budget_utilization: float | None = Field(default=None, ge=0)
    duration_ms: float = Field(ge=0)
    execution_profile: Literal["synthetic", "live"]
    started_at: datetime.datetime
    ended_at: datetime.datetime
    recorded_at: datetime.datetime


class ConfigurationReadModel(_ReadModel):
    snapshot_id: str
    version: int = Field(ge=1)
    status: str
    configuration: dict[str, Any]
    published_at: datetime.datetime
    published_by: str


class ComponentReadModel(_ReadModel):
    component_id: str
    name: str
    kind: str
    availability: Literal[
        "operational and evidenced",
        "adapter integrated, execution deferred",
        "evaluated and rejected",
        "blocked pending authorization",
    ]
    environment: str
    detail: str
    version: str
    target_access: str
    capabilities: list[str]
    owasp_llm: list[str]
    owasp_web: list[str]
    operational_scope: list[str]
    adapter_only_scope: list[str]
    execution_evidence: list[str]
    heartbeat_at: datetime.datetime


_LIST_ADAPTERS = {
    "campaigns": TypeAdapter(list[CampaignReadModel]),
    "attempts": TypeAdapter(list[AttemptReadModel]),
    "approvals": TypeAdapter(list[ApprovalReadModel]),
    "targets": TypeAdapter(list[TargetReadModel]),
    "audit": TypeAdapter(list[AuditReadModel]),
    "findings": TypeAdapter(list[FindingReadModel]),
    "coverage": TypeAdapter(list[CoverageReadModel]),
    "resilience": TypeAdapter(list[ResilienceReadModel]),
    "costs": TypeAdapter(list[CostReadModel]),
    "traces": TypeAdapter(list[TraceReadModel]),
    "components": TypeAdapter(list[ComponentReadModel]),
}
_SINGLE_ADAPTERS = {
    "principal": TypeAdapter(PrincipalReadModel),
    "campaign": TypeAdapter(CampaignReadModel),
    "evidence": TypeAdapter(EvidenceReadModel),
    "target": TypeAdapter(TargetReadModel),
    "finding": TypeAdapter(FindingReadModel),
    "configuration": TypeAdapter(ConfigurationReadModel),
}


def validate_ready_data(resource: str, data: Any) -> Any:
    """Decode and normalize a ready PostgreSQL projection, failing on schema drift."""

    adapter = _LIST_ADAPTERS.get(resource) or _SINGLE_ADAPTERS.get(resource)
    if adapter is None:
        return data
    return adapter.dump_python(adapter.validate_python(data), mode="json")


__all__ = [
    "ApprovalReadModel",
    "AttemptReadModel",
    "AuditReadModel",
    "CampaignReadModel",
    "CampaignTemplateReadModel",
    "ComponentReadModel",
    "ConfigurationReadModel",
    "CostReadModel",
    "CoverageReadModel",
    "EvidenceReadModel",
    "FindingReadModel",
    "PrincipalReadModel",
    "ResilienceReadModel",
    "SurfaceReadModel",
    "TargetReadModel",
    "TraceReadModel",
    "validate_ready_data",
]
