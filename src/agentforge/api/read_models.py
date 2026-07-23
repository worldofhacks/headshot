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
    self_approval_override: bool = False
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
    case_count: int = Field(gt=0)
    tool_sources: tuple[str, ...]
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
    request_preview: str | None
    response_preview: str | None
    request_sha256: str | None
    response_sha256: str | None
    inspection_flags: list[str]
    inspection_owasp_mappings: list[str]


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


class AgentAssignmentReadModel(_ReadModel):
    role: str
    provider: str
    model: str
    execution_mode: Literal["deterministic", "hosted_advisory"]
    activation_state: Literal["active", "staged_pending_authorization"]
    version: int = Field(ge=1)
    configuration_sha256: str
    configured_at: datetime.datetime | None = None
    configured_by: str | None = None


class AgentReadModel(_ReadModel):
    role: str
    display_name: str
    responsibility: str
    trust_level: str
    target_access: str
    input_contract: str
    output_contract: str
    active_assignment: AgentAssignmentReadModel
    staged_assignment: AgentAssignmentReadModel | None = None
    execution_count: int = Field(ge=0)
    running_count: int = Field(ge=0)
    succeeded_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    measured_cost: float = Field(ge=0)
    currency: str
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    token_observation_count: int = Field(ge=0)
    average_duration_ms: float | None = Field(default=None, ge=0)
    last_activity_at: datetime.datetime | None = None
    last_status: str | None = None
    last_campaign_run_id: str | None = None
    last_attempt_id: str | None = None


class AgentActivityReadModel(_ReadModel):
    execution_id: str
    campaign_run_id: str
    attempt_id: str | None = None
    parent_execution_id: str | None = None
    agent_role: str
    status: Literal["running", "succeeded", "failed", "skipped"]
    provider: str
    model: str
    execution_mode: Literal["deterministic", "hosted_advisory"]
    configuration_version: int = Field(ge=1)
    input_sha256: str
    output_sha256: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    measured_cost: float = Field(ge=0)
    currency: str
    trace_id: str
    detail: dict[str, Any]
    error_code: str | None = None
    started_at: datetime.datetime
    finished_at: datetime.datetime | None = None
    duration_ms: float | None = Field(default=None, ge=0)


class ToolScopeReadModel(_ReadModel):
    tool_id: str
    name: str
    version: str
    kind: str
    availability: str
    target_access: str
    target_id: str
    target_version: str
    target_lifecycle: str
    surface_id: str
    surface_version: str
    surface_kind: str
    endpoint: str
    applicability: Literal[
        "in_campaign",
        "companion_scan",
        "platform_assurance",
        "adapter_available",
        "not_applicable",
    ]
    execution_mode: str
    scope_reason: str
    requires_separate_authorization: bool
    capabilities: tuple[str, ...]
    owasp_llm: tuple[str, ...]
    owasp_web: tuple[str, ...]
    reviewed_candidate_count: int = Field(ge=0)
    executed_attempt_count: int = Field(ge=0)
    recorded_scan_count: int = Field(ge=0)
    recorded_finding_count: int = Field(ge=0)
    last_executed_at: datetime.datetime | None = None


class BirdseyeCampaignReadModel(_ReadModel):
    run_id: str
    target_id: str
    target_name: str
    target_version: str
    state: Literal["queued", "running", "complete", "aborted", "failed"]
    execution_profile: Literal["synthetic", "live"]
    scope_hash: str
    attempt_count: int = Field(ge=0)


class BirdseyeInstrumentationReadModel(_ReadModel):
    budget_usd: float = Field(ge=0)
    measured_cost_usd: float = Field(ge=0)
    budget_utilization: float = Field(ge=0)
    requests_per_second_cap: float = Field(ge=0)
    queue_queued: int = Field(ge=0)
    queue_leased: int = Field(ge=0)
    queue_dead_letter: int = Field(ge=0)
    confirmed_count: int = Field(ge=0)
    likely_count: int = Field(ge=0)
    review_count: int = Field(ge=0)
    healthy_components: int = Field(ge=0)
    total_components: int = Field(ge=0)
    system_state: Literal["nominal", "degraded", "unavailable"]


class BirdseyeSecurityPostureReadModel(_ReadModel):
    tested_categories: int = Field(ge=0)
    required_categories: int = Field(ge=1)
    verified_case_count: int = Field(ge=0)
    held_count: int = Field(ge=0)
    exploited_count: int = Field(ge=0)
    review_count: int = Field(ge=0)
    observed_hold_rate: float | None = Field(default=None, ge=0, le=1)
    open_finding_count: int = Field(ge=0)
    in_progress_finding_count: int = Field(ge=0)
    resolved_finding_count: int = Field(ge=0)
    critical_open_finding_count: int = Field(ge=0)
    resilience_direction: Literal["improving", "steady", "degrading", "unavailable"]
    current_regression_hold_rate: float | None = Field(default=None, ge=0, le=1)
    previous_regression_hold_rate: float | None = Field(default=None, ge=0, le=1)
    resilience_delta: float | None = Field(default=None, ge=-1, le=1)
    cost_per_attempt_usd: float | None = Field(default=None, ge=0)
    cost_velocity_usd_per_minute: float | None = Field(default=None, ge=0)
    projected_cost_at_attempt_cap_usd: float | None = Field(default=None, ge=0)
    priority_category: str | None = None
    priority_reason: str
    priority_source: Literal["orchestrator_decision", "coverage_policy", "unavailable"]
    priority_at: datetime.datetime | None = None


class BirdseyeCategoryOutcomeReadModel(_ReadModel):
    target_version: str
    category: str
    verified_case_count: int = Field(ge=0)
    verified_attempt_count: int = Field(ge=0)
    held_count: int = Field(ge=0)
    exploited_count: int = Field(ge=0)
    review_count: int = Field(ge=0)
    last_evaluated_at: datetime.datetime | None = None


class BirdseyeAgentActivityReadModel(_ReadModel):
    execution_id: str
    parent_execution_id: str | None = None
    agent_role: Literal["orchestrator", "red_team", "judge", "documentation"]
    status: Literal["running", "succeeded", "failed", "skipped"]
    phase: str
    attempt_id: str | None = None
    category: str | None = None
    verdict_state: str | None = None
    finding_id: str | None = None
    error_code: str | None = None
    started_at: datetime.datetime
    finished_at: datetime.datetime | None = None
    duration_ms: float | None = Field(default=None, ge=0)


class BirdseyeNodeReadModel(_ReadModel):
    component_id: str
    name: str
    kind: str
    trust_zone: Literal[
        "human",
        "untrusted",
        "control",
        "execution",
        "evaluation",
        "governance",
        "data",
        "observability",
        "unclassified",
    ]
    availability: str
    runtime_state: Literal[
        "ready",
        "working",
        "waiting",
        "degraded",
        "error",
        "stale",
        "unavailable",
    ]
    detail: str
    current_task: str
    heartbeat_at: datetime.datetime | None = None
    freshness_seconds: float | None = Field(default=None, ge=0)
    is_fresh: bool
    healthy_instances: int = Field(ge=0)
    total_instances: int = Field(ge=1)
    p50_latency_ms: float | None = Field(default=None, ge=0)
    p95_latency_ms: float | None = Field(default=None, ge=0)
    queue_depth: int | None = Field(default=None, ge=0)
    target_access: str


class BirdseyeEdgeReadModel(_ReadModel):
    edge_id: str
    source_component_id: str
    target_component_id: str
    contract_name: str
    state: Literal["idle", "active", "complete", "error", "stale", "unavailable"]
    attempt_id: str | None = None
    last_event_at: datetime.datetime | None = None
    detail: str


class BirdseyeAttentionReadModel(_ReadModel):
    attention_id: str
    priority: int = Field(ge=0)
    kind: Literal["integrity", "approval", "finding", "component"]
    title: str
    detail: str
    continuation: str
    record_type: str
    record_id: str
    route: str
    created_at: datetime.datetime


class BirdseyeTimelineReadModel(_ReadModel):
    cursor: int = Field(ge=1)
    event_type: str
    actor: str
    summary: str
    aggregate_type: str
    aggregate_id: str
    created_at: datetime.datetime


class BirdseyeSnapshotReadModel(_ReadModel):
    campaign: BirdseyeCampaignReadModel | None = None
    instrumentation: BirdseyeInstrumentationReadModel
    security_posture: BirdseyeSecurityPostureReadModel
    category_outcomes: tuple[BirdseyeCategoryOutcomeReadModel, ...]
    agent_activity: tuple[BirdseyeAgentActivityReadModel, ...]
    nodes: tuple[BirdseyeNodeReadModel, ...]
    edges: tuple[BirdseyeEdgeReadModel, ...]
    attention: tuple[BirdseyeAttentionReadModel, ...]
    timeline: tuple[BirdseyeTimelineReadModel, ...]
    cursor: int = Field(ge=0)
    as_of: datetime.datetime


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
    "agents": TypeAdapter(list[AgentReadModel]),
    "agent_activity": TypeAdapter(list[AgentActivityReadModel]),
    "tooling": TypeAdapter(list[ToolScopeReadModel]),
}
_SINGLE_ADAPTERS = {
    "principal": TypeAdapter(PrincipalReadModel),
    "campaign": TypeAdapter(CampaignReadModel),
    "evidence": TypeAdapter(EvidenceReadModel),
    "target": TypeAdapter(TargetReadModel),
    "finding": TypeAdapter(FindingReadModel),
    "configuration": TypeAdapter(ConfigurationReadModel),
    "birdseye": TypeAdapter(BirdseyeSnapshotReadModel),
}


def validate_ready_data(resource: str, data: Any) -> Any:
    """Decode and normalize a ready PostgreSQL projection, failing on schema drift."""

    adapter = _LIST_ADAPTERS.get(resource) or _SINGLE_ADAPTERS.get(resource)
    if adapter is None:
        return data
    return adapter.dump_python(adapter.validate_python(data), mode="json")


__all__ = [
    "ApprovalReadModel",
    "AgentActivityReadModel",
    "AgentAssignmentReadModel",
    "AgentReadModel",
    "AttemptReadModel",
    "AuditReadModel",
    "BirdseyeAgentActivityReadModel",
    "BirdseyeAttentionReadModel",
    "BirdseyeCampaignReadModel",
    "BirdseyeCategoryOutcomeReadModel",
    "BirdseyeEdgeReadModel",
    "BirdseyeInstrumentationReadModel",
    "BirdseyeNodeReadModel",
    "BirdseyeSecurityPostureReadModel",
    "BirdseyeSnapshotReadModel",
    "BirdseyeTimelineReadModel",
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
    "ToolScopeReadModel",
    "TraceReadModel",
    "validate_ready_data",
]
