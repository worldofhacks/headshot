"""Explicit v1 read contracts for authoritative console projections.

Every adapter registered below has a concrete PostgreSQL or code-owned projection. Reads fail
closed as typed ``unavailable`` results when a query, integrity check, or strict schema check
cannot be satisfied; they never manufacture placeholder rows.
"""

from __future__ import annotations

import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

_LANGFUSE_DELIVERY_STATES = (
    "not_attempted",
    "disabled",
    "queued",
    "exported",
    "error",
)


def _validate_token_observation(
    *,
    input_tokens: int | None,
    output_tokens: int | None,
    observation_count: int,
    label: str,
) -> None:
    if observation_count == 0 and (input_tokens is not None or output_tokens is not None):
        raise ValueError(f"{label} token totals require an observation")
    if observation_count > 0 and input_tokens is None and output_tokens is None:
        raise ValueError(f"{label} token observation requires a reported total")


class _ReadModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrincipalReadModel(_ReadModel):
    user_id: str
    organization_id: str
    organization_role: str
    organization_permissions: tuple[str, ...]


class SafetyCapsReadModel(_ReadModel):
    budget_usd: float
    max_attempts_per_run: int
    target_requests_per_second: float
    run_timeout_seconds: float
    logical_case_limit: int | None = Field(default=None, gt=0)
    physical_request_limit: int | None = Field(default=None, gt=0)
    target_retries_per_turn: int | None = Field(default=None, ge=0)


class HostedRunBindingReadModel(_ReadModel):
    configuration_set_sha256: str
    generation_policy_sha256: str
    session_generation: str
    provider_model_call_limit: int = Field(gt=0, le=56)
    provider_model_spend_limit_usd: str
    provider_max_retries: int = Field(ge=0, le=1)
    provider_max_concurrency: Literal[1]
    provider_timeout_seconds: float = Field(gt=0)


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
    hosted_run: HostedRunBindingReadModel | None = None


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
    expired: bool
    consumed: bool


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


class TargetCatalogEntryReadModel(_ReadModel):
    """Safe selectable identity for one immutable server-owned catalog bundle."""

    target_id: str
    version: str
    name: str
    environment: Literal["local", "staging", "production"]
    synthetic_data_only: Literal[True]
    surface_count: int = Field(gt=0)
    registration_state: Literal["available", "registered", "conflict"]


class AuditReadModel(_ReadModel):
    cursor: int = Field(ge=1)
    event_type: str
    aggregate_type: str
    aggregate_id: str
    actor_user_id: str | None = None
    payload: dict[str, Any]
    created_at: datetime.datetime


class FindingHistoryReadModel(_ReadModel):
    decision: str
    actor_user_id: str
    rationale: str
    created_at: datetime.datetime


class FindingReadModel(_ReadModel):
    finding_id: str
    state: str
    severity: str
    category: str | None
    target_version: str | None
    publication_status: str
    evidence_integrity: Literal["verified", "unavailable"]
    source_kind: str
    execution_profile: Literal["synthetic", "live"]
    evidence_provenance: str
    campaign_run_id: str | None
    attempt_id: str | None
    evidence_content_hash: str | None
    history: tuple[FindingHistoryReadModel, ...]

    @model_validator(mode="after")
    def validate_evidence_integrity_binding(self) -> Self:
        content_hash = self.evidence_content_hash
        if self.evidence_integrity == "verified":
            if (
                content_hash is None
                or len(content_hash) != 64
                or any(character not in "0123456789abcdef" for character in content_hash)
            ):
                raise ValueError(
                    "verified finding evidence requires a lowercase SHA-256 content hash"
                )
        elif content_hash is not None:
            raise ValueError("unavailable finding evidence cannot include a content hash")
        return self


class AttackCaseEvidenceReadModel(_ReadModel):
    case_id: str
    case_content_sha256: str | None = None
    category: str | None = None
    attack_class: Literal["boundary", "invariant", "regression"] | None = None
    owasp_mappings: tuple[dict[str, Any], ...]
    oracle_expectation: dict[str, Any] | None = None
    corpus_reconciliation: Literal["verified", "unavailable"]


class JudgeBasisReadModel(_ReadModel):
    state: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason_codes: tuple[str, ...]
    confirmation_source: Literal["oracle", "canary", "calibrated_model", "human"] | None = None
    oracle_refs: tuple[str, ...]
    canary_refs: tuple[str, ...]
    rationale: str | None = None
    rationale_availability: Literal["unavailable"]
    rationale_detail: str
    error_code: str | None = None


class EvidenceIntegrityReadModel(_ReadModel):
    stored_content_sha256: str
    finding_link_sha256: str
    recomputed_content_sha256: str
    evidence_record: Literal["verified"]
    finding_link: Literal["verified"]
    observability_reconciliation: Literal["unavailable"]
    observability_detail: str


class RegressionDispositionReadModel(_ReadModel):
    disposition_id: str
    state: str
    reason_codes: tuple[str, ...]
    reproduction_attempted: bool
    deterministic_reproduction: bool
    passes_for_right_reason: bool
    human_approved: bool
    admitted: bool


class FindingVerificationReadModel(_ReadModel):
    availability: Literal["ready", "unavailable"]
    reason_code: str | None = None
    finding_id: str
    campaign_run_id: str | None = None
    attempt_id: str | None = None
    attack_case: AttackCaseEvidenceReadModel | None = None
    attack_attempt: dict[str, Any] | None = None
    input_sequence: tuple[str, ...]
    request_transcript: dict[str, Any] | None = None
    response_transcript: str | None = None
    policy_decision_id: str | None = None
    executed_at: datetime.datetime | None = None
    trace_id: str | None = None
    judge: JudgeBasisReadModel | None = None
    report_id: str | None = None
    minimal_reproduction: tuple[str, ...]
    reproduction_sha256: str | None = None
    regression: RegressionDispositionReadModel | None = None
    integrity: EvidenceIntegrityReadModel | None = None
    redaction_state: Literal["synthetic_identifiers_redacted"]


class FindingDetailReadModel(FindingReadModel):
    verification: FindingVerificationReadModel


class ApprovalDetailReadModel(ApprovalReadModel):
    campaign_run_id: str | None = None
    verification_chain: tuple[FindingVerificationReadModel, ...]


class ReportReadModel(_ReadModel):
    schema_version: Literal["1"]
    report_id: str
    finding_id: str
    campaign_run_id: str
    attempt_id: str
    source_case_id: str
    severity: Literal["low", "medium", "high", "critical"]
    category: str
    description: str
    clinical_impact: str
    minimal_reproduction: tuple[str, ...]
    reproduction_sha256: str
    observed_behavior: str
    expected_behavior: str
    recommended_remediation: str
    status: Literal[
        "draft",
        "validated",
        "remediation_pending",
        "fix_pending",
        "fixed",
        "regressed",
    ]
    fix_validation: dict[str, Any]
    evidence_references: tuple[str, ...]
    publication_state: Literal[
        "draft_unpublished",
        "blocked_pending_human_approval",
    ]
    regression: RegressionDispositionReadModel | None = None
    report_integrity: Literal["verified"]
    created_at: datetime.datetime
    verification: FindingVerificationReadModel


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
    execution_id: str | None = None
    parent_execution_id: str | None = None
    trace_id: str
    campaign_id: str
    attempt_id: str | None
    operation: str
    provider: str
    agent_role: Literal["orchestrator", "red_team", "judge", "documentation"] | None = None
    execution_mode: Literal["deterministic", "hosted_advisory"] | None = None
    returned_model: str | None = None
    upstream_provider: str | None = None
    provider_request_id: str | None = None
    configuration_set_sha256: str | None = None
    role_configuration_sha256: str | None = None
    generation_policy_sha256: str | None = None
    physical_attempts: int | None = Field(default=None, ge=1)
    method: str | None
    destination_host: str | None
    relative_path: str | None
    status: str
    status_code: int | None
    error_code: str | None
    started_at: datetime.datetime
    finished_at: datetime.datetime | None
    duration_ms: float | None = Field(default=None, ge=0)
    request_bytes: int = Field(ge=0)
    response_bytes: int | None = Field(default=None, ge=0)
    measured_cost: float = Field(ge=0)
    accounting_status: Literal["measured", "partial", "unavailable"]
    currency: str
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    judge_calibration_id: str | None = None
    judge_calibration_state: (
        Literal["unavailable", "failed", "passed", "invalidated", "enabled"] | None
    ) = None
    oracle_agreement: bool | None = None
    decision_authority: Literal["oracle", "model", "none"] | None = None
    p50_duration_ms: float | None = Field(default=None, ge=0)
    p95_duration_ms: float | None = Field(default=None, ge=0)
    langfuse_status: Literal[
        "not_attempted",
        "disabled",
        "queued",
        "exported",
        "error",
        "historical_not_instrumented",
    ]
    langfuse_verified_at: datetime.datetime | None = None
    request_preview: str | None
    response_preview: str | None
    request_sha256: str | None
    response_sha256: str | None
    inspection_flags: list[str]
    inspection_owasp_mappings: list[str]

    @model_validator(mode="after")
    def validate_accounting_status(self) -> Self:
        if self.accounting_status == "unavailable" and (
            self.measured_cost != 0
            or self.input_tokens is not None
            or self.output_tokens is not None
            or self.reasoning_tokens is not None
        ):
            raise ValueError("unavailable trace accounting cannot contain measured values")
        if self.accounting_status == "partial" and (
            self.agent_role is None or self.physical_attempts is None
        ):
            raise ValueError("partial trace accounting requires an observed agent provider call")
        provider_identity = (
            self.returned_model,
            self.upstream_provider,
            self.provider_request_id,
        )
        if any(value is None for value in provider_identity) != all(
            value is None for value in provider_identity
        ):
            raise ValueError("trace provider identity must be recorded as one complete tuple")
        if self.agent_role is None and any(
            value is not None
            for value in (
                *provider_identity,
                self.configuration_set_sha256,
                self.role_configuration_sha256,
                self.generation_policy_sha256,
                self.physical_attempts,
                self.reasoning_tokens,
                self.judge_calibration_id,
                self.judge_calibration_state,
                self.oracle_agreement,
                self.decision_authority,
            )
        ):
            raise ValueError("non-agent traces cannot contain hosted agent lineage")
        if self.decision_authority == "model" and self.judge_calibration_state != "enabled":
            raise ValueError("model authority requires an enabled Judge calibration")
        if (self.langfuse_status == "exported") != (self.langfuse_verified_at is not None):
            raise ValueError("exported trace delivery requires exact Langfuse query-back proof")
        role_latencies = (self.p50_duration_ms, self.p95_duration_ms)
        if self.agent_role is None and any(value is not None for value in role_latencies):
            raise ValueError("non-agent traces cannot contain agent role latency percentiles")
        if (self.p50_duration_ms is None) != (self.p95_duration_ms is None):
            raise ValueError("agent role latency percentiles must be recorded together")
        if (
            self.p50_duration_ms is not None
            and self.p95_duration_ms is not None
            and self.p50_duration_ms > self.p95_duration_ms
        ):
            raise ValueError("agent role p50 latency cannot exceed p95 latency")
        if (
            self.agent_role is not None
            and self.finished_at is not None
            and any(value is None for value in role_latencies)
        ):
            raise ValueError("terminal agent traces require role latency percentiles")
        return self


class AgentBudgetReadModel(_ReadModel):
    """One role's campaign-scoped subcap plus the shared provider kill switch."""

    status: Literal["staged_pending_authorization", "active", "historical", "unavailable"]
    campaign_run_id: str | None = None
    configuration_set_sha256: str | None = None
    role_usd_cap: float | None = Field(default=None, ge=0)
    role_usd_spent: float = Field(ge=0)
    role_unresolved_usd_exposure: float = Field(ge=0)
    role_usd_remaining: float | None = Field(default=None, ge=0)
    role_usd_overrun: float = Field(ge=0)
    role_call_cap: int | None = Field(default=None, ge=1)
    role_physical_calls: int = Field(ge=0)
    role_unresolved_physical_calls: int = Field(ge=0)
    role_calls_remaining: int | None = Field(default=None, ge=0)
    role_call_overrun: int = Field(ge=0)
    global_usd_cap: float | None = Field(default=None, ge=0)
    global_usd_spent: float = Field(ge=0)
    global_unresolved_usd_exposure: float = Field(ge=0)
    global_usd_remaining: float | None = Field(default=None, ge=0)
    global_usd_overrun: float = Field(ge=0)
    global_call_cap: int | None = Field(default=None, ge=1)
    global_physical_calls: int = Field(ge=0)
    global_unresolved_physical_calls: int = Field(ge=0)
    global_calls_remaining: int | None = Field(default=None, ge=0)
    global_call_overrun: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_budget_reconciliation(self) -> Self:
        cap_values = (
            self.role_usd_cap,
            self.role_usd_remaining,
            self.role_call_cap,
            self.role_calls_remaining,
            self.global_usd_cap,
            self.global_usd_remaining,
            self.global_call_cap,
            self.global_calls_remaining,
        )
        if self.status == "unavailable":
            if any(value is not None for value in cap_values):
                raise ValueError("unavailable hosted budget cannot contain inferred caps")
            if self.configuration_set_sha256 is not None or self.campaign_run_id is not None:
                raise ValueError("unavailable hosted budget cannot identify a configuration")
            if any(
                value != 0
                for value in (
                    self.role_usd_spent,
                    self.role_unresolved_usd_exposure,
                    self.role_usd_overrun,
                    self.role_physical_calls,
                    self.role_unresolved_physical_calls,
                    self.role_call_overrun,
                    self.global_usd_spent,
                    self.global_unresolved_usd_exposure,
                    self.global_usd_overrun,
                    self.global_physical_calls,
                    self.global_unresolved_physical_calls,
                    self.global_call_overrun,
                )
            ):
                raise ValueError("unavailable hosted budget cannot claim provider usage")
            return self
        if any(value is None for value in cap_values):
            raise ValueError("hosted budget requires complete role and global cap reconciliation")
        if self.configuration_set_sha256 is None:
            raise ValueError("hosted budget requires its configuration-set identity")
        if self.status in {"active", "historical"} and self.campaign_run_id is None:
            raise ValueError("campaign-scoped hosted budget requires its campaign identity")
        if self.status == "staged_pending_authorization" and self.campaign_run_id is not None:
            raise ValueError("staged hosted budget cannot claim campaign activity")
        assert self.role_usd_cap is not None
        assert self.role_usd_remaining is not None
        assert self.role_call_cap is not None
        assert self.role_calls_remaining is not None
        assert self.global_usd_cap is not None
        assert self.global_usd_remaining is not None
        assert self.global_call_cap is not None
        assert self.global_calls_remaining is not None
        if (
            abs(
                (self.role_usd_spent + self.role_unresolved_usd_exposure + self.role_usd_remaining)
                - (self.role_usd_cap + self.role_usd_overrun)
            )
            > 0.000001
        ):
            raise ValueError("role provider spend does not reconcile to its subcap")
        if (
            self.role_physical_calls
            + self.role_unresolved_physical_calls
            + self.role_calls_remaining
            != self.role_call_cap + self.role_call_overrun
        ):
            raise ValueError("role provider calls do not reconcile to their subcap")
        if (
            abs(
                (
                    self.global_usd_spent
                    + self.global_unresolved_usd_exposure
                    + self.global_usd_remaining
                )
                - (self.global_usd_cap + self.global_usd_overrun)
            )
            > 0.000001
        ):
            raise ValueError("global provider spend does not reconcile to its kill switch")
        if (
            self.global_physical_calls
            + self.global_unresolved_physical_calls
            + self.global_calls_remaining
            != self.global_call_cap + self.global_call_overrun
        ):
            raise ValueError("global provider calls do not reconcile to their kill switch")
        return self


class CostReadModel(_ReadModel):
    accounting_id: str
    campaign_id: str
    provider: str
    agent_role: Literal["orchestrator", "red_team", "judge", "documentation"] | None = None
    record_kind: Literal["campaign", "agent"]
    measured_cost: float = Field(ge=0)
    accounting_status: Literal["not_applicable", "measured", "partial", "unavailable"]
    currency: str
    request_count: int = Field(ge=0)
    execution_count: int = Field(ge=0)
    attempt_count: int = Field(ge=0)
    confirmed_finding_count: int = Field(ge=0)
    average_cost_per_request: float = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    token_observation_count: int = Field(ge=0)
    physical_call_count: int = Field(ge=0)
    provider_budget: AgentBudgetReadModel | None = None
    p50_duration_ms: float | None = Field(default=None, ge=0)
    p95_duration_ms: float | None = Field(default=None, ge=0)
    budget_usd: float | None = Field(default=None, ge=0)
    budget_utilization: float | None = Field(default=None, ge=0)
    duration_ms: float = Field(ge=0)
    execution_profile: Literal["synthetic", "live"]
    started_at: datetime.datetime
    ended_at: datetime.datetime
    recorded_at: datetime.datetime

    @model_validator(mode="after")
    def validate_observed_accounting(self) -> Self:
        _validate_token_observation(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            observation_count=self.token_observation_count,
            label="cost",
        )
        if (self.record_kind == "agent") != (self.agent_role is not None):
            raise ValueError("agent cost records require exactly one agent role")
        if self.accounting_status in {"partial", "unavailable"} and self.record_kind != "agent":
            raise ValueError("partial accounting states apply only to agent cost records")
        if self.accounting_status == "unavailable" and (
            self.measured_cost != 0
            or self.token_observation_count != 0
            or self.reasoning_tokens is not None
            or self.physical_call_count != 0
        ):
            raise ValueError("unavailable agent accounting cannot contain measured values")
        if (self.record_kind == "agent") != (self.provider_budget is not None):
            raise ValueError("only agent cost records carry a role provider budget")
        if self.record_kind == "campaign" and (
            self.reasoning_tokens is not None or self.physical_call_count != 0
        ):
            raise ValueError("target campaign cost records cannot contain provider call accounting")
        role_latencies = (self.p50_duration_ms, self.p95_duration_ms)
        if self.record_kind == "campaign" and any(value is not None for value in role_latencies):
            raise ValueError("campaign cost records cannot contain agent role percentiles")
        if self.record_kind == "agent":
            if self.execution_count == 0 and any(value is not None for value in role_latencies):
                raise ValueError("agent cost latency percentiles require a completed execution")
            if self.execution_count > 0 and any(value is None for value in role_latencies):
                raise ValueError("completed agent cost records require role latency percentiles")
        if (
            self.p50_duration_ms is not None
            and self.p95_duration_ms is not None
            and self.p50_duration_ms > self.p95_duration_ms
        ):
            raise ValueError("agent role p50 latency cannot exceed p95 latency")
        return self


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
    resolved_model: str | None
    upstream_provider: str | None = None
    prompt_sha256: str | None = None
    prompt_version: str | None = None
    execution_mode: Literal["deterministic", "hosted_advisory"]
    activation_state: Literal["active", "staged_pending_authorization"]
    version: int = Field(ge=1)
    configuration_sha256: str
    configured_at: datetime.datetime | None = None
    configured_by: str | None = None

    @model_validator(mode="after")
    def validate_served_identity_binding(self) -> Self:
        if (self.resolved_model is None) != (self.upstream_provider is None):
            raise ValueError(
                "provider-served model and upstream provider must be recorded together"
            )
        return self


class JudgeCalibrationSummaryReadModel(_ReadModel):
    """Observed live-evaluator reconciliation; never a substitute for calibration evidence."""

    state: Literal["unavailable", "failed", "passed", "invalidated", "enabled"]
    calibration_id: str | None = None
    decision_authority: Literal["oracle", "model", "none"]
    oracle_comparison_count: int = Field(ge=0)
    oracle_agreement_count: int = Field(ge=0)
    oracle_agreement_rate: float | None = Field(default=None, ge=0, le=1)
    status_label: Literal[
        "not yet measured",
        "live, verified against oracle",
        "live, model-decisive after calibration",
    ]

    @model_validator(mode="after")
    def validate_calibration_status(self) -> Self:
        if self.oracle_agreement_count > self.oracle_comparison_count:
            raise ValueError("Judge agreements cannot exceed observed comparisons")
        if self.oracle_comparison_count == 0:
            if self.oracle_agreement_rate is not None:
                raise ValueError("Judge agreement rate requires observed comparisons")
        else:
            expected = self.oracle_agreement_count / self.oracle_comparison_count
            if (
                self.oracle_agreement_rate is None
                or abs(self.oracle_agreement_rate - expected) > 1e-9
            ):
                raise ValueError("Judge agreement rate does not reconcile to observed calls")
        if self.state == "unavailable":
            if self.calibration_id is not None:
                raise ValueError("unavailable Judge calibration cannot claim an artifact")
        elif self.calibration_id is None:
            raise ValueError("measured Judge calibration requires its artifact identity")
        if self.decision_authority == "model":
            if (
                self.state != "enabled"
                or self.status_label != "live, model-decisive after calibration"
            ):
                raise ValueError("model authority requires an enabled, honestly labeled gate")
        elif self.status_label == "live, model-decisive after calibration":
            raise ValueError("model-decisive label contradicts the recorded authority")
        if self.oracle_comparison_count == 0 and self.status_label != "not yet measured":
            raise ValueError("live Judge label requires at least one oracle comparison")
        if (
            self.oracle_comparison_count > 0
            and self.decision_authority != "model"
            and self.status_label != "live, verified against oracle"
        ):
            raise ValueError("oracle-checked Judge activity requires the verified label")
        return self


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
    accounting_status: Literal["not_applicable", "measured", "partial", "unavailable"]
    currency: str
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    token_observation_count: int = Field(ge=0)
    physical_call_count: int = Field(ge=0)
    provider_budget: AgentBudgetReadModel
    judge_calibration: JudgeCalibrationSummaryReadModel | None = None
    average_duration_ms: float | None = Field(default=None, ge=0)
    p50_duration_ms: float | None = Field(default=None, ge=0)
    p95_duration_ms: float | None = Field(default=None, ge=0)
    langfuse_not_attempted_count: int = Field(ge=0)
    langfuse_disabled_count: int = Field(ge=0)
    langfuse_queued_count: int = Field(ge=0)
    langfuse_exported_count: int = Field(ge=0)
    langfuse_error_count: int = Field(ge=0)
    langfuse_verified_count: int = Field(ge=0)
    last_langfuse_verified_at: datetime.datetime | None = None
    last_activity_at: datetime.datetime | None = None
    last_status: str | None = None
    last_campaign_run_id: str | None = None
    last_attempt_id: str | None = None

    @model_validator(mode="after")
    def validate_observed_execution_totals(self) -> Self:
        status_total = (
            self.running_count + self.succeeded_count + self.failed_count + self.skipped_count
        )
        if status_total != self.execution_count:
            raise ValueError("agent status counts do not reconcile to execution_count")
        delivery_total = sum(
            getattr(self, f"langfuse_{state}_count") for state in _LANGFUSE_DELIVERY_STATES
        )
        if delivery_total != self.execution_count:
            raise ValueError("agent Langfuse counts do not reconcile to execution_count")
        if self.langfuse_verified_count != self.langfuse_exported_count:
            raise ValueError("exported Langfuse executions must equal remotely verified executions")
        if (self.langfuse_verified_count == 0) != (self.last_langfuse_verified_at is None):
            raise ValueError("agent Langfuse verification time must match verified executions")
        _validate_token_observation(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            observation_count=self.token_observation_count,
            label="agent",
        )
        if self.token_observation_count > self.execution_count:
            raise ValueError("agent token observations cannot exceed executions")
        if (self.execution_count == 0) != (self.accounting_status == "not_applicable"):
            raise ValueError("agent accounting applicability must match execution_count")
        if self.accounting_status == "unavailable" and (
            self.measured_cost != 0
            or self.token_observation_count != 0
            or self.reasoning_tokens is not None
            or self.physical_call_count != 0
        ):
            raise ValueError("unavailable agent accounting cannot contain measured values")
        if (self.role == "judge") != (self.judge_calibration is not None):
            raise ValueError("only the Judge carries evaluator calibration status")
        completed_count = status_total - self.running_count
        latency_values = (
            self.average_duration_ms,
            self.p50_duration_ms,
            self.p95_duration_ms,
        )
        if completed_count > 0 and any(value is None for value in latency_values):
            raise ValueError("completed agent executions require latency percentiles")
        if completed_count == 0 and any(value is not None for value in latency_values):
            raise ValueError("agent latency percentiles require a completed execution")
        return self


class AgentPromptReadModel(_ReadModel):
    role: Literal["orchestrator", "red_team", "judge", "documentation"]
    prompt_version: str
    prompt_sha256: str
    system_prompt: str


class AgentActivityReadModel(_ReadModel):
    execution_id: str
    campaign_run_id: str
    attempt_id: str | None = None
    parent_execution_id: str | None = None
    agent_role: str
    status: Literal["running", "succeeded", "failed", "skipped"]
    provider: str
    model: str
    returned_model: str | None = None
    upstream_provider: str | None = None
    provider_request_id: str | None = None
    execution_mode: Literal["deterministic", "hosted_advisory"]
    configuration_version: int = Field(ge=1)
    configuration_set_sha256: str | None = None
    role_configuration_sha256: str | None = None
    generation_policy_sha256: str | None = None
    input_sha256: str
    output_sha256: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    physical_attempts: int | None = Field(default=None, ge=1)
    measured_cost: float = Field(ge=0)
    accounting_status: Literal["measured", "partial", "unavailable"]
    currency: str
    trace_id: str
    langfuse_status: Literal["not_attempted", "disabled", "queued", "exported", "error"]
    langfuse_verified_at: datetime.datetime | None = None
    detail: dict[str, Any]
    judge_calibration_id: str | None = None
    judge_calibration_state: (
        Literal["unavailable", "failed", "passed", "invalidated", "enabled"] | None
    ) = None
    oracle_agreement: bool | None = None
    decision_authority: Literal["oracle", "model", "none"] | None = None
    error_code: str | None = None
    started_at: datetime.datetime
    finished_at: datetime.datetime | None = None
    duration_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_terminal_shape(self) -> Self:
        terminal_values = (self.output_sha256, self.finished_at, self.duration_ms)
        if self.status == "running" and any(value is not None for value in terminal_values):
            raise ValueError("running agent activity cannot contain terminal fields")
        if self.status != "running" and any(value is None for value in terminal_values):
            raise ValueError("terminal agent activity requires output, finish time, and duration")
        provider_accounting_complete = (
            self.input_tokens is not None
            and self.output_tokens is not None
            and (self.configuration_set_sha256 is None or self.reasoning_tokens is not None)
        )
        expected_accounting_status = (
            "measured"
            if self.execution_mode == "deterministic" or provider_accounting_complete
            else "partial"
            if self.physical_attempts is not None
            else "unavailable"
        )
        if self.accounting_status != expected_accounting_status:
            raise ValueError("agent activity accounting status contradicts its execution record")
        if self.accounting_status == "unavailable" and (
            self.measured_cost != 0
            or (self.input_tokens or 0) != 0
            or (self.output_tokens or 0) != 0
            or (self.reasoning_tokens or 0) != 0
        ):
            raise ValueError("unavailable agent activity accounting cannot contain measured values")
        if self.accounting_status == "partial" and self.physical_attempts is None:
            raise ValueError("partial agent activity requires an observed provider call")
        provider_identity = (
            self.returned_model,
            self.upstream_provider,
            self.provider_request_id,
        )
        if any(value is None for value in provider_identity) != all(
            value is None for value in provider_identity
        ):
            raise ValueError("agent activity provider identity must be one complete tuple")
        authority = (
            self.configuration_set_sha256,
            self.role_configuration_sha256,
            self.generation_policy_sha256,
        )
        if any(value is None for value in authority) != all(value is None for value in authority):
            raise ValueError("agent activity hosted authority must be one complete tuple")
        if self.execution_mode == "deterministic" and any(
            value is not None
            for value in (
                *provider_identity,
                *authority,
                self.reasoning_tokens,
                self.physical_attempts,
                self.judge_calibration_id,
                self.judge_calibration_state,
                self.oracle_agreement,
                self.decision_authority,
            )
        ):
            raise ValueError("deterministic activity cannot claim hosted provider lineage")
        if (
            self.execution_mode == "hosted_advisory"
            and self.status == "succeeded"
            and self.configuration_set_sha256 is not None
            and (
                any(value is None for value in provider_identity)
                or not provider_accounting_complete
                or self.physical_attempts is None
            )
        ):
            raise ValueError("successful hosted activity requires complete measured lineage")
        judge_values = (
            self.judge_calibration_id,
            self.judge_calibration_state,
            self.oracle_agreement,
            self.decision_authority,
        )
        if self.agent_role != "judge" and any(value is not None for value in judge_values):
            raise ValueError("non-Judge activity cannot claim evaluator reconciliation")
        if self.decision_authority == "model" and self.judge_calibration_state != "enabled":
            raise ValueError("model authority requires an enabled Judge calibration")
        if (self.langfuse_status == "exported") != (self.langfuse_verified_at is not None):
            raise ValueError("exported agent activity requires exact Langfuse query-back proof")
        return self


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
    # Per-tool execution evidence + runtime state, projected from authoritative attempts,
    # security-tool runs, findings, and typed execution errors.
    runtime_state: Literal["idle", "running", "evidenced", "error"] = "idle"
    evidenced_finding_count: int = Field(default=0, ge=0)
    last_error_code: str | None = None


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
    confirmed_finding_count: int = Field(ge=0)
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
    execution_count: int | None = Field(default=None, ge=0)
    measured_cost_usd: float | None = Field(default=None, ge=0)
    accounting_status: Literal["not_applicable", "measured", "partial", "unavailable"] | None = None
    currency: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    token_observation_count: int | None = Field(default=None, ge=0)
    langfuse_not_attempted_count: int | None = Field(default=None, ge=0)
    langfuse_disabled_count: int | None = Field(default=None, ge=0)
    langfuse_queued_count: int | None = Field(default=None, ge=0)
    langfuse_exported_count: int | None = Field(default=None, ge=0)
    langfuse_error_count: int | None = Field(default=None, ge=0)
    langfuse_verified_count: int | None = Field(default=None, ge=0)
    last_langfuse_verified_at: datetime.datetime | None = None
    langfuse_status: Literal["not_attempted", "disabled", "queued", "exported", "error"] | None = (
        None
    )
    queue_depth: int | None = Field(default=None, ge=0)
    target_access: str

    @model_validator(mode="after")
    def validate_agent_observability(self) -> Self:
        if not self.kind.startswith("agent:"):
            if self.accounting_status is not None:
                raise ValueError("non-agent nodes cannot claim agent accounting status")
            return self
        if self.execution_count is None or self.token_observation_count is None:
            raise ValueError("agent nodes require execution and token observation counts")
        delivery_counts = (
            self.langfuse_not_attempted_count,
            self.langfuse_disabled_count,
            self.langfuse_queued_count,
            self.langfuse_exported_count,
            self.langfuse_error_count,
        )
        if any(value is None for value in delivery_counts):
            raise ValueError("agent nodes require complete Langfuse delivery counts")
        if sum(value for value in delivery_counts if value is not None) != self.execution_count:
            raise ValueError("agent node Langfuse counts do not reconcile to execution_count")
        if self.langfuse_verified_count is None:
            raise ValueError("agent nodes require a Langfuse verification count")
        if self.langfuse_verified_count != (self.langfuse_exported_count or 0):
            raise ValueError("exported Langfuse executions must equal remotely verified executions")
        if (self.langfuse_verified_count == 0) != (self.last_langfuse_verified_at is None):
            raise ValueError("agent node Langfuse verification time must match verified executions")
        _validate_token_observation(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            observation_count=self.token_observation_count,
            label="agent node",
        )
        if self.token_observation_count > self.execution_count:
            raise ValueError("agent node token observations cannot exceed executions")
        latency_values = (self.p50_latency_ms, self.p95_latency_ms)
        if (self.p50_latency_ms is None) != (self.p95_latency_ms is None):
            raise ValueError("agent node latency percentiles must be reported together")
        if self.execution_count == 0 and any(value is not None for value in latency_values):
            raise ValueError("unexecuted agent nodes cannot have latency percentiles")
        if (
            self.execution_count > 0
            and self.runtime_state in {"ready", "error", "waiting"}
            and any(value is None for value in latency_values)
        ):
            raise ValueError("terminal agent nodes require latency percentiles")
        if self.execution_count == 0:
            if self.accounting_status != "not_applicable":
                raise ValueError("unexecuted agent nodes require not-applicable accounting")
            if self.measured_cost_usd is not None or self.currency is not None:
                raise ValueError("unexecuted agent nodes cannot claim observed cost")
            if self.langfuse_status is not None:
                raise ValueError("unexecuted agent nodes cannot have a latest Langfuse state")
        else:
            if self.accounting_status in {None, "not_applicable"}:
                raise ValueError("executed agent nodes require an applicable accounting state")
            if self.measured_cost_usd is None or self.currency is None:
                raise ValueError("executed agent nodes require observed cost and currency")
            if self.langfuse_status is None:
                raise ValueError("executed agent nodes require a latest Langfuse state")
            if self.accounting_status == "unavailable" and (
                self.measured_cost_usd != 0 or self.token_observation_count != 0
            ):
                raise ValueError("unavailable agent accounting cannot contain measured values")
        return self


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
    "target_catalog": TypeAdapter(list[TargetCatalogEntryReadModel]),
    "audit": TypeAdapter(list[AuditReadModel]),
    "findings": TypeAdapter(list[FindingReadModel]),
    "reports": TypeAdapter(list[ReportReadModel]),
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
    "finding": TypeAdapter(FindingDetailReadModel),
    "approval": TypeAdapter(ApprovalDetailReadModel),
    "report": TypeAdapter(ReportReadModel),
    "agent_prompt": TypeAdapter(AgentPromptReadModel),
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
    "ApprovalDetailReadModel",
    "AgentActivityReadModel",
    "AgentAssignmentReadModel",
    "AgentBudgetReadModel",
    "AgentPromptReadModel",
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
    "FindingDetailReadModel",
    "FindingVerificationReadModel",
    "JudgeCalibrationSummaryReadModel",
    "PrincipalReadModel",
    "ReportReadModel",
    "ResilienceReadModel",
    "SurfaceReadModel",
    "TargetCatalogEntryReadModel",
    "TargetReadModel",
    "ToolScopeReadModel",
    "TraceReadModel",
    "validate_ready_data",
]
