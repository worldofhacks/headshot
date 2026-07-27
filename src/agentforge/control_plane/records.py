"""Immutable, credential-free records returned by the control-plane store."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from agentforge.target.spec import AuthorizationScope


@dataclass(frozen=True, slots=True)
class TargetSnapshotRecord:
    organization_id: str
    target_id: str
    version: str
    content_hash: str
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class SurfaceSnapshotRecord:
    organization_id: str
    target_id: str
    target_version: str
    surface_id: str
    version: str
    content_hash: str
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class AuthorizationRequestRecord:
    request_id: str
    organization_id: str
    scope_hash: str
    scope_payload: dict[str, Any] = field(repr=False)
    launcher_user_id: str
    launcher_session_id: str
    expires_at: datetime.datetime
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class AuthorizationDecisionRecord:
    decision_id: str
    organization_id: str
    request_id: str
    scope_hash: str
    decision: str
    approver_user_id: str
    approver_session_id: str
    self_approval_override: bool
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CampaignRunRecord:
    run_id: str
    organization_id: str
    authorization_request_id: str
    scope_hash: str
    launcher_user_id: str
    launcher_session_id: str
    state: str
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class AuthorizedRunRecord:
    run: CampaignRunRecord
    scope: AuthorizationScope = field(repr=False)
    approval: AuthorizationDecisionRecord
    expires_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CampaignAttemptRecord:
    run_id: str
    organization_id: str
    attempt_id: str
    ordinal: int
    case_id: str
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CampaignWorkUnitReservationRecord:
    organization_id: str
    run_id: str
    attempt_id: str
    turn_index: int
    retry_index: int
    job_id: str
    job_attempt: int
    worker_id: str
    reserved_at: datetime.datetime
    observed_at: datetime.datetime | None
    observation_outcome: str | None


@dataclass(frozen=True, slots=True)
class AgentPromptSnapshotRecord:
    """Protected prompt evidence; large untrusted text is deliberately absent from ``repr``."""

    organization_id: str
    execution_id: str
    campaign_run_id: str
    attempt_id: str | None
    agent_role: str
    system_prompt_version: str
    system_prompt_sha256: str
    system_prompt_content: str = field(repr=False)
    provider_messages: tuple[dict[str, str], ...] = field(repr=False)
    transcript_sha256: str
    redactions: tuple[dict[str, str], ...] = field(repr=False)
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class FindingDecisionRecord:
    decision_id: str
    organization_id: str
    finding_id: str
    decision: str
    actor_user_id: str
    actor_session_id: str
    rationale: str = field(repr=False)
    reason_code: str | None
    created_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class AuditEventRecord:
    cursor: int
    organization_id: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    actor_user_id: str | None
    actor_session_id: str | None
    payload: dict[str, Any]
    created_at: datetime.datetime
