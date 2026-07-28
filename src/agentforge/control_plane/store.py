"""Transactional, organization-scoped persistence for M1d human control-plane commands."""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from types import SimpleNamespace
from typing import Any

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedRoleConfiguration,
    resolve_hosted_prompt,
    validate_hosted_configuration_set,
)
from agentforge.agents.runtime import (
    AGENT_ROLES,
    AgentAssignment,
    AgentRole,
    default_assignment,
    validate_agent_configuration,
)
from agentforge.auth.permissions import (
    AUDIT_READ,
    CAMPAIGN_ABORT,
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    CONFIG_MANAGE,
    EVIDENCE_READ,
    FINDINGS_APPROVE,
    FINDINGS_RESOLVE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal
from agentforge.case_taxonomy import (
    REVIEWED_WORKLOAD_SOURCE_KINDS,
    SUPPORTED_CASE_CATEGORIES,
    WORKLOAD_INSTANCE_ID_PATTERN,
)
from agentforge.contracts import validate as validate_contract
from agentforge.control_plane.errors import (
    AuthorizationDeniedError,
    IdempotencyConflictError,
    InvalidControlPlaneInput,
    RecordConflictError,
    RecordNotFoundError,
)
from agentforge.control_plane.finding_decisions import (
    validate_finding_decision_reason_code,
)
from agentforge.control_plane.records import (
    AgentPromptSnapshotRecord,
    AuditEventRecord,
    AuthorizationDecisionRecord,
    AuthorizationRequestRecord,
    AuthorizedRunRecord,
    CampaignAttemptRecord,
    CampaignRunRecord,
    CampaignWorkUnitReservationRecord,
    FindingDecisionRecord,
    SurfaceSnapshotRecord,
    TargetSnapshotRecord,
)
from agentforge.control_plane.serialization import (
    canonical_json,
    content_hash,
    scope_from_payload,
    surface_from_payload,
    surface_payload,
    target_from_payload,
    target_payload,
)
from agentforge.correlation import campaign_trace_id
from agentforge.policy.recorder import (
    PERSISTED_EVIDENCE_COLUMNS,
    EvidenceIntegrityError,
    ExecutionRecorder,
)
from agentforge.providers.lineage import (
    ProviderInvocationContextV1,
    ProviderLogicalContextV1,
    ProviderTerminalEventV1,
    served_provider_matches_configured,
)
from agentforge.security_tools.catalog import SECURITY_TOOL_CATALOG
from agentforge.target.registry import TargetRegistry, TargetRegistryError
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthorizationScope,
    ExecutionProfile,
    HostedRunBinding,
    SafetyCaps,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)

_ENVIRONMENTS = frozenset(environment.value for environment in TargetEnvironment)
_IDEMPOTENCY_KEY = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REASON_CODE = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")
_BEARER_SECRET = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT_SECRET = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PROVIDER_SECRET = re.compile(r"\bsk-(?:ant-|or-|proj-)?[A-Za-z0-9_-]{12,}\b")
_COOKIE_SECRET = re.compile(r"(?i)\b(?:cookie|set-cookie)\s*:\s*[^\s;]+")
_LABELED_SECRET = re.compile(
    r"(?i)\b(?:api[_ -]?key|token|secret|password|authorization|credential)\b"
    r"\s*[:=]\s*[^\s;]+"
)
_URL_USERINFO_SECRET = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@[^\s]+")
_CREDENTIAL_REFERENCE_SECRET = re.compile(r"(?i)\bsecretref://[A-Za-z0-9._~/-]+")
_AWS_ACCESS_KEY_SECRET = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GOOGLE_API_KEY_SECRET = re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")
_GITHUB_TOKEN_SECRET = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"
)
_GITLAB_TOKEN_SECRET = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")
_SLACK_TOKEN_SECRET = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
_STRIPE_LIVE_KEY_SECRET = re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")
_PRIVATE_KEY_SECRET = re.compile(
    r"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_RATIONALE_MAX_LENGTH = 2_000
_MAX_AUTHORIZATION_LIFETIME = datetime.timedelta(hours=24)
_CAMPAIGN_JOB_ATTEMPT_ID = "campaign"
_CAMPAIGN_PAYLOAD_SCHEMA = "campaign.execute"
_CAMPAIGN_PAYLOAD_VERSION = 1
_SHA256 = re.compile(r"\A[a-f0-9]{64}\Z")
# Case categories are the shared accept-list in agentforge.case_taxonomy. They previously lived
# here as a private three-element copy, which silently made every state_corruption,
# denial_of_service and identity_role_exploitation case in the reviewed live-100 workload
# inadmissible. The MVP coverage FLOOR is a separate concept and is unchanged.
_ATTACK_CLASSES = frozenset({"boundary", "invariant", "regression"})
# Only a tool the platform can actually execute may be recorded as having produced a case, so the
# accepted identifiers are the trusted catalog itself rather than any well-formed string. The
# catalog module imports nothing from agentforge, so this cannot create an import cycle.
_CATALOG_TOOL_IDS = frozenset(tool.tool_id for tool in SECURITY_TOOL_CATALOG)
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_EXACT_COUNT_CORPUS_ID = "headshot-live-100-v1"
_JUDGE_CALIBRATION_STATES = frozenset({"unavailable", "failed", "passed", "invalidated", "enabled"})
_DECISION_AUTHORITIES = frozenset({"oracle", "model", "none"})
_JUDGE_CALIBRATION_ID = re.compile(r"\AJC-[0-9a-f]{64}\Z")
_USD = re.compile(r"\A(?:0|[1-9][0-9]*)(?:\.[0-9]{1,12})?\Z")
_LEGACY_AGENT_ACCEPTANCE_ROLES: tuple[AgentRole, ...] = (
    "orchestrator",
    "judge",
    "documentation",
)
_AGENT_ACCEPTANCE_ROLES: tuple[AgentRole, ...] = (
    "orchestrator",
    "red_team",
    "judge",
    "documentation",
)
_AGENT_ACCEPTANCE_ACTOR_ID = "system:live-acceptance"
_AGENT_ACCEPTANCE_ACTOR = re.compile(r"\Asystem:[A-Za-z0-9][A-Za-z0-9._:-]{0,120}\Z")
_AGENT_ACCEPTANCE_MAX_LIFETIME = datetime.timedelta(minutes=30)
_AGENT_ACCEPTANCE_CASE_ID = "agentforge-hosted-acceptance-v1"
_AGENT_ACCEPTANCE_FIXTURE = {
    "classification": "synthetic",
    "contains_real_phi": False,
    "schema_version": "1",
    "source": "agentforge.live_acceptance",
}
_AGENT_ACCEPTANCE_PROVENANCE = {
    "actor_type": "system",
    "source": "agentforge.live_acceptance",
    "schema_version": "1",
}
_AGENT_ACCEPTANCE_ROLE_USD_CAPS: Mapping[AgentRole, Decimal] = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}
_AGENT_ACCEPTANCE_GLOBAL_USD_CAP = Decimal("10")
_AGENT_ACCEPTANCE_ROLE_TOKEN_CAPS: Mapping[AgentRole, tuple[int, int, int]] = {
    "orchestrator": (32_768, 512, 1_024),
    "red_team": (32_768, 8_192, 8_192),
    "judge": (32_768, 512, 1_024),
    "documentation": (32_768, 512, 1_024),
}
_AGENT_ACCEPTANCE_GLOBAL_TOKEN_CAPS = (131_072, 9_728, 11_264)
_PROMPT_SNAPSHOT_MESSAGE_ROLES = frozenset({"system", "user", "assistant", "tool"})
_PROMPT_SNAPSHOT_MAX_MESSAGES = 64
_PROMPT_SNAPSHOT_MAX_TRANSCRIPT_BYTES = 1_572_864
_PROMPT_SNAPSHOT_MAX_REDACTIONS = 64
_PROMPT_SNAPSHOT_MAX_REDACTIONS_BYTES = 16_384
_PROMPT_SNAPSHOT_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|_)(?:sid|session_id|patient_id|patient_name|full_name|pid|mrn|"
    r"medical_record_number|ssn|social_security_number|date_of_birth|birth_date|dob|"
    r"address|email|phone|phone_number)(?:$|_)"
)
_PROMPT_SNAPSHOT_REDACTION_MARKER = re.compile(r"\A\[REDACTED:[A-Za-z0-9_:-]{1,110}\]\Z")
_PROMPT_SNAPSHOT_REDACTED_SECRET_LINE = re.compile(
    r"(?im)^[ \t]*(?:access[_ -]?token|api[_ -]?key|authorization|bearer|cookie|"
    r"credential|password|refresh[_ -]?token|secret|session[_ -]?token|set-cookie)"
    r"\s*[:=]\s*\[REDACTED:[A-Za-z0-9_:-]{1,110}\][ \t]*$"
)
_PROMPT_SNAPSHOT_SYNTHETIC_VALUE = re.compile(r"\ASYNTH-[A-Z0-9]+(?:-[A-Z0-9]+)*\Z")
_PROMPT_SNAPSHOT_REDACTION_PATH = re.compile(
    r"\A\$\.messages\[(?P<message_index>0|[1-9][0-9]?)\]\.content"
    r"(?P<tail>(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*)\Z"
)
_PROMPT_SNAPSHOT_REDACTION_PATH_TOKEN = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+)\]")
_PROMPT_SNAPSHOT_REDACTION_REASONS = frozenset(
    {
        "access_token",
        "authorization",
        "authorization_header",
        "cookie",
        "credential",
        "patient_identifier",
        "phi",
        "secret",
        "session_identifier",
        "synthetic_fixture",
        "synthetic_identifier",
        "target_response",
    }
)
_PROMPT_SNAPSHOT_HIGH_CONFIDENCE_PHI = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"(?i)\b(?:mrn|medical\s+record(?:\s+number)?)\s*[:#=-]?\s*\d{6,}\b"),
    re.compile(
        r"(?i:\b(?:patient[_ -]?name|full[_ -]?name|patient[_ -]?id|"
        r"date[_ -]?of[_ -]?birth|birth[_ -]?date|dob|address|email|"
        r"phone(?:[_ -]?number)?)\b\s*[:=])"
        r"(?!\s*[\"']?(?:\[REDACTED:[A-Za-z0-9_:-]{1,110}\]|"
        r"SYNTH-[A-Z0-9]+(?:-[A-Z0-9]+)*)(?=[\s\"';,.)\]}]|$))"
        r"\s*[\"']?[^\r\n;,]{2,}"
    ),
    re.compile(r"(?i)\b(?:mrn|ssn|patient[_ -]?id)[_.:-]?[0-9]{6,}\b"),
)
_PROMPT_SNAPSHOT_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@(?P<domain>[A-Z0-9.-]+\.[A-Z]{2,})\b")
_PROMPT_SNAPSHOT_PHONE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]"
    r"(?P<exchange>\d{3})[-.\s](?P<line>\d{4})(?![A-Za-z0-9])"
)
_PROMPT_SNAPSHOT_FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "authorization_header",
        "cookie",
        "credential_ref",
        "credential_reference",
        "credentials",
        "password",
        "raw_target_response",
        "refresh_token",
        "response_body",
        "response_headers",
        "secret",
        "session_token",
        "set_cookie",
        "target_response",
    }
)
_PROMPT_SNAPSHOT_RAW_TARGET_EVIDENCE_KEYS = frozenset(
    {
        "assistant_text",
        "body",
        "content",
        "headers",
        "output",
        "raw_body",
        "response",
        "text",
    }
)


@dataclass(frozen=True, slots=True)
class AuthorizedHostedRoleConfiguration:
    """One role resolved only from an approved run's immutable four-role binding."""

    organization_id: str
    run_id: str
    configuration: HostedConfigurationSet
    role_configuration: HostedRoleConfiguration
    authorization: HostedRunBinding


@dataclass(frozen=True, slots=True)
class AgentAcceptanceRunIdentity:
    """The run and singleton synthetic attempt created in one transaction."""

    run_id: str
    attempt_id: str


@dataclass(frozen=True, slots=True)
class GovernedAcceptanceRunIdentity:
    """The governed run and its single reviewed-corpus attempt created in one transaction."""

    run_id: str
    attempt_id: str


@dataclass(frozen=True, slots=True)
class AuthorizedAgentAcceptanceRoleConfiguration:
    """One non-target role resolved from a short-lived acceptance authority."""

    organization_id: str
    run_id: str
    acceptance_attempt_id: str
    configuration: HostedConfigurationSet
    role_configuration: HostedRoleConfiguration
    generation_policy_sha256: str
    acceptance_context_sha256: str
    limits: Mapping[str, Any]
    expires_at: datetime.datetime


def _agent_acceptance_roles_for_version(version: str) -> tuple[AgentRole, ...]:
    if version == "1":
        return _LEGACY_AGENT_ACCEPTANCE_ROLES
    if version == "2":
        return _AGENT_ACCEPTANCE_ROLES
    raise AuthorizationDeniedError("agent acceptance limits version is unavailable")


def _closed_agent_acceptance_limits(version: str = "2") -> dict[str, Any]:
    roles = _agent_acceptance_roles_for_version(version)
    return {
        "schema_version": version,
        "network_scope": "openrouter_langfuse_only",
        "target_call_limit": 0,
        "allowed_roles": list(roles),
        "role_call_caps": {role: 1 for role in roles},
        "role_usd_caps": {
            role: format(_AGENT_ACCEPTANCE_ROLE_USD_CAPS[role], "f") for role in roles
        },
        "global_call_cap": len(roles),
        "global_usd_cap": format(_AGENT_ACCEPTANCE_GLOBAL_USD_CAP, "f"),
    }


_GOVERNED_ACCEPTANCE_ROLES: tuple[AgentRole, ...] = (
    "orchestrator",
    "red_team",
    "judge",
    "documentation",
)
_GOVERNED_ACCEPTANCE_RUN_PREFIX = "GA-"


# The platform physical-call ceiling (agents.hosted.HOSTED_MAX_PHYSICAL_CALLS); the governed
# global call budget is config-DERIVED but can never exceed this absolute platform bound.
_GOVERNED_GLOBAL_CALL_CEILING = 56
_GOVERNED_LIMIT_KEYS = frozenset(
    {
        "schema_version",
        "network_scope",
        "target_call_limit",
        "allowed_roles",
        "role_call_caps",
        "role_usd_caps",
        "global_call_cap",
        "global_usd_cap",
    }
)


def _governed_limits_shape_ok(limits: Mapping[str, Any]) -> bool:
    """Structural validity of a governed envelope: the four-role shape + the ABSOLUTE one-dispatch
    invariant. The per-role/global call+spend BUDGET is validated for positivity/shape only; its
    EXACT values are config-DERIVED and matched to the staged config by the role authorizer.

    The one-dispatch invariant (``target_call_limit=1`` + ``network_scope=policy_gateway_target``)
    is pinned here by construction and is NEVER among the derived values — a relaxed budget cannot
    relax the dispatch ceiling.
    """

    if not isinstance(limits, Mapping) or set(limits) != _GOVERNED_LIMIT_KEYS:
        return False
    roles = _GOVERNED_ACCEPTANCE_ROLES
    if (
        limits.get("schema_version") != "3"
        or limits.get("network_scope") != "policy_gateway_target"  # ABSOLUTE
        or limits.get("target_call_limit") != 1  # ABSOLUTE
        or limits.get("allowed_roles") != list(roles)
    ):
        return False
    call_caps = limits.get("role_call_caps")
    usd_caps = limits.get("role_usd_caps")
    if (
        not isinstance(call_caps, Mapping)
        or set(call_caps) != set(roles)
        or not isinstance(usd_caps, Mapping)
        or set(usd_caps) != set(roles)
    ):
        return False
    if any(type(call_caps[role]) is not int or call_caps[role] < 1 for role in roles):
        return False
    try:
        if any(
            not isinstance(usd_caps[role], str)
            or _USD.fullmatch(usd_caps[role]) is None
            or Decimal(usd_caps[role]) <= 0
            for role in roles
        ):
            return False
        global_calls = limits.get("global_call_cap")
        global_usd = limits.get("global_usd_cap")
        if (
            type(global_calls) is not int
            or not (len(roles) <= global_calls <= _GOVERNED_GLOBAL_CALL_CEILING)
            or not isinstance(global_usd, str)
            or _USD.fullmatch(global_usd) is None
            or not (Decimal("0") < Decimal(global_usd) <= _AGENT_ACCEPTANCE_GLOBAL_USD_CAP)
        ):
            return False
    except (InvalidOperation, TypeError):
        return False
    return True


def _canonical_agent_acceptance_limits_for_configuration(
    configuration: HostedConfigurationSet,
) -> dict[str, Any]:
    validate_hosted_configuration_set(configuration)
    if configuration.global_limits.max_calls == len(_LEGACY_AGENT_ACCEPTANCE_ROLES):
        version = "1"
    elif configuration.global_limits.max_calls >= len(_AGENT_ACCEPTANCE_ROLES):
        version = "2"
    else:
        raise InvalidControlPlaneInput(
            "global hosted limits cannot contain the closed acceptance call envelope"
        )
    acceptance_roles = _agent_acceptance_roles_for_version(version)
    roles = {role.role: role for role in configuration.roles}
    for role_name in acceptance_roles:
        role = roles[role_name]
        if (
            role.limits.max_calls < 1
            or role.limits.max_usd < _AGENT_ACCEPTANCE_ROLE_USD_CAPS[role_name]
            or role.limits.max_retries != 0
            or role.limits.max_concurrency != 1
        ):
            raise InvalidControlPlaneInput(
                f"{role_name} hosted limits cannot contain the closed one-call envelope"
            )
        if version == "2" and any(
            configured < required
            for configured, required in zip(
                (
                    role.limits.max_input_tokens,
                    role.limits.max_output_tokens,
                    role.limits.max_reasoning_tokens,
                ),
                _AGENT_ACCEPTANCE_ROLE_TOKEN_CAPS[role_name],
                strict=True,
            )
        ):
            raise InvalidControlPlaneInput(
                f"{role_name} hosted token limits cannot contain the closed one-call envelope"
            )
    if (
        configuration.global_limits.max_usd < _AGENT_ACCEPTANCE_GLOBAL_USD_CAP
        or configuration.global_limits.max_retries != 0
        or configuration.global_limits.max_concurrency != 1
    ):
        raise InvalidControlPlaneInput(
            "global hosted limits cannot contain the closed acceptance runtime envelope"
        )
    if version == "2" and any(
        configured < required
        for configured, required in zip(
            (
                configuration.global_limits.max_input_tokens,
                configuration.global_limits.max_output_tokens,
                configuration.global_limits.max_reasoning_tokens,
            ),
            _AGENT_ACCEPTANCE_GLOBAL_TOKEN_CAPS,
            strict=True,
        )
    ):
        raise InvalidControlPlaneInput(
            "global hosted token limits cannot contain the closed four-call envelope"
        )
    return _closed_agent_acceptance_limits(version)


def canonical_agent_acceptance_limits(
    configuration: HostedConfigurationSet,
) -> dict[str, Any]:
    """Derive the exact zero-target sub-envelope contained by a staged configuration."""

    return _canonical_agent_acceptance_limits_for_configuration(configuration)


def canonical_governed_acceptance_limits(
    configuration: HostedConfigurationSet,
) -> dict[str, Any]:
    """DERIVE the v3 governed envelope from the staged, reviewed four-role configuration.

    The per-role/global call+spend BUDGET is the config's own reviewed budget (so a governed run is
    bounded by exactly the authorized configuration — the closed 4-call harness config OR the
    56-call production config, whichever is staged). The one-dispatch invariant
    (``target_call_limit=1`` + ``network_scope=policy_gateway_target``) is PINNED here by
    construction and is never among the derived values. Retries live only at the agent-reasoning
    (provider) level in the config; they can never add a second target dispatch because the dispatch
    ceiling is structural, not derived.
    """

    validate_hosted_configuration_set(configuration)
    roles = _GOVERNED_ACCEPTANCE_ROLES
    role_map = {role.role: role for role in configuration.roles}
    if set(role_map) != set(roles):
        raise InvalidControlPlaneInput(
            "governed acceptance requires the exact four-role configuration"
        )
    global_calls = configuration.global_limits.max_calls
    if type(global_calls) is not int or not (
        len(roles) <= global_calls <= _GOVERNED_GLOBAL_CALL_CEILING
    ):
        raise InvalidControlPlaneInput(
            "governed acceptance global call budget is outside the platform ceiling"
        )
    if configuration.global_limits.max_usd > _AGENT_ACCEPTANCE_GLOBAL_USD_CAP:
        raise InvalidControlPlaneInput(
            "governed acceptance global spend budget exceeds the platform ceiling"
        )
    for role in roles:
        limits = role_map[role].limits
        if type(limits.max_calls) is not int or limits.max_calls < 1 or limits.max_usd <= 0:
            raise InvalidControlPlaneInput(f"{role} governed call/spend budget is invalid")
    return {
        "schema_version": "3",
        "network_scope": "policy_gateway_target",  # ABSOLUTE — pinned, never derived
        "target_call_limit": 1,  # ABSOLUTE — pinned, never derived
        "allowed_roles": list(roles),
        "role_call_caps": {role: role_map[role].limits.max_calls for role in roles},
        "role_usd_caps": {role: format(role_map[role].limits.max_usd, "f") for role in roles},
        "global_call_cap": global_calls,
        "global_usd_cap": format(configuration.global_limits.max_usd, "f"),
    }


class ControlPlaneStore:
    """Persist security decisions without accepting client authority or credential values."""

    def __init__(self, engine: Engine, *, environment: str) -> None:
        if not isinstance(engine, Engine):
            raise TypeError("control-plane store requires a SQLAlchemy Engine")
        if environment not in _ENVIRONMENTS:
            raise InvalidControlPlaneInput("control-plane environment is invalid")
        self._engine = engine
        self._environment = environment

    # ------------------------------------------------------------------ target registry writes

    def register_target(
        self,
        *,
        principal: Principal,
        target: TargetDefinition,
        idempotency_key: str,
    ) -> TargetSnapshotRecord:
        self._require_permission(principal, TARGETS_MANAGE)
        if (
            not isinstance(target, TargetDefinition)
            or target.lifecycle is not TargetLifecycle.DRAFT
        ):
            raise InvalidControlPlaneInput("a target snapshot must be a draft TargetDefinition")
        if target.environment.value != self._environment:
            raise AuthorizationDeniedError("target environment does not match this control plane")
        if self._environment != TargetEnvironment.LOCAL.value and target.adapter_kind == "fake":
            raise AuthorizationDeniedError("fake targets are local-test-only")
        payload = target_payload(target)
        digest = content_hash(payload)
        document = {"target": payload}
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "target.register", idempotency_key, document
            )
            if existing is not None:
                return self._target_snapshot(
                    connection,
                    principal.organization_id,
                    existing["target_id"],
                    existing["version"],
                )

            self._aggregate_lock(
                connection, f"target:{principal.organization_id}:{target.target_id}"
            )
            versions = (
                connection.execute(
                    text(
                        "SELECT version FROM target_definitions "
                        "WHERE organization_id = :org AND target_id = :target"
                    ),
                    {"org": principal.organization_id, "target": target.target_id},
                )
                .scalars()
                .all()
            )
            if target.version in versions:
                raise RecordConflictError("target id/version is already immutable")
            if versions and self._version_key(target.version) <= max(
                self._version_key(version) for version in versions
            ):
                raise RecordConflictError("target versions must increase monotonically")

            connection.execute(
                text(
                    "INSERT INTO target_identities (organization_id, target_id) "
                    "VALUES (:org, :target) ON CONFLICT DO NOTHING"
                ),
                {"org": principal.organization_id, "target": target.target_id},
            )
            row = (
                connection.execute(
                    text(
                        "INSERT INTO target_definitions "
                        "(organization_id, target_id, version, content_hash, payload, "
                        "actor_user_id, actor_session_id) VALUES "
                        "(:org, :target, :version, :hash, CAST(:payload AS jsonb), "
                        ":user, :session) "
                        "RETURNING created_at"
                    ),
                    {
                        "org": principal.organization_id,
                        "target": target.target_id,
                        "version": target.version,
                        "hash": digest,
                        "payload": canonical_json(payload),
                        "user": principal.user_id,
                        "session": principal.session_id,
                    },
                )
                .mappings()
                .one()
            )
            connection.execute(
                text(
                    "INSERT INTO target_lifecycle_events "
                    "(organization_id, target_id, target_version, from_lifecycle, to_lifecycle, "
                    "actor_user_id, actor_session_id) VALUES "
                    "(:org, :target, :version, NULL, 'draft', :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "target": target.target_id,
                    "version": target.version,
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._audit(
                connection,
                principal.organization_id,
                "target.registered",
                "target",
                f"{target.target_id}@{target.version}",
                principal,
                {"content_hash": digest},
            )
            response = {"target_id": target.target_id, "version": target.version}
            self._finish_command(
                connection,
                principal,
                "target.register",
                idempotency_key,
                request_hash,
                response,
            )
            return TargetSnapshotRecord(
                organization_id=principal.organization_id,
                target_id=target.target_id,
                version=target.version,
                content_hash=digest,
                created_at=row["created_at"],
            )

    def transition_target(
        self,
        *,
        principal: Principal,
        target_id: str,
        version: str,
        lifecycle: TargetLifecycle,
        idempotency_key: str,
    ) -> TargetDefinition:
        self._require_permission(principal, TARGETS_MANAGE)
        try:
            requested_lifecycle = TargetLifecycle(lifecycle)
        except (TypeError, ValueError) as exc:
            raise InvalidControlPlaneInput("target lifecycle is invalid") from exc
        document = {
            "target_id": target_id,
            "version": version,
            "lifecycle": requested_lifecycle.value,
        }
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "target.transition", idempotency_key, document
            )
            if existing is not None:
                base, _current, _events = self._load_target(
                    connection, principal.organization_id, target_id, version
                )
                return replace(base, lifecycle=TargetLifecycle(existing["lifecycle"]))

            self._aggregate_lock(
                connection, f"target-version:{principal.organization_id}:{target_id}:{version}"
            )
            _base, current, _events = self._load_target(
                connection, principal.organization_id, target_id, version
            )
            try:
                transitioned = current.transition(requested_lifecycle)
            except ValueError as exc:
                raise RecordConflictError("target lifecycle transition is not allowed") from exc
            connection.execute(
                text(
                    "INSERT INTO target_lifecycle_events "
                    "(organization_id, target_id, target_version, from_lifecycle, to_lifecycle, "
                    "actor_user_id, actor_session_id) VALUES "
                    "(:org, :target, :version, :before, :after, :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "target": target_id,
                    "version": version,
                    "before": current.lifecycle.value,
                    "after": transitioned.lifecycle.value,
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._audit(
                connection,
                principal.organization_id,
                "target.lifecycle_changed",
                "target",
                f"{target_id}@{version}",
                principal,
                {"from": current.lifecycle.value, "to": transitioned.lifecycle.value},
            )
            response = {"lifecycle": transitioned.lifecycle.value}
            self._finish_command(
                connection,
                principal,
                "target.transition",
                idempotency_key,
                request_hash,
                response,
            )
            return transitioned

    def register_surface(
        self,
        *,
        principal: Principal,
        surface: AttackSurfaceDefinition,
        idempotency_key: str,
    ) -> SurfaceSnapshotRecord:
        self._require_permission(principal, TARGETS_MANAGE)
        if not isinstance(surface, AttackSurfaceDefinition):
            raise InvalidControlPlaneInput("surface snapshot is invalid")
        payload = surface_payload(surface)
        digest = content_hash(payload)
        document = {"surface": payload}
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "surface.register", idempotency_key, document
            )
            if existing is not None:
                return self._surface_snapshot(
                    connection,
                    principal.organization_id,
                    existing["surface_id"],
                    existing["version"],
                )

            self._aggregate_lock(
                connection, f"surface:{principal.organization_id}:{surface.surface_id}"
            )
            target_base, target, _events = self._load_target(
                connection,
                principal.organization_id,
                surface.target_id,
                surface.target_version,
            )
            registry = TargetRegistry()
            registry.register_target(target_base)
            if target.lifecycle is not TargetLifecycle.DRAFT:
                raise RecordConflictError("surface registration requires a draft target version")
            try:
                registry.register_surface(surface)
            except TargetRegistryError as exc:
                raise RecordConflictError("surface snapshot conflicts with its target") from exc

            owner = connection.execute(
                text(
                    "SELECT target_id FROM surface_identities "
                    "WHERE organization_id = :org AND surface_id = :surface"
                ),
                {"org": principal.organization_id, "surface": surface.surface_id},
            ).scalar_one_or_none()
            if owner is not None and owner != surface.target_id:
                raise RecordConflictError("surface identity has a different immutable target owner")
            versions = (
                connection.execute(
                    text(
                        "SELECT version FROM attack_surface_definitions "
                        "WHERE organization_id = :org AND surface_id = :surface"
                    ),
                    {"org": principal.organization_id, "surface": surface.surface_id},
                )
                .scalars()
                .all()
            )
            if surface.version in versions:
                raise RecordConflictError("surface id/version is already immutable")
            if versions and self._version_key(surface.version) <= max(
                self._version_key(version) for version in versions
            ):
                raise RecordConflictError("surface versions must increase monotonically")

            connection.execute(
                text(
                    "INSERT INTO surface_identities "
                    "(organization_id, surface_id, target_id) VALUES (:org, :surface, :target) "
                    "ON CONFLICT DO NOTHING"
                ),
                {
                    "org": principal.organization_id,
                    "surface": surface.surface_id,
                    "target": surface.target_id,
                },
            )
            row = (
                connection.execute(
                    text(
                        "INSERT INTO attack_surface_definitions "
                        "(organization_id, surface_id, version, target_id, target_version, "
                        "content_hash, "
                        "payload, actor_user_id, actor_session_id) VALUES "
                        "(:org, :surface, :version, :target, :target_version, :hash, "
                        "CAST(:payload AS jsonb), :user, :session) RETURNING created_at"
                    ),
                    {
                        "org": principal.organization_id,
                        "surface": surface.surface_id,
                        "version": surface.version,
                        "target": surface.target_id,
                        "target_version": surface.target_version,
                        "hash": digest,
                        "payload": canonical_json(payload),
                        "user": principal.user_id,
                        "session": principal.session_id,
                    },
                )
                .mappings()
                .one()
            )
            connection.execute(
                text(
                    "INSERT INTO surface_state_events "
                    "(organization_id, surface_id, surface_version, target_id, from_enabled, "
                    "to_enabled, actor_user_id, actor_session_id) VALUES "
                    "(:org, :surface, :version, :target, NULL, :enabled, :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "surface": surface.surface_id,
                    "version": surface.version,
                    "target": surface.target_id,
                    "enabled": surface.enabled,
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._audit(
                connection,
                principal.organization_id,
                "surface.registered",
                "surface",
                f"{surface.surface_id}@{surface.version}",
                principal,
                {"target_id": surface.target_id, "content_hash": digest},
            )
            response = {"surface_id": surface.surface_id, "version": surface.version}
            self._finish_command(
                connection,
                principal,
                "surface.register",
                idempotency_key,
                request_hash,
                response,
            )
            return SurfaceSnapshotRecord(
                organization_id=principal.organization_id,
                target_id=surface.target_id,
                target_version=surface.target_version,
                surface_id=surface.surface_id,
                version=surface.version,
                content_hash=digest,
                created_at=row["created_at"],
            )

    def set_surface_enabled(
        self,
        *,
        principal: Principal,
        target_id: str,
        surface_id: str,
        version: str,
        enabled: bool,
        idempotency_key: str,
    ) -> AttackSurfaceDefinition:
        self._require_permission(principal, TARGETS_MANAGE)
        if not isinstance(enabled, bool):
            raise InvalidControlPlaneInput("surface enabled state must be a boolean")
        document = {
            "target_id": target_id,
            "surface_id": surface_id,
            "version": version,
            "enabled": enabled,
        }
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "surface.state", idempotency_key, document
            )
            if existing is not None:
                surface = self._load_surface(
                    connection, principal.organization_id, target_id, surface_id, version
                )
                return replace(surface, enabled=bool(existing["enabled"]))

            self._aggregate_lock(
                connection, f"surface-version:{principal.organization_id}:{surface_id}:{version}"
            )
            surface = self._load_surface(
                connection, principal.organization_id, target_id, surface_id, version
            )
            if surface.enabled is enabled:
                raise RecordConflictError("surface already has the requested effective state")
            if enabled:
                _base, target, _events = self._load_target(
                    connection, principal.organization_id, target_id, surface.target_version
                )
                if target.lifecycle is not TargetLifecycle.DRAFT:
                    raise RecordConflictError(
                        "a disabled surface may only be re-enabled while its target is draft"
                    )
            connection.execute(
                text(
                    "INSERT INTO surface_state_events "
                    "(organization_id, surface_id, surface_version, target_id, from_enabled, "
                    "to_enabled, actor_user_id, actor_session_id) VALUES "
                    "(:org, :surface, :version, :target, :before, :after, :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "surface": surface_id,
                    "version": version,
                    "target": target_id,
                    "before": surface.enabled,
                    "after": enabled,
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._audit(
                connection,
                principal.organization_id,
                "surface.state_changed",
                "surface",
                f"{surface_id}@{version}",
                principal,
                {"from_enabled": surface.enabled, "to_enabled": enabled},
            )
            response = {"enabled": enabled}
            self._finish_command(
                connection,
                principal,
                "surface.state",
                idempotency_key,
                request_hash,
                response,
            )
            return replace(surface, enabled=enabled)

    # ------------------------------------------------------------------ authorization workflow

    def build_scope(
        self,
        *,
        principal: Principal,
        target_id: str,
        target_version: str,
        surface_id: str,
        surface_version: str,
        corpus_hash: str,
        caps: SafetyCaps,
        run_nonce: str,
        corpus_id: str = "m11-seed-corpus-v1",
        execution_profile: ExecutionProfile = ExecutionProfile.LIVE,
        hosted_run: HostedRunBinding | None = None,
    ) -> AuthorizationScope:
        self._require_permission(principal, CAMPAIGN_LAUNCH)
        with self._engine.connect() as connection:
            return self._build_scope_from_database(
                connection,
                principal.organization_id,
                target_id,
                target_version,
                surface_id,
                surface_version,
                corpus_hash,
                caps,
                run_nonce,
                corpus_id,
                execution_profile,
                hosted_run,
            )

    def request_campaign_authorization(
        self,
        *,
        principal: Principal,
        scope: AuthorizationScope,
        expires_at: datetime.datetime,
        idempotency_key: str,
    ) -> AuthorizationRequestRecord:
        self._require_permission(principal, CAMPAIGN_LAUNCH)
        if not isinstance(scope, AuthorizationScope):
            raise InvalidControlPlaneInput("authorization requires a canonical PR7 scope")
        expiry = self._normalize_expiry(expires_at)
        payload = scope.canonical_payload()
        document = {"scope": payload, "expires_at": expiry.isoformat()}
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "campaign.authorization.request", idempotency_key, document
            )
            if existing is not None:
                return self._authorization_request(
                    connection, principal.organization_id, existing["request_id"]
                )
            database_now = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
            if expiry <= database_now or expiry - database_now > _MAX_AUTHORIZATION_LIFETIME:
                raise InvalidControlPlaneInput(
                    "authorization expiry must be future and within 24 hours"
                )
            self._validate_scope(connection, principal.organization_id, scope)
            request_id = uuid.uuid4().hex
            row = (
                connection.execute(
                    text(
                        "INSERT INTO campaign_authorization_requests "
                        "(request_id, organization_id, scope_hash, scope_payload, "
                        "launcher_user_id, "
                        "launcher_session_id, expires_at) VALUES "
                        "(:request_id, :org, :scope_hash, CAST(:payload AS jsonb), "
                        ":user, :session, :expiry) "
                        "RETURNING created_at"
                    ),
                    {
                        "request_id": request_id,
                        "org": principal.organization_id,
                        "scope_hash": scope.scope_hash(),
                        "payload": canonical_json(payload),
                        "user": principal.user_id,
                        "session": principal.session_id,
                        "expiry": expiry,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                connection,
                principal.organization_id,
                "campaign.authorization_requested",
                "campaign_authorization_request",
                request_id,
                principal,
                {"scope_hash": scope.scope_hash(), "expires_at": expiry.isoformat()},
            )
            response = {"request_id": request_id}
            self._finish_command(
                connection,
                principal,
                "campaign.authorization.request",
                idempotency_key,
                request_hash,
                response,
            )
            return AuthorizationRequestRecord(
                request_id=request_id,
                organization_id=principal.organization_id,
                scope_hash=scope.scope_hash(),
                scope_payload=dict(payload),
                launcher_user_id=principal.user_id,
                launcher_session_id=principal.session_id,
                expires_at=expiry,
                created_at=row["created_at"],
            )

    def decide_campaign_authorization(
        self,
        *,
        principal: Principal,
        request_id: str,
        decision: str,
        idempotency_key: str,
    ) -> AuthorizationDecisionRecord:
        self._require_permission(principal, CAMPAIGN_AUTHORIZE)
        if decision not in {"approved", "rejected"}:
            raise InvalidControlPlaneInput("authorization decision is invalid")
        document = {"request_id": request_id, "decision": decision}
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "campaign.authorization.decide", idempotency_key, document
            )
            if existing is not None:
                return self._authorization_decision(
                    connection, principal.organization_id, existing["decision_id"]
                )
            self._aggregate_lock(
                connection, f"authorization-request:{principal.organization_id}:{request_id}"
            )
            request = self._authorization_request(
                connection, principal.organization_id, request_id, for_update=True
            )
            prior = connection.execute(
                text(
                    "SELECT decision_id FROM campaign_authorization_decisions "
                    "WHERE organization_id = :org AND request_id = :request_id"
                ),
                {"org": principal.organization_id, "request_id": request_id},
            ).scalar_one_or_none()
            if prior is not None:
                raise RecordConflictError("authorization request already has a terminal decision")
            database_now = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
            if request.expires_at <= database_now:
                raise AuthorizationDeniedError("authorization request is expired")
            # The legacy column remains in the expand-only schema for compatibility, but no
            # application role may set it. Two-person authorization is unconditional.
            self_approval_override = False
            if decision == "approved":
                if principal.user_id == request.launcher_user_id:
                    raise AuthorizationDeniedError(
                        "launcher cannot approve own authorization request"
                    )
                self._validate_scope(
                    connection,
                    principal.organization_id,
                    scope_from_payload(request.scope_payload),
                )
            decision_id = uuid.uuid4().hex
            row = (
                connection.execute(
                    text(
                        "INSERT INTO campaign_authorization_decisions "
                        "(decision_id, organization_id, request_id, scope_hash, decision, "
                        "approver_user_id, approver_session_id, self_approval_override) VALUES "
                        "(:decision_id, :org, :request_id, :scope_hash, :decision, "
                        ":user, :session, :self_approval_override) "
                        "RETURNING created_at"
                    ),
                    {
                        "decision_id": decision_id,
                        "org": principal.organization_id,
                        "request_id": request_id,
                        "scope_hash": request.scope_hash,
                        "decision": decision,
                        "user": principal.user_id,
                        "session": principal.session_id,
                        "self_approval_override": self_approval_override,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                connection,
                principal.organization_id,
                f"campaign.authorization_{decision}",
                "campaign_authorization_request",
                request_id,
                principal,
                {
                    "decision_id": decision_id,
                    "scope_hash": request.scope_hash,
                    "self_approval_override": self_approval_override,
                },
            )
            response = {"decision_id": decision_id}
            self._finish_command(
                connection,
                principal,
                "campaign.authorization.decide",
                idempotency_key,
                request_hash,
                response,
            )
            return AuthorizationDecisionRecord(
                decision_id=decision_id,
                organization_id=principal.organization_id,
                request_id=request_id,
                scope_hash=request.scope_hash,
                decision=decision,
                approver_user_id=principal.user_id,
                approver_session_id=principal.session_id,
                self_approval_override=self_approval_override,
                created_at=row["created_at"],
            )

    def launch_campaign(
        self,
        *,
        principal: Principal,
        request_id: str,
        idempotency_key: str,
    ) -> CampaignRunRecord:
        self._require_permission(principal, CAMPAIGN_LAUNCH)
        document = {"authorization_request_id": request_id}
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "campaign.launch", idempotency_key, document
            )
            if existing is not None:
                return self._campaign_run(connection, principal.organization_id, existing["run_id"])
            self._aggregate_lock(
                connection, f"authorization-request:{principal.organization_id}:{request_id}"
            )
            request = self._authorization_request(
                connection, principal.organization_id, request_id, for_update=True
            )
            if request.launcher_user_id != principal.user_id:
                raise AuthorizationDeniedError(
                    "only the persisted launcher may launch this request"
                )
            database_now = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
            scope = scope_from_payload(request.scope_payload)
            required_until = database_now + datetime.timedelta(
                seconds=scope.caps.run_timeout_seconds
            )
            if request.expires_at <= required_until:
                raise AuthorizationDeniedError(
                    "approved authorization cannot cover the full campaign timeout"
                )
            decision_row = (
                connection.execute(
                    text(
                        "SELECT * FROM campaign_authorization_decisions "
                        "WHERE organization_id = :org AND request_id = :request_id"
                    ),
                    {"org": principal.organization_id, "request_id": request_id},
                )
                .mappings()
                .one_or_none()
            )
            if decision_row is None or decision_row["decision"] != "approved":
                raise AuthorizationDeniedError("campaign launch requires an approved request")
            self._validate_scope(connection, principal.organization_id, scope)
            prior_run = connection.execute(
                text(
                    "SELECT run_id FROM campaign_runs WHERE organization_id = :org "
                    "AND authorization_request_id = :request_id"
                ),
                {"org": principal.organization_id, "request_id": request_id},
            ).scalar_one_or_none()
            if prior_run is not None:
                raise RecordConflictError("approved authorization was already consumed")

            run_id = uuid.uuid4().hex
            row = (
                connection.execute(
                    text(
                        "INSERT INTO campaign_runs "
                        "(run_id, organization_id, authorization_request_id, scope_hash, "
                        "launcher_user_id, launcher_session_id) VALUES "
                        "(:run_id, :org, :request_id, :scope_hash, :user, :session) "
                        "RETURNING created_at"
                    ),
                    {
                        "run_id": run_id,
                        "org": principal.organization_id,
                        "request_id": request_id,
                        "scope_hash": request.scope_hash,
                        "user": request.launcher_user_id,
                        "session": request.launcher_session_id,
                    },
                )
                .mappings()
                .one()
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id) "
                    "VALUES (:org, :run_id, 'queued', :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "run_id": run_id,
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._enqueue_campaign_job(connection, run_id, request_id, request.scope_hash)
            self._audit(
                connection,
                principal.organization_id,
                "campaign.queued",
                "campaign_run",
                run_id,
                principal,
                {"authorization_request_id": request_id, "scope_hash": request.scope_hash},
            )
            response = {"run_id": run_id}
            self._finish_command(
                connection,
                principal,
                "campaign.launch",
                idempotency_key,
                request_hash,
                response,
            )
            return CampaignRunRecord(
                run_id=run_id,
                organization_id=principal.organization_id,
                authorization_request_id=request_id,
                scope_hash=request.scope_hash,
                launcher_user_id=request.launcher_user_id,
                launcher_session_id=request.launcher_session_id,
                state="queued",
                created_at=row["created_at"],
            )

    def abort_campaign(
        self,
        *,
        principal: Principal,
        run_id: str,
        rationale: str,
        reason_code: str,
        idempotency_key: str,
    ) -> CampaignRunRecord:
        """Abort an organization-scoped run and cancel its queued work atomically."""

        self._require_permission(principal, CAMPAIGN_ABORT)
        if not isinstance(reason_code, str) or _REASON_CODE.fullmatch(reason_code) is None:
            raise InvalidControlPlaneInput("abort reason code is invalid")
        safe_rationale = self._sanitize_plaintext_rationale(rationale)
        document = {
            "run_id": run_id,
            "rationale": safe_rationale,
            "reason_code": reason_code,
        }
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "campaign.abort", idempotency_key, document
            )
            if existing is not None:
                return self._campaign_run(connection, principal.organization_id, existing["run_id"])
            self._aggregate_lock(connection, f"campaign-run:{run_id}")
            current = self._campaign_run(connection, principal.organization_id, run_id)
            if current.state not in {"queued", "running"}:
                raise RecordConflictError("campaign run can no longer be aborted")
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id, "
                    "reason_code) VALUES "
                    "(:org, :run_id, 'aborted', :user, :session, :reason)"
                ),
                {
                    "org": principal.organization_id,
                    "run_id": run_id,
                    "user": principal.user_id,
                    "session": principal.session_id,
                    "reason": reason_code,
                },
            )
            cancelled = connection.execute(
                text("SELECT m1d_cancel_queued_campaign_jobs(:org, :run_id)"),
                {"org": principal.organization_id, "run_id": run_id},
            ).scalar_one()
            self._audit(
                connection,
                principal.organization_id,
                "campaign.aborted",
                "campaign_run",
                run_id,
                principal,
                {
                    "rationale": safe_rationale,
                    "reason_code": reason_code,
                    "cancelled_queued_jobs": cancelled,
                },
            )
            self._finish_command(
                connection,
                principal,
                "campaign.abort",
                idempotency_key,
                request_hash,
                {"run_id": run_id},
            )
            return replace(current, state="aborted")

    # ------------------------------------------------------------------ reads / workload seams

    def get_authorization_request(
        self, *, principal: Principal, request_id: str
    ) -> AuthorizationRequestRecord:
        self._require_any_permission(principal, CAMPAIGN_LAUNCH, CAMPAIGN_AUTHORIZE)
        with self._engine.connect() as connection:
            return self._authorization_request(connection, principal.organization_id, request_id)

    def get_campaign_run(self, *, principal: Principal, run_id: str) -> CampaignRunRecord:
        self._require_permission(principal, CAMPAIGN_LAUNCH)
        with self._engine.connect() as connection:
            return self._campaign_run(connection, principal.organization_id, run_id)

    def load_authorization_request(
        self,
        *,
        organization_id: str,
        request_id: str,
    ) -> AuthorizationRequestRecord:
        """Read one authorization request, revalidating its scope integrity.

        A composition root that has to build a run's dependencies BEFORE the run row exists (the
        governed acceptance entrypoint) needs the approved scope, its hash, and the launcher
        identity. This is a read-only view over the same verified path the write flows use — the
        recomputed ``scope_hash`` must equal the stored one — and it grants no authority by itself:
        the approval decision and two-person control are still enforced where the run is created.
        """

        if (
            not isinstance(organization_id, str)
            or not organization_id
            or len(organization_id) > 64
            or not isinstance(request_id, str)
            or not request_id
            or len(request_id) > 128
        ):
            raise InvalidControlPlaneInput("authorization request identity is invalid")
        with self._engine.connect() as connection:
            return self._authorization_request(connection, organization_id, request_id)

    def load_run_for_execution(self, run_id: str) -> AuthorizedRunRecord:
        """Load and revalidate a persisted human authorization without accepting browser state."""

        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT r.*, q.scope_payload, q.expires_at, "
                        "d.decision_id, d.decision, d.approver_user_id, d.approver_session_id, "
                        "d.self_approval_override, "
                        "d.created_at AS decision_created_at, "
                        "(q.expires_at > clock_timestamp()) AS authorization_live, "
                        "(SELECT state FROM campaign_run_events e "
                        "WHERE e.organization_id = r.organization_id "
                        "AND e.run_id = r.run_id ORDER BY e.id DESC LIMIT 1) AS state "
                        "FROM campaign_runs r "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "AND q.scope_hash = r.scope_hash "
                        "JOIN campaign_authorization_decisions d "
                        "ON d.organization_id = q.organization_id "
                        "AND d.request_id = q.request_id AND d.scope_hash = q.scope_hash "
                        "WHERE r.run_id = :run_id"
                    ),
                    {"run_id": run_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("campaign run does not exist")
            if row["decision"] != "approved" or not row["authorization_live"]:
                raise AuthorizationDeniedError("campaign run authorization is not live")
            same_person = row["approver_user_id"] == row["launcher_user_id"]
            if same_person:
                raise AuthorizationDeniedError("campaign run violates two-person control")
            if row["self_approval_override"]:
                raise AuthorizationDeniedError("campaign self-approval override is disabled")
            if row["state"] not in {"queued", "running"}:
                raise AuthorizationDeniedError("campaign run is not executable")
            scope = scope_from_payload(dict(row["scope_payload"]))
            if scope.scope_hash() != row["scope_hash"]:
                raise AuthorizationDeniedError("campaign run scope hash is invalid")
            self._validate_scope(connection, row["organization_id"], scope)
            run = self._campaign_run_from_row(row)
            approval = AuthorizationDecisionRecord(
                decision_id=row["decision_id"],
                organization_id=row["organization_id"],
                request_id=row["authorization_request_id"],
                scope_hash=row["scope_hash"],
                decision=row["decision"],
                approver_user_id=row["approver_user_id"],
                approver_session_id=row["approver_session_id"],
                self_approval_override=bool(row["self_approval_override"]),
                created_at=row["decision_created_at"],
            )
            return AuthorizedRunRecord(
                run=run, scope=scope, approval=approval, expires_at=row["expires_at"]
            )

    def append_campaign_state(
        self,
        *,
        run_id: str,
        state: str,
        actor_user_id: str | None = None,
        actor_session_id: str | None = None,
        reason_code: str | None = None,
    ) -> CampaignRunRecord:
        transitions = {
            "queued": {"running", "aborted", "failed"},
            "running": {"complete", "aborted", "failed"},
            "complete": set(),
            "aborted": set(),
            "failed": set(),
        }
        if state not in transitions:
            raise InvalidControlPlaneInput("campaign state is invalid")
        if reason_code is not None and _REASON_CODE.fullmatch(reason_code) is None:
            raise InvalidControlPlaneInput("reason code is invalid")
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"campaign-run:{run_id}")
            row = (
                connection.execute(
                    text("SELECT organization_id FROM campaign_runs WHERE run_id = :run_id"),
                    {"run_id": run_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("campaign run does not exist")
            current = self._campaign_run(connection, row["organization_id"], run_id)
            if current.state == state:
                return current
            if state not in transitions[current.state]:
                raise RecordConflictError("campaign state transition is not allowed")
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id, "
                    "reason_code) "
                    "VALUES (:org, :run_id, :state, :user, :session, :reason)"
                ),
                {
                    "org": current.organization_id,
                    "run_id": run_id,
                    "state": state,
                    "user": actor_user_id,
                    "session": actor_session_id,
                    "reason": reason_code,
                },
            )
            if state in {"aborted", "failed"}:
                # An aborted or failed run still found whatever it found before it stopped, and a
                # reviewer needs to see that together with the fact that coverage was partial.
                # `complete` is written by complete_campaign_job, which composes its own report
                # alongside the run summary.
                self._compose_campaign_report(
                    connection,
                    organization_id=current.organization_id,
                    run_id=run_id,
                    run_state=state,
                )
            self._audit(
                connection,
                current.organization_id,
                f"campaign.{state}",
                "campaign_run",
                run_id,
                None,
                {"reason_code": reason_code} if reason_code else {},
                actor_user_id=actor_user_id,
                actor_session_id=actor_session_id,
            )
            return replace(current, state=state)

    def ensure_campaign_attempt(
        self,
        *,
        run_id: str,
        ordinal: int,
        case_id: str,
        case_content_hash: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        attack_class: str | None = None,
        owasp_mappings: Sequence[Mapping[str, Any]] | None = None,
        fixture_provenance: Mapping[str, Any] | None = None,
        source_tool: str | None = None,
        source_technique: str | None = None,
        source_kind: str | None = None,
        workload_instance_id: str | None = None,
        review_record_sha256: str | None = None,
        source_generation_sha256: str | None = None,
    ) -> CampaignAttemptRecord:
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
            raise InvalidControlPlaneInput("attempt ordinal must be non-negative")
        if not isinstance(case_id, str) or not case_id or len(case_id) > 128:
            raise InvalidControlPlaneInput("case identity is invalid")
        metadata_supplied = any(
            value is not None
            for value in (
                case_content_hash,
                category,
                severity,
                attack_class,
                owasp_mappings,
                fixture_provenance,
                source_tool,
                source_technique,
            )
        )
        if metadata_supplied:
            if (
                not isinstance(case_content_hash, str)
                or _SHA256.fullmatch(case_content_hash) is None
            ):
                raise InvalidControlPlaneInput("case content hash is invalid")
            if category not in SUPPORTED_CASE_CATEGORIES:
                raise InvalidControlPlaneInput("case category is invalid")
            if severity not in _SEVERITIES:
                raise InvalidControlPlaneInput("case severity is invalid")
            if attack_class not in _ATTACK_CLASSES:
                raise InvalidControlPlaneInput("case attack classification is invalid")
            if not isinstance(owasp_mappings, Sequence) or not owasp_mappings:
                raise InvalidControlPlaneInput("case OWASP mappings are required")
            normalized_mappings = [dict(mapping) for mapping in owasp_mappings]
            for mapping in normalized_mappings:
                if set(mapping) != {"framework", "version", "id", "name"}:
                    raise InvalidControlPlaneInput("case OWASP mapping is invalid")
                if mapping["framework"] not in {"OWASP Web", "OWASP LLM"}:
                    raise InvalidControlPlaneInput("case OWASP framework is invalid")
            if not isinstance(fixture_provenance, Mapping):
                raise InvalidControlPlaneInput("case fixture provenance is required")
            normalized_fixture = dict(fixture_provenance)
            if (
                normalized_fixture.get("classification") != "synthetic"
                or normalized_fixture.get("contains_real_phi") is not False
            ):
                raise AuthorizationDeniedError("only synthetic no-PHI case fixtures may execute")
            if source_tool is not None and (
                not isinstance(source_tool, str)
                or not source_tool
                or len(source_tool) > 64
                or re.fullmatch(r"[a-z0-9][a-z0-9-]*", source_tool) is None
                # A tool identity is only meaningful if it names a tool the platform actually
                # knows how to run. Accepting arbitrary well-formed strings here is what let a
                # producer kind ("hosted_red_team") be recorded as though it were a scanner.
                or source_tool not in _CATALOG_TOOL_IDS
            ):
                raise InvalidControlPlaneInput("case source tool is invalid")
            if source_technique is not None and (
                not isinstance(source_technique, str)
                or not source_technique
                or len(source_technique) > 200
            ):
                raise InvalidControlPlaneInput("case source technique is invalid")
            if (source_tool is None) != (source_technique is None):
                raise InvalidControlPlaneInput("case tool provenance must be complete")
        else:
            normalized_mappings = None
            normalized_fixture = None
        # Reviewed-workload (producer) lineage is an all-or-nothing tuple, validated independently
        # of the case metadata above. Legacy attempts predate reviewed workloads and legitimately
        # carry none of it, so "all four absent" stays valid; what must never happen is PARTIAL
        # provenance, which would let a case claim review without naming the record that reviewed
        # it. This mirrors the same-shaped CHECK constraints added in migration 0025.
        workload_lineage = (
            source_kind,
            workload_instance_id,
            review_record_sha256,
            source_generation_sha256,
        )
        if any(value is not None for value in workload_lineage):
            if not metadata_supplied:
                raise InvalidControlPlaneInput(
                    "reviewed-workload lineage requires complete case metadata"
                )
            if source_kind not in REVIEWED_WORKLOAD_SOURCE_KINDS:
                raise InvalidControlPlaneInput("case source kind is invalid")
            if (
                not isinstance(workload_instance_id, str)
                or re.fullmatch(WORKLOAD_INSTANCE_ID_PATTERN, workload_instance_id) is None
            ):
                raise InvalidControlPlaneInput("case workload instance identity is invalid")
            for lineage_hash in (review_record_sha256, source_generation_sha256):
                if not isinstance(lineage_hash, str) or _SHA256.fullmatch(lineage_hash) is None:
                    raise InvalidControlPlaneInput("case reviewed lineage hash is invalid")
            if source_kind == "reviewed_full_scan":
                if source_tool is None:
                    raise InvalidControlPlaneInput(
                        "reviewed full-scan lineage requires security-tool provenance"
                    )
            elif source_tool is not None:
                raise InvalidControlPlaneInput(
                    "non-tool reviewed source kind cannot carry security-tool provenance"
                )
        identity = f"m1d-attempt:v1\0{run_id}\0{ordinal}\0{case_id}"
        attempt_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"campaign-attempt:{run_id}:{ordinal}")
            run = (
                connection.execute(
                    text("SELECT organization_id FROM campaign_runs WHERE run_id = :run_id"),
                    {"run_id": run_id},
                )
                .mappings()
                .one_or_none()
            )
            if run is None:
                raise RecordNotFoundError("campaign run does not exist")
            existing = (
                connection.execute(
                    text(
                        "SELECT * FROM campaign_attempts WHERE organization_id = :org "
                        "AND run_id = :run_id AND ordinal = :ordinal"
                    ),
                    {"org": run["organization_id"], "run_id": run_id, "ordinal": ordinal},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                if existing["case_id"] != case_id or existing["attempt_id"] != attempt_id:
                    raise RecordConflictError(
                        "attempt ordinal already names different immutable work"
                    )
                if metadata_supplied and (
                    existing["case_content_hash"] != case_content_hash
                    or existing["category"] != category
                    or existing["severity"] != severity
                    or existing["attack_class"] != attack_class
                    or existing["owasp_mappings"] != normalized_mappings
                    or existing["fixture_provenance"] != normalized_fixture
                    or existing["source_tool"] != source_tool
                    or existing["source_technique"] != source_technique
                ):
                    raise RecordConflictError("attempt metadata differs from immutable case")
                # Reviewed-workload lineage is compared on its own so an idempotent replay cannot
                # quietly re-attribute an already-persisted attempt to a different producer,
                # review record, or generation record.
                if (
                    existing["source_kind"] != source_kind
                    or existing["workload_instance_id"] != workload_instance_id
                    or existing["review_record_sha256"] != review_record_sha256
                    or existing["source_generation_sha256"] != source_generation_sha256
                ):
                    raise RecordConflictError(
                        "attempt reviewed-workload lineage differs from immutable case"
                    )
                return self._campaign_attempt_from_row(existing)
            row = (
                connection.execute(
                    text(
                        "INSERT INTO campaign_attempts "
                        "(organization_id, run_id, attempt_id, ordinal, case_id, "
                        "case_content_hash, category, severity, attack_class, owasp_mappings, "
                        "fixture_provenance, source_tool, source_technique, source_kind, "
                        "workload_instance_id, review_record_sha256, source_generation_sha256) "
                        "VALUES "
                        "(:org, :run_id, :attempt_id, :ordinal, :case_id, :case_hash, :category, "
                        ":severity, :attack_class, CAST(:owasp AS jsonb), CAST(:fixture AS jsonb), "
                        ":source_tool, :source_technique, :source_kind, :workload_instance_id, "
                        ":review_record_sha256, :source_generation_sha256) "
                        "RETURNING *"
                    ),
                    {
                        "org": run["organization_id"],
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                        "ordinal": ordinal,
                        "case_id": case_id,
                        "case_hash": case_content_hash,
                        "category": category,
                        "severity": severity,
                        "attack_class": attack_class,
                        "owasp": canonical_json(normalized_mappings)
                        if normalized_mappings is not None
                        else None,
                        "fixture": canonical_json(normalized_fixture)
                        if normalized_fixture is not None
                        else None,
                        "source_tool": source_tool,
                        "source_technique": source_technique,
                        "source_kind": source_kind,
                        "workload_instance_id": workload_instance_id,
                        "review_record_sha256": review_record_sha256,
                        "source_generation_sha256": source_generation_sha256,
                    },
                )
                .mappings()
                .one()
            )
            return self._campaign_attempt_from_row(row)

    def resolve_dispatch(self, run_id: str, attempt_id: str) -> AuthorizedRunRecord:
        """Reconstruct exact authority from persisted state immediately before dispatch."""

        authorized = self.load_run_for_execution(run_id)
        with self._engine.connect() as connection:
            attempt = connection.execute(
                text(
                    "SELECT 1 FROM campaign_attempts WHERE organization_id = :org "
                    "AND run_id = :run_id AND attempt_id = :attempt_id"
                ),
                {
                    "org": authorized.run.organization_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                },
            ).scalar_one_or_none()
            if attempt is None:
                raise AuthorizationDeniedError("persisted campaign attempt is unavailable")
            prior = connection.execute(
                text(
                    "SELECT 1 FROM attempt_result WHERE organization_id = :org "
                    "AND campaign_run_id = :run_id AND attempt_id = :attempt_id"
                ),
                {
                    "org": authorized.run.organization_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                },
            ).scalar_one_or_none()
            if prior is not None:
                raise AuthorizationDeniedError("campaign attempt evidence already exists")
        return authorized

    def assert_job_lease(self, job: Any) -> None:
        """Reject stale or mismatched Runner ownership using database time."""

        with self._engine.connect() as connection:
            owned = connection.execute(
                text(
                    "SELECT 1 FROM jobs WHERE job_id = :job_id "
                    "AND status = 'leased'::job_status AND worker_id = :worker "
                    "AND lease_token = :token AND lease_expires_at > clock_timestamp()"
                ),
                {
                    "job_id": getattr(job, "job_id", None),
                    "worker": getattr(job, "worker_id", None),
                    "token": getattr(job, "lease_token", None),
                },
            ).scalar_one_or_none()
        if owned is None:
            raise AuthorizationDeniedError("runner lease ownership is stale")

    def reserve_campaign_work_unit(
        self,
        *,
        job: Any,
        attempt_id: str,
        turn_index: int,
        retry_index: int,
    ) -> CampaignWorkUnitReservationRecord:
        """Reserve one physical target send under the caller's live queue lease.

        The job row is locked while duplicate and run-wide limit checks execute, making admission
        and insertion one transaction.  Reservations survive worker restart and lease reclaim;
        the same coordinate is therefore never silently replayed.
        """

        self._validate_work_unit_coordinate(attempt_id, turn_index, retry_index)
        run_id = str(getattr(job, "campaign_run_id", ""))
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"campaign-work-units:{run_id}")
            context = self._locked_work_unit_context(connection, job)
            if context["campaign_run_id"] != run_id:
                raise AuthorizationDeniedError("campaign queue job does not own this run")
            if context["run_state"] != "running":
                raise AuthorizationDeniedError("campaign run is not accepting physical work")

            scope = scope_from_payload(dict(context["scope_payload"]))
            if scope.scope_hash() != context["scope_hash"]:
                raise AuthorizationDeniedError("campaign work-unit scope integrity failed")
            self._validate_scope(connection, context["organization_id"], scope)
            physical_limit = scope.caps.physical_request_limit
            if physical_limit is None:
                raise AuthorizationDeniedError(
                    "campaign scope has no durable physical work-unit limit"
                )
            retry_limit = scope.caps.target_retries_per_turn
            if retry_limit is None:
                raise AuthorizationDeniedError("campaign scope has no durable per-turn retry limit")
            if retry_index > retry_limit:
                raise AuthorizationDeniedError(
                    "campaign physical work-unit exceeds its per-turn retry limit"
                )

            attempt_exists = connection.execute(
                text(
                    "SELECT 1 FROM campaign_attempts WHERE organization_id = :org "
                    "AND run_id = :run_id AND attempt_id = :attempt_id"
                ),
                {
                    "org": context["organization_id"],
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                },
            ).scalar_one_or_none()
            if attempt_exists is None:
                raise AuthorizationDeniedError("campaign work-unit attempt is unavailable")

            duplicate = connection.execute(
                text(
                    "SELECT 1 FROM campaign_work_unit_reservations "
                    "WHERE run_id = :run_id AND attempt_id = :attempt_id "
                    "AND turn_index = :turn_index AND retry_index = :retry_index"
                ),
                {
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "turn_index": turn_index,
                    "retry_index": retry_index,
                },
            ).scalar_one_or_none()
            if duplicate is not None:
                raise RecordConflictError("campaign physical work-unit is already reserved")

            reserved_count = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM campaign_work_unit_reservations "
                        "WHERE run_id = :run_id"
                    ),
                    {"run_id": run_id},
                ).scalar_one()
            )
            if reserved_count >= physical_limit:
                raise AuthorizationDeniedError(
                    "campaign physical work-unit limit is already exhausted"
                )

            lease_hash = self._work_unit_lease_hash(context["lease_token"])
            row = (
                connection.execute(
                    text(
                        "INSERT INTO campaign_work_unit_reservations "
                        "(organization_id, run_id, attempt_id, turn_index, retry_index, job_id, "
                        "job_attempt, worker_id, lease_token_sha256) VALUES "
                        "(:org, :run_id, :attempt_id, :turn_index, :retry_index, :job_id, "
                        ":job_attempt, :worker_id, :lease_hash) RETURNING *"
                    ),
                    {
                        "org": context["organization_id"],
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                        "turn_index": turn_index,
                        "retry_index": retry_index,
                        "job_id": context["job_id"],
                        "job_attempt": context["attempts"],
                        "worker_id": context["worker_id"],
                        "lease_hash": lease_hash,
                    },
                )
                .mappings()
                .one()
            )
            return self._work_unit_reservation_from_row(row)

    def observe_campaign_work_unit(
        self,
        *,
        job: Any,
        attempt_id: str,
        turn_index: int,
        retry_index: int,
        outcome: str,
    ) -> CampaignWorkUnitReservationRecord:
        """Mark a reserved send observed once adapter control returns or raises.

        Only the exact queue claim that created the reservation may mark it.  If the lease is lost
        before this transaction, the reservation stays ambiguous and completion fails closed.
        """

        self._validate_work_unit_coordinate(attempt_id, turn_index, retry_index)
        if outcome not in {"returned", "raised"}:
            raise InvalidControlPlaneInput("campaign work-unit outcome is invalid")
        run_id = str(getattr(job, "campaign_run_id", ""))
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"campaign-work-units:{run_id}")
            context = self._locked_work_unit_context(connection, job)
            if context["campaign_run_id"] != run_id:
                raise AuthorizationDeniedError("campaign queue job does not own this run")
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM campaign_work_unit_reservations "
                        "WHERE run_id = :run_id AND attempt_id = :attempt_id "
                        "AND turn_index = :turn_index AND retry_index = :retry_index FOR UPDATE"
                    ),
                    {
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                        "turn_index": turn_index,
                        "retry_index": retry_index,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("campaign physical work-unit reservation does not exist")
            if (
                row["job_id"] != context["job_id"]
                or row["job_attempt"] != context["attempts"]
                or row["worker_id"] != context["worker_id"]
                or row["lease_token_sha256"] != self._work_unit_lease_hash(context["lease_token"])
            ):
                raise AuthorizationDeniedError(
                    "campaign physical work-unit belongs to a different queue claim"
                )
            if row["observed_at"] is not None:
                if row["observation_outcome"] != outcome:
                    raise RecordConflictError(
                        "campaign physical work-unit observation is immutable"
                    )
                return self._work_unit_reservation_from_row(row)
            observed = (
                connection.execute(
                    text(
                        "UPDATE campaign_work_unit_reservations "
                        "SET observed_at = clock_timestamp(), observation_outcome = :outcome "
                        "WHERE run_id = :run_id AND attempt_id = :attempt_id "
                        "AND turn_index = :turn_index AND retry_index = :retry_index "
                        "AND observed_at IS NULL RETURNING *"
                    ),
                    {
                        "outcome": outcome,
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                        "turn_index": turn_index,
                        "retry_index": retry_index,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if observed is None:
                raise RecordConflictError("campaign physical work-unit observation was lost")
            return self._work_unit_reservation_from_row(observed)

    def configure_agent(
        self,
        *,
        principal: Principal,
        agent_role: str,
        provider: str,
        model: str,
        execution_mode: str,
        rationale: str,
        idempotency_key: str,
    ) -> AgentAssignment:
        """Append one validated role assignment; unsafe hosted choices remain staged."""

        self._require_permission(principal, CONFIG_MANAGE)
        if (
            not isinstance(rationale, str)
            or not rationale.strip()
            or len(rationale) > _RATIONALE_MAX_LENGTH
            or self._contains_secret(rationale)
        ):
            raise InvalidControlPlaneInput("agent configuration rationale is invalid")
        (
            role,
            normalized_provider,
            normalized_model,
            normalized_mode,
            activation_state,
            digest,
        ) = validate_agent_configuration(
            role=agent_role,
            provider=provider,
            model=model,
            execution_mode=execution_mode,
        )
        document = {
            "agent_role": role,
            "provider": normalized_provider,
            "model": normalized_model,
            "execution_mode": normalized_mode,
            "activation_state": activation_state,
            "configuration_sha256": digest,
            "rationale": rationale.strip(),
        }
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection,
                principal,
                "agent.configure",
                idempotency_key,
                document,
            )
            if existing is not None:
                return self._agent_assignment(
                    connection,
                    principal.organization_id,
                    role,
                    version=int(existing["version"]),
                )
            self._aggregate_lock(
                connection,
                f"agent-configuration:{principal.organization_id}:{role}",
            )
            version = int(
                connection.execute(
                    text(
                        "SELECT coalesce(max(version), 0) + 1 "
                        "FROM agent_configuration_versions "
                        "WHERE organization_id = :org AND agent_role = :role"
                    ),
                    {"org": principal.organization_id, "role": role},
                ).scalar_one()
            )
            connection.execute(
                text(
                    "INSERT INTO agent_configuration_versions "
                    "(organization_id, agent_role, version, provider, model, execution_mode, "
                    "activation_state, configuration_sha256, rationale, actor_user_id, "
                    "actor_session_id) VALUES "
                    "(:org, :role, :version, :provider, :model, :mode, :activation, :hash, "
                    ":rationale, :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "role": role,
                    "version": version,
                    "provider": normalized_provider,
                    "model": normalized_model,
                    "mode": normalized_mode,
                    "activation": activation_state,
                    "hash": digest,
                    "rationale": rationale.strip(),
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._audit(
                connection,
                principal.organization_id,
                "agent.configuration_published"
                if activation_state == "active"
                else "agent.configuration_staged",
                "agent",
                role,
                principal,
                {
                    "version": version,
                    "provider": normalized_provider,
                    "model": normalized_model,
                    "execution_mode": normalized_mode,
                    "activation_state": activation_state,
                    "configuration_sha256": digest,
                },
            )
            response = {"agent_role": role, "version": version}
            self._finish_command(
                connection,
                principal,
                "agent.configure",
                idempotency_key,
                request_hash,
                response,
            )
            return self._agent_assignment(
                connection,
                principal.organization_id,
                role,
                version=version,
            )

    def stage_hosted_configuration_set(
        self,
        *,
        principal: Principal,
        configuration: HostedConfigurationSet,
        release_sha256: str,
        rationale: str,
        idempotency_key: str,
    ) -> str:
        """Atomically append all four hosted role authorities as one content-addressed row."""

        self._require_permission(principal, CONFIG_MANAGE)
        validate_hosted_configuration_set(configuration)
        if not isinstance(release_sha256, str) or _SHA256.fullmatch(release_sha256) is None:
            raise InvalidControlPlaneInput("hosted configuration release hash is invalid")
        safe_rationale = self._sanitize_plaintext_rationale(rationale)
        document = {
            "configuration": configuration.canonical_payload(),
            "configuration_sha256": configuration.configuration_sha256,
            "release_sha256": release_sha256,
            "rationale": safe_rationale,
        }
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection,
                principal,
                "hosted-configuration-set.stage",
                idempotency_key,
                document,
            )
            if existing is not None:
                return str(existing["configuration_sha256"])
            self._aggregate_lock(
                connection,
                f"hosted-configuration-set:{principal.organization_id}",
            )
            prior = connection.execute(
                text(
                    "SELECT configuration_sha256 FROM hosted_configuration_sets "
                    "WHERE organization_id = :org "
                    "AND (configuration_sha256 = :configuration OR release_sha256 = :release)"
                ),
                {
                    "org": principal.organization_id,
                    "configuration": configuration.configuration_sha256,
                    "release": release_sha256,
                },
            ).scalar_one_or_none()
            if prior is not None:
                raise RecordConflictError(
                    "hosted configuration or application release is already staged"
                )
            connection.execute(
                text(
                    "INSERT INTO hosted_configuration_sets "
                    "(organization_id, configuration_sha256, schema_version, release_sha256, "
                    "payload, rationale, actor_user_id, actor_session_id) VALUES "
                    "(:org, :configuration, :schema, :release, CAST(:payload AS jsonb), "
                    ":rationale, :user, :session)"
                ),
                {
                    "org": principal.organization_id,
                    "configuration": configuration.configuration_sha256,
                    "schema": configuration.schema_version,
                    "release": release_sha256,
                    "payload": configuration.canonical_bytes().decode("utf-8"),
                    "rationale": safe_rationale,
                    "user": principal.user_id,
                    "session": principal.session_id,
                },
            )
            self._audit(
                connection,
                principal.organization_id,
                "hosted_configuration_set.staged",
                "hosted_configuration_set",
                configuration.configuration_sha256,
                principal,
                {
                    "configuration_sha256": configuration.configuration_sha256,
                    "release_sha256": release_sha256,
                    "role_count": len(configuration.roles),
                    "activation_state": "staged_pending_authorization",
                },
            )
            response = {"configuration_sha256": configuration.configuration_sha256}
            self._finish_command(
                connection,
                principal,
                "hosted-configuration-set.stage",
                idempotency_key,
                request_hash,
                response,
            )
            return configuration.configuration_sha256

    def create_agent_acceptance_run(
        self,
        *,
        organization_id: str,
        configuration_set_sha256: str,
        generation_policy_sha256: str,
        acceptance_context: Mapping[str, Any],
        expires_at: datetime.datetime,
        limits: Mapping[str, Any],
        acceptance_actor_id: str = _AGENT_ACCEPTANCE_ACTOR_ID,
    ) -> AgentAcceptanceRunIdentity:
        """Create one short-lived zero-target run and its singleton attempt atomically.

        The four-role configuration must already have crossed the human CONFIG_MANAGE gate.
        New authority always derives the fixed four-call v2 sub-envelope without staging or
        substituting configuration. Populated v1 rows remain readable and completable, but this
        method cannot mint another legacy three-call authority.
        """

        if not isinstance(organization_id, str) or not organization_id or len(organization_id) > 64:
            raise InvalidControlPlaneInput("acceptance organization identity is invalid")
        if (
            not isinstance(configuration_set_sha256, str)
            or _SHA256.fullmatch(configuration_set_sha256) is None
        ):
            raise InvalidControlPlaneInput("acceptance configuration hash is invalid")
        if (
            not isinstance(generation_policy_sha256, str)
            or _SHA256.fullmatch(generation_policy_sha256) is None
        ):
            raise InvalidControlPlaneInput("acceptance generation policy hash is invalid")
        context_sha256 = self._agent_payload_sha256(
            acceptance_context,
            label="agent acceptance context",
        )
        supplied_limits = self._bounded_agent_payload(
            limits,
            label="agent acceptance limits",
        )
        if (
            not isinstance(acceptance_actor_id, str)
            or _AGENT_ACCEPTANCE_ACTOR.fullmatch(acceptance_actor_id) is None
        ):
            raise InvalidControlPlaneInput(
                "agent acceptance actor must be a non-human system identity"
            )
        if (
            not isinstance(expires_at, datetime.datetime)
            or expires_at.tzinfo is None
            or expires_at.utcoffset() is None
        ):
            raise InvalidControlPlaneInput("agent acceptance expiry must be timezone-aware")
        normalized_expiry = expires_at.astimezone(datetime.UTC)
        now = datetime.datetime.now(datetime.UTC)
        if normalized_expiry <= now or normalized_expiry > now + _AGENT_ACCEPTANCE_MAX_LIFETIME:
            raise AuthorizationDeniedError("agent acceptance expiry is outside the closed lifetime")

        run_id = f"AR-{uuid.uuid4().hex}"
        attempt_id = hashlib.sha256(
            f"m1d-attempt:v1\0{run_id}\0{0}\0{_AGENT_ACCEPTANCE_CASE_ID}".encode()
        ).hexdigest()
        with self._engine.begin() as connection:
            self._aggregate_lock(
                connection,
                f"agent-acceptance-create:{organization_id}",
            )
            try:
                configuration = self._stored_hosted_configuration(
                    connection,
                    organization_id=organization_id,
                    configuration_sha256=configuration_set_sha256,
                )
            except (AuthorizationDeniedError, RecordNotFoundError) as exc:
                raise AuthorizationDeniedError(
                    "agent acceptance requires an existing human-staged configuration"
                ) from exc
            expected_limits = canonical_agent_acceptance_limits(configuration)
            if expected_limits["schema_version"] != "2":
                raise AuthorizationDeniedError(
                    "new agent acceptance requires the closed four-call runtime envelope"
                )
            if supplied_limits != expected_limits:
                raise AuthorizationDeniedError(
                    "agent acceptance limits differ from the closed runtime envelope"
                )

            connection.execute(
                text(
                    "INSERT INTO campaign_runs "
                    "(run_id, organization_id, authorization_request_id, scope_hash, "
                    "launcher_user_id, launcher_session_id, run_kind, "
                    "acceptance_configuration_sha256, "
                    "acceptance_generation_policy_sha256, acceptance_context_sha256, "
                    "acceptance_attempt_id, acceptance_limits, acceptance_expires_at, "
                    "acceptance_actor_id, acceptance_provenance) VALUES "
                    "(:run_id, :org, NULL, NULL, NULL, NULL, 'agent_acceptance', "
                    ":configuration, :generation_policy, :context, :attempt, "
                    "CAST(:limits AS jsonb), :expires_at, :actor, CAST(:provenance AS jsonb))"
                ),
                {
                    "run_id": run_id,
                    "org": organization_id,
                    "configuration": configuration.configuration_sha256,
                    "generation_policy": generation_policy_sha256,
                    "context": context_sha256,
                    "attempt": attempt_id,
                    "limits": canonical_json(expected_limits),
                    "expires_at": normalized_expiry,
                    "actor": acceptance_actor_id,
                    "provenance": canonical_json(_AGENT_ACCEPTANCE_PROVENANCE),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_attempts "
                    "(organization_id, run_id, attempt_id, ordinal, case_id, "
                    "case_content_hash, category, severity, attack_class, owasp_mappings, "
                    "fixture_provenance, source_tool, source_technique) VALUES "
                    "(:org, :run_id, :attempt, 0, :case_id, :context, "
                    "NULL, NULL, NULL, NULL, CAST(:fixture AS jsonb), NULL, NULL)"
                ),
                {
                    "org": organization_id,
                    "run_id": run_id,
                    "attempt": attempt_id,
                    "case_id": _AGENT_ACCEPTANCE_CASE_ID,
                    "context": context_sha256,
                    "fixture": canonical_json(_AGENT_ACCEPTANCE_FIXTURE),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id) "
                    "VALUES (:org, :run_id, 'running', :actor, :session)"
                ),
                {
                    "org": organization_id,
                    "run_id": run_id,
                    "actor": acceptance_actor_id,
                    "session": "runner:live-acceptance",
                },
            )
            self._audit(
                connection,
                organization_id,
                "agent_acceptance.started",
                "campaign_run",
                run_id,
                None,
                {
                    "run_kind": "agent_acceptance",
                    "attempt_id": attempt_id,
                    "configuration_set_sha256": configuration.configuration_sha256,
                    "generation_policy_sha256": generation_policy_sha256,
                    "acceptance_context_sha256": context_sha256,
                    "acceptance_limits": expected_limits,
                    "network_scope": "openrouter_langfuse_only",
                    "target_call_limit": 0,
                    "expires_at": normalized_expiry.isoformat(),
                },
                actor_user_id=acceptance_actor_id,
                actor_session_id="runner:live-acceptance",
            )
        return AgentAcceptanceRunIdentity(run_id=run_id, attempt_id=attempt_id)

    def load_hosted_configuration_set(
        self,
        *,
        organization_id: str,
        configuration_set_sha256: str,
        release_sha256: str,
    ) -> HostedConfigurationSet:
        """Load one exact CONFIG_MANAGE-staged four-role set for one reviewed release."""

        if (
            not isinstance(organization_id, str)
            or not organization_id
            or len(organization_id) > 64
            or not isinstance(configuration_set_sha256, str)
            or _SHA256.fullmatch(configuration_set_sha256) is None
            or not isinstance(release_sha256, str)
            or _SHA256.fullmatch(release_sha256) is None
        ):
            raise InvalidControlPlaneInput("hosted configuration identity is invalid")
        with self._engine.connect() as connection:
            return self._stored_hosted_configuration(
                connection,
                organization_id=organization_id,
                configuration_sha256=configuration_set_sha256,
                expected_release_sha256=release_sha256,
            )

    def load_acceptance_role_for_execution(
        self,
        *,
        run_id: str,
        agent_role: AgentRole,
    ) -> AuthorizedAgentAcceptanceRoleConfiguration:
        """Resolve one still-live role from a system acceptance run."""

        with self._engine.connect() as connection:
            return self._authorized_agent_acceptance_role(
                connection,
                run_id=run_id,
                agent_role=agent_role,
            )

    def active_agent_assignment(self, *, organization_id: str, agent_role: str) -> AgentAssignment:
        """Return the latest active assignment or the code-owned deterministic default."""

        default = default_assignment(agent_role)
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM agent_configuration_versions "
                        "WHERE organization_id = :org AND agent_role = :role "
                        "AND activation_state = 'active' ORDER BY version DESC LIMIT 1"
                    ),
                    {"org": organization_id, "role": default.role},
                )
                .mappings()
                .one_or_none()
            )
        return default if row is None else self._agent_assignment_from_row(row)

    def load_hosted_role_for_execution(
        self,
        *,
        run_id: str,
        agent_role: AgentRole,
    ) -> AuthorizedHostedRoleConfiguration:
        """Resolve an exact role only from a still-live, human-approved four-role run binding."""

        with self._engine.connect() as connection:
            return self._authorized_hosted_role(
                connection,
                run_id=run_id,
                agent_role=agent_role,
            )

    def start_hosted_agent_execution(
        self,
        *,
        run_id: str,
        agent_role: AgentRole,
        input_payload: Mapping[str, Any],
        provider: str,
        model: str,
        upstream_provider: str,
        configuration_set_sha256: str,
        role_configuration_sha256: str,
        generation_policy_sha256: str,
        judge_calibration_id: str | None = None,
        judge_calibration_state: str | None = None,
        attempt_id: str | None = None,
        parent_execution_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        system_prompt_version: str | None = None,
        system_prompt_sha256: str | None = None,
        system_prompt_content: str | None = None,
        provider_messages: Sequence[Mapping[str, Any]] | None = None,
        prompt_redactions: Sequence[Mapping[str, Any]] = (),
    ) -> str:
        """Start one hosted call after re-resolving every identity from its approved run.

        The exact credential-free provider transcript is retained in a separate protected,
        immutable snapshot. It is born in the same transaction as this logical execution and is
        never projected into outbound telemetry.
        """

        if agent_role not in AGENT_ROLES:
            raise InvalidControlPlaneInput("hosted agent role is invalid")
        self._validate_judge_calibration_lineage(
            agent_role=agent_role,
            calibration_id=judge_calibration_id,
            calibration_state=judge_calibration_state,
        )
        input_sha256 = self._agent_payload_sha256(
            input_payload,
            label="hosted agent input",
        )
        sanitized_detail = self._bounded_agent_payload(
            detail or {},
            label="hosted agent detail",
        )
        if "provider_lineage_state" in sanitized_detail:
            raise InvalidControlPlaneInput("provider lineage state is server-owned")
        sanitized_detail["telemetry_contract"] = "hosted-agent-execution-v1"
        sanitized_detail["provider_lineage_state"] = "canonical_physical"
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"hosted-agent-execution:{run_id}")
            authority = self._authorized_hosted_role(
                connection,
                run_id=run_id,
                agent_role=agent_role,
            )
            role = authority.role_configuration
            binding = authority.authorization
            if (
                provider != role.provider
                or model != role.model_id
                or upstream_provider != role.upstream_provider
                or configuration_set_sha256 != authority.configuration.configuration_sha256
                or role_configuration_sha256 != role.configuration_sha256
                or generation_policy_sha256 != binding.generation_policy_sha256
            ):
                raise AuthorizationDeniedError(
                    "hosted execution identity differs from the approved run binding"
                )
            self._validate_agent_parent(
                connection,
                organization_id=authority.organization_id,
                run_id=run_id,
                parent_execution_id=parent_execution_id,
            )
            execution_id = uuid.uuid4().hex
            trace_id = campaign_trace_id(run_id)
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, provider, model, execution_mode, "
                    "configuration_version, input_sha256, trace_id, detail, "
                    "configuration_set_sha256, role_configuration_sha256, "
                    "generation_policy_sha256, judge_calibration_id, "
                    "judge_calibration_state) VALUES "
                    "(:execution, :org, :run_id, :attempt_id, :parent, :role, :provider, "
                    ":model, 'hosted_advisory', :version, :input_hash, :trace_id, "
                    "CAST(:detail AS jsonb), :configuration, :role_configuration, "
                    ":generation_policy, :calibration_id, :calibration_state)"
                ),
                {
                    "execution": execution_id,
                    "org": authority.organization_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "parent": parent_execution_id,
                    "role": role.role,
                    "provider": role.provider,
                    "model": role.model_id,
                    "version": int(authority.configuration.schema_version),
                    "input_hash": input_sha256,
                    "trace_id": trace_id,
                    "detail": canonical_json(sanitized_detail),
                    "configuration": authority.configuration.configuration_sha256,
                    "role_configuration": role.configuration_sha256,
                    "generation_policy": binding.generation_policy_sha256,
                    "calibration_id": judge_calibration_id,
                    "calibration_state": judge_calibration_state,
                },
            )
            self._insert_agent_prompt_snapshot(
                connection,
                organization_id=authority.organization_id,
                execution_id=execution_id,
                campaign_run_id=run_id,
                attempt_id=attempt_id,
                agent_role=role.role,
                input_payload=input_payload,
                authorized_prompt_sha256=role.prompt_sha256,
                system_prompt_version=system_prompt_version,
                system_prompt_sha256=system_prompt_sha256,
                system_prompt_content=system_prompt_content,
                provider_messages=provider_messages,
                redactions=prompt_redactions,
            )
            self._audit(
                connection,
                authority.organization_id,
                "agent.started",
                "agent_execution",
                execution_id,
                None,
                {
                    "campaign_run_id": run_id,
                    "attempt_id": attempt_id,
                    "parent_execution_id": parent_execution_id,
                    "agent_role": role.role,
                    "provider": role.provider,
                    "requested_model": role.model_id,
                    "requested_upstream_provider": role.upstream_provider,
                    "execution_mode": "hosted_advisory",
                    "configuration_set_sha256": authority.configuration.configuration_sha256,
                    "role_configuration_sha256": role.configuration_sha256,
                    "generation_policy_sha256": binding.generation_policy_sha256,
                    "judge_calibration_id": judge_calibration_id,
                    "judge_calibration_state": judge_calibration_state,
                    "input_sha256": input_sha256,
                    "trace_id": trace_id,
                },
                actor_user_id=f"agent:{role.role}",
                actor_session_id="runner:system",
            )
            return execution_id

    def start_acceptance_agent_execution(
        self,
        *,
        run_id: str,
        agent_role: AgentRole,
        input_payload: Mapping[str, Any],
        provider: str,
        model: str,
        upstream_provider: str,
        configuration_set_sha256: str,
        role_configuration_sha256: str,
        generation_policy_sha256: str,
        judge_calibration_id: str | None = None,
        judge_calibration_state: str | None = None,
        parent_execution_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        system_prompt_version: str | None = None,
        system_prompt_sha256: str | None = None,
        system_prompt_content: str | None = None,
        provider_messages: Sequence[Mapping[str, Any]] | None = None,
        prompt_redactions: Sequence[Mapping[str, Any]] = (),
    ) -> str:
        """Start one logical call under the zero-target acceptance authority."""

        if agent_role not in _AGENT_ACCEPTANCE_ROLES:
            raise AuthorizationDeniedError("agent role is outside the live-acceptance allowlist")
        if agent_role == "judge" and judge_calibration_state != "failed":
            raise AuthorizationDeniedError(
                "agent acceptance Judge must start with failed calibration"
            )
        self._validate_judge_calibration_lineage(
            agent_role=agent_role,
            calibration_id=judge_calibration_id,
            calibration_state=judge_calibration_state,
        )
        input_sha256 = self._agent_payload_sha256(
            input_payload,
            label="agent acceptance input",
        )
        sanitized_detail = self._bounded_agent_payload(
            detail or {},
            label="agent acceptance detail",
        )
        if "provider_lineage_state" in sanitized_detail:
            raise InvalidControlPlaneInput("provider lineage state is server-owned")
        sanitized_detail.update(
            {
                "acceptance_id": run_id,
                "run_kind": "agent_acceptance",
                "telemetry_contract": "hosted-agent-execution-v1",
                "provider_lineage_state": "canonical_physical",
            }
        )
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"agent-acceptance:{run_id}")
            authority = self._authorized_agent_acceptance_role(
                connection,
                run_id=run_id,
                agent_role=agent_role,
                for_update=True,
            )
            role = authority.role_configuration
            if (
                provider != role.provider
                or model != role.model_id
                or upstream_provider != role.upstream_provider
                or configuration_set_sha256 != authority.configuration.configuration_sha256
                or role_configuration_sha256 != role.configuration_sha256
                or generation_policy_sha256 != authority.generation_policy_sha256
            ):
                raise AuthorizationDeniedError(
                    "hosted execution identity differs from the acceptance authority"
                )
            self._assert_agent_acceptance_has_no_target_traffic(
                connection,
                organization_id=authority.organization_id,
                run_id=run_id,
            )
            self._assert_agent_acceptance_call_available(
                connection,
                authority=authority,
            )
            self._validate_acceptance_parent(
                connection,
                authority=authority,
                agent_role=agent_role,
                parent_execution_id=parent_execution_id,
            )
            prior = connection.execute(
                text(
                    "SELECT count(*) FROM agent_executions "
                    "WHERE organization_id = :org AND campaign_run_id = :run "
                    "AND agent_role = :role"
                ),
                {
                    "org": authority.organization_id,
                    "run": run_id,
                    "role": agent_role,
                },
            ).scalar_one()
            if prior:
                raise RecordConflictError("acceptance role already has a logical execution")

            execution_id = uuid.uuid4().hex
            trace_id = campaign_trace_id(run_id)
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, provider, model, execution_mode, "
                    "configuration_version, input_sha256, trace_id, detail, "
                    "configuration_set_sha256, role_configuration_sha256, "
                    "generation_policy_sha256, judge_calibration_id, "
                    "judge_calibration_state) VALUES "
                    "(:execution, :org, :run_id, :attempt, :parent, :role, :provider, "
                    ":model, 'hosted_advisory', :version, :input_hash, :trace_id, "
                    "CAST(:detail AS jsonb), :configuration, :role_configuration, "
                    ":generation_policy, :calibration_id, :calibration_state)"
                ),
                {
                    "execution": execution_id,
                    "org": authority.organization_id,
                    "run_id": run_id,
                    "attempt": authority.acceptance_attempt_id,
                    "parent": parent_execution_id,
                    "role": role.role,
                    "provider": role.provider,
                    "model": role.model_id,
                    "version": int(authority.configuration.schema_version),
                    "input_hash": input_sha256,
                    "trace_id": trace_id,
                    "detail": canonical_json(sanitized_detail),
                    "configuration": authority.configuration.configuration_sha256,
                    "role_configuration": role.configuration_sha256,
                    "generation_policy": authority.generation_policy_sha256,
                    "calibration_id": judge_calibration_id,
                    "calibration_state": judge_calibration_state,
                },
            )
            self._insert_agent_prompt_snapshot(
                connection,
                organization_id=authority.organization_id,
                execution_id=execution_id,
                campaign_run_id=run_id,
                attempt_id=authority.acceptance_attempt_id,
                agent_role=role.role,
                input_payload=input_payload,
                authorized_prompt_sha256=role.prompt_sha256,
                system_prompt_version=system_prompt_version,
                system_prompt_sha256=system_prompt_sha256,
                system_prompt_content=system_prompt_content,
                provider_messages=provider_messages,
                redactions=prompt_redactions,
            )
            self._audit(
                connection,
                authority.organization_id,
                "agent.started",
                "agent_execution",
                execution_id,
                None,
                {
                    "acceptance_id": run_id,
                    "run_kind": "agent_acceptance",
                    "attempt_id": authority.acceptance_attempt_id,
                    "parent_execution_id": parent_execution_id,
                    "agent_role": role.role,
                    "provider": role.provider,
                    "requested_model": role.model_id,
                    "requested_upstream_provider": role.upstream_provider,
                    "execution_mode": "hosted_advisory",
                    "configuration_set_sha256": authority.configuration.configuration_sha256,
                    "role_configuration_sha256": role.configuration_sha256,
                    "generation_policy_sha256": authority.generation_policy_sha256,
                    "judge_calibration_id": judge_calibration_id,
                    "judge_calibration_state": judge_calibration_state,
                    "input_sha256": input_sha256,
                    "trace_id": trace_id,
                    "network_scope": "openrouter_langfuse_only",
                },
                actor_user_id=f"agent:{role.role}",
                actor_session_id="runner:live-acceptance",
            )
            return execution_id

    def complete_agent_acceptance_run(self, *, run_id: str) -> str:
        """Close a successful versioned acceptance after exact calls and zero target I/O."""

        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"agent-acceptance:{run_id}")
            row = self._agent_acceptance_run_row(
                connection,
                run_id=run_id,
                for_update=True,
            )
            self._assert_agent_acceptance_has_no_target_traffic(
                connection,
                organization_id=str(row["organization_id"]),
                run_id=run_id,
            )
            if row["state"] == "complete":
                return run_id
            if row["state"] != "running":
                raise RecordConflictError("agent acceptance run is no longer completable")
            if not row["acceptance_live"]:
                raise AuthorizationDeniedError("agent acceptance authority has expired")
            limits = self._agent_acceptance_limits_from_row(row)
            acceptance_roles = _agent_acceptance_roles_for_version(str(limits["schema_version"]))
            attempts = (
                connection.execute(
                    text(
                        "SELECT attempt_id, ordinal, case_id FROM campaign_attempts "
                        "WHERE organization_id = :org AND run_id = :run ORDER BY ordinal"
                    ),
                    {"org": row["organization_id"], "run": run_id},
                )
                .mappings()
                .all()
            )
            if (
                len(attempts) != 1
                or attempts[0]["attempt_id"] != row["acceptance_attempt_id"]
                or attempts[0]["ordinal"] != 0
                or attempts[0]["case_id"] != _AGENT_ACCEPTANCE_CASE_ID
            ):
                raise RecordConflictError(
                    "agent acceptance completion requires its singleton synthetic attempt"
                )
            executions = (
                connection.execute(
                    text(
                        "SELECT execution_id, agent_role, attempt_id, status, "
                        "returned_model, upstream_provider, provider_request_id, "
                        "input_tokens, output_tokens, reasoning_tokens, "
                        "cost_measurement_state, measured_cost, provider_event_ids, "
                        "physical_attempts, judge_calibration_id, "
                        "judge_calibration_state, oracle_agreement, decision_authority "
                        "FROM agent_executions "
                        "WHERE organization_id = :org AND campaign_run_id = :run "
                        "ORDER BY id"
                    ),
                    {
                        "org": row["organization_id"],
                        "run": run_id,
                    },
                )
                .mappings()
                .all()
            )
            if (
                len(executions) != len(acceptance_roles)
                or {item["agent_role"] for item in executions} != set(acceptance_roles)
                or any(
                    item["attempt_id"] != row["acceptance_attempt_id"]
                    or item["status"] != "succeeded"
                    or item["cost_measurement_state"] != "measured"
                    or item["measured_cost"] is None
                    or item["physical_attempts"] != 1
                    for item in executions
                )
            ):
                raise RecordConflictError(
                    "agent acceptance completion requires its exact measured successful calls"
                )
            judge = next(item for item in executions if item["agent_role"] == "judge")
            if (
                judge["judge_calibration_id"] is None
                or judge["judge_calibration_state"] != "failed"
                or judge["decision_authority"] != "oracle"
                or judge["oracle_agreement"] is None
            ):
                raise RecordConflictError(
                    "agent acceptance completion requires fail-closed Judge oracle reconciliation"
                )
            events = (
                connection.execute(
                    text(
                        "SELECT event_id, logical_execution_id, agent_role, "
                        "campaign_attempt_id, status, returned_model, "
                        "upstream_provider, provider_request_id, input_tokens, "
                        "output_tokens, reasoning_tokens, cost_measurement_state, "
                        "measured_cost_usd "
                        "FROM provider_call_events WHERE organization_id = :org "
                        "AND campaign_run_id = :run ORDER BY finished_at, event_id"
                    ),
                    {
                        "org": row["organization_id"],
                        "run": run_id,
                    },
                )
                .mappings()
                .all()
            )
            if (
                len(events) != len(acceptance_roles)
                or {item["agent_role"] for item in events} != set(acceptance_roles)
                or any(
                    item["campaign_attempt_id"] != row["acceptance_attempt_id"]
                    or item["status"] != "succeeded"
                    or item["cost_measurement_state"] != "measured"
                    or item["measured_cost_usd"] is None
                    for item in events
                )
            ):
                raise RecordConflictError(
                    "agent acceptance completion requires its exact durable provider events"
                )
            events_by_execution = {str(item["logical_execution_id"]): item for item in events}
            if len(events_by_execution) != len(acceptance_roles):
                raise RecordConflictError(
                    "agent acceptance provider events do not map one-to-one to executions"
                )
            for execution in executions:
                event = events_by_execution.get(str(execution["execution_id"]))
                event_id = event["event_id"] if event is not None else None
                if (
                    event is None
                    or not isinstance(event_id, str)
                    or _SHA256.fullmatch(event_id) is None
                    or event["agent_role"] != execution["agent_role"]
                    or execution["provider_event_ids"] != [event_id]
                    or event["returned_model"] != execution["returned_model"]
                    or event["upstream_provider"] != execution["upstream_provider"]
                    or event["provider_request_id"] != execution["provider_request_id"]
                    or event["input_tokens"] != execution["input_tokens"]
                    or event["output_tokens"] != execution["output_tokens"]
                    or event["reasoning_tokens"] != execution["reasoning_tokens"]
                    or event["measured_cost_usd"] != execution["measured_cost"]
                ):
                    raise RecordConflictError(
                        "agent acceptance provider events do not reconcile to logical executions"
                    )
            total_cost = sum(
                (Decimal(str(item["measured_cost_usd"])) for item in events),
                Decimal(0),
            )
            if total_cost > Decimal(str(limits["global_usd_cap"])):
                raise AuthorizationDeniedError("agent acceptance global spend cap was exceeded")
            for role_name in acceptance_roles:
                role_cost = sum(
                    (
                        Decimal(str(item["measured_cost_usd"]))
                        for item in events
                        if item["agent_role"] == role_name
                    ),
                    Decimal(0),
                )
                if role_cost > Decimal(str(limits["role_usd_caps"][role_name])):
                    raise AuthorizationDeniedError(f"{role_name} acceptance spend cap was exceeded")
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id) "
                    "VALUES (:org, :run, 'complete', :actor, :session)"
                ),
                {
                    "org": row["organization_id"],
                    "run": run_id,
                    "actor": row["acceptance_actor_id"],
                    "session": "runner:live-acceptance",
                },
            )
            self._audit(
                connection,
                str(row["organization_id"]),
                "agent_acceptance.complete",
                "campaign_run",
                run_id,
                None,
                {
                    "run_kind": "agent_acceptance",
                    "attempt_id": row["acceptance_attempt_id"],
                    "agent_execution_count": len(executions),
                    "provider_call_count": len(events),
                    "measured_cost_usd": format(total_cost, "f"),
                    "target_request_count": 0,
                },
                actor_user_id=str(row["acceptance_actor_id"]),
                actor_session_id="runner:live-acceptance",
            )
        return run_id

    def abort_agent_acceptance_run(
        self,
        *,
        run_id: str,
        reason_code: str,
    ) -> str:
        """Trip the acceptance kill switch without creating target or human authority."""

        if not isinstance(reason_code, str) or _REASON_CODE.fullmatch(reason_code) is None:
            raise InvalidControlPlaneInput("acceptance abort reason code is invalid")
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"agent-acceptance:{run_id}")
            row = self._agent_acceptance_run_row(
                connection,
                run_id=run_id,
                for_update=True,
            )
            self._assert_agent_acceptance_has_no_target_traffic(
                connection,
                organization_id=str(row["organization_id"]),
                run_id=run_id,
            )
            if row["state"] == "aborted":
                return run_id
            if row["state"] != "running":
                raise RecordConflictError("agent acceptance run can no longer be aborted")
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id, "
                    "reason_code) VALUES "
                    "(:org, :run, 'aborted', :actor, :session, :reason)"
                ),
                {
                    "org": row["organization_id"],
                    "run": run_id,
                    "actor": row["acceptance_actor_id"],
                    "session": "runner:live-acceptance",
                    "reason": reason_code,
                },
            )
            self._audit(
                connection,
                str(row["organization_id"]),
                "agent_acceptance.aborted",
                "campaign_run",
                run_id,
                None,
                {
                    "run_kind": "agent_acceptance",
                    "attempt_id": row["acceptance_attempt_id"],
                    "reason_code": reason_code,
                    "target_request_count": 0,
                },
                actor_user_id=str(row["acceptance_actor_id"]),
                actor_session_id="runner:live-acceptance",
            )
        return run_id

    # ------------------------------------------------------- governed acceptance authority

    def create_governed_acceptance_run(
        self,
        *,
        organization_id: str,
        authorization_request_id: str,
        scope_hash: str,
        launcher_user_id: str,
        launcher_session_id: str,
        configuration_set_sha256: str,
        generation_policy_sha256: str,
        reviewed_case_id: str,
        reviewed_case_content_hash: str,
        reviewed_category: str,
        expires_at: datetime.datetime,
        limits: Mapping[str, Any] | None = None,
    ) -> GovernedAcceptanceRunIdentity:
        """Create one governed, target-BOUND four-role run bound to an exact reviewed case.

        Human-launched under a live two-person authorization (campaign-style): the launcher's
        live, exact-scope request must already be approved by a DIFFERENT principal. The run's
        ``acceptance_context_sha256`` is the reviewed case's content hash, so the authority is
        pinned to the EXACT reviewed bytes the seed-replay dispatch sends — no unreviewed content.
        """

        if not isinstance(organization_id, str) or not organization_id or len(organization_id) > 64:
            raise InvalidControlPlaneInput("governed acceptance organization identity is invalid")
        for label, value in (
            ("authorization request", authorization_request_id),
            ("launcher user", launcher_user_id),
            ("launcher session", launcher_session_id),
            ("reviewed case", reviewed_case_id),
        ):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise InvalidControlPlaneInput(f"governed acceptance {label} identity is invalid")
        for label, value in (
            ("scope hash", scope_hash),
            ("context", reviewed_case_content_hash),
            ("configuration hash", configuration_set_sha256),
            ("generation policy hash", generation_policy_sha256),
        ):
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise InvalidControlPlaneInput(f"governed acceptance {label} is invalid")
        if (
            not isinstance(reviewed_category, str)
            or not reviewed_category
            or len(reviewed_category) > 64
            # This value is written straight into campaign_attempts.category, which is now
            # constrained by the database. Accepting any well-formed string here would let the
            # runtime admit a category PostgreSQL then rejects, so the two must agree.
            or reviewed_category not in SUPPORTED_CASE_CATEGORIES
        ):
            raise InvalidControlPlaneInput("governed acceptance category is invalid")
        supplied_limits = (
            self._bounded_agent_payload(dict(limits), label="governed acceptance limits")
            if limits is not None
            else None
        )
        if (
            not isinstance(expires_at, datetime.datetime)
            or expires_at.tzinfo is None
            or expires_at.utcoffset() is None
        ):
            raise InvalidControlPlaneInput("governed acceptance expiry must be timezone-aware")
        normalized_expiry = expires_at.astimezone(datetime.UTC)
        now = datetime.datetime.now(datetime.UTC)
        if normalized_expiry <= now or normalized_expiry > now + _AGENT_ACCEPTANCE_MAX_LIFETIME:
            raise AuthorizationDeniedError(
                "governed acceptance expiry is outside the closed lifetime"
            )

        context_sha256 = reviewed_case_content_hash
        run_id = f"{_GOVERNED_ACCEPTANCE_RUN_PREFIX}{uuid.uuid4().hex}"
        attempt_id = hashlib.sha256(
            f"m1d-attempt:v1\0{run_id}\0{0}\0{reviewed_case_id}".encode()
        ).hexdigest()
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"governed-acceptance-create:{organization_id}")
            try:
                configuration = self._stored_hosted_configuration(
                    connection,
                    organization_id=organization_id,
                    configuration_sha256=configuration_set_sha256,
                )
            except (AuthorizationDeniedError, RecordNotFoundError) as exc:
                raise AuthorizationDeniedError(
                    "governed acceptance requires an existing human-staged configuration"
                ) from exc
            # The stored budget is DERIVED from the staged, content-hashed config (guardrail 2:
            # no unreviewed dispatch); a supplied envelope, if any, must match it exactly.
            expected_limits = canonical_governed_acceptance_limits(configuration)
            if supplied_limits is not None and supplied_limits != expected_limits:
                raise AuthorizationDeniedError(
                    "governed acceptance limits differ from the configuration-derived envelope"
                )
            authorization = (
                connection.execute(
                    text(
                        "SELECT q.launcher_user_id, q.launcher_session_id, "
                        "(q.expires_at > clock_timestamp()) AS authorization_live, "
                        "d.decision, d.approver_user_id, d.self_approval_override "
                        "FROM campaign_authorization_requests q "
                        "JOIN campaign_authorization_decisions d "
                        "ON d.organization_id = q.organization_id "
                        "AND d.request_id = q.request_id AND d.scope_hash = q.scope_hash "
                        "WHERE q.organization_id = :org AND q.request_id = :req "
                        "AND q.scope_hash = :scope FOR SHARE OF q, d"
                    ),
                    {"org": organization_id, "req": authorization_request_id, "scope": scope_hash},
                )
                .mappings()
                .one_or_none()
            )
            if (
                authorization is None
                or authorization["decision"] != "approved"
                or not authorization["authorization_live"]
            ):
                raise AuthorizationDeniedError("governed acceptance authorization is not live")
            if (
                authorization["launcher_user_id"] != launcher_user_id
                or authorization["launcher_session_id"] != launcher_session_id
            ):
                raise AuthorizationDeniedError(
                    "governed acceptance launcher differs from its approval"
                )
            if (
                authorization["approver_user_id"] == launcher_user_id
                or authorization["self_approval_override"]
            ):
                raise AuthorizationDeniedError("governed acceptance violates two-person control")

            connection.execute(
                text(
                    "INSERT INTO campaign_runs "
                    "(run_id, organization_id, run_kind, authorization_request_id, scope_hash, "
                    "launcher_user_id, launcher_session_id, acceptance_configuration_sha256, "
                    "acceptance_generation_policy_sha256, acceptance_context_sha256, "
                    "acceptance_attempt_id, acceptance_limits, acceptance_expires_at) VALUES "
                    "(:run, :org, 'governed_acceptance', :req, :scope, :launcher, :session, "
                    ":configuration, :generation_policy, :context, :attempt, "
                    "CAST(:limits AS jsonb), :expires_at)"
                ),
                {
                    "run": run_id,
                    "org": organization_id,
                    "req": authorization_request_id,
                    "scope": scope_hash,
                    "launcher": launcher_user_id,
                    "session": launcher_session_id,
                    "configuration": configuration.configuration_sha256,
                    "generation_policy": generation_policy_sha256,
                    "context": context_sha256,
                    "attempt": attempt_id,
                    "limits": canonical_json(expected_limits),
                    "expires_at": normalized_expiry,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_attempts "
                    "(organization_id, run_id, attempt_id, ordinal, case_id, "
                    "case_content_hash, category, fixture_provenance) VALUES "
                    "(:org, :run, :attempt, 0, :case_id, :context, :category, "
                    "CAST(:fixture AS jsonb))"
                ),
                {
                    "org": organization_id,
                    "run": run_id,
                    "attempt": attempt_id,
                    "case_id": reviewed_case_id,
                    "context": context_sha256,
                    "category": reviewed_category,
                    "fixture": canonical_json(_AGENT_ACCEPTANCE_FIXTURE),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id) "
                    "VALUES (:org, :run, 'running', :actor, :session)"
                ),
                {
                    "org": organization_id,
                    "run": run_id,
                    "actor": launcher_user_id,
                    "session": launcher_session_id,
                },
            )
            self._audit(
                connection,
                organization_id,
                "governed_acceptance.started",
                "campaign_run",
                run_id,
                None,
                {
                    "run_kind": "governed_acceptance",
                    "attempt_id": attempt_id,
                    "authorization_request_id": authorization_request_id,
                    "scope_hash": scope_hash,
                    "configuration_set_sha256": configuration.configuration_sha256,
                    "generation_policy_sha256": generation_policy_sha256,
                    "acceptance_context_sha256": context_sha256,
                    "reviewed_case_id": reviewed_case_id,
                    "acceptance_limits": expected_limits,
                    "network_scope": "policy_gateway_target",
                    "target_call_limit": 1,
                    "expires_at": normalized_expiry.isoformat(),
                },
                actor_user_id=launcher_user_id,
                actor_session_id=launcher_session_id,
            )
        return GovernedAcceptanceRunIdentity(run_id=run_id, attempt_id=attempt_id)

    def start_governed_agent_execution(
        self,
        *,
        run_id: str,
        agent_role: AgentRole,
        input_payload: Mapping[str, Any],
        provider: str,
        model: str,
        upstream_provider: str,
        configuration_set_sha256: str,
        role_configuration_sha256: str,
        generation_policy_sha256: str,
        judge_calibration_id: str | None = None,
        judge_calibration_state: str | None = None,
        parent_execution_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        system_prompt_version: str | None = None,
        system_prompt_sha256: str | None = None,
        system_prompt_content: str | None = None,
        provider_messages: Sequence[Mapping[str, Any]] | None = None,
        prompt_redactions: Sequence[Mapping[str, Any]] = (),
    ) -> str:
        """Start one governed four-role logical call — permits the one bounded target dispatch.

        Unlike the target-free acceptance start, this does NOT forbid target traffic (the governed
        authority permits exactly one bounded dispatch). The governed Judge is the real calibrated,
        human-enabled independent model Judge, so it starts ``enabled`` — not failed-advisory.
        """

        if agent_role not in _GOVERNED_ACCEPTANCE_ROLES:
            raise AuthorizationDeniedError(
                "agent role is outside the governed acceptance allowlist"
            )
        if agent_role == "judge" and judge_calibration_state != "enabled":
            raise AuthorizationDeniedError(
                "governed acceptance Judge must start with an enabled calibration"
            )
        self._validate_judge_calibration_lineage(
            agent_role=agent_role,
            calibration_id=judge_calibration_id,
            calibration_state=judge_calibration_state,
        )
        input_sha256 = self._agent_payload_sha256(
            input_payload,
            label="governed acceptance input",
        )
        sanitized_detail = self._bounded_agent_payload(
            detail or {},
            label="governed acceptance detail",
        )
        if "provider_lineage_state" in sanitized_detail:
            raise InvalidControlPlaneInput("provider lineage state is server-owned")
        sanitized_detail.update(
            {
                "acceptance_id": run_id,
                "run_kind": "governed_acceptance",
                "telemetry_contract": "hosted-agent-execution-v1",
                "provider_lineage_state": "canonical_physical",
            }
        )
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"governed-acceptance:{run_id}")
            authority = self._authorized_governed_role(
                connection,
                run_id=run_id,
                agent_role=agent_role,
                for_update=True,
            )
            role = authority.role_configuration
            if (
                provider != role.provider
                or model != role.model_id
                or upstream_provider != role.upstream_provider
                or configuration_set_sha256 != authority.configuration.configuration_sha256
                or role_configuration_sha256 != role.configuration_sha256
                or generation_policy_sha256 != authority.generation_policy_sha256
            ):
                raise AuthorizationDeniedError(
                    "hosted execution identity differs from the governed authority"
                )
            self._assert_agent_acceptance_call_available(
                connection,
                authority=authority,
            )
            self._validate_acceptance_parent(
                connection,
                authority=authority,
                agent_role=agent_role,
                parent_execution_id=parent_execution_id,
            )
            prior = connection.execute(
                text(
                    "SELECT count(*) FROM agent_executions "
                    "WHERE organization_id = :org AND campaign_run_id = :run "
                    "AND agent_role = :role"
                ),
                {
                    "org": authority.organization_id,
                    "run": run_id,
                    "role": agent_role,
                },
            ).scalar_one()
            if prior:
                raise RecordConflictError(
                    "governed acceptance role already has a logical execution"
                )

            execution_id = uuid.uuid4().hex
            trace_id = campaign_trace_id(run_id)
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, provider, model, execution_mode, "
                    "configuration_version, input_sha256, trace_id, detail, "
                    "configuration_set_sha256, role_configuration_sha256, "
                    "generation_policy_sha256, judge_calibration_id, "
                    "judge_calibration_state) VALUES "
                    "(:execution, :org, :run_id, :attempt, :parent, :role, :provider, "
                    ":model, 'hosted_advisory', :version, :input_hash, :trace_id, "
                    "CAST(:detail AS jsonb), :configuration, :role_configuration, "
                    ":generation_policy, :calibration_id, :calibration_state)"
                ),
                {
                    "execution": execution_id,
                    "org": authority.organization_id,
                    "run_id": run_id,
                    "attempt": authority.acceptance_attempt_id,
                    "parent": parent_execution_id,
                    "role": role.role,
                    "provider": role.provider,
                    "model": role.model_id,
                    "version": int(authority.configuration.schema_version),
                    "input_hash": input_sha256,
                    "trace_id": trace_id,
                    "detail": canonical_json(sanitized_detail),
                    "configuration": authority.configuration.configuration_sha256,
                    "role_configuration": role.configuration_sha256,
                    "generation_policy": authority.generation_policy_sha256,
                    "calibration_id": judge_calibration_id,
                    "calibration_state": judge_calibration_state,
                },
            )
            self._insert_agent_prompt_snapshot(
                connection,
                organization_id=authority.organization_id,
                execution_id=execution_id,
                campaign_run_id=run_id,
                attempt_id=authority.acceptance_attempt_id,
                agent_role=role.role,
                input_payload=input_payload,
                authorized_prompt_sha256=role.prompt_sha256,
                system_prompt_version=system_prompt_version,
                system_prompt_sha256=system_prompt_sha256,
                system_prompt_content=system_prompt_content,
                provider_messages=provider_messages,
                redactions=prompt_redactions,
            )
            self._audit(
                connection,
                authority.organization_id,
                "agent.started",
                "agent_execution",
                execution_id,
                None,
                {
                    "acceptance_id": run_id,
                    "run_kind": "governed_acceptance",
                    "attempt_id": authority.acceptance_attempt_id,
                    "parent_execution_id": parent_execution_id,
                    "agent_role": role.role,
                    "provider": role.provider,
                    "requested_model": role.model_id,
                    "requested_upstream_provider": role.upstream_provider,
                    "execution_mode": "hosted_advisory",
                    "configuration_set_sha256": authority.configuration.configuration_sha256,
                    "role_configuration_sha256": role.configuration_sha256,
                    "generation_policy_sha256": authority.generation_policy_sha256,
                    "judge_calibration_id": judge_calibration_id,
                    "judge_calibration_state": judge_calibration_state,
                    "input_sha256": input_sha256,
                    "trace_id": trace_id,
                    "network_scope": "policy_gateway_target",
                },
                actor_user_id=f"agent:{role.role}",
                actor_session_id="runner:governed-acceptance",
            )
            return execution_id

    def complete_governed_acceptance_run(self, *, run_id: str) -> str:
        """Close a governed run after four measured calls and its single recorded dispatch."""

        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"governed-acceptance:{run_id}")
            row = self._governed_acceptance_run_row(
                connection,
                run_id=run_id,
                for_update=True,
            )
            if row["state"] == "complete":
                return run_id
            if row["state"] != "running":
                raise RecordConflictError("governed acceptance run is no longer completable")
            if not row["acceptance_live"]:
                raise AuthorizationDeniedError("governed acceptance authority has expired")
            executions = (
                connection.execute(
                    text(
                        "SELECT agent_role, attempt_id, status, cost_measurement_state, "
                        "measured_cost, physical_attempts, judge_calibration_id, "
                        "decision_authority, oracle_agreement "
                        "FROM agent_executions "
                        "WHERE organization_id = :org AND campaign_run_id = :run ORDER BY id"
                    ),
                    {"org": row["organization_id"], "run": run_id},
                )
                .mappings()
                .all()
            )
            if (
                len(executions) != len(_GOVERNED_ACCEPTANCE_ROLES)
                or {item["agent_role"] for item in executions} != set(_GOVERNED_ACCEPTANCE_ROLES)
                or any(
                    item["attempt_id"] != row["acceptance_attempt_id"]
                    or item["status"] != "succeeded"
                    or item["cost_measurement_state"] != "measured"
                    or item["measured_cost"] is None
                    or item["physical_attempts"] != 1
                    for item in executions
                )
            ):
                raise RecordConflictError(
                    "governed acceptance completion requires its exact measured successful calls"
                )
            judge = next(item for item in executions if item["agent_role"] == "judge")
            if judge["judge_calibration_id"] is None or judge["decision_authority"] not in {
                "oracle",
                "model",
            }:
                raise RecordConflictError(
                    "governed acceptance completion requires a calibration-bound adjudicated Judge"
                )
            dispatch_count = connection.execute(
                text(
                    "SELECT count(*) FROM attempt_result "
                    "WHERE campaign_run_id = :run AND attempt_id = :attempt"
                ),
                {"run": run_id, "attempt": row["acceptance_attempt_id"]},
            ).scalar_one()
            if dispatch_count != 1:
                raise RecordConflictError(
                    "governed acceptance completion requires its single recorded target dispatch"
                )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id) "
                    "VALUES (:org, :run, 'complete', :actor, :session)"
                ),
                {
                    "org": row["organization_id"],
                    "run": run_id,
                    "actor": row["launcher_user_id"],
                    "session": row["launcher_session_id"],
                },
            )
            self._audit(
                connection,
                str(row["organization_id"]),
                "governed_acceptance.completed",
                "campaign_run",
                run_id,
                None,
                {
                    "run_kind": "governed_acceptance",
                    "attempt_id": row["acceptance_attempt_id"],
                    "target_dispatch_count": 1,
                },
                actor_user_id=str(row["launcher_user_id"]),
                actor_session_id=str(row["launcher_session_id"]),
            )
        return run_id

    def abort_governed_acceptance_run(
        self,
        *,
        run_id: str,
        reason_code: str,
    ) -> str:
        """Trip the governed run kill switch without minting any new authority."""

        if not isinstance(reason_code, str) or _REASON_CODE.fullmatch(reason_code) is None:
            raise InvalidControlPlaneInput("governed acceptance abort reason code is invalid")
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"governed-acceptance:{run_id}")
            row = self._governed_acceptance_run_row(
                connection,
                run_id=run_id,
                for_update=True,
            )
            if row["state"] == "aborted":
                return run_id
            if row["state"] != "running":
                raise RecordConflictError("governed acceptance run can no longer be aborted")
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, actor_user_id, actor_session_id, "
                    "reason_code) VALUES "
                    "(:org, :run, 'aborted', :actor, :session, :reason)"
                ),
                {
                    "org": row["organization_id"],
                    "run": run_id,
                    "actor": row["launcher_user_id"],
                    "session": row["launcher_session_id"],
                    "reason": reason_code,
                },
            )
            self._audit(
                connection,
                str(row["organization_id"]),
                "governed_acceptance.aborted",
                "campaign_run",
                run_id,
                None,
                {
                    "run_kind": "governed_acceptance",
                    "attempt_id": row["acceptance_attempt_id"],
                    "reason_code": reason_code,
                },
                actor_user_id=str(row["launcher_user_id"]),
                actor_session_id=str(row["launcher_session_id"]),
            )
        return run_id

    def _governed_acceptance_run_row(
        self,
        connection: Connection,
        *,
        run_id: str,
        for_update: bool,
    ) -> Mapping[str, Any]:
        if not isinstance(run_id, str) or not run_id.startswith(_GOVERNED_ACCEPTANCE_RUN_PREFIX):
            raise InvalidControlPlaneInput("governed acceptance run identity is invalid")
        lock_clause = " FOR UPDATE OF r" if for_update else ""
        row = (
            connection.execute(
                text(
                    "SELECT r.*, "
                    "(r.acceptance_expires_at > clock_timestamp()) AS acceptance_live, "
                    "(SELECT state FROM campaign_run_events e "
                    "WHERE e.organization_id = r.organization_id "
                    "AND e.run_id = r.run_id ORDER BY e.id DESC LIMIT 1) AS state "
                    "FROM campaign_runs r WHERE r.run_id = :run_id" + lock_clause
                ),
                {"run_id": run_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("governed acceptance run does not exist")
        if (
            row["run_kind"] != "governed_acceptance"
            or row["authorization_request_id"] is None
            or row["scope_hash"] is None
            or row["launcher_user_id"] is None
            or row["launcher_session_id"] is None
            or row["acceptance_actor_id"] is not None
            or row["acceptance_provenance"] is not None
            or not isinstance(row["acceptance_expires_at"], datetime.datetime)
            or row["state"] is None
        ):
            raise AuthorizationDeniedError("governed acceptance authority is malformed")
        for column in (
            "acceptance_configuration_sha256",
            "acceptance_generation_policy_sha256",
            "acceptance_context_sha256",
            "acceptance_attempt_id",
        ):
            if not isinstance(row[column], str) or _SHA256.fullmatch(row[column]) is None:
                raise AuthorizationDeniedError("governed acceptance authority hash is invalid")
        raw_limits = row["acceptance_limits"]
        # Row-level check is STRUCTURAL (four-role shape + the absolute one-dispatch invariant); the
        # EXACT config-derived budget is matched against the staged config by the role authorizer.
        if not isinstance(raw_limits, Mapping) or not _governed_limits_shape_ok(raw_limits):
            raise AuthorizationDeniedError(
                "governed acceptance limits differ from the closed governed envelope"
            )
        return row

    def _authorized_governed_role(
        self,
        connection: Connection,
        *,
        run_id: str,
        agent_role: AgentRole,
        for_update: bool = False,
    ) -> AuthorizedAgentAcceptanceRoleConfiguration:
        row = self._governed_acceptance_run_row(
            connection,
            run_id=run_id,
            for_update=for_update,
        )
        if agent_role not in _GOVERNED_ACCEPTANCE_ROLES:
            raise AuthorizationDeniedError(
                "agent role is outside the governed acceptance allowlist"
            )
        if row["state"] != "running":
            raise AuthorizationDeniedError("governed acceptance run is not executable")
        if not row["acceptance_live"]:
            raise AuthorizationDeniedError("governed acceptance authority has expired")
        configuration = self._stored_hosted_configuration(
            connection,
            organization_id=str(row["organization_id"]),
            configuration_sha256=str(row["acceptance_configuration_sha256"]),
        )
        expected_limits = canonical_governed_acceptance_limits(configuration)
        limits = dict(row["acceptance_limits"])
        if limits != expected_limits:
            raise AuthorizationDeniedError(
                "governed acceptance limits differ from hosted configuration"
            )
        role = next(
            (item for item in configuration.roles if item.role == agent_role),
            None,
        )
        if role is None:
            raise AuthorizationDeniedError(
                "agent role is absent from the governed configuration set"
            )
        return AuthorizedAgentAcceptanceRoleConfiguration(
            organization_id=str(row["organization_id"]),
            run_id=run_id,
            acceptance_attempt_id=str(row["acceptance_attempt_id"]),
            configuration=configuration,
            role_configuration=role,
            generation_policy_sha256=str(row["acceptance_generation_policy_sha256"]),
            acceptance_context_sha256=str(row["acceptance_context_sha256"]),
            limits=limits,
            expires_at=row["acceptance_expires_at"],
        )

    # ------------------------------------------------------- provider physical-call lineage

    def provider_logical_context(
        self,
        *,
        execution_id: str,
        prompt_version: str,
        prompt_sha256: str,
    ) -> ProviderLogicalContextV1:
        """Resolve physical-call authority from one still-running logical execution.

        The prompt text remains in the immutable hosted prompt registry. Only its existing version
        and digest cross this seam; this ledger does not create a second prompt authority.
        """

        if not isinstance(execution_id, str) or not execution_id:
            raise InvalidControlPlaneInput("logical execution identity is invalid")
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text("SELECT * FROM agent_executions WHERE execution_id = :execution"),
                    {"execution": execution_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("logical agent execution does not exist")
            if (
                row["status"] != "running"
                or row["execution_mode"] != "hosted_advisory"
                or row["configuration_set_sha256"] is None
                or row["role_configuration_sha256"] is None
                or row["generation_policy_sha256"] is None
            ):
                raise RecordConflictError(
                    "physical provider context requires a running hosted execution"
                )
            configuration = self._stored_hosted_configuration(
                connection,
                organization_id=str(row["organization_id"]),
                configuration_sha256=str(row["configuration_set_sha256"]),
            )
            role = next(
                (item for item in configuration.roles if item.role == row["agent_role"]),
                None,
            )
            if role is None:
                raise AuthorizationDeniedError(
                    "physical provider context differs from hosted authority"
                )
            try:
                trusted_prompt = resolve_hosted_prompt(role.role, role.prompt_sha256)
            except ValueError:
                raise AuthorizationDeniedError(
                    "physical provider context differs from hosted authority"
                ) from None
            if (
                row["model"] != role.model_id
                or row["role_configuration_sha256"] != role.configuration_sha256
                or prompt_version != trusted_prompt.version
                or prompt_sha256 != trusted_prompt.sha256
                or prompt_sha256 != role.prompt_sha256
            ):
                raise AuthorizationDeniedError(
                    "physical provider context differs from hosted authority"
                )
            return ProviderLogicalContextV1(
                organization_id=str(row["organization_id"]),
                campaign_run_id=str(row["campaign_run_id"]),
                campaign_attempt_id=(
                    str(row["attempt_id"]) if row["attempt_id"] is not None else None
                ),
                logical_execution_id=str(row["execution_id"]),
                parent_execution_id=(
                    str(row["parent_execution_id"])
                    if row["parent_execution_id"] is not None
                    else None
                ),
                agent_role=str(row["agent_role"]),
                requested_model=role.model_id,
                configured_upstream=role.upstream_provider,
                prompt_version=trusted_prompt.version,
                prompt_sha256=trusted_prompt.sha256,
                configuration_set_sha256=configuration.configuration_sha256,
                role_configuration_sha256=role.configuration_sha256,
                generation_policy_sha256=str(row["generation_policy_sha256"]),
            )

    def begin_physical_attempt(
        self,
        logical_context: ProviderLogicalContextV1,
        sequence: int,
    ) -> ProviderInvocationContextV1:
        """Commit immutable physical-call identity before any provider network send."""

        if not isinstance(logical_context, ProviderLogicalContextV1):
            raise TypeError("logical provider context is invalid")
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or not 1 <= sequence <= 2_147_483_647
        ):
            raise InvalidControlPlaneInput("physical provider sequence is invalid")
        identity = (
            f"provider-call:v1\0{logical_context.organization_id}\0"
            f"{logical_context.logical_execution_id}\0{sequence}"
        )
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        invocation = ProviderInvocationContextV1(
            invocation_id=digest,
            organization_id=logical_context.organization_id,
            campaign_run_id=logical_context.campaign_run_id,
            campaign_attempt_id=logical_context.campaign_attempt_id,
            logical_execution_id=logical_context.logical_execution_id,
            parent_execution_id=logical_context.parent_execution_id,
            agent_role=logical_context.agent_role,
            physical_sequence=sequence,
            idempotency_key=f"provider-call:{digest}",
            requested_model=logical_context.requested_model,
            configured_upstream=logical_context.configured_upstream,
            prompt_version=logical_context.prompt_version,
            prompt_sha256=logical_context.prompt_sha256,
            configuration_set_sha256=logical_context.configuration_set_sha256,
            role_configuration_sha256=logical_context.role_configuration_sha256,
            generation_policy_sha256=logical_context.generation_policy_sha256,
            started_at=datetime.datetime.now(datetime.UTC),
        )
        try:
            with self._engine.begin() as connection:
                run_kind = connection.execute(
                    text(
                        "SELECT run_kind FROM campaign_runs "
                        "WHERE organization_id = :org AND run_id = :run"
                    ),
                    {
                        "org": invocation.organization_id,
                        "run": invocation.campaign_run_id,
                    },
                ).scalar_one_or_none()
                if run_kind == "agent_acceptance":
                    self._aggregate_lock(
                        connection,
                        f"agent-acceptance:{invocation.campaign_run_id}",
                    )
                logical = (
                    connection.execute(
                        text(
                            "SELECT * FROM agent_executions "
                            "WHERE organization_id = :org AND execution_id = :execution "
                            "FOR UPDATE"
                        ),
                        {
                            "org": invocation.organization_id,
                            "execution": invocation.logical_execution_id,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
                if logical is None:
                    raise RecordNotFoundError("logical agent execution does not exist")
                if (
                    logical["campaign_run_id"] != invocation.campaign_run_id
                    or logical["attempt_id"] != invocation.campaign_attempt_id
                    or logical["parent_execution_id"] != invocation.parent_execution_id
                    or logical["agent_role"] != invocation.agent_role
                    or logical["model"] != invocation.requested_model
                    or logical["execution_mode"] != "hosted_advisory"
                    or logical["configuration_set_sha256"] != invocation.configuration_set_sha256
                    or logical["role_configuration_sha256"] != invocation.role_configuration_sha256
                    or logical["generation_policy_sha256"] != invocation.generation_policy_sha256
                    or logical["status"] != "running"
                ):
                    raise RecordConflictError(
                        "physical provider context does not match the logical execution"
                    )
                configuration = self._stored_hosted_configuration(
                    connection,
                    organization_id=invocation.organization_id,
                    configuration_sha256=invocation.configuration_set_sha256,
                )
                role = next(
                    (item for item in configuration.roles if item.role == invocation.agent_role),
                    None,
                )
                if role is None:
                    raise AuthorizationDeniedError(
                        "physical provider identity differs from hosted authority"
                    )
                try:
                    trusted_prompt = resolve_hosted_prompt(role.role, role.prompt_sha256)
                except ValueError:
                    raise AuthorizationDeniedError(
                        "physical provider identity differs from hosted authority"
                    ) from None
                if (
                    role.model_id != invocation.requested_model
                    or role.upstream_provider != invocation.configured_upstream
                    or trusted_prompt.version != invocation.prompt_version
                    or trusted_prompt.sha256 != invocation.prompt_sha256
                    or role.prompt_sha256 != invocation.prompt_sha256
                    or role.configuration_sha256 != invocation.role_configuration_sha256
                ):
                    raise AuthorizationDeniedError(
                        "physical provider identity differs from hosted authority"
                    )
                if run_kind == "agent_acceptance":
                    acceptance_authority = self._authorized_agent_acceptance_role(
                        connection,
                        run_id=invocation.campaign_run_id,
                        agent_role=invocation.agent_role,  # type: ignore[arg-type]
                        for_update=True,
                    )
                    if (
                        invocation.campaign_attempt_id != acceptance_authority.acceptance_attempt_id
                        or acceptance_authority.organization_id != invocation.organization_id
                        or acceptance_authority.configuration.configuration_sha256
                        != invocation.configuration_set_sha256
                        or acceptance_authority.role_configuration.configuration_sha256
                        != invocation.role_configuration_sha256
                        or acceptance_authority.generation_policy_sha256
                        != invocation.generation_policy_sha256
                        or acceptance_authority.role_configuration.model_id
                        != invocation.requested_model
                        or acceptance_authority.role_configuration.upstream_provider
                        != invocation.configured_upstream
                        or trusted_prompt.version != invocation.prompt_version
                        or trusted_prompt.sha256 != invocation.prompt_sha256
                    ):
                        raise AuthorizationDeniedError(
                            "physical provider context differs from acceptance authority"
                        )
                    self._assert_agent_acceptance_has_no_target_traffic(
                        connection,
                        organization_id=invocation.organization_id,
                        run_id=invocation.campaign_run_id,
                    )
                    self._assert_agent_acceptance_call_available(
                        connection,
                        authority=acceptance_authority,
                    )
                has_open_invocation = connection.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM provider_call_invocations i "
                        "LEFT JOIN provider_call_events e "
                        "ON e.organization_id = i.organization_id "
                        "AND e.invocation_id = i.invocation_id "
                        "WHERE i.organization_id = :org "
                        "AND i.logical_execution_id = :execution "
                        "AND e.event_id IS NULL)"
                    ),
                    {
                        "org": invocation.organization_id,
                        "execution": invocation.logical_execution_id,
                    },
                ).scalar_one()
                if has_open_invocation:
                    raise RecordConflictError(
                        "logical execution already has an unfinished physical attempt"
                    )
                expected_sequence = int(
                    connection.execute(
                        text(
                            "SELECT count(*) + 1 FROM provider_call_invocations "
                            "WHERE organization_id = :org "
                            "AND logical_execution_id = :execution"
                        ),
                        {
                            "org": invocation.organization_id,
                            "execution": invocation.logical_execution_id,
                        },
                    ).scalar_one()
                )
                if invocation.physical_sequence != expected_sequence:
                    raise RecordConflictError("physical provider sequence must be contiguous")
                connection.execute(
                    text(
                        "INSERT INTO provider_call_invocations "
                        "(invocation_id, organization_id, campaign_run_id, "
                        "campaign_attempt_id, logical_execution_id, parent_execution_id, "
                        "agent_role, physical_sequence, idempotency_key, requested_model, "
                        "configured_upstream, prompt_version, prompt_sha256, "
                        "configuration_set_sha256, role_configuration_sha256, "
                        "generation_policy_sha256, started_at) VALUES "
                        "(:invocation, :org, :run, :attempt, :execution, :parent, :role, "
                        ":sequence, :idempotency, :model, :upstream, :prompt_version, "
                        ":prompt_hash, :configuration_hash, :role_hash, :policy_hash, :started)"
                    ),
                    {
                        "invocation": invocation.invocation_id,
                        "org": invocation.organization_id,
                        "run": invocation.campaign_run_id,
                        "attempt": invocation.campaign_attempt_id,
                        "execution": invocation.logical_execution_id,
                        "parent": invocation.parent_execution_id,
                        "role": invocation.agent_role,
                        "sequence": invocation.physical_sequence,
                        "idempotency": invocation.idempotency_key,
                        "model": invocation.requested_model,
                        "upstream": invocation.configured_upstream,
                        "prompt_version": invocation.prompt_version,
                        "prompt_hash": invocation.prompt_sha256,
                        "configuration_hash": invocation.configuration_set_sha256,
                        "role_hash": invocation.role_configuration_sha256,
                        "policy_hash": invocation.generation_policy_sha256,
                        "started": invocation.started_at,
                    },
                )
        except IntegrityError as exc:
            raise RecordConflictError("physical provider attempt is already reserved") from exc
        return invocation

    def finish_physical_attempt(
        self,
        invocation: ProviderInvocationContextV1,
        event: ProviderTerminalEventV1,
    ) -> ProviderTerminalEventV1:
        """Append physical facts and refresh accounting without terminalizing logical work."""

        if not isinstance(invocation, ProviderInvocationContextV1):
            raise TypeError("provider invocation context is invalid")
        if not isinstance(event, ProviderTerminalEventV1):
            raise TypeError("provider terminal event is invalid")
        if (
            event.invocation_id != invocation.invocation_id
            or event.physical_sequence != invocation.physical_sequence
            or event.finished_at < invocation.started_at
        ):
            raise RecordConflictError("provider terminal event does not match its invocation")
        if event.status == "succeeded" and event.returned_model != invocation.requested_model:
            raise InvalidControlPlaneInput("successful provider event returned a different model")
        if event.status == "succeeded" and (
            event.upstream_provider is None
            or not served_provider_matches_configured(
                invocation.configured_upstream,
                event.upstream_provider,
            )
        ):
            raise InvalidControlPlaneInput(
                "successful provider event used a different configured route"
            )
        with self._engine.begin() as connection:
            durable_invocation = self._provider_invocation_row(
                connection,
                invocation.organization_id,
                invocation.invocation_id,
            )
            if durable_invocation is None:
                raise RecordNotFoundError("provider invocation does not exist")
            self._assert_provider_invocation_identity(durable_invocation, invocation)
            logical = (
                connection.execute(
                    text(
                        "SELECT status FROM agent_executions "
                        "WHERE organization_id = :org AND execution_id = :execution "
                        "FOR UPDATE"
                    ),
                    {
                        "org": invocation.organization_id,
                        "execution": invocation.logical_execution_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if logical is None:
                raise RecordNotFoundError("logical agent execution does not exist")
            # The logical row serializes provider completion, crash reconciliation, and logical
            # terminalization. Re-read the append-only event only after acquiring that lock.
            existing = self._provider_event_for_invocation(
                connection,
                invocation.organization_id,
                invocation.invocation_id,
            )
            if existing is not None:
                if existing != event:
                    raise RecordConflictError(
                        "provider invocation already has different terminal facts"
                    )
                return existing
            if logical["status"] != "running":
                raise RecordConflictError("physical event cannot bypass logical terminalization")
            elapsed = event.finished_at - invocation.started_at
            duration_microseconds = (
                elapsed.days * 86_400_000_000 + elapsed.seconds * 1_000_000 + elapsed.microseconds
            )
            duration_ms = Decimal(duration_microseconds) / Decimal(1_000)
            connection.execute(
                text(
                    "INSERT INTO provider_call_events "
                    "(event_id, invocation_id, organization_id, campaign_run_id, "
                    "campaign_attempt_id, logical_execution_id, agent_role, physical_sequence, "
                    "status, returned_model, upstream_provider, provider_request_id, "
                    "input_tokens, output_tokens, reasoning_tokens, cost_measurement_state, "
                    "measured_cost_usd, error_code, finished_at, duration_ms, "
                    "response_text, response_truncated, response_sha256) VALUES "
                    "(:event, :invocation, :org, :run, :attempt, :execution, :role, :sequence, "
                    ":status, :returned_model, :upstream, :request_id, :input_tokens, "
                    ":output_tokens, :reasoning_tokens, :cost_state, :cost, :error, "
                    ":finished, :duration, :response_text, :response_truncated, "
                    ":response_sha256)"
                ),
                {
                    "event": event.event_id,
                    "invocation": invocation.invocation_id,
                    "org": invocation.organization_id,
                    "run": invocation.campaign_run_id,
                    "attempt": invocation.campaign_attempt_id,
                    "execution": invocation.logical_execution_id,
                    "role": invocation.agent_role,
                    "sequence": invocation.physical_sequence,
                    "status": event.status,
                    "returned_model": event.returned_model,
                    "upstream": event.upstream_provider,
                    "request_id": event.provider_request_id,
                    "input_tokens": event.input_tokens,
                    "output_tokens": event.output_tokens,
                    "reasoning_tokens": event.reasoning_tokens,
                    "cost_state": event.cost_measurement_state,
                    "cost": event.measured_cost_usd,
                    "error": event.error_code,
                    "finished": event.finished_at,
                    "duration": duration_ms,
                    # Already redacted, bounded and digested by the transport; the event contract
                    # refuses any other combination, so this INSERT stores it verbatim.
                    "response_text": event.response_text,
                    "response_truncated": event.response_truncated,
                    "response_sha256": event.response_sha256,
                },
            )
            cost, cost_state, event_ids, physical_attempts = self._provider_cost_projection(
                connection,
                organization_id=invocation.organization_id,
                execution_id=invocation.logical_execution_id,
            )
            result = connection.execute(
                text(
                    "UPDATE agent_executions SET measured_cost = :cost, "
                    "cost_measurement_state = :cost_state, "
                    "provider_event_ids = CAST(:event_ids AS jsonb), "
                    "physical_attempts = :physical_attempts "
                    "WHERE organization_id = :org AND execution_id = :execution "
                    "AND status = 'running'"
                ),
                {
                    "cost": cost,
                    "cost_state": cost_state,
                    "event_ids": canonical_json(event_ids),
                    "physical_attempts": physical_attempts,
                    "org": invocation.organization_id,
                    "execution": invocation.logical_execution_id,
                },
            )
            if result.rowcount != 1:
                raise RecordConflictError("physical event could not refresh its logical projection")
        return event

    def list_open_provider_invocations(
        self,
        *,
        limit: int = 100,
    ) -> tuple[ProviderInvocationContextV1, ...]:
        """Reconstruct bounded unfinished physical attempts entirely from durable rows."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise InvalidControlPlaneInput("provider recovery limit is invalid")
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT i.* FROM provider_call_invocations i "
                        "LEFT JOIN provider_call_events e "
                        "ON e.organization_id = i.organization_id "
                        "AND e.invocation_id = i.invocation_id "
                        "WHERE e.event_id IS NULL "
                        "ORDER BY i.started_at, i.organization_id, i.invocation_id "
                        "LIMIT :limit"
                    ),
                    {"limit": limit},
                )
                .mappings()
                .all()
            )
        return tuple(self._provider_invocation_context(dict(row)) for row in rows)

    def recover_interrupted_hosted_executions(
        self,
        *,
        limit: int = 100,
        stale_after_seconds: float,
    ) -> tuple[tuple[str, str], ...]:
        """Atomically fail bounded stale hosted work without provider or target I/O.

        Candidate enumeration is only an optimization. Each recovery transaction locks the
        campaign's agent-work jobs before the logical row, then rechecks the live lease, staleness,
        and full physical ledger. That lock order prevents a lease reacquisition or provider
        reservation from racing the terminal decision.
        """

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise InvalidControlPlaneInput("provider recovery limit is invalid")
        if (
            isinstance(stale_after_seconds, bool)
            or not isinstance(stale_after_seconds, (int, float))
            or not math.isfinite(stale_after_seconds)
            or not 0 <= stale_after_seconds <= 86_400
        ):
            raise InvalidControlPlaneInput("provider recovery stale interval is invalid")
        with self._engine.connect() as connection:
            candidate_ids = (
                connection.execute(
                    text(
                        "SELECT a.execution_id FROM agent_executions a "
                        "WHERE a.execution_mode = 'hosted_advisory' "
                        "AND a.configuration_set_sha256 IS NOT NULL "
                        "AND a.status = 'running' "
                        "AND NOT EXISTS (SELECT 1 FROM jobs j "
                        "WHERE j.campaign_run_id = a.campaign_run_id "
                        "AND j.queue = 'agent_work'::job_queue "
                        "AND j.status = 'leased'::job_status "
                        "AND j.lease_expires_at > clock_timestamp()) "
                        "AND ((NOT EXISTS (SELECT 1 FROM provider_call_invocations i "
                        "WHERE i.organization_id = a.organization_id "
                        "AND i.logical_execution_id = a.execution_id) "
                        "AND a.started_at <= clock_timestamp() - "
                        "(:stale_seconds * interval '1 second')) "
                        "OR (EXISTS (SELECT 1 FROM provider_call_invocations i "
                        "WHERE i.organization_id = a.organization_id "
                        "AND i.logical_execution_id = a.execution_id) "
                        "AND NOT EXISTS (SELECT 1 FROM provider_call_invocations recent "
                        "WHERE recent.organization_id = a.organization_id "
                        "AND recent.logical_execution_id = a.execution_id "
                        "AND recent.started_at > clock_timestamp() - "
                        "(:stale_seconds * interval '1 second')))) "
                        "ORDER BY a.started_at, a.organization_id, a.execution_id "
                        "LIMIT :limit"
                    ),
                    {
                        "limit": limit,
                        "stale_seconds": float(stale_after_seconds),
                    },
                )
                .scalars()
                .all()
            )
        recovered: list[tuple[str, str]] = []
        for execution_id in candidate_ids:
            reason = self._recover_interrupted_hosted_execution(
                execution_id=str(execution_id),
                stale_after_seconds=float(stale_after_seconds),
            )
            if reason is not None:
                recovered.append((str(execution_id), reason))
        return tuple(recovered)

    def _recover_interrupted_hosted_execution(
        self,
        *,
        execution_id: str,
        stale_after_seconds: float,
    ) -> str | None:
        """Recover one candidate under job, logical, and physical-ledger locks."""

        with self._engine.begin() as connection:
            campaign_run_id = connection.execute(
                text(
                    "SELECT campaign_run_id FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            ).scalar_one_or_none()
            if campaign_run_id is None:
                return None
            job_rows = (
                connection.execute(
                    text(
                        "SELECT id, job_id, status, worker_id, lease_expires_at FROM jobs "
                        "WHERE campaign_run_id = :run_id "
                        "AND queue = 'agent_work'::job_queue FOR UPDATE"
                    ),
                    {"run_id": campaign_run_id},
                )
                .mappings()
                .all()
            )
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM agent_executions WHERE execution_id = :execution FOR UPDATE"
                    ),
                    {"execution": execution_id},
                )
                .mappings()
                .one_or_none()
            )
            if (
                row is None
                or row["campaign_run_id"] != campaign_run_id
                or row["execution_mode"] != "hosted_advisory"
                or row["configuration_set_sha256"] is None
                or row["status"] != "running"
            ):
                return None
            database_now = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
            if any(
                job["status"] == "leased"
                and job["lease_expires_at"] is not None
                and job["lease_expires_at"] > database_now
                for job in job_rows
            ):
                return None
            physical_rows = (
                connection.execute(
                    text(
                        "SELECT i.*, e.event_id, e.status AS event_status, "
                        "e.returned_model AS event_returned_model, "
                        "e.upstream_provider AS event_upstream_provider, "
                        "e.provider_request_id AS event_provider_request_id, "
                        "e.input_tokens AS event_input_tokens, "
                        "e.output_tokens AS event_output_tokens, "
                        "e.reasoning_tokens AS event_reasoning_tokens, "
                        "e.cost_measurement_state AS event_cost_measurement_state, "
                        "e.measured_cost_usd AS event_measured_cost_usd "
                        "FROM provider_call_invocations i "
                        "LEFT JOIN provider_call_events e "
                        "ON e.organization_id = i.organization_id "
                        "AND e.invocation_id = i.invocation_id "
                        "WHERE i.organization_id = :org "
                        "AND i.logical_execution_id = :execution "
                        "ORDER BY i.physical_sequence, i.invocation_id"
                    ),
                    {
                        "org": row["organization_id"],
                        "execution": execution_id,
                    },
                )
                .mappings()
                .all()
            )
            newest_activity = (
                max(item["started_at"] for item in physical_rows)
                if physical_rows
                else row["started_at"]
            )
            if newest_activity > database_now - datetime.timedelta(seconds=stale_after_seconds):
                return None

            had_open_invocation = False
            for physical_row in physical_rows:
                if physical_row["event_id"] is not None:
                    continue
                had_open_invocation = True
                invocation = self._provider_invocation_context(dict(physical_row))
                finished_at = max(database_now, invocation.started_at)
                recovery_identity = (
                    "provider-outcome-unknown:v1\0"
                    f"{invocation.organization_id}\0{invocation.invocation_id}"
                )
                event_id = hashlib.sha256(recovery_identity.encode("utf-8")).hexdigest()
                elapsed = finished_at - invocation.started_at
                duration_microseconds = (
                    elapsed.days * 86_400_000_000
                    + elapsed.seconds * 1_000_000
                    + elapsed.microseconds
                )
                connection.execute(
                    text(
                        "INSERT INTO provider_call_events "
                        "(event_id, invocation_id, organization_id, campaign_run_id, "
                        "campaign_attempt_id, logical_execution_id, agent_role, "
                        "physical_sequence, status, returned_model, upstream_provider, "
                        "provider_request_id, input_tokens, output_tokens, reasoning_tokens, "
                        "cost_measurement_state, measured_cost_usd, error_code, finished_at, "
                        "duration_ms, response_text, response_truncated, response_sha256) VALUES "
                        "(:event, :invocation, :org, :run, :attempt, :execution, :role, "
                        ":sequence, 'outcome_unknown', NULL, NULL, NULL, NULL, NULL, NULL, "
                        "'not_observed', NULL, 'provider_outcome_unknown', :finished, :duration, "
                        # Recovery reconstructs this row from the reservation alone: the process
                        # that made the call is gone and nobody saw what came back. NULL is that
                        # fact. Anything else here would be invented evidence.
                        "NULL, false, NULL)"
                    ),
                    {
                        "event": event_id,
                        "invocation": invocation.invocation_id,
                        "org": invocation.organization_id,
                        "run": invocation.campaign_run_id,
                        "attempt": invocation.campaign_attempt_id,
                        "execution": invocation.logical_execution_id,
                        "role": invocation.agent_role,
                        "sequence": invocation.physical_sequence,
                        "finished": finished_at,
                        "duration": Decimal(duration_microseconds) / Decimal(1_000),
                    },
                )

            event_rows = (
                connection.execute(
                    text(
                        "SELECT returned_model, upstream_provider, provider_request_id, "
                        "input_tokens, output_tokens, reasoning_tokens "
                        "FROM provider_call_events WHERE organization_id = :org "
                        "AND logical_execution_id = :execution "
                        "ORDER BY physical_sequence, event_id"
                    ),
                    {
                        "org": row["organization_id"],
                        "execution": execution_id,
                    },
                )
                .mappings()
                .all()
            )
            (
                returned_model,
                upstream_provider,
                provider_request_id,
                input_tokens,
                output_tokens,
                reasoning_tokens,
            ) = self._provider_observation_projection(
                event_rows,
                field_prefix="",
            )
            cost, cost_state, event_ids, physical_attempts = self._provider_cost_projection(
                connection,
                organization_id=str(row["organization_id"]),
                execution_id=execution_id,
            )
            reason = (
                "provider_invocation_not_started"
                if not physical_rows
                else (
                    "provider_outcome_unknown"
                    if had_open_invocation
                    else "provider_lifecycle_interrupted"
                )
            )
            output_payload = {"status": "failed", "reason_code": reason}
            output_sha256 = self._agent_payload_sha256(
                output_payload,
                label="hosted agent output",
            )
            terminal_detail = self._bounded_agent_payload(
                {"phase": "runner_crash_recovery"},
                label="hosted agent detail",
            )
            terminal_detail["telemetry_contract"] = "hosted-agent-execution-v1"
            connection.execute(
                text(
                    "UPDATE agent_executions SET status = 'failed', "
                    "output_sha256 = :output_hash, returned_model = :returned_model, "
                    "upstream_provider = :upstream_provider, "
                    "provider_request_id = :provider_request_id, "
                    "input_tokens = :input_tokens, output_tokens = :output_tokens, "
                    "reasoning_tokens = :reasoning_tokens, measured_cost = :cost, "
                    "cost_measurement_state = :cost_state, "
                    "provider_event_ids = CAST(:provider_event_ids AS jsonb), "
                    "physical_attempts = :physical_attempts, error_code = :error, "
                    "langfuse_status = CASE WHEN langfuse_status = 'queued' "
                    "THEN 'error' ELSE langfuse_status END, "
                    "langfuse_verified_at = CASE WHEN langfuse_status = 'queued' "
                    "THEN NULL ELSE langfuse_verified_at END, "
                    "detail = detail || CAST(:detail AS jsonb), "
                    "finished_at = clock_timestamp(), "
                    "duration_ms = extract(epoch FROM "
                    "(clock_timestamp() - started_at)) * 1000 "
                    "WHERE execution_id = :execution AND status = 'running'"
                ),
                {
                    "output_hash": output_sha256,
                    "returned_model": returned_model,
                    "upstream_provider": upstream_provider,
                    "provider_request_id": provider_request_id,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "reasoning_tokens": reasoning_tokens,
                    "cost": cost,
                    "cost_state": cost_state,
                    "provider_event_ids": canonical_json(event_ids),
                    "physical_attempts": physical_attempts or None,
                    "error": reason,
                    "detail": canonical_json(terminal_detail),
                    "execution": execution_id,
                },
            )
            connection.execute(
                text(
                    "UPDATE jobs SET status = 'dead_letter'::job_status, "
                    "last_failure_code = 'provider_crash_recovery', "
                    "last_failure_message = "
                    "'stale hosted execution was terminalized without replay', "
                    "last_failure_at = clock_timestamp(), "
                    "last_failure_worker_id = worker_id, "
                    "dead_lettered_at = clock_timestamp(), "
                    "worker_id = NULL, lease_token = NULL, leased_at = NULL, "
                    "lease_expires_at = NULL, last_heartbeat_at = NULL, "
                    "updated_at = clock_timestamp() "
                    "WHERE campaign_run_id = :run_id "
                    "AND queue = 'agent_work'::job_queue "
                    "AND status IN ('queued'::job_status, 'leased'::job_status)"
                ),
                {"run_id": row["campaign_run_id"]},
            )
            campaign_state = connection.execute(
                text(
                    "SELECT state FROM campaign_run_events "
                    "WHERE organization_id = :org AND run_id = :run_id "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {
                    "org": row["organization_id"],
                    "run_id": row["campaign_run_id"],
                },
            ).scalar_one_or_none()
            if campaign_state in {"queued", "running"}:
                connection.execute(
                    text(
                        "INSERT INTO campaign_run_events "
                        "(organization_id, run_id, state, actor_user_id, "
                        "actor_session_id, reason_code) VALUES "
                        "(:org, :run_id, 'aborted', 'runner:recovery', "
                        "'runner:system', 'provider_crash_recovery')"
                    ),
                    {
                        "org": row["organization_id"],
                        "run_id": row["campaign_run_id"],
                    },
                )
                self._audit(
                    connection,
                    str(row["organization_id"]),
                    "campaign.aborted",
                    "campaign_run",
                    str(row["campaign_run_id"]),
                    None,
                    {"reason_code": "provider_crash_recovery"},
                    actor_user_id="runner:recovery",
                    actor_session_id="runner:system",
                )
            self._audit(
                connection,
                str(row["organization_id"]),
                "agent.failed",
                "agent_execution",
                execution_id,
                None,
                {
                    "campaign_run_id": row["campaign_run_id"],
                    "attempt_id": row["attempt_id"],
                    "parent_execution_id": row["parent_execution_id"],
                    "agent_role": row["agent_role"],
                    "provider": row["provider"],
                    "requested_model": row["model"],
                    "returned_model": returned_model,
                    "upstream_provider": upstream_provider,
                    "provider_request_id": provider_request_id,
                    "execution_mode": row["execution_mode"],
                    "configuration_set_sha256": row["configuration_set_sha256"],
                    "role_configuration_sha256": row["role_configuration_sha256"],
                    "generation_policy_sha256": row["generation_policy_sha256"],
                    "output_sha256": output_sha256,
                    "measured_cost": format(cost, "f") if cost is not None else None,
                    "cost_measurement_state": cost_state,
                    "provider_event_ids": event_ids,
                    "currency": "USD",
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "reasoning_tokens": reasoning_tokens,
                    "physical_attempts": physical_attempts or None,
                    "judge_calibration_id": row["judge_calibration_id"],
                    "judge_calibration_state": row["judge_calibration_state"],
                    "oracle_agreement": None,
                    "decision_authority": None,
                    "error_code": reason,
                    "trace_id": row["trace_id"],
                },
                actor_user_id=f"agent:{row['agent_role']}",
                actor_session_id="runner:system",
            )
            return reason

    def list_provider_call_events(
        self,
        *,
        organization_id: str,
    ) -> tuple[Any, ...]:
        """Return physical facts for one already-authorized organization scope.

        Measurements only. The recorded response body is deliberately NOT projected here: it is
        single-call evidence gated on ``org:evidence:read`` and read one call at a time, and a
        bulk listing is exactly the shape that would spread it into logs and aggregate views.
        """

        if not isinstance(organization_id, str) or not organization_id:
            raise InvalidControlPlaneInput("organization identity is invalid")
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT event_id, invocation_id, organization_id, campaign_run_id, "
                        "campaign_attempt_id, logical_execution_id, agent_role, "
                        "physical_sequence, status, returned_model, upstream_provider, "
                        "provider_request_id, input_tokens, output_tokens, reasoning_tokens, "
                        "cost_measurement_state, measured_cost_usd, error_code, finished_at, "
                        "duration_ms "
                        "FROM provider_call_events "
                        "WHERE organization_id = :org "
                        "ORDER BY finished_at, physical_sequence, event_id"
                    ),
                    {"org": organization_id},
                )
                .mappings()
                .all()
            )
        return tuple(SimpleNamespace(**dict(row)) for row in rows)

    @staticmethod
    def _provider_invocation_row(
        connection: Connection,
        organization_id: str,
        invocation_id: str,
    ) -> Mapping[str, Any] | None:
        row = (
            connection.execute(
                text(
                    "SELECT * FROM provider_call_invocations "
                    "WHERE organization_id = :org AND invocation_id = :invocation"
                ),
                {"org": organization_id, "invocation": invocation_id},
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else dict(row)

    @staticmethod
    def _assert_provider_invocation_identity(
        durable_invocation: Mapping[str, Any],
        invocation: ProviderInvocationContextV1,
    ) -> None:
        expected = {
            name: getattr(invocation, name)
            for name in ProviderInvocationContextV1.__dataclass_fields__
        }
        if any(durable_invocation[name] != value for name, value in expected.items()):
            raise RecordConflictError("provider invocation identity changed")

    @staticmethod
    def _provider_invocation_context(
        row: Mapping[str, Any],
    ) -> ProviderInvocationContextV1:
        return ProviderInvocationContextV1(
            **{name: row[name] for name in ProviderInvocationContextV1.__dataclass_fields__}
        )

    @staticmethod
    def _provider_event_for_invocation(
        connection: Connection,
        organization_id: str,
        invocation_id: str,
    ) -> ProviderTerminalEventV1 | None:
        row = (
            connection.execute(
                text(
                    "SELECT * FROM provider_call_events "
                    "WHERE organization_id = :org AND invocation_id = :invocation"
                ),
                {"org": organization_id, "invocation": invocation_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return ProviderTerminalEventV1(
            event_id=row["event_id"],
            invocation_id=row["invocation_id"],
            physical_sequence=row["physical_sequence"],
            status=row["status"],
            returned_model=row["returned_model"],
            upstream_provider=row["upstream_provider"],
            provider_request_id=row["provider_request_id"],
            input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"],
            reasoning_tokens=row["reasoning_tokens"],
            cost_measurement_state=row["cost_measurement_state"],
            measured_cost_usd=row["measured_cost_usd"],
            error_code=row["error_code"],
            finished_at=row["finished_at"],
            # Included so an idempotent replay compares the whole durable row. Omitting them would
            # make a re-recorded call look like it had "different terminal facts".
            response_text=row["response_text"],
            response_truncated=row["response_truncated"],
            response_sha256=row["response_sha256"],
        )

    @staticmethod
    def _provider_observation_projection(
        rows: Sequence[Mapping[str, Any]],
        *,
        field_prefix: str,
    ) -> tuple[str | None, str | None, str | None, int | None, int | None, int | None]:
        """Project identity and independently known token lower bounds from physical events."""

        identity_fields = tuple(
            f"{field_prefix}{name}"
            for name in ("returned_model", "upstream_provider", "provider_request_id")
        )
        identity_rows = [
            row for row in rows if all(row[field] is not None for field in identity_fields)
        ]
        last_identity = identity_rows[-1] if identity_rows else None
        identities = tuple(
            str(last_identity[field]) if last_identity is not None else None
            for field in identity_fields
        )
        token_totals: list[int | None] = []
        for name in ("input_tokens", "output_tokens", "reasoning_tokens"):
            field = f"{field_prefix}{name}"
            observed = [int(row[field]) for row in rows if row[field] is not None]
            total = sum(observed) if observed else None
            if total is not None and total > 2_147_483_647:
                raise RecordConflictError("logical provider token count exceeds storage precision")
            token_totals.append(total)
        return (
            identities[0],
            identities[1],
            identities[2],
            token_totals[0],
            token_totals[1],
            token_totals[2],
        )

    @staticmethod
    def _provider_cost_projection(
        connection: Connection,
        *,
        organization_id: str,
        execution_id: str,
    ) -> tuple[Decimal | None, str, list[str], int]:
        rows = (
            connection.execute(
                text(
                    "SELECT event_id, cost_measurement_state, measured_cost_usd "
                    "FROM provider_call_events WHERE organization_id = :org "
                    "AND logical_execution_id = :execution "
                    "ORDER BY physical_sequence, event_id"
                ),
                {
                    "org": organization_id,
                    "execution": execution_id,
                },
            )
            .mappings()
            .all()
        )
        physical_attempts = int(
            connection.execute(
                text(
                    "SELECT count(*) FROM provider_call_invocations "
                    "WHERE organization_id = :org AND logical_execution_id = :execution"
                ),
                {
                    "org": organization_id,
                    "execution": execution_id,
                },
            ).scalar_one()
        )
        if not rows:
            return None, "not_observed", [], physical_attempts
        amounts = [row["measured_cost_usd"] for row in rows if row["measured_cost_usd"] is not None]
        measured_cost = sum(amounts, Decimal(0)) if amounts else None
        if measured_cost is not None and measured_cost > Decimal("99999999.999999999999"):
            raise RecordConflictError("logical provider cost exceeds storage precision")
        states = {str(row["cost_measurement_state"]) for row in rows}
        if len(amounts) == len(rows) and states == {"measured"}:
            cost_state = "measured"
        elif amounts:
            cost_state = "partial"
        elif "invalid" in states:
            cost_state = "invalid"
        else:
            cost_state = "not_observed"
        return (
            measured_cost,
            cost_state,
            [str(row["event_id"]) for row in rows],
            physical_attempts,
        )

    def start_agent_execution(
        self,
        *,
        run_id: str,
        agent_role: str,
        input_payload: Mapping[str, Any],
        attempt_id: str | None = None,
        parent_execution_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> str:
        """Persist live agent work before execution and append an ordered SSE/audit event."""

        sanitized_input = self._bounded_agent_payload(input_payload, label="agent input")
        sanitized_detail = self._bounded_agent_payload(detail or {}, label="agent detail")
        if "provider_lineage_state" in sanitized_detail:
            raise InvalidControlPlaneInput("provider lineage state is server-owned")
        with self._engine.begin() as connection:
            run = (
                connection.execute(
                    text("SELECT organization_id FROM campaign_runs WHERE run_id = :run_id"),
                    {"run_id": run_id},
                )
                .mappings()
                .one_or_none()
            )
            if run is None:
                raise RecordNotFoundError("campaign run does not exist")
            if parent_execution_id is not None:
                parent = (
                    connection.execute(
                        text(
                            "SELECT organization_id, campaign_run_id FROM agent_executions "
                            "WHERE execution_id = :execution_id"
                        ),
                        {"execution_id": parent_execution_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    parent is None
                    or parent["organization_id"] != run["organization_id"]
                    or parent["campaign_run_id"] != run_id
                ):
                    raise InvalidControlPlaneInput(
                        "parent agent execution must belong to the same campaign"
                    )
            assignment_row = (
                connection.execute(
                    text(
                        "SELECT * FROM agent_configuration_versions "
                        "WHERE organization_id = :org AND agent_role = :role "
                        "AND activation_state = 'active' ORDER BY version DESC LIMIT 1"
                    ),
                    {"org": run["organization_id"], "role": agent_role},
                )
                .mappings()
                .one_or_none()
            )
            assignment = (
                default_assignment(agent_role)
                if assignment_row is None
                else self._agent_assignment_from_row(assignment_row)
            )
            if assignment.execution_mode != "deterministic":
                raise AuthorizationDeniedError(
                    "hosted agent work requires an exact run-bound configuration set"
                )
            execution_id = uuid.uuid4().hex
            trace_id = campaign_trace_id(run_id)
            input_sha256 = content_hash(sanitized_input)
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, provider, model, execution_mode, "
                    "configuration_version, input_sha256, trace_id, detail) VALUES "
                    "(:execution, :org, :run_id, :attempt_id, :parent, :role, :provider, "
                    ":model, :mode, :version, :input_hash, :trace_id, CAST(:detail AS jsonb))"
                ),
                {
                    "execution": execution_id,
                    "org": run["organization_id"],
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "parent": parent_execution_id,
                    "role": assignment.role,
                    "provider": assignment.provider,
                    "model": assignment.model,
                    "mode": assignment.execution_mode,
                    "version": assignment.version,
                    "input_hash": input_sha256,
                    "trace_id": trace_id,
                    "detail": canonical_json(sanitized_detail),
                },
            )
            self._audit(
                connection,
                run["organization_id"],
                "agent.started",
                "agent_execution",
                execution_id,
                None,
                {
                    "campaign_run_id": run_id,
                    "attempt_id": attempt_id,
                    "agent_role": assignment.role,
                    "provider": assignment.provider,
                    "model": assignment.model,
                    "execution_mode": assignment.execution_mode,
                    "input_sha256": input_sha256,
                    "trace_id": trace_id,
                },
                actor_user_id=f"agent:{assignment.role}",
                actor_session_id="runner:system",
            )
            return execution_id

    def bind_agent_execution_attempt(
        self,
        *,
        execution_id: str,
        run_id: str,
        attempt_id: str,
    ) -> None:
        """Bind an in-flight agent to the durable attempt selected during that execution.

        Red Team must begin before it can select a case, while the attempt identity is derived
        only after that exact authorized case is selected. This one-way binding closes that
        chronology gap without inventing an attempt up front or rewriting terminal history.
        """

        if not isinstance(execution_id, str) or not execution_id:
            raise InvalidControlPlaneInput("agent execution identity is invalid")
        if not isinstance(attempt_id, str) or not attempt_id:
            raise InvalidControlPlaneInput("attempt identity is invalid")
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT e.organization_id, e.campaign_run_id, e.attempt_id, "
                        "e.agent_role, e.status, (a.attempt_id IS NOT NULL) AS attempt_exists "
                        "FROM agent_executions e LEFT JOIN campaign_attempts a "
                        "ON a.organization_id = e.organization_id "
                        "AND a.run_id = e.campaign_run_id AND a.attempt_id = :attempt_id "
                        "WHERE e.execution_id = :execution_id FOR UPDATE OF e"
                    ),
                    {
                        "execution_id": execution_id,
                        "attempt_id": attempt_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("agent execution does not exist")
            if row["campaign_run_id"] != run_id or not row["attempt_exists"]:
                raise InvalidControlPlaneInput(
                    "agent execution and attempt must belong to the same campaign"
                )
            if row["agent_role"] != "red_team":
                raise InvalidControlPlaneInput(
                    "only the selecting Red Team execution may bind a derived attempt"
                )
            if row["status"] != "running":
                raise RecordConflictError("only a running agent execution may bind an attempt")
            if row["attempt_id"] not in {None, attempt_id}:
                raise RecordConflictError("agent execution is already bound to another attempt")
            provider_invocation_exists = connection.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM provider_call_invocations "
                    "WHERE organization_id = :org "
                    "AND logical_execution_id = :execution)"
                ),
                {
                    "org": row["organization_id"],
                    "execution": execution_id,
                },
            ).scalar_one()
            if row["attempt_id"] is None and provider_invocation_exists:
                raise RecordConflictError(
                    "agent execution cannot bind an attempt after provider invocation"
                )
            connection.execute(
                text(
                    "UPDATE agent_executions SET attempt_id = :attempt_id "
                    "WHERE execution_id = :execution_id"
                ),
                {
                    "execution_id": execution_id,
                    "attempt_id": attempt_id,
                },
            )
            self._audit(
                connection,
                row["organization_id"],
                "agent.attempt_bound",
                "agent_execution",
                execution_id,
                None,
                {
                    "campaign_run_id": run_id,
                    "attempt_id": attempt_id,
                    "agent_role": row["agent_role"],
                },
                actor_user_id="agent:red_team",
                actor_session_id="runner:system",
            )

    def finish_hosted_agent_execution(
        self,
        *,
        execution_id: str,
        status: str,
        output_payload: Mapping[str, Any],
        returned_model: str | None = None,
        upstream_provider: str | None = None,
        provider_request_id: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        reasoning_tokens: int | None = None,
        measured_cost_usd: str | None = None,
        configuration_set_sha256: str | None = None,
        role_configuration_sha256: str | None = None,
        generation_policy_sha256: str | None = None,
        physical_attempts: int | None = None,
        oracle_agreement: bool | None = None,
        decision_authority: str | None = None,
        error_code: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        """Terminally persist provider-observed lineage for one run-bound hosted invocation."""

        if status not in {"succeeded", "failed"}:
            raise InvalidControlPlaneInput("hosted agent terminal status is invalid")
        if status == "failed":
            if (
                not isinstance(error_code, str)
                or not error_code
                or _REASON_CODE.fullmatch(error_code) is None
            ):
                raise InvalidControlPlaneInput("failed hosted execution needs a typed error")
        elif error_code is not None:
            raise InvalidControlPlaneInput("successful hosted execution cannot carry an error")
        if oracle_agreement is not None and type(oracle_agreement) is not bool:
            raise InvalidControlPlaneInput("oracle agreement must be a boolean when observed")
        if decision_authority is not None and decision_authority not in _DECISION_AUTHORITIES:
            raise InvalidControlPlaneInput("hosted decision authority is invalid")

        caller_provider_lineage = (
            returned_model,
            upstream_provider,
            provider_request_id,
            input_tokens,
            output_tokens,
            reasoning_tokens,
            measured_cost_usd,
            configuration_set_sha256,
            role_configuration_sha256,
            generation_policy_sha256,
        )
        has_caller_provider_lineage = any(value is not None for value in caller_provider_lineage)

        measured_cost: Decimal | None = None
        if measured_cost_usd is not None:
            if not isinstance(measured_cost_usd, str) or _USD.fullmatch(measured_cost_usd) is None:
                raise InvalidControlPlaneInput("hosted measured cost must be canonical USD text")
            measured_cost = Decimal(measured_cost_usd)
            if not measured_cost.is_finite() or measured_cost < 0:
                raise InvalidControlPlaneInput("hosted measured cost is invalid")
        for value in (input_tokens, output_tokens, reasoning_tokens):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise InvalidControlPlaneInput("hosted token accounting is invalid")
        if physical_attempts is not None and (
            isinstance(physical_attempts, bool)
            or not isinstance(physical_attempts, int)
            or physical_attempts <= 0
        ):
            raise InvalidControlPlaneInput("hosted physical-attempt accounting is invalid")
        for label, value, maximum in (
            ("returned model", returned_model, 192),
            ("upstream provider", upstream_provider, 128),
            ("provider request identity", provider_request_id, 256),
        ):
            if value is not None and (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or len(value) > maximum
            ):
                raise InvalidControlPlaneInput(f"hosted {label} is invalid")
        for label, value in (
            ("configuration set", configuration_set_sha256),
            ("role configuration", role_configuration_sha256),
            ("generation policy", generation_policy_sha256),
        ):
            if value is not None and (
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
            ):
                raise InvalidControlPlaneInput(f"hosted {label} hash is invalid")

        output_sha256 = self._agent_payload_sha256(
            output_payload,
            label="hosted agent output",
        )
        terminal_detail = self._bounded_agent_payload(
            detail or {},
            label="hosted agent detail",
        )
        if "provider_lineage_state" in terminal_detail:
            raise InvalidControlPlaneInput("provider lineage state is server-owned")
        terminal_detail["telemetry_contract"] = "hosted-agent-execution-v1"
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM agent_executions WHERE execution_id = :execution FOR UPDATE"
                    ),
                    {"execution": execution_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("agent execution does not exist")
            if (
                row["execution_mode"] != "hosted_advisory"
                or row["configuration_set_sha256"] is None
            ):
                raise InvalidControlPlaneInput(
                    "hosted terminalization requires a run-bound hosted execution"
                )
            physical_rows = (
                connection.execute(
                    text(
                        "SELECT i.*, e.event_id, e.status AS event_status, "
                        "e.returned_model AS event_returned_model, "
                        "e.upstream_provider AS event_upstream_provider, "
                        "e.provider_request_id AS event_provider_request_id, "
                        "e.input_tokens AS event_input_tokens, "
                        "e.output_tokens AS event_output_tokens, "
                        "e.reasoning_tokens AS event_reasoning_tokens, "
                        "e.cost_measurement_state AS event_cost_measurement_state, "
                        "e.measured_cost_usd AS event_measured_cost_usd "
                        "FROM provider_call_invocations i "
                        "LEFT JOIN provider_call_events e "
                        "ON e.organization_id = i.organization_id "
                        "AND e.invocation_id = i.invocation_id "
                        "WHERE i.organization_id = :org "
                        "AND i.logical_execution_id = :execution "
                        "ORDER BY i.physical_sequence, i.invocation_id"
                    ),
                    {
                        "org": row["organization_id"],
                        "execution": execution_id,
                    },
                )
                .mappings()
                .all()
            )
            open_invocations = [item for item in physical_rows if item["event_id"] is None]
            if open_invocations:
                raise RecordConflictError("hosted execution has an unfinished physical invocation")
            event_rows = [item for item in physical_rows if item["event_id"] is not None]
            if status == "succeeded" and not event_rows:
                raise RecordConflictError(
                    "successful hosted execution requires a durable provider event"
                )
            if not event_rows and (has_caller_provider_lineage or physical_attempts is not None):
                raise AuthorizationDeniedError(
                    "eventless hosted failure cannot claim provider lineage"
                )
            (
                projected_cost,
                projected_cost_state,
                projected_event_ids,
                projected_physical_attempts,
            ) = self._provider_cost_projection(
                connection,
                organization_id=str(row["organization_id"]),
                execution_id=execution_id,
            )
            effective_physical_attempts = (
                projected_physical_attempts if projected_physical_attempts else None
            )
            effective_returned_model: str | None = None
            effective_upstream_provider: str | None = None
            effective_provider_request_id: str | None = None
            effective_input_tokens: int | None = None
            effective_output_tokens: int | None = None
            effective_reasoning_tokens: int | None = None
            effective_cost = projected_cost
            effective_cost_state = projected_cost_state
            last_provider_event: Mapping[str, Any] | None = None
            if event_rows:
                if (
                    physical_attempts is not None
                    and physical_attempts != projected_physical_attempts
                ):
                    raise AuthorizationDeniedError(
                        "logical physical-attempt count differs from provider events"
                    )
                last_provider_event = event_rows[-1]
                if status == "succeeded" and last_provider_event["event_status"] != "succeeded":
                    raise AuthorizationDeniedError(
                        "successful logical execution lacks a successful final provider event"
                    )
                (
                    effective_returned_model,
                    effective_upstream_provider,
                    effective_provider_request_id,
                    effective_input_tokens,
                    effective_output_tokens,
                    effective_reasoning_tokens,
                ) = self._provider_observation_projection(
                    event_rows,
                    field_prefix="event_",
                )
                configuration = self._stored_hosted_configuration(
                    connection,
                    organization_id=str(row["organization_id"]),
                    configuration_sha256=str(row["configuration_set_sha256"]),
                )
                role = next(
                    (item for item in configuration.roles if item.role == row["agent_role"]),
                    None,
                )
                if role is None:
                    raise AuthorizationDeniedError(
                        "hosted execution role is absent from its configuration set"
                    )
                if any(
                    item["campaign_run_id"] != row["campaign_run_id"]
                    or item["campaign_attempt_id"] != row["attempt_id"]
                    or item["parent_execution_id"] != row["parent_execution_id"]
                    or item["agent_role"] != row["agent_role"]
                    or item["requested_model"] != row["model"]
                    or item["requested_model"] != role.model_id
                    or item["configured_upstream"] != role.upstream_provider
                    or item["configuration_set_sha256"] != row["configuration_set_sha256"]
                    or item["configuration_set_sha256"] != configuration.configuration_sha256
                    or item["role_configuration_sha256"] != row["role_configuration_sha256"]
                    or item["role_configuration_sha256"] != role.configuration_sha256
                    or item["generation_policy_sha256"] != row["generation_policy_sha256"]
                    or (
                        item["event_status"] == "succeeded"
                        and (
                            item["event_upstream_provider"] is None
                            or not served_provider_matches_configured(
                                str(item["configured_upstream"]),
                                str(item["event_upstream_provider"]),
                            )
                        )
                    )
                    for item in event_rows
                ):
                    raise AuthorizationDeniedError(
                        "provider events differ from the started hosted authority"
                    )
                if status == "succeeded" and (
                    effective_returned_model != row["model"]
                    or effective_returned_model != role.model_id
                ):
                    raise AuthorizationDeniedError(
                        "served model differs from the started hosted authority"
                    )
                caller_expectations = (
                    (returned_model, effective_returned_model),
                    (upstream_provider, effective_upstream_provider),
                    (provider_request_id, effective_provider_request_id),
                    (
                        input_tokens,
                        (
                            last_provider_event["event_input_tokens"]
                            if last_provider_event is not None
                            else None
                        ),
                    ),
                    (
                        output_tokens,
                        (
                            last_provider_event["event_output_tokens"]
                            if last_provider_event is not None
                            else None
                        ),
                    ),
                    (
                        reasoning_tokens,
                        (
                            last_provider_event["event_reasoning_tokens"]
                            if last_provider_event is not None
                            else None
                        ),
                    ),
                    (
                        measured_cost,
                        (
                            last_provider_event["event_measured_cost_usd"]
                            if last_provider_event is not None
                            else None
                        ),
                    ),
                    (configuration_set_sha256, row["configuration_set_sha256"]),
                    (role_configuration_sha256, row["role_configuration_sha256"]),
                    (generation_policy_sha256, row["generation_policy_sha256"]),
                )
                if any(
                    claimed is not None and claimed != durable
                    for claimed, durable in caller_expectations
                ):
                    raise AuthorizationDeniedError(
                        "caller provider lineage differs from durable physical facts"
                    )
            else:
                projected_event_ids = []
            if row["status"] != "running":
                if (
                    row["status"] == status
                    and row["output_sha256"] == output_sha256
                    and self._hosted_terminal_matches(
                        row,
                        returned_model=effective_returned_model,
                        upstream_provider=effective_upstream_provider,
                        provider_request_id=effective_provider_request_id,
                        input_tokens=effective_input_tokens,
                        output_tokens=effective_output_tokens,
                        reasoning_tokens=effective_reasoning_tokens,
                        measured_cost=effective_cost,
                        cost_measurement_state=effective_cost_state,
                        physical_attempts=effective_physical_attempts,
                        oracle_agreement=oracle_agreement,
                        decision_authority=decision_authority,
                    )
                ):
                    return
                raise RecordConflictError("agent execution is already terminal")

            if row["agent_role"] == "judge":
                if status == "succeeded" and decision_authority is None:
                    raise InvalidControlPlaneInput(
                        "successful hosted Judge requires an explicit decision authority"
                    )
                if decision_authority == "model" and row["judge_calibration_state"] != "enabled":
                    raise AuthorizationDeniedError(
                        "model authority requires enabled Judge calibration"
                    )
            elif oracle_agreement is not None or decision_authority is not None:
                raise InvalidControlPlaneInput(
                    "Judge reconciliation is invalid for a non-Judge execution"
                )

            connection.execute(
                text(
                    "UPDATE agent_executions SET status = :status, "
                    "output_sha256 = :output_hash, returned_model = :returned_model, "
                    "upstream_provider = :upstream_provider, "
                    "provider_request_id = :provider_request_id, "
                    "input_tokens = :input_tokens, output_tokens = :output_tokens, "
                    "reasoning_tokens = :reasoning_tokens, measured_cost = :cost, "
                    "cost_measurement_state = :cost_state, "
                    "provider_event_ids = CAST(:provider_event_ids AS jsonb), "
                    "physical_attempts = :physical_attempts, "
                    "oracle_agreement = :oracle_agreement, "
                    "decision_authority = :decision_authority, error_code = :error, "
                    "detail = detail || CAST(:detail AS jsonb), "
                    "finished_at = clock_timestamp(), "
                    "duration_ms = extract(epoch FROM "
                    "(clock_timestamp() - started_at)) * 1000 "
                    "WHERE execution_id = :execution"
                ),
                {
                    "status": status,
                    "output_hash": output_sha256,
                    "returned_model": effective_returned_model,
                    "upstream_provider": effective_upstream_provider,
                    "provider_request_id": effective_provider_request_id,
                    "input_tokens": effective_input_tokens,
                    "output_tokens": effective_output_tokens,
                    "reasoning_tokens": effective_reasoning_tokens,
                    "cost": effective_cost,
                    "cost_state": effective_cost_state,
                    "provider_event_ids": canonical_json(projected_event_ids),
                    "physical_attempts": effective_physical_attempts,
                    "oracle_agreement": oracle_agreement,
                    "decision_authority": decision_authority,
                    "error": error_code,
                    "detail": canonical_json(terminal_detail),
                    "execution": execution_id,
                },
            )
            self._audit(
                connection,
                row["organization_id"],
                f"agent.{status}",
                "agent_execution",
                execution_id,
                None,
                {
                    "campaign_run_id": row["campaign_run_id"],
                    "attempt_id": row["attempt_id"],
                    "parent_execution_id": row["parent_execution_id"],
                    "agent_role": row["agent_role"],
                    "provider": row["provider"],
                    "requested_model": row["model"],
                    "returned_model": effective_returned_model,
                    "upstream_provider": effective_upstream_provider,
                    "provider_request_id": effective_provider_request_id,
                    "execution_mode": row["execution_mode"],
                    "configuration_set_sha256": row["configuration_set_sha256"],
                    "role_configuration_sha256": row["role_configuration_sha256"],
                    "generation_policy_sha256": row["generation_policy_sha256"],
                    "output_sha256": output_sha256,
                    "measured_cost": (
                        format(effective_cost, "f") if effective_cost is not None else None
                    ),
                    "cost_measurement_state": effective_cost_state,
                    "provider_event_ids": projected_event_ids,
                    "currency": "USD",
                    "input_tokens": effective_input_tokens,
                    "output_tokens": effective_output_tokens,
                    "reasoning_tokens": effective_reasoning_tokens,
                    "physical_attempts": effective_physical_attempts,
                    "judge_calibration_id": row["judge_calibration_id"],
                    "judge_calibration_state": row["judge_calibration_state"],
                    "oracle_agreement": oracle_agreement,
                    "decision_authority": decision_authority,
                    "error_code": error_code,
                    "trace_id": row["trace_id"],
                },
                actor_user_id=f"agent:{row['agent_role']}",
                actor_session_id="runner:system",
            )

    def finish_agent_execution(
        self,
        *,
        execution_id: str,
        status: str,
        output_payload: Mapping[str, Any],
        measured_cost: float = 0.0,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        error_code: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        """Complete one real activity with measured—not estimated—cost and token fields."""

        if status not in {"succeeded", "failed", "skipped"}:
            raise InvalidControlPlaneInput("agent execution terminal status is invalid")
        if (
            isinstance(measured_cost, bool)
            or not isinstance(measured_cost, (int, float))
            or measured_cost < 0
            or any(
                value is not None
                and (isinstance(value, bool) or not isinstance(value, int) or value < 0)
                for value in (input_tokens, output_tokens)
            )
        ):
            raise InvalidControlPlaneInput("agent execution accounting is invalid")
        if status == "failed":
            if (
                not isinstance(error_code, str)
                or not error_code
                or _REASON_CODE.fullmatch(error_code) is None
            ):
                raise InvalidControlPlaneInput("failed agent execution needs a typed error")
        elif error_code is not None:
            raise InvalidControlPlaneInput("successful agent execution cannot carry an error")
        output = self._bounded_agent_payload(output_payload, label="agent output")
        terminal_detail = self._bounded_agent_payload(detail or {}, label="agent detail")
        if "provider_lineage_state" in terminal_detail:
            raise InvalidControlPlaneInput("provider lineage state is server-owned")
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM agent_executions WHERE execution_id = :execution FOR UPDATE"
                    ),
                    {"execution": execution_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RecordNotFoundError("agent execution does not exist")
            if row["configuration_set_sha256"] is not None:
                raise InvalidControlPlaneInput(
                    "run-bound hosted work requires hosted terminalization"
                )
            if row["status"] != "running":
                if row["status"] == status and row["output_sha256"] == content_hash(output):
                    return
                raise RecordConflictError("agent execution is already terminal")
            output_sha256 = content_hash(output)
            connection.execute(
                text(
                    "UPDATE agent_executions SET status = :status, output_sha256 = :output_hash, "
                    "input_tokens = :input_tokens, output_tokens = :output_tokens, "
                    "measured_cost = :cost, cost_measurement_state = 'measured', "
                    "error_code = :error, "
                    "detail = detail || CAST(:detail AS jsonb), finished_at = clock_timestamp(), "
                    "duration_ms = extract(epoch FROM (clock_timestamp() - started_at)) * 1000 "
                    "WHERE execution_id = :execution"
                ),
                {
                    "status": status,
                    "output_hash": output_sha256,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost": measured_cost,
                    "error": error_code,
                    "detail": canonical_json(terminal_detail),
                    "execution": execution_id,
                },
            )
            self._audit(
                connection,
                row["organization_id"],
                f"agent.{status}",
                "agent_execution",
                execution_id,
                None,
                {
                    "campaign_run_id": row["campaign_run_id"],
                    "attempt_id": row["attempt_id"],
                    "agent_role": row["agent_role"],
                    "provider": row["provider"],
                    "model": row["model"],
                    "execution_mode": row["execution_mode"],
                    "output_sha256": output_sha256,
                    "measured_cost": measured_cost,
                    "currency": "USD",
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "error_code": error_code,
                    "trace_id": row["trace_id"],
                },
                actor_user_id=f"agent:{row['agent_role']}",
                actor_session_id="runner:system",
            )

    def persisted_evidence_content_hash(self, *, run_id: str, attempt_id: str) -> str | None:
        """Return the immutable evidence hash already recorded for one attempt, if any.

        Needed when adjudication fails *after* the target turns were observed and their evidence
        was durably written. The campaign can still record a typed ERROR verdict against that
        exact evidence, but only ``record_attempt_outcome`` may do so and it demands the precise
        hash — which the caller no longer holds once the Judge raised. This is read-only and never
        invents a hash: a missing row returns ``None`` so the caller fails closed.
        """

        with self._engine.connect() as connection:
            return connection.execute(
                text(
                    "SELECT ar.content_hash FROM campaign_attempts a JOIN attempt_result ar "
                    "ON ar.organization_id = a.organization_id "
                    "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
                    "WHERE a.run_id = :run_id AND a.attempt_id = :attempt_id"
                ),
                {"run_id": run_id, "attempt_id": attempt_id},
            ).scalar_one_or_none()

    def record_attempt_outcome(
        self,
        *,
        run_id: str,
        attempt_id: str,
        verdict: Mapping[str, Any],
        evidence_content_hash: str,
    ) -> str | None:
        """Persist a Judge verdict and its human-gated finding/evidence link atomically."""

        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"campaign-outcome:{run_id}:{attempt_id}")
            row = (
                connection.execute(
                    text(
                        "SELECT a.category, a.severity, ar.* "
                        "FROM campaign_attempts a JOIN attempt_result ar "
                        "ON ar.organization_id = a.organization_id "
                        "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
                        "WHERE a.run_id = :run_id AND a.attempt_id = :attempt_id"
                    ),
                    {"run_id": run_id, "attempt_id": attempt_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None or row["content_hash"] != evidence_content_hash:
                raise AuthorizationDeniedError("outcome evidence integrity is unavailable")
            candidate: dict[str, Any] = {}
            for column in PERSISTED_EVIDENCE_COLUMNS:
                value = row[column]
                if isinstance(value, datetime.datetime):
                    value = value.astimezone(datetime.UTC).isoformat()
                candidate[column] = value
            candidate["content_hash"] = row["content_hash"]
            try:
                ExecutionRecorder().verify(candidate)
            except (EvidenceIntegrityError, TypeError, ValueError) as exc:
                raise AuthorizationDeniedError("outcome evidence integrity is unavailable") from exc
            if (
                row["category"] not in SUPPORTED_CASE_CATEGORIES
                or row["severity"] not in _SEVERITIES
                or row["execution_profile"] not in {"synthetic", "live"}
                or row["evidence_provenance"] not in {"synthetic_offline", "live_target"}
            ):
                raise AuthorizationDeniedError("outcome provenance or taxonomy is invalid")

            existing = (
                connection.execute(
                    text(
                        "SELECT id, state, confidence FROM verdict WHERE organization_id = :org "
                        "AND campaign_run_id = :run_id AND attempt_id = :attempt_id"
                    ),
                    {"org": row["organization_id"], "run_id": run_id, "attempt_id": attempt_id},
                )
                .mappings()
                .one_or_none()
            )
            state = str(verdict.get("state", ""))
            confidence = verdict.get("confidence")
            if existing is None:
                verdict_row = (
                    connection.execute(
                        text(
                            "INSERT INTO verdict (state, confidence, campaign_run_id, attempt_id, "
                            "organization_id, reason_codes, confirmation_source, error_code, "
                            "rationale, criteria_hits) "
                            "VALUES "
                            "(CAST(:state AS verdict_state), :confidence, :run_id, :attempt_id, "
                            ":org, CAST(:reasons AS jsonb), :source, :error, :rationale, "
                            "CAST(:criteria AS jsonb)) RETURNING id"
                        ),
                        {
                            "state": state,
                            "confidence": confidence,
                            "run_id": run_id,
                            "attempt_id": attempt_id,
                            "org": row["organization_id"],
                            "reasons": canonical_json(list(verdict.get("reason_codes", []))),
                            "source": verdict.get("confirmation_source"),
                            "error": verdict.get("error_code"),
                            # Absent on any verdict the model did not author, and NULL is the
                            # honest representation of that -- migration 0029 refuses a rationale
                            # paired with an oracle/canary/human confirmation source.
                            "rationale": verdict.get("rationale"),
                            "criteria": (
                                canonical_json(list(verdict["criteria_hits"]))
                                if verdict.get("criteria_hits")
                                else None
                            ),
                        },
                    )
                    .mappings()
                    .one()
                )
                verdict_id = verdict_row["id"]
            else:
                if existing["state"] != state or float(existing["confidence"] or 0.0) != float(
                    confidence or 0.0
                ):
                    raise RecordConflictError("attempt verdict is immutable")
                verdict_id = existing["id"]

            # A finding is opened for the two states that assert something happened. They are NOT
            # equal, and the difference is carried by finding.state rather than by presence:
            #
            #   EXPLOIT_CONFIRMED -> 'judged'    a deterministic oracle or canary hit. Confirmed.
            #   EXPLOIT_LIKELY    -> 'candidate' the model's opinion, corroborated by nothing.
            #
            # Opening candidates is what makes the human review loop reachable at all. Until this
            # existed, EXPLOIT_LIKELY produced a verdict row and nothing else: no finding, so the
            # Findings page was empty, the Documentation agent never ran, and no report existed for
            # a reviewer to approve. Since EXPLOIT_CONFIRMED requires an oracle hit and no oracle
            # has ever fired, that meant the entire review-then-approve path was unreachable in
            # practice -- 20 findings across every run to date, none of them reviewable.
            #
            # 'candidate' is the first state of the finding lifecycle and was already defined in
            # the enum for exactly this purpose. Promotion to 'judged' is a HUMAN decision made
            # after reading the drafted report; nothing here promotes itself, and migration 0031
            # forbids a candidate from ever reaching published.
            finding_state = {
                "EXPLOIT_CONFIRMED": "judged",
                "EXPLOIT_LIKELY": "candidate",
            }.get(state)
            finding_id: str | None = None
            if finding_state is not None:
                finding_id = hashlib.sha256(
                    f"finding:v1\0{row['organization_id']}\0{run_id}\0{attempt_id}".encode()
                ).hexdigest()
                connection.execute(
                    text(
                        "INSERT INTO finding "
                        "(finding_id, state, severity, category, target_version, "
                        "organization_id, source_kind, execution_profile, published) VALUES "
                        "(:finding, CAST(:finding_state AS finding_state), "
                        "CAST(:severity AS finding_severity), "
                        ":category, :target_version, :org, 'campaign', :profile, false) "
                        "ON CONFLICT (finding_id) DO NOTHING"
                    ),
                    {
                        "finding": finding_id,
                        "finding_state": finding_state,
                        "severity": row["severity"],
                        "category": row["category"],
                        "target_version": row["target_version"],
                        "org": row["organization_id"],
                        "profile": row["execution_profile"],
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO finding_evidence_links "
                        "(organization_id, finding_id, campaign_run_id, attempt_id, "
                        "evidence_content_hash, verdict_id, provenance) VALUES "
                        "(:org, :finding, :run_id, :attempt_id, :hash, :verdict, :provenance) "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {
                        "org": row["organization_id"],
                        "finding": finding_id,
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                        "hash": evidence_content_hash,
                        "verdict": verdict_id,
                        "provenance": row["evidence_provenance"],
                    },
                )
            self._audit(
                connection,
                row["organization_id"],
                "attempt.adjudicated",
                "campaign_attempt",
                attempt_id,
                None,
                {
                    "run_id": run_id,
                    "verdict": state,
                    "evidence_content_hash": evidence_content_hash,
                    "finding_id": finding_id,
                    "finding_state": finding_state,
                    "publication_state": "unpublished",
                },
            )
            return finding_id

    def load_orchestration_snapshot(
        self,
        *,
        run_id: str,
        case_counts: Mapping[str, int],
        queue_backpressure_threshold: int = 20,
        low_signal_streak: int = 0,
        previous_category: str | None = None,
    ) -> dict[str, Any]:
        """Build the Orchestrator's input only from recomputed authoritative evidence.

        Raw spans are never queried.  Any row whose ``AttemptResult`` hash fails recomputation is
        excluded from coverage, finding, and regression signals rather than steering work.
        """

        if (
            not isinstance(case_counts, Mapping)
            or not case_counts
            or any(
                not isinstance(category, str)
                or not category
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 1
                for category, count in case_counts.items()
            )
        ):
            raise InvalidControlPlaneInput("orchestration case counts are invalid")
        if (
            isinstance(queue_backpressure_threshold, bool)
            or not isinstance(queue_backpressure_threshold, int)
            or queue_backpressure_threshold < 1
            or isinstance(low_signal_streak, bool)
            or not isinstance(low_signal_streak, int)
            or low_signal_streak < 0
            or (previous_category is not None and previous_category not in case_counts)
        ):
            raise InvalidControlPlaneInput("orchestration control values are invalid")

        authorized = self.load_run_for_execution(run_id)
        scope = authorized.scope
        organization_id = authorized.run.organization_id
        verified_cases: dict[str, set[str]] = {category: set() for category in case_counts}
        anchored_cases: dict[str, set[str]] = {category: set() for category in case_counts}
        findings: dict[str, dict[str, Any]] = {}
        regressions: dict[str, dict[str, Any]] = {}
        recorder = ExecutionRecorder()

        with self._engine.connect() as connection:
            coverage_rows = (
                connection.execute(
                    text(
                        "SELECT ar.*, a.case_id, a.category, v.state AS verdict_state "
                        "FROM campaign_attempts a JOIN attempt_result ar "
                        "ON ar.organization_id = a.organization_id "
                        "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
                        "JOIN campaign_runs cr ON cr.organization_id = a.organization_id "
                        "AND cr.run_id = a.run_id JOIN campaign_authorization_requests cq "
                        "ON cq.organization_id = cr.organization_id "
                        "AND cq.request_id = cr.authorization_request_id "
                        "AND cq.scope_hash = cr.scope_hash "
                        "JOIN verdict v ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE ar.organization_id = :org AND ar.target_id = :target "
                        "AND ar.target_version = :version "
                        "AND cq.scope_payload->>'corpus_id' = :corpus_id "
                        "AND cq.scope_payload->>'corpus_hash' = :corpus_hash"
                    ),
                    {
                        "org": organization_id,
                        "target": scope.target_id,
                        "version": scope.target_version,
                        "corpus_id": scope.corpus_id,
                        "corpus_hash": scope.corpus_hash,
                    },
                )
                .mappings()
                .all()
            )
            for row in coverage_rows:
                category = row["category"]
                if category not in verified_cases or not self._orchestration_evidence_verified(
                    recorder, row
                ):
                    continue
                verified_cases[category].add(row["case_id"])
                if row["verdict_state"] == "EXPLOIT_CONFIRMED":
                    anchored_cases[category].add(row["case_id"])

            finding_rows = (
                connection.execute(
                    text(
                        "SELECT ar.*, f.finding_id AS linked_finding_id, f.category AS "
                        "finding_category, f.severity AS finding_severity, f.state AS "
                        "finding_state, vr.report_id FROM finding f "
                        "JOIN finding_evidence_links l ON l.organization_id = f.organization_id "
                        "AND l.finding_id = f.finding_id JOIN attempt_result ar "
                        "ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id LEFT JOIN vuln_reports vr "
                        "ON vr.organization_id = f.organization_id "
                        "AND vr.finding_id = f.finding_id "
                        "WHERE f.organization_id = :org AND ar.target_id = :target "
                        "AND ar.target_version = :version AND f.published = false "
                        "AND NOT EXISTS (SELECT 1 FROM finding_decision_events d "
                        "WHERE d.organization_id = f.organization_id "
                        "AND d.finding_id = f.finding_id AND d.decision = 'resolved')"
                    ),
                    {
                        "org": organization_id,
                        "target": scope.target_id,
                        "version": scope.target_version,
                    },
                )
                .mappings()
                .all()
            )
            for row in finding_rows:
                category = row["finding_category"]
                if category not in case_counts or not self._orchestration_evidence_verified(
                    recorder, row
                ):
                    continue
                # A candidate is withheld from the Planner because there is nothing it may
                # authorize about one. The only mechanism for acting on an unresolved finding is a
                # regression trigger, and a trigger is valid only against an entry in
                # ``regressions`` -- which fails closed as empty until replay lineage exists, and
                # which a candidate can never reach because candidates do not enter the regression
                # lifecycle at all.
                #
                # Advertising a finding with no authorized action available is what aborted run
                # 009f7d3c at case 1: the Planner saw an unresolved critical finding, proposed
                # `regression_triggers: [<candidate finding id>]` with mutation policy
                # `validate_unresolved_finding`, and clamping rejected it as an unauthorized
                # trigger. The model's proposal was reasonable; the snapshot was not.
                #
                # This is deliberately keyed on the durable finding STATE rather than on `status`
                # below, which reports "documented" as soon as a report exists -- and a candidate
                # now always has one, so status alone would hide exactly the rows to withhold.
                # Revisit when a promotion path makes a candidate actionable.
                if row["finding_state"] == "candidate":
                    continue
                finding_id = row["linked_finding_id"]
                findings[finding_id] = {
                    "finding_id": finding_id,
                    "category": category,
                    "severity": row["finding_severity"],
                    "status": "documented"
                    if row["report_id"] is not None
                    else row["finding_state"],
                    "evidence_verified": True,
                }

            # The legacy ``regression_case`` row has no replay-result or authorization lineage.
            # It must never be promoted into an evidence-verified Orchestrator signal. The
            # versioned replay tables become eligible here only after an exact persisted replay
            # manifest is bound into campaign authorization and the result writer independently
            # verifies every observation. Until then, regression signals fail closed as empty.

            spent = connection.execute(
                text(
                    "SELECT COALESCE(sum(measured_cost), 0) FROM outbound_http_requests "
                    "WHERE organization_id = :org AND campaign_run_id = :run_id"
                ),
                {"org": organization_id, "run_id": run_id},
            ).scalar_one()
            queue_depth = connection.execute(
                text("SELECT count(*) FROM jobs WHERE status = 'queued'::job_status"),
            ).scalar_one()

        rate_per_minute = int(scope.caps.target_requests_per_second * 60)
        timeout_seconds = int(scope.caps.run_timeout_seconds)
        if rate_per_minute < 1 or timeout_seconds < 1:
            raise InvalidControlPlaneInput(
                "authorized caps are below CampaignDirective v1 resolution; refusing expansion"
            )
        snapshot: dict[str, Any] = {
            "schema_version": "1",
            "campaign_run_id": run_id,
            "target_ref": scope.target_id,
            "target_version": scope.target_version,
            "signal_provenance": "hash_verified_postgres",
            "coverage": [
                {
                    "category": category,
                    "total_case_count": case_counts[category],
                    "verified_attempt_count": len(verified_cases[category]),
                    "deterministic_anchor_count": len(anchored_cases[category]),
                }
                for category in sorted(case_counts)
            ],
            "findings": [findings[key] for key in sorted(findings)],
            "regressions": [regressions[key] for key in sorted(regressions)],
            "budget": {
                "cap_usd": scope.caps.budget_usd,
                "spent_usd": float(spent),
            },
            "queue": {
                "depth": int(queue_depth),
                "backpressure_threshold": queue_backpressure_threshold,
            },
            "authorized_caps": {
                "budget_usd": scope.caps.budget_usd,
                "rate_per_min": rate_per_minute,
                "timeout_s": timeout_seconds,
            },
            "low_signal_streak": low_signal_streak,
            "previous_category": previous_category,
        }
        try:
            validate_contract("orchestration_snapshot", snapshot)
        except Exception as exc:
            raise InvalidControlPlaneInput(
                f"verified orchestration snapshot fails its contract: {exc}"
            ) from exc
        return snapshot

    def record_orchestration_decision(
        self,
        *,
        run_id: str,
        directive: Mapping[str, Any],
        signal_sha256: str,
        priority_reason: str,
        regression_triggers: Sequence[str] = (),
    ) -> None:
        """Persist one immutable, idempotent Orchestrator decision in the audit stream."""

        payload = dict(directive)
        try:
            validate_contract("campaign_directive", payload)
        except Exception as exc:
            raise InvalidControlPlaneInput(
                f"orchestration directive fails its contract: {exc}"
            ) from exc
        if _SHA256.fullmatch(signal_sha256) is None:
            raise InvalidControlPlaneInput("orchestration signal hash is invalid")
        if not isinstance(priority_reason, str) or not priority_reason:
            raise InvalidControlPlaneInput("orchestration priority reason is invalid")
        if not isinstance(regression_triggers, Sequence) or isinstance(
            regression_triggers, (str, bytes)
        ):
            raise InvalidControlPlaneInput("regression triggers are invalid")
        triggers = list(regression_triggers)
        if any(not isinstance(item, str) or not item for item in triggers):
            raise InvalidControlPlaneInput("regression trigger is invalid")

        authorized = self.load_run_for_execution(run_id)
        scope = authorized.scope
        rate_per_minute = int(scope.caps.target_requests_per_second * 60)
        timeout_seconds = int(scope.caps.run_timeout_seconds)
        if rate_per_minute < 1 or timeout_seconds < 1:
            raise AuthorizationDeniedError(
                "authorized caps are below CampaignDirective v1 resolution"
            )
        expected_caps = {
            "budget_usd": scope.caps.budget_usd,
            "rate_per_min": rate_per_minute,
            "timeout_s": timeout_seconds,
        }
        if (
            payload["campaign_id"] != run_id
            or payload["target_ref"] != scope.target_id
            or payload["caps"] != expected_caps
        ):
            raise AuthorizationDeniedError(
                "orchestration directive differs from persisted campaign authority"
            )
        audit_payload = {
            "directive": payload,
            "signal_sha256": signal_sha256,
            "priority_reason": priority_reason,
            "regression_triggers": triggers,
        }
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"orchestration:{run_id}")
            existing = connection.execute(
                text(
                    "SELECT payload FROM audit_events WHERE organization_id = :org "
                    "AND aggregate_type = 'campaign_run' AND aggregate_id = :run_id "
                    "AND event_type = 'campaign.orchestrated' ORDER BY cursor ASC LIMIT 1"
                ),
                {"org": authorized.run.organization_id, "run_id": run_id},
            ).scalar_one_or_none()
            if existing is not None:
                if dict(existing) != audit_payload:
                    raise RecordConflictError(
                        "immutable orchestration decision differs from existing audit record"
                    )
                return
            self._audit(
                connection,
                authorized.run.organization_id,
                "campaign.orchestrated",
                "campaign_run",
                run_id,
                None,
                audit_payload,
                actor_user_id="agent:orchestrator",
                actor_session_id="runner:system",
            )

    @staticmethod
    def _orchestration_evidence_verified(
        recorder: ExecutionRecorder, row: Mapping[str, Any]
    ) -> bool:
        fields: dict[str, Any] = {}
        for column in PERSISTED_EVIDENCE_COLUMNS:
            value = row.get(column)
            if isinstance(value, datetime.datetime):
                value = value.astimezone(datetime.UTC).isoformat()
            fields[column] = value
        fields["content_hash"] = row.get("content_hash")
        try:
            recorder.verify(fields)
        except (EvidenceIntegrityError, TypeError, ValueError):
            return False
        return True

    def record_documentation_outcome(
        self,
        *,
        organization_id: str,
        report: Mapping[str, Any],
        regression_disposition: Mapping[str, Any] | None,
        reproduction_plan: Mapping[str, Any] | None,
    ) -> tuple[str, str | None]:
        """Persist a report, and — for a confirmed finding — its disposition and reproduction.

        This boundary revalidates every supplied contract and its evidence lineage.  The replay
        plan remains execution-blocked and has no authorization scope; it is durable work to be
        reviewed and authorized, never authority to contact a target.  This method accepts no
        published report and no claimed human approval.  Identical retries are idempotent, while
        any immutable-content drift fails.

        A CANDIDATE report passes both regression arguments as ``None``, and that is not a
        weakening.  The regression lifecycle exists to prove a *confirmed* vulnerability does not
        return: admission requires ``EXPLOIT_CONFIRMED``, and a reproduction plan requires the
        deterministic oracle signal that confirmed it.  A candidate has neither — nothing
        corroborated it, so there is nothing to reproduce and nothing to regress against.  Passing
        a synthesized disposition would fabricate a lifecycle the evidence does not support.  The
        pair is admitted when a human promotes the finding out of ``candidate``.

        Both must be present or both absent; a disposition without its plan, or the reverse, is a
        half-written lifecycle and is refused.
        """

        report_payload = dict(report)
        if (regression_disposition is None) != (reproduction_plan is None):
            raise InvalidControlPlaneInput(
                "regression disposition and reproduction plan must be supplied together"
            )
        regression_admitted = regression_disposition is not None
        try:
            validate_contract("vuln_report", report_payload)
        except Exception as exc:
            raise InvalidControlPlaneInput(
                f"documentation outcome fails its published contract: {exc}"
            ) from exc
        # A confirmed report without its regression lifecycle would silently drop the durable
        # proof-of-non-recurrence the confirmed path is required to schedule.
        if report_payload.get("confirmation_status") == "confirmed" and not regression_admitted:
            raise InvalidControlPlaneInput(
                "a confirmed report must schedule its regression disposition and reproduction"
            )
        if report_payload.get("confirmation_status") == "candidate_unconfirmed" and (
            regression_admitted
        ):
            raise InvalidControlPlaneInput(
                "a candidate report may not enter the regression lifecycle before promotion"
            )
        if not isinstance(organization_id, str) or not organization_id.startswith("org_"):
            raise InvalidControlPlaneInput("documentation organization is invalid")

        disposition_payload: dict[str, Any] = {}
        plan_payload: dict[str, Any] = {}
        disposition_id: str | None = None
        replay_id: str | None = None
        if regression_admitted:
            disposition_payload = dict(regression_disposition or {})
            plan_payload = dict(reproduction_plan or {})
            try:
                validate_contract("regression_disposition", disposition_payload)
                validate_contract("regression_replay_plan", plan_payload)
            except Exception as exc:
                raise InvalidControlPlaneInput(
                    f"documentation outcome fails its published contract: {exc}"
                ) from exc
            for key in ("finding_id", "campaign_run_id", "attempt_id", "report_id"):
                report_key = "report_id" if key == "report_id" else key
                if disposition_payload[key] != report_payload[report_key]:
                    raise InvalidControlPlaneInput(
                        "report and regression disposition correlation differs"
                    )
            if disposition_payload["human_approved"] or disposition_payload["admitted"]:
                raise AuthorizationDeniedError(
                    "regression admission requires a separately bound human approval command"
                )
            if (
                disposition_payload["state"] != "pending_deterministic_reproduction"
                or plan_payload["trigger"] != "deterministic_reproduction"
                or plan_payload["authorization_state"] != "pending_human_authorization"
                or plan_payload["authorization_scope_hash"] is not None
                or plan_payload["execution_state"] != "blocked"
            ):
                raise AuthorizationDeniedError(
                    "documentation may only schedule an execution-blocked deterministic "
                    "reproduction"
                )
            for key in ("finding_id", "report_id"):
                if (
                    plan_payload[key] != report_payload[key]
                    or plan_payload[key] != disposition_payload[key]
                ):
                    raise InvalidControlPlaneInput(
                        "reproduction plan does not match documentation lineage"
                    )
            disposition_id = str(disposition_payload["disposition_id"])
            replay_id = str(plan_payload["replay_id"])

        report_id = str(report_payload["report_id"])
        finding_id = str(report_payload["finding_id"])
        run_id = str(report_payload["campaign_run_id"])
        attempt_id = str(report_payload["attempt_id"])
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"documentation:{organization_id}:{finding_id}")
            lineage = (
                connection.execute(
                    text(
                        "SELECT f.severity, f.category, l.evidence_content_hash, v.state, "
                        "v.confirmation_source, a.case_id, ar.attack_attempt, q.scope_payload "
                        "FROM finding f JOIN finding_evidence_links l "
                        "ON l.organization_id = f.organization_id "
                        "AND l.finding_id = f.finding_id JOIN verdict v ON v.id = l.verdict_id "
                        "JOIN campaign_attempts a ON a.organization_id = l.organization_id "
                        "AND a.run_id = l.campaign_run_id AND a.attempt_id = l.attempt_id "
                        "JOIN attempt_result ar ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id JOIN campaign_runs cr "
                        "ON cr.organization_id = l.organization_id "
                        "AND cr.run_id = l.campaign_run_id "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = cr.organization_id "
                        "AND q.request_id = cr.authorization_request_id "
                        "AND q.scope_hash = cr.scope_hash "
                        "WHERE f.organization_id = :org AND f.finding_id = :finding "
                        "AND l.campaign_run_id = :run_id AND l.attempt_id = :attempt_id"
                    ),
                    {
                        "org": organization_id,
                        "finding": finding_id,
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            # The verdict state the lineage must show is the one the report claims. A candidate is
            # required to be EXPLOIT_LIKELY here for the same reason a confirmed report is required
            # to be EXPLOIT_CONFIRMED: the durable verdict, not the caller, decides what this
            # report is allowed to be.
            required_state = "EXPLOIT_CONFIRMED" if regression_admitted else "EXPLOIT_LIKELY"
            if lineage is None or lineage["state"] != required_state:
                raise AuthorizationDeniedError(
                    "documentation requires a finding whose authoritative lineage matches its "
                    "claimed confirmation status"
                )
            expected_reference = f"evidence://sha256/{lineage['evidence_content_hash']}"
            if (
                report_payload["severity"] != lineage["severity"]
                or report_payload["category"] != lineage["category"]
                or report_payload["source_case_id"] != lineage["case_id"]
                or expected_reference not in report_payload["evidence_references"]
            ):
                raise AuthorizationDeniedError(
                    "documentation taxonomy or evidence reference does not match the finding"
                )
            # Every check below concerns the reproduction plan, which a candidate does not have.
            # They are not skipped for convenience: each one binds the plan to the deterministic
            # signal that confirmed the exploit, and a candidate has no such signal to bind to.
            if regression_admitted:
                scope_payload = dict(lineage["scope_payload"])
                if (
                    plan_payload["source_case_ref"]["case_id"] != lineage["case_id"]
                    or plan_payload["attack_attempt"] != dict(lineage["attack_attempt"])
                    or plan_payload["target_id"] != scope_payload.get("target_id")
                    or plan_payload["source_target_version"] != scope_payload.get("target_version")
                    or plan_payload["replay_target_version"] != scope_payload.get("target_version")
                ):
                    raise AuthorizationDeniedError(
                        "reproduction plan differs from the authorization-bound source attempt"
                    )
                expected_attack_hash = hashlib.sha256(
                    json.dumps(
                        plan_payload["attack_attempt"]["input_sequence"],
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest()
                if plan_payload["attack_sequence_sha256"] != expected_attack_hash:
                    raise AuthorizationDeniedError("reproduction attack sequence integrity failed")
                # AttemptResult v1 does not persist the trusted signal identifier. The exact ID is
                # carried from the just-evaluated coordinator outcome into this still-blocked plan,
                # while the durable verdict independently proves only its oracle/canary class. A
                # future result writer must fail closed until exact signal IDs and replay-manifest
                # authorization are durable; this planning write grants no execution authority.
                if lineage["confirmation_source"] not in {"oracle", "canary"}:
                    raise AuthorizationDeniedError(
                        "reproduction plan is not bound to the persisted deterministic source"
                    )

            # A candidate whose reproduction is already documented is a case this platform has
            # found before, which is the normal outcome of scanning the same corpus twice -- the
            # attack is deterministic, so re-finding it yields byte-identical reproduction steps
            # and therefore the identical `reproduction_sha256`.
            #
            # `uq_vuln_report_org_reproduction` is org-wide and deliberately so: one report per
            # distinct reproduction, ever. That held trivially while reports existed only for
            # EXPLOIT_CONFIRMED, which never occurred. Opening candidates made re-documentation
            # routine, and the second run to flag an already-documented case died on the constraint
            # -- run 9f96d923 failed at case 1 re-finding AF-M11-DX-002 from run 25cd7295.
            #
            # The existing report is reused rather than duplicated. The finding still opens and the
            # run's campaign report still lists the case, so what this run found is reported in
            # full; only the evidence document is shared, which is exactly what the constraint
            # exists to guarantee. A CONFIRMED finding is deliberately excluded: it must schedule
            # its own regression lifecycle keyed to its own report, so it may not silently adopt
            # another finding's document.
            if not regression_admitted:
                reused = (
                    connection.execute(
                        text(
                            "SELECT report_id FROM vuln_reports WHERE organization_id = :org "
                            "AND reproduction_sha256 = :reproduction AND finding_id <> :finding"
                        ),
                        {
                            "org": organization_id,
                            "reproduction": report_payload["reproduction_sha256"],
                            "finding": finding_id,
                        },
                    )
                    .scalars()
                    .first()
                )
                if reused is not None:
                    self._audit(
                        connection,
                        organization_id,
                        "finding.documented",
                        "finding",
                        finding_id,
                        None,
                        {
                            "report_id": str(reused),
                            "reused_existing_reproduction": True,
                            "publication_state": report_payload["publication_state"],
                            "confirmation_status": report_payload["confirmation_status"],
                            "regression_disposition_id": None,
                            "admitted": False,
                        },
                        actor_user_id="agent:documentation",
                        actor_session_id="runner:system",
                    )
                    return str(reused), None

            existing_report = connection.execute(
                text(
                    "SELECT contract_payload FROM vuln_reports "
                    "WHERE organization_id = :org AND report_id = :report"
                ),
                {"org": organization_id, "report": report_id},
            ).scalar_one_or_none()
            existing_disposition = (
                connection.execute(
                    text(
                        "SELECT contract_payload FROM regression_dispositions "
                        "WHERE organization_id = :org AND disposition_id = :disposition"
                    ),
                    {"org": organization_id, "disposition": disposition_id},
                ).scalar_one_or_none()
                if regression_admitted
                else None
            )
            existing_plan = (
                connection.execute(
                    text(
                        "SELECT replay_id, disposition_id, contract_payload "
                        "FROM regression_replay_plans WHERE organization_id = :org "
                        "AND report_id = :report "
                        "AND contract_payload->>'trigger' = 'deterministic_reproduction'"
                    ),
                    {"org": organization_id, "report": report_id},
                )
                .mappings()
                .one_or_none()
            )
            # Idempotency is asserted over exactly the records this call is responsible for. For a
            # candidate that is the report alone, so requiring a disposition here would turn every
            # honest retry into a spurious conflict.
            if existing_report is not None or existing_disposition is not None:
                drifted = (
                    existing_report is None
                    or dict(existing_report) != report_payload
                    or (
                        regression_admitted
                        and (
                            existing_disposition is None
                            or dict(existing_disposition) != disposition_payload
                        )
                    )
                    or (not regression_admitted and existing_disposition is not None)
                )
                if drifted:
                    raise RecordConflictError(
                        "immutable documentation outcome differs from its existing record"
                    )
            else:
                connection.execute(
                    text(
                        "INSERT INTO vuln_reports "
                        "(organization_id, report_id, finding_id, campaign_run_id, attempt_id, "
                        "reproduction_sha256, status, publication_state, confirmation_status, "
                        "contract_payload) VALUES "
                        "(:org, :report, :finding, :run_id, :attempt_id, :reproduction, :status, "
                        ":publication, :confirmation_status, CAST(:payload AS jsonb))"
                    ),
                    {
                        "org": organization_id,
                        "report": report_id,
                        "finding": finding_id,
                        "run_id": run_id,
                        "attempt_id": attempt_id,
                        "reproduction": report_payload["reproduction_sha256"],
                        "status": report_payload["status"],
                        "publication": report_payload["publication_state"],
                        # Projected from the payload the Documentation agent derived from the
                        # verdict, never chosen here. Migration 0031 asserts the two agree, so a
                        # divergence fails the write rather than storing a report whose column and
                        # payload disagree about whether it is confirmed.
                        "confirmation_status": report_payload["confirmation_status"],
                        "payload": canonical_json(report_payload),
                    },
                )
                if regression_admitted:
                    connection.execute(
                        text(
                            "INSERT INTO regression_dispositions "
                            "(organization_id, disposition_id, finding_id, report_id, "
                            "campaign_run_id, attempt_id, state, admitted, contract_payload) "
                            "VALUES "
                            "(:org, :disposition, :finding, :report, :run_id, :attempt_id, :state, "
                            ":admitted, CAST(:payload AS jsonb))"
                        ),
                        {
                            "org": organization_id,
                            "disposition": disposition_id,
                            "finding": finding_id,
                            "report": report_id,
                            "run_id": run_id,
                            "attempt_id": attempt_id,
                            "state": disposition_payload["state"],
                            "admitted": disposition_payload["admitted"],
                            "payload": canonical_json(disposition_payload),
                        },
                    )
            if not regression_admitted:
                # A candidate's documentation is complete once its report is durable. It schedules
                # no reproduction, so it records the report and stops here.
                self._audit(
                    connection,
                    organization_id,
                    "finding.documented",
                    "finding",
                    finding_id,
                    None,
                    {
                        "report_id": report_id,
                        "publication_state": report_payload["publication_state"],
                        "confirmation_status": report_payload["confirmation_status"],
                        "regression_disposition_id": None,
                        "admitted": False,
                    },
                    actor_user_id="agent:documentation",
                    actor_session_id="runner:system",
                )
                return report_id, None
            if existing_plan is not None:
                if (
                    existing_plan["replay_id"] != replay_id
                    or existing_plan["disposition_id"] != disposition_id
                    or dict(existing_plan["contract_payload"]) != plan_payload
                ):
                    raise RecordConflictError(
                        "immutable reproduction plan differs from its existing record"
                    )
                return report_id, disposition_id
            connection.execute(
                text(
                    "INSERT INTO regression_replay_plans "
                    "(organization_id, replay_id, regression_case_id, finding_id, report_id, "
                    "disposition_id, target_id, source_target_version, replay_target_version, "
                    "attack_sequence_sha256, contract_payload) VALUES "
                    "(:org, :replay, :case, :finding, :report, :disposition, :target, "
                    ":source_version, :replay_version, :attack_hash, CAST(:payload AS jsonb))"
                ),
                {
                    "org": organization_id,
                    "replay": replay_id,
                    "case": plan_payload["regression_case_id"],
                    "finding": finding_id,
                    "report": report_id,
                    "disposition": disposition_id,
                    "target": plan_payload["target_id"],
                    "source_version": plan_payload["source_target_version"],
                    "replay_version": plan_payload["replay_target_version"],
                    "attack_hash": plan_payload["attack_sequence_sha256"],
                    "payload": canonical_json(plan_payload),
                },
            )
            self._audit(
                connection,
                organization_id,
                "finding.documented",
                "finding",
                finding_id,
                None,
                {
                    "report_id": report_id,
                    "publication_state": report_payload["publication_state"],
                    "regression_disposition_id": disposition_id,
                    "regression_state": disposition_payload["state"],
                    "reproduction_replay_id": replay_id,
                    "reproduction_execution_state": plan_payload["execution_state"],
                    "admitted": False,
                },
                actor_user_id="agent:documentation",
                actor_session_id="runner:system",
            )
            return report_id, disposition_id

    def complete_campaign_job(
        self,
        *,
        job: Any,
        request_count: int | None = None,
        measured_cost: float,
    ) -> CampaignRunRecord:
        """Atomically reconcile durable work, persist the summary, and complete the queue job.

        ``request_count`` remains a compatibility-only argument and is deliberately ignored.
        Physical work is derived from observed durable reservations, never a process-local meter.
        """

        if (
            (
                request_count is not None
                and (
                    isinstance(request_count, bool)
                    or not isinstance(request_count, int)
                    or request_count < 0
                )
            )
            or not isinstance(measured_cost, (int, float))
            or measured_cost < 0
        ):
            raise InvalidControlPlaneInput("campaign accounting is invalid")
        run_id = str(getattr(job, "campaign_run_id", ""))
        with self._engine.begin() as connection:
            self._aggregate_lock(connection, f"campaign-run:{run_id}")
            owned = (
                connection.execute(
                    text(
                        "SELECT status, campaign_run_id, completion_worker_id, "
                        "completion_lease_token FROM jobs WHERE job_id = :job_id FOR UPDATE"
                    ),
                    {"job_id": getattr(job, "job_id", None)},
                )
                .mappings()
                .one_or_none()
            )
            worker = getattr(job, "worker_id", None)
            token = getattr(job, "lease_token", None)
            if owned is None:
                raise AuthorizationDeniedError("campaign queue job is unavailable")
            if owned["campaign_run_id"] != run_id:
                raise AuthorizationDeniedError("campaign queue job does not own this run")
            if owned["status"] == "completed":
                if (
                    owned["completion_worker_id"] == worker
                    and owned["completion_lease_token"] == token
                ):
                    org = connection.execute(
                        text("SELECT organization_id FROM campaign_runs WHERE run_id = :run_id"),
                        {"run_id": run_id},
                    ).scalar_one()
                    return self._campaign_run(connection, org, run_id)
                raise AuthorizationDeniedError("campaign queue completion ownership differs")
            live_lease = connection.execute(
                text(
                    "SELECT 1 FROM jobs WHERE job_id = :job_id AND status = 'leased'::job_status "
                    "AND worker_id = :worker AND lease_token = :token "
                    "AND lease_expires_at > clock_timestamp()"
                ),
                {"job_id": getattr(job, "job_id", None), "worker": worker, "token": token},
            ).scalar_one_or_none()
            if live_lease is None:
                raise AuthorizationDeniedError("runner lease ownership is stale")

            run_row = (
                connection.execute(
                    text(
                        "SELECT r.*, q.scope_payload, "
                        "(SELECT state FROM campaign_run_events e "
                        "WHERE e.organization_id = r.organization_id AND e.run_id = r.run_id "
                        "ORDER BY e.id DESC LIMIT 1) AS state FROM campaign_runs r "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "WHERE r.run_id = :run_id FOR UPDATE OF r"
                    ),
                    {"run_id": run_id},
                )
                .mappings()
                .one_or_none()
            )
            if run_row is None or run_row["state"] != "running":
                raise AuthorizationDeniedError("campaign run is no longer completable")
            scope = scope_from_payload(dict(run_row["scope_payload"]))
            if scope.scope_hash() != run_row["scope_hash"]:
                raise AuthorizationDeniedError("campaign completion scope integrity failed")
            self._validate_scope(connection, run_row["organization_id"], scope)
            current = self._campaign_run_from_row(run_row)
            org = current.organization_id
            attempt_count = int(
                connection.execute(
                    text(
                        "SELECT count(DISTINCT a.attempt_id) FROM campaign_attempts a "
                        "JOIN attempt_result ar ON ar.organization_id = a.organization_id "
                        "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
                        "JOIN verdict v ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE a.organization_id = :org AND a.run_id = :run_id"
                    ),
                    {"org": org, "run_id": run_id},
                ).scalar_one()
            )
            reservation_counts = (
                connection.execute(
                    text(
                        "SELECT count(*) AS reserved_count, "
                        "count(*) FILTER (WHERE observed_at IS NOT NULL) AS observed_count, "
                        "count(*) FILTER (WHERE retry_index <> 0) AS retry_count "
                        "FROM campaign_work_unit_reservations "
                        "WHERE organization_id = :org AND run_id = :run_id"
                    ),
                    {"org": org, "run_id": run_id},
                )
                .mappings()
                .one()
            )
            reserved_count = int(reservation_counts["reserved_count"])
            observed_count = int(reservation_counts["observed_count"])
            retry_count = int(reservation_counts["retry_count"])
            if reserved_count != observed_count:
                raise RecordConflictError(
                    "campaign has an unobserved physical work-unit reservation"
                )
            exact_counts_declared = (
                scope.corpus_id == _EXACT_COUNT_CORPUS_ID
                and scope.caps.logical_case_limit is not None
                and scope.caps.physical_request_limit is not None
                and scope.caps.target_retries_per_turn == 0
            )
            if exact_counts_declared and (
                attempt_count != scope.caps.logical_case_limit
                or observed_count != scope.caps.physical_request_limit
                or retry_count != 0
            ):
                raise RecordConflictError(
                    "campaign durable work does not match its exact completion counts"
                )
            confirmed_count = connection.execute(
                text(
                    "SELECT count(*) FROM finding_evidence_links WHERE organization_id = :org "
                    "AND campaign_run_id = :run_id"
                ),
                {"org": org, "run_id": run_id},
            ).scalar_one()
            started_at = connection.execute(
                text(
                    "SELECT min(created_at) FROM campaign_run_events "
                    "WHERE organization_id = :org AND run_id = :run_id"
                ),
                {"org": org, "run_id": run_id},
            ).scalar_one()
            provenance = (
                "synthetic_offline"
                if scope.execution_profile.value == "synthetic"
                else "live_target"
            )
            # Adjudication outcomes are projected from the durable verdict rows in this same
            # transaction, never from an in-process tally: a Runner restart must not be able to
            # reset how many cases a completed run failed to adjudicate.
            outcomes = (
                connection.execute(
                    text(
                        "SELECT "
                        "count(*) FILTER (WHERE state IN "
                        "  ('EXPLOIT_CONFIRMED','EXPLOIT_LIKELY','NO_EXPLOIT_OBSERVED')) "
                        "  AS decisive, "
                        "count(*) FILTER (WHERE state = 'INDETERMINATE') AS indeterminate, "
                        "count(*) FILTER (WHERE state = 'ERROR') AS operational_errors "
                        "FROM verdict WHERE organization_id = :org AND campaign_run_id = :run_id"
                    ),
                    {"org": org, "run_id": run_id},
                )
                .mappings()
                .one()
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_summaries "
                    "(organization_id, run_id, execution_profile, provenance, attempt_count, "
                    "request_count, confirmed_finding_count, measured_cost, started_at, ended_at, "
                    "decisive_verdict_count, indeterminate_verdict_count, operational_error_count) "
                    "VALUES (:org, :run_id, :profile, :provenance, :attempts, :requests, "
                    ":findings, :cost, :started, clock_timestamp(), "
                    ":decisive, :indeterminate, :operational_errors)"
                ),
                {
                    "org": org,
                    "run_id": run_id,
                    "profile": scope.execution_profile.value,
                    "provenance": provenance,
                    "attempts": attempt_count,
                    "requests": observed_count,
                    "findings": confirmed_count,
                    "cost": measured_cost,
                    "started": started_at,
                    "decisive": outcomes["decisive"],
                    "indeterminate": outcomes["indeterminate"],
                    "operational_errors": outcomes["operational_errors"],
                },
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events (organization_id, run_id, state) "
                    "VALUES (:org, :run_id, 'complete')"
                ),
                {"org": org, "run_id": run_id},
            )
            # Same transaction as the summary and the terminal event, so a completed run always
            # has exactly one report naming what it found.
            self._compose_campaign_report(
                connection,
                organization_id=org,
                run_id=run_id,
                run_state="complete",
            )
            self._audit(
                connection,
                org,
                "campaign.complete",
                "campaign_run",
                run_id,
                None,
                {
                    "attempt_count": attempt_count,
                    "request_count": observed_count,
                    "confirmed_finding_count": confirmed_count,
                    "execution_profile": scope.execution_profile.value,
                    "provenance": provenance,
                },
            )
            completed = connection.execute(
                text(
                    "UPDATE jobs SET status = 'completed'::job_status, "
                    "completion_worker_id = worker_id, completion_lease_token = lease_token, "
                    "completed_at = clock_timestamp(), worker_id = NULL, lease_token = NULL, "
                    "leased_at = NULL, lease_expires_at = NULL, last_heartbeat_at = NULL, "
                    "updated_at = clock_timestamp() WHERE job_id = :job_id "
                    "AND status = 'leased'::job_status AND worker_id = :worker "
                    "AND lease_token = :token RETURNING completed_at"
                ),
                {"job_id": getattr(job, "job_id", None), "worker": worker, "token": token},
            ).scalar_one_or_none()
            if completed is None:
                raise AuthorizationDeniedError("campaign queue completion lost ownership")
            return replace(current, state="complete")

    def record_finding_decision(
        self,
        *,
        principal: Principal,
        finding_id: str,
        decision: str,
        rationale: str,
        idempotency_key: str,
        reason_code: str | None = None,
    ) -> FindingDecisionRecord:
        if decision == "resolved":
            self._require_permission(principal, FINDINGS_RESOLVE)
            if reason_code is not None:
                raise InvalidControlPlaneInput("resolved findings do not accept a review code")
        elif decision in {"approved", "rejected"}:
            self._require_permission(principal, FINDINGS_APPROVE)
            try:
                reason_code = validate_finding_decision_reason_code(
                    decision=decision,
                    reason_code=reason_code,
                )
            except ValueError as exc:
                raise InvalidControlPlaneInput(str(exc)) from exc
        else:
            raise InvalidControlPlaneInput("finding decision is invalid")
        safe_rationale = self._sanitize_plaintext_rationale(rationale)
        document = {
            "finding_id": finding_id,
            "decision": decision,
            "rationale": safe_rationale,
            "reason_code": reason_code,
        }
        with self._engine.begin() as connection:
            existing, request_hash = self._begin_command(
                connection, principal, "finding.decide", idempotency_key, document
            )
            if existing is not None:
                return self._finding_decision(
                    connection, principal.organization_id, existing["decision_id"]
                )
            self._aggregate_lock(
                connection,
                f"finding-decision:{principal.organization_id}:{finding_id}",
            )
            finding_exists = connection.execute(
                text(
                    "SELECT 1 FROM finding WHERE organization_id = :org AND finding_id = :finding"
                ),
                {"org": principal.organization_id, "finding": finding_id},
            ).scalar_one_or_none()
            if finding_exists is None:
                raise RecordNotFoundError("finding does not exist")
            evidence_rows = (
                connection.execute(
                    text(
                        "SELECT ar.*, l.evidence_content_hash, "
                        "cr.run_kind AS finding_run_kind, "
                        "cr.launcher_user_id AS finding_launcher_user_id, "
                        "cr.launcher_session_id AS finding_launcher_session_id, "
                        "q.launcher_user_id AS finding_submitter_user_id, "
                        "q.launcher_session_id AS finding_submitter_session_id "
                        "FROM finding_evidence_links l JOIN attempt_result ar "
                        "ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id "
                        "LEFT JOIN campaign_runs cr ON cr.organization_id = l.organization_id "
                        "AND cr.run_id = l.campaign_run_id "
                        "LEFT JOIN campaign_authorization_requests q "
                        "ON q.organization_id = cr.organization_id "
                        "AND q.request_id = cr.authorization_request_id "
                        "AND q.scope_hash = cr.scope_hash "
                        "WHERE l.organization_id = :org "
                        "AND l.finding_id = :finding ORDER BY l.id LIMIT 2"
                    ),
                    {"org": principal.organization_id, "finding": finding_id},
                )
                .mappings()
                .all()
            )
            if not evidence_rows:
                if decision == "approved":
                    raise AuthorizationDeniedError("finding approval lineage is unavailable")
                raise RecordNotFoundError("finding evidence does not exist")
            if len(evidence_rows) != 1:
                raise AuthorizationDeniedError("finding evidence lineage is ambiguous")
            evidence = evidence_rows[0]
            if decision == "approved":
                approval_lineage_valid = (
                    evidence["finding_run_kind"] in {"campaign", "governed_acceptance"}
                    and evidence["finding_launcher_user_id"] is not None
                    and evidence["finding_launcher_user_id"]
                    == evidence["finding_submitter_user_id"]
                    and evidence["finding_launcher_session_id"]
                    == evidence["finding_submitter_session_id"]
                )
                if not approval_lineage_valid:
                    raise AuthorizationDeniedError("finding approval lineage is unavailable")
                if principal.user_id == evidence["finding_submitter_user_id"]:
                    raise AuthorizationDeniedError("finding submitter cannot approve own finding")
            candidate: dict[str, Any] = {}
            for column in PERSISTED_EVIDENCE_COLUMNS:
                value = evidence[column]
                if isinstance(value, datetime.datetime):
                    value = value.astimezone(datetime.UTC).isoformat()
                candidate[column] = value
            candidate["content_hash"] = evidence["content_hash"]
            try:
                ExecutionRecorder().verify(candidate)
            except (EvidenceIntegrityError, TypeError, ValueError) as exc:
                raise AuthorizationDeniedError("finding evidence integrity is unavailable") from exc
            if evidence["content_hash"] != evidence["evidence_content_hash"]:
                raise AuthorizationDeniedError("finding evidence link integrity failed")
            decision_id = uuid.uuid4().hex
            row = (
                connection.execute(
                    text(
                        "INSERT INTO finding_decision_events "
                        "(decision_id, organization_id, finding_id, decision, actor_user_id, "
                        "actor_session_id, rationale, reason_code) VALUES "
                        "(:decision_id, :org, :finding, :decision, :user, :session, "
                        ":rationale, :reason) "
                        "RETURNING created_at"
                    ),
                    {
                        "decision_id": decision_id,
                        "org": principal.organization_id,
                        "finding": finding_id,
                        "decision": decision,
                        "user": principal.user_id,
                        "session": principal.session_id,
                        "rationale": safe_rationale,
                        "reason": reason_code,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                connection,
                principal.organization_id,
                f"finding.{decision}",
                "finding",
                finding_id,
                principal,
                {
                    "decision_id": decision_id,
                    "rationale": safe_rationale,
                    "reason_code": reason_code,
                },
            )
            self._finish_command(
                connection,
                principal,
                "finding.decide",
                idempotency_key,
                request_hash,
                {"decision_id": decision_id},
            )
            return FindingDecisionRecord(
                decision_id=decision_id,
                organization_id=principal.organization_id,
                finding_id=finding_id,
                decision=decision,
                actor_user_id=principal.user_id,
                actor_session_id=principal.session_id,
                rationale=safe_rationale,
                reason_code=reason_code,
                created_at=row["created_at"],
            )

    def list_audit_events(
        self, *, principal: Principal, after_cursor: int = 0, limit: int = 100
    ) -> tuple[AuditEventRecord, ...]:
        self._require_permission(principal, AUDIT_READ)
        if (
            isinstance(after_cursor, bool)
            or not isinstance(after_cursor, int)
            or after_cursor < 0
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 500
        ):
            raise InvalidControlPlaneInput("audit cursor or limit is invalid")
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT * FROM audit_events WHERE organization_id = :org "
                        "AND cursor > :cursor ORDER BY cursor ASC LIMIT :limit"
                    ),
                    {"org": principal.organization_id, "cursor": after_cursor, "limit": limit},
                )
                .mappings()
                .all()
            )
        return tuple(
            AuditEventRecord(
                cursor=row["cursor"],
                organization_id=row["organization_id"],
                event_type=row["event_type"],
                aggregate_type=row["aggregate_type"],
                aggregate_id=row["aggregate_id"],
                actor_user_id=row["actor_user_id"],
                actor_session_id=row["actor_session_id"],
                payload=dict(row["payload"]),
                created_at=row["created_at"],
            )
            for row in rows
        )

    def agent_prompt_snapshot(
        self,
        *,
        principal: Principal,
        execution_id: str,
    ) -> AgentPromptSnapshotRecord:
        """Return one organization-scoped prompt transcript to an evidence-authorized human."""

        self._require_permission(principal, EVIDENCE_READ)
        if not isinstance(execution_id, str) or not execution_id or len(execution_id) > 64:
            raise InvalidControlPlaneInput("agent execution identity is invalid")
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT organization_id, execution_id, campaign_run_id, attempt_id, "
                        "agent_role, system_prompt_version, system_prompt_sha256, "
                        "system_prompt_content, provider_messages, transcript_sha256, "
                        "redactions, created_at FROM agent_prompt_snapshots "
                        "WHERE organization_id = :org AND execution_id = :execution"
                    ),
                    {
                        "org": principal.organization_id,
                        "execution": execution_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise RecordNotFoundError("agent prompt snapshot does not exist")
        agent_role = str(row["agent_role"])
        system_prompt_content = str(row["system_prompt_content"])
        system_prompt_sha256 = str(row["system_prompt_sha256"])
        try:
            trusted_prompt = resolve_hosted_prompt(agent_role, system_prompt_sha256)
        except ValueError as exc:
            raise InvalidControlPlaneInput("persisted system prompt identity is invalid") from exc
        if (
            not 1 <= len(system_prompt_content.encode("utf-8")) <= 1_048_576
            or hashlib.sha256(system_prompt_content.encode("utf-8")).hexdigest()
            != system_prompt_sha256
            or str(row["system_prompt_version"]) != trusted_prompt.version
            or system_prompt_content != trusted_prompt.content
            or self._prompt_snapshot_contains_sensitive_text(system_prompt_content)
        ):
            raise InvalidControlPlaneInput("persisted system prompt identity is invalid")

        raw_messages = row["provider_messages"]
        if not isinstance(raw_messages, list) or not 1 <= len(raw_messages) <= 64:
            raise InvalidControlPlaneInput("persisted provider prompt transcript is invalid")
        provider_messages: list[dict[str, str]] = []
        for item in raw_messages:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"role", "content"}
                or not isinstance(item["role"], str)
                or item["role"] not in _PROMPT_SNAPSHOT_MESSAGE_ROLES
                or not isinstance(item["content"], str)
                or "\x00" in item["content"]
            ):
                raise InvalidControlPlaneInput("persisted provider prompt transcript is invalid")
            content = item["content"]
            if item["role"] != "system":
                try:
                    structured_content = json.loads(content)
                except (TypeError, ValueError):
                    structured_content = None
                inspected_content = (
                    structured_content if structured_content is not None else content
                )
                if self._prompt_snapshot_contains_forbidden_content(inspected_content):
                    raise InvalidControlPlaneInput(
                        "persisted provider prompt transcript is invalid"
                    )
            provider_messages.append(
                {
                    "role": str(item["role"]),
                    "content": content,
                }
            )
        if provider_messages[0] != {
            "role": "system",
            "content": system_prompt_content,
        } or any(message["role"] == "system" for message in provider_messages[1:]):
            raise InvalidControlPlaneInput("persisted provider prompt transcript is invalid")
        transcript_json = canonical_json({"messages": provider_messages})
        if (
            len(transcript_json.encode("utf-8")) > _PROMPT_SNAPSHOT_MAX_TRANSCRIPT_BYTES
            or hashlib.sha256(transcript_json.encode("utf-8")).hexdigest()
            != str(row["transcript_sha256"])
            or self._prompt_snapshot_contains_unredacted_secret(provider_messages)
        ):
            raise InvalidControlPlaneInput("persisted provider prompt identity is invalid")

        raw_redactions = row["redactions"]
        if not isinstance(raw_redactions, list) or len(raw_redactions) > 64:
            raise InvalidControlPlaneInput("persisted prompt redaction metadata is invalid")
        redactions: list[dict[str, str]] = []
        for item in raw_redactions:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"path", "reason", "replacement"}
                or not isinstance(item["path"], str)
                or _PROMPT_SNAPSHOT_REDACTION_PATH.fullmatch(item["path"]) is None
                or len(item["path"]) > 256
                or not isinstance(item["reason"], str)
                or item["reason"] not in _PROMPT_SNAPSHOT_REDACTION_REASONS
                or not isinstance(item["replacement"], str)
                or _PROMPT_SNAPSHOT_REDACTION_MARKER.fullmatch(item["replacement"]) is None
                or len(item["replacement"]) > 128
                or self._prompt_snapshot_contains_sensitive_text(item["path"])
                or self._prompt_snapshot_contains_sensitive_text(item["reason"])
            ):
                raise InvalidControlPlaneInput("persisted prompt redaction metadata is invalid")
            path_match = _PROMPT_SNAPSHOT_REDACTION_PATH.fullmatch(item["path"])
            assert path_match is not None
            redacted_value = self._prompt_snapshot_redaction_value(
                path_match=path_match,
                provider_messages=provider_messages,
            )
            if not self._prompt_snapshot_redaction_matches(redacted_value, item["replacement"]):
                raise InvalidControlPlaneInput("persisted prompt redaction metadata is invalid")
            redactions.append(
                {
                    "path": item["path"],
                    "reason": item["reason"],
                    "replacement": item["replacement"],
                }
            )
        if (
            len(canonical_json({"redactions": redactions}).encode("utf-8"))
            > _PROMPT_SNAPSHOT_MAX_REDACTIONS_BYTES
            or self._prompt_snapshot_contains_forbidden_content({"redactions": redactions})
        ):
            raise InvalidControlPlaneInput("persisted prompt redaction metadata is invalid")
        return AgentPromptSnapshotRecord(
            organization_id=str(row["organization_id"]),
            execution_id=str(row["execution_id"]),
            campaign_run_id=str(row["campaign_run_id"]),
            attempt_id=(str(row["attempt_id"]) if row["attempt_id"] is not None else None),
            agent_role=agent_role,
            system_prompt_version=str(row["system_prompt_version"]),
            system_prompt_sha256=system_prompt_sha256,
            system_prompt_content=system_prompt_content,
            provider_messages=tuple(provider_messages),
            transcript_sha256=str(row["transcript_sha256"]),
            redactions=tuple(redactions),
            created_at=row["created_at"],
        )

    # ------------------------------------------------------------------ internal validation / rows

    @staticmethod
    def _require_permission(principal: Principal, permission: str) -> None:
        if (
            not isinstance(principal, Principal)
            or permission not in principal.organization_permissions
        ):
            raise AuthorizationDeniedError("verified principal lacks required custom permission")

    @staticmethod
    def _require_any_permission(principal: Principal, *permissions: str) -> None:
        if not isinstance(
            principal, Principal
        ) or not principal.organization_permissions.intersection(permissions):
            raise AuthorizationDeniedError("verified principal lacks required custom permission")

    @staticmethod
    def _version_key(version: str) -> tuple[int, int, int]:
        try:
            parts = tuple(int(part) for part in version.split("."))
        except (AttributeError, ValueError) as exc:
            raise InvalidControlPlaneInput("version is invalid") from exc
        if len(parts) != 3:
            raise InvalidControlPlaneInput("version is invalid")
        return parts  # type: ignore[return-value]

    @staticmethod
    def _contains_secret(value: str) -> bool:
        if not isinstance(value, str):
            return True
        return any(
            pattern.search(value) is not None
            for pattern in (
                _BEARER_SECRET,
                _JWT_SECRET,
                _PROVIDER_SECRET,
                _COOKIE_SECRET,
                _LABELED_SECRET,
                _URL_USERINFO_SECRET,
                _CREDENTIAL_REFERENCE_SECRET,
                _AWS_ACCESS_KEY_SECRET,
                _GOOGLE_API_KEY_SECRET,
                _GITHUB_TOKEN_SECRET,
                _GITLAB_TOKEN_SECRET,
                _SLACK_TOKEN_SECRET,
                _STRIPE_LIVE_KEY_SECRET,
                _PRIVATE_KEY_SECRET,
            )
        )

    @staticmethod
    def _prompt_snapshot_key(value: object) -> str:
        text = str(value)
        snake_case = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
        return re.sub(r"[^A-Za-z0-9]+", "_", snake_case).strip("_").lower()

    @classmethod
    def _prompt_snapshot_contains_unredacted_secret(cls, value: object) -> bool:
        if isinstance(value, Mapping):
            return any(
                cls._prompt_snapshot_contains_unredacted_secret(key)
                or cls._prompt_snapshot_contains_unredacted_secret(item)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(cls._prompt_snapshot_contains_unredacted_secret(item) for item in value)
        if not isinstance(value, str):
            return False
        inspected = _PROMPT_SNAPSHOT_REDACTED_SECRET_LINE.sub("", value)
        return cls._contains_secret(inspected)

    @classmethod
    def _prompt_snapshot_contains_sensitive_text(cls, value: str) -> bool:
        if cls._prompt_snapshot_contains_unredacted_secret(value):
            return True
        if any(
            pattern.search(value) is not None for pattern in _PROMPT_SNAPSHOT_HIGH_CONFIDENCE_PHI
        ):
            return True
        for match in _PROMPT_SNAPSHOT_EMAIL.finditer(value):
            domain = match.group("domain").lower()
            if not (
                domain in {"example.com", "example.net", "example.org"}
                or domain.endswith(".example")
                or domain.endswith(".test")
            ):
                return True
        for match in _PROMPT_SNAPSHOT_PHONE.finditer(value):
            if not (match.group("exchange") == "555" and 100 <= int(match.group("line")) <= 199):
                return True
        return False

    @classmethod
    def _prompt_snapshot_contains_forbidden_content(
        cls,
        value: object,
        *,
        inside_target_evidence: bool = False,
    ) -> bool:
        """Reject explicit non-synthetic claims and credential fields, not clinical text.

        Every runnable target is already authorized only after its synthetic-data attestation is
        verified. Prompt snapshots therefore must preserve the exact synthetic clinical evidence
        sent to the Judge; pattern-matching labels such as ``DOB`` or ``MRN`` here both destroys
        useful evidence and can abort an otherwise valid campaign. Credential screening remains
        independent and fail-closed.
        """

        def is_explicitly_safe_sensitive_value(item: object) -> bool:
            if item is None:
                return True
            if isinstance(item, str):
                normalized = item.strip()
                return (
                    not normalized
                    or _PROMPT_SNAPSHOT_REDACTION_MARKER.fullmatch(normalized) is not None
                    or _PROMPT_SNAPSHOT_SYNTHETIC_VALUE.fullmatch(normalized) is not None
                )
            if isinstance(item, (list, tuple)):
                return all(is_explicitly_safe_sensitive_value(member) for member in item)
            return False

        if isinstance(value, Mapping):
            for key, item in value.items():
                raw_key = str(key)
                normalized_key = cls._prompt_snapshot_key(raw_key)
                if (
                    (normalized_key == "contains_real_phi" and item is not False)
                    or (normalized_key == "synthetic_data_only" and item is not True)
                    or (
                        normalized_key
                        in {
                            "access_token",
                            "api_key",
                            "authorization",
                            "authorization_header",
                            "cookie",
                            "credential_ref",
                            "credential_reference",
                            "credentials",
                            "password",
                            "refresh_token",
                            "secret",
                            "session_token",
                            "set_cookie",
                        }
                        and not is_explicitly_safe_sensitive_value(item)
                    )
                ):
                    return True
                if cls._prompt_snapshot_contains_forbidden_content(
                    item,
                    inside_target_evidence=(
                        inside_target_evidence
                        or normalized_key in {"target_evidence", "target_result"}
                    ),
                ):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            return any(
                cls._prompt_snapshot_contains_forbidden_content(
                    item,
                    inside_target_evidence=inside_target_evidence,
                )
                for item in value
            )
        return False

    @staticmethod
    def _prompt_snapshot_redaction_value(
        *,
        path_match: re.Match[str],
        provider_messages: Sequence[Mapping[str, str]],
    ) -> object:
        message_index = int(path_match.group("message_index"))
        if message_index >= len(provider_messages):
            raise InvalidControlPlaneInput("prompt redaction metadata is invalid")
        value: object = provider_messages[message_index]["content"]
        tail = path_match.group("tail")
        if tail:
            try:
                value = json.loads(str(value))
            except (TypeError, ValueError) as exc:
                raise InvalidControlPlaneInput("prompt redaction metadata is invalid") from exc
            for token in _PROMPT_SNAPSHOT_REDACTION_PATH_TOKEN.finditer(tail):
                key, index = token.groups()
                if key is not None and isinstance(value, Mapping) and key in value:
                    value = value[key]
                elif index is not None and isinstance(value, list) and int(index) < len(value):
                    value = value[int(index)]
                else:
                    raise InvalidControlPlaneInput("prompt redaction metadata is invalid")
        return value

    @staticmethod
    def _prompt_snapshot_redaction_matches(value: object, replacement: str) -> bool:
        if isinstance(value, str):
            return replacement in value
        return value == replacement

    @classmethod
    def _bounded_agent_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        label: str,
    ) -> dict[str, Any]:
        """Keep activity records compact, JSON-safe, and credential-free."""

        if not isinstance(payload, Mapping):
            raise InvalidControlPlaneInput(f"{label} must be an object")
        normalized = dict(payload)
        try:
            encoded = canonical_json(normalized)
        except (TypeError, ValueError) as exc:
            raise InvalidControlPlaneInput(f"{label} must be canonical JSON") from exc
        if len(encoded.encode("utf-8")) > 16_384:
            raise InvalidControlPlaneInput(f"{label} exceeds 16 KiB")
        if cls._prompt_snapshot_contains_unredacted_secret(normalized):
            raise InvalidControlPlaneInput(f"{label} contains credential material")
        return normalized

    @classmethod
    def _agent_payload_sha256(
        cls,
        payload: Mapping[str, Any],
        *,
        label: str,
    ) -> str:
        """Hash a model payload without persisting it or forcing it into the 16 KiB detail bound."""

        if not isinstance(payload, Mapping):
            raise InvalidControlPlaneInput(f"{label} must be an object")
        try:
            encoded = canonical_json(dict(payload))
        except (TypeError, ValueError) as exc:
            raise InvalidControlPlaneInput(f"{label} must be canonical JSON") from exc
        encoded_bytes = encoded.encode("utf-8")
        if len(encoded_bytes) > 262_144:
            raise InvalidControlPlaneInput(f"{label} exceeds 256 KiB")
        if cls._prompt_snapshot_contains_unredacted_secret(payload):
            raise InvalidControlPlaneInput(f"{label} contains credential material")
        return hashlib.sha256(encoded_bytes).hexdigest()

    @classmethod
    def _normalize_agent_prompt_snapshot(
        cls,
        *,
        agent_role: AgentRole,
        input_payload: Mapping[str, Any],
        authorized_prompt_sha256: str,
        system_prompt_version: str | None,
        system_prompt_sha256: str | None,
        system_prompt_content: str | None,
        provider_messages: Sequence[Mapping[str, Any]] | None,
        redactions: Sequence[Mapping[str, Any]],
    ) -> tuple[str, str, str, list[dict[str, str]], str, list[dict[str, str]]]:
        """Validate exact, bounded, package-owned prompt evidence before it becomes durable."""

        if cls._prompt_snapshot_contains_forbidden_content(input_payload):
            raise InvalidControlPlaneInput(
                "prompt snapshot input contains forbidden PHI, credential, "
                "or target-response fields"
            )
        try:
            trusted_prompt = resolve_hosted_prompt(agent_role, authorized_prompt_sha256)
        except ValueError as exc:
            raise InvalidControlPlaneInput("prompt snapshot identity is not package-owned") from exc
        supplied = (
            system_prompt_version,
            system_prompt_sha256,
            system_prompt_content,
            provider_messages,
        )
        if all(value is None for value in supplied):
            system_prompt_version = trusted_prompt.version
            system_prompt_sha256 = trusted_prompt.sha256
            system_prompt_content = trusted_prompt.content
            provider_messages = (
                {"role": "system", "content": trusted_prompt.content},
                {"role": "user", "content": canonical_json(dict(input_payload))},
            )
        elif any(value is None for value in supplied):
            raise InvalidControlPlaneInput("prompt snapshot evidence is incomplete")
        if (
            not isinstance(system_prompt_version, str)
            or system_prompt_version != trusted_prompt.version
            or not isinstance(system_prompt_sha256, str)
            or system_prompt_sha256 != authorized_prompt_sha256
            or not isinstance(system_prompt_content, str)
            or system_prompt_content != trusted_prompt.content
            or hashlib.sha256(system_prompt_content.encode("utf-8")).hexdigest()
            != system_prompt_sha256
            or cls._prompt_snapshot_contains_sensitive_text(system_prompt_content)
        ):
            raise InvalidControlPlaneInput(
                "prompt snapshot content differs from its immutable identity"
            )
        system_prompt_bytes = system_prompt_content.encode("utf-8")
        if not 1 <= len(system_prompt_bytes) <= 1_048_576:
            raise InvalidControlPlaneInput("system prompt is outside its storage bound")

        if (
            isinstance(provider_messages, (str, bytes))
            or not isinstance(provider_messages, Sequence)
            or not 1 <= len(provider_messages) <= _PROMPT_SNAPSHOT_MAX_MESSAGES
        ):
            raise InvalidControlPlaneInput("provider prompt transcript has invalid bounds")
        normalized_messages: list[dict[str, str]] = []
        for message in provider_messages:
            if not isinstance(message, Mapping) or set(message) != {"role", "content"}:
                raise InvalidControlPlaneInput(
                    "provider prompt transcript message has invalid shape"
                )
            role = message["role"]
            content = message["content"]
            if (
                not isinstance(role, str)
                or role not in _PROMPT_SNAPSHOT_MESSAGE_ROLES
                or not isinstance(content, str)
                or "\x00" in content
            ):
                raise InvalidControlPlaneInput("provider prompt transcript message is unsafe")
            if role != "system":
                if cls._prompt_snapshot_contains_unredacted_secret(content):
                    raise InvalidControlPlaneInput(
                        "provider prompt transcript contains credential material"
                    )
                try:
                    structured_content = json.loads(content)
                except (TypeError, ValueError):
                    structured_content = None
                inspected_content = (
                    structured_content if structured_content is not None else content
                )
                if cls._prompt_snapshot_contains_forbidden_content(inspected_content):
                    raise InvalidControlPlaneInput(
                        "provider prompt transcript contains forbidden PHI, credential, "
                        "or target-response fields"
                    )
            normalized_messages.append({"role": role, "content": content})
        if normalized_messages[0] != {
            "role": "system",
            "content": system_prompt_content,
        } or any(message["role"] == "system" for message in normalized_messages[1:]):
            raise InvalidControlPlaneInput(
                "provider prompt transcript does not begin with its exact system prompt"
            )
        canonical_input = canonical_json(dict(input_payload))
        if not any(
            message["role"] == "user" and message["content"] == canonical_input
            for message in normalized_messages
        ):
            raise InvalidControlPlaneInput(
                "provider prompt transcript differs from the exact execution input"
            )

        if (
            isinstance(redactions, (str, bytes))
            or not isinstance(redactions, Sequence)
            or len(redactions) > _PROMPT_SNAPSHOT_MAX_REDACTIONS
        ):
            raise InvalidControlPlaneInput("prompt redaction metadata has invalid bounds")
        normalized_redactions: list[dict[str, str]] = []
        for redaction in redactions:
            if not isinstance(redaction, Mapping) or set(redaction) != {
                "path",
                "reason",
                "replacement",
            }:
                raise InvalidControlPlaneInput("prompt redaction metadata has invalid shape")
            path = redaction["path"]
            reason = redaction["reason"]
            replacement = redaction["replacement"]
            path_match = (
                _PROMPT_SNAPSHOT_REDACTION_PATH.fullmatch(path) if isinstance(path, str) else None
            )
            if (
                path_match is None
                or len(path) > 256
                or not isinstance(reason, str)
                or reason not in _PROMPT_SNAPSHOT_REDACTION_REASONS
                or not isinstance(replacement, str)
                or _PROMPT_SNAPSHOT_REDACTION_MARKER.fullmatch(replacement) is None
                or len(replacement) > 128
                or cls._prompt_snapshot_contains_sensitive_text(path)
                or cls._prompt_snapshot_contains_sensitive_text(reason)
            ):
                raise InvalidControlPlaneInput("prompt redaction metadata is invalid")
            redacted_value = cls._prompt_snapshot_redaction_value(
                path_match=path_match,
                provider_messages=normalized_messages,
            )
            if not cls._prompt_snapshot_redaction_matches(redacted_value, replacement):
                raise InvalidControlPlaneInput("prompt redaction metadata is invalid")
            normalized_redactions.append(
                {
                    "path": path,
                    "reason": reason,
                    "replacement": replacement,
                }
            )

        transcript_json = canonical_json({"messages": normalized_messages})
        redactions_json = canonical_json({"redactions": normalized_redactions})
        if len(transcript_json.encode("utf-8")) > _PROMPT_SNAPSHOT_MAX_TRANSCRIPT_BYTES:
            raise InvalidControlPlaneInput("provider prompt transcript exceeds 1.5 MiB")
        if len(redactions_json.encode("utf-8")) > _PROMPT_SNAPSHOT_MAX_REDACTIONS_BYTES:
            raise InvalidControlPlaneInput("prompt redaction metadata exceeds 16 KiB")
        if cls._prompt_snapshot_contains_unredacted_secret(normalized_messages):
            raise InvalidControlPlaneInput(
                "provider prompt transcript contains credential material"
            )
        if cls._prompt_snapshot_contains_forbidden_content({"redactions": normalized_redactions}):
            raise InvalidControlPlaneInput(
                "prompt redaction metadata contains forbidden PHI or credential material"
            )
        for redaction in normalized_redactions:
            if transcript_json.count(redaction["replacement"]) < 1:
                raise InvalidControlPlaneInput(
                    "prompt redaction metadata does not identify persisted text"
                )
        return (
            system_prompt_version,
            system_prompt_sha256,
            system_prompt_content,
            normalized_messages,
            hashlib.sha256(transcript_json.encode("utf-8")).hexdigest(),
            normalized_redactions,
        )

    @classmethod
    def _insert_agent_prompt_snapshot(
        cls,
        connection: Connection,
        *,
        organization_id: str,
        execution_id: str,
        campaign_run_id: str,
        attempt_id: str | None,
        agent_role: AgentRole,
        input_payload: Mapping[str, Any],
        authorized_prompt_sha256: str,
        system_prompt_version: str | None,
        system_prompt_sha256: str | None,
        system_prompt_content: str | None,
        provider_messages: Sequence[Mapping[str, Any]] | None,
        redactions: Sequence[Mapping[str, Any]],
    ) -> None:
        (
            prompt_version,
            prompt_sha256,
            prompt_content,
            messages,
            transcript_sha256,
            normalized_redactions,
        ) = cls._normalize_agent_prompt_snapshot(
            agent_role=agent_role,
            input_payload=input_payload,
            authorized_prompt_sha256=authorized_prompt_sha256,
            system_prompt_version=system_prompt_version,
            system_prompt_sha256=system_prompt_sha256,
            system_prompt_content=system_prompt_content,
            provider_messages=provider_messages,
            redactions=redactions,
        )
        connection.execute(
            text(
                "INSERT INTO agent_prompt_snapshots "
                "(organization_id, execution_id, campaign_run_id, attempt_id, agent_role, "
                "system_prompt_version, system_prompt_sha256, system_prompt_content, "
                "provider_messages, transcript_sha256, redactions) VALUES "
                "(:org, :execution, :run, :attempt, :role, :prompt_version, :prompt_sha, "
                ":prompt_content, CAST(:messages AS jsonb), :transcript_sha, "
                "CAST(:redactions AS jsonb))"
            ),
            {
                "org": organization_id,
                "execution": execution_id,
                "run": campaign_run_id,
                "attempt": attempt_id,
                "role": agent_role,
                "prompt_version": prompt_version,
                "prompt_sha": prompt_sha256,
                "prompt_content": prompt_content,
                "messages": json.dumps(
                    messages,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                "transcript_sha": transcript_sha256,
                "redactions": json.dumps(
                    normalized_redactions,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            },
        )

    @staticmethod
    def _validate_judge_calibration_lineage(
        *,
        agent_role: AgentRole,
        calibration_id: str | None,
        calibration_state: str | None,
    ) -> None:
        if agent_role != "judge":
            if calibration_id is not None or calibration_state is not None:
                raise InvalidControlPlaneInput(
                    "Judge calibration lineage is invalid for a non-Judge execution"
                )
            return
        if calibration_state not in _JUDGE_CALIBRATION_STATES:
            raise InvalidControlPlaneInput("hosted Judge requires an explicit calibration state")
        if calibration_state == "unavailable":
            if calibration_id is not None:
                raise InvalidControlPlaneInput(
                    "unavailable Judge calibration cannot claim an artifact"
                )
            return
        if (
            not isinstance(calibration_id, str)
            or _JUDGE_CALIBRATION_ID.fullmatch(calibration_id) is None
        ):
            raise InvalidControlPlaneInput("Judge calibration artifact identity is invalid")

    @staticmethod
    def _validate_agent_parent(
        connection: Connection,
        *,
        organization_id: str,
        run_id: str,
        parent_execution_id: str | None,
    ) -> None:
        if parent_execution_id is None:
            return
        parent = (
            connection.execute(
                text(
                    "SELECT organization_id, campaign_run_id FROM agent_executions "
                    "WHERE execution_id = :execution_id"
                ),
                {"execution_id": parent_execution_id},
            )
            .mappings()
            .one_or_none()
        )
        if (
            parent is None
            or parent["organization_id"] != organization_id
            or parent["campaign_run_id"] != run_id
        ):
            raise InvalidControlPlaneInput(
                "parent agent execution must belong to the same campaign"
            )

    @staticmethod
    def _hosted_terminal_matches(
        row: Mapping[str, Any],
        *,
        returned_model: str | None,
        upstream_provider: str | None,
        provider_request_id: str | None,
        input_tokens: int | None,
        output_tokens: int | None,
        reasoning_tokens: int | None,
        measured_cost: Decimal | None,
        cost_measurement_state: str,
        physical_attempts: int | None,
        oracle_agreement: bool | None,
        decision_authority: str | None,
    ) -> bool:
        return bool(
            row["returned_model"] == returned_model
            and row["upstream_provider"] == upstream_provider
            and row["provider_request_id"] == provider_request_id
            and row["input_tokens"] == input_tokens
            and row["output_tokens"] == output_tokens
            and row["reasoning_tokens"] == reasoning_tokens
            and (Decimal(str(row["measured_cost"])) if row["measured_cost"] is not None else None)
            == measured_cost
            and row["cost_measurement_state"] == cost_measurement_state
            and row["physical_attempts"] == physical_attempts
            and row["oracle_agreement"] == oracle_agreement
            and row["decision_authority"] == decision_authority
        )

    def _agent_acceptance_run_row(
        self,
        connection: Connection,
        *,
        run_id: str,
        for_update: bool,
    ) -> Mapping[str, Any]:
        if not isinstance(run_id, str) or not run_id.startswith("AR-"):
            raise InvalidControlPlaneInput("agent acceptance run identity is invalid")
        lock_clause = " FOR UPDATE OF r" if for_update else ""
        row = (
            connection.execute(
                text(
                    "SELECT r.*, "
                    "(r.acceptance_expires_at > clock_timestamp()) AS acceptance_live, "
                    "(SELECT state FROM campaign_run_events e "
                    "WHERE e.organization_id = r.organization_id "
                    "AND e.run_id = r.run_id ORDER BY e.id DESC LIMIT 1) AS state "
                    "FROM campaign_runs r WHERE r.run_id = :run_id" + lock_clause
                ),
                {"run_id": run_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("agent acceptance run does not exist")
        if (
            row["run_kind"] != "agent_acceptance"
            or row["authorization_request_id"] is not None
            or row["scope_hash"] is not None
            or row["launcher_user_id"] is not None
            or row["launcher_session_id"] is not None
            or not isinstance(row["acceptance_actor_id"], str)
            or _AGENT_ACCEPTANCE_ACTOR.fullmatch(row["acceptance_actor_id"]) is None
            or not isinstance(row["acceptance_expires_at"], datetime.datetime)
            or row["state"] is None
        ):
            raise AuthorizationDeniedError("agent acceptance authority is malformed")
        for column in (
            "acceptance_configuration_sha256",
            "acceptance_generation_policy_sha256",
            "acceptance_context_sha256",
            "acceptance_attempt_id",
        ):
            if not isinstance(row[column], str) or _SHA256.fullmatch(row[column]) is None:
                raise AuthorizationDeniedError("agent acceptance authority hash is invalid")
        provenance = row["acceptance_provenance"]
        if not isinstance(provenance, Mapping) or dict(provenance) != _AGENT_ACCEPTANCE_PROVENANCE:
            raise AuthorizationDeniedError("agent acceptance provenance is invalid")
        self._agent_acceptance_limits_from_row(row)
        return row

    @staticmethod
    def _agent_acceptance_limits_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
        raw_limits = row["acceptance_limits"]
        if not isinstance(raw_limits, Mapping):
            raise AuthorizationDeniedError("agent acceptance limits are invalid")
        limits = dict(raw_limits)
        version = limits.get("schema_version")
        if not isinstance(version, str) or limits != _closed_agent_acceptance_limits(version):
            raise AuthorizationDeniedError(
                "agent acceptance limits differ from the closed runtime envelope"
            )
        return limits

    def _authorized_agent_acceptance_role(
        self,
        connection: Connection,
        *,
        run_id: str,
        agent_role: AgentRole,
        for_update: bool = False,
    ) -> AuthorizedAgentAcceptanceRoleConfiguration:
        row = self._agent_acceptance_run_row(
            connection,
            run_id=run_id,
            for_update=for_update,
        )
        limits = self._agent_acceptance_limits_from_row(row)
        acceptance_roles = _agent_acceptance_roles_for_version(str(limits["schema_version"]))
        if agent_role not in acceptance_roles:
            raise AuthorizationDeniedError("agent role is outside the live-acceptance allowlist")
        if row["state"] != "running":
            raise AuthorizationDeniedError("agent acceptance run is not executable")
        if not row["acceptance_live"]:
            raise AuthorizationDeniedError("agent acceptance authority has expired")
        configuration = self._stored_hosted_configuration(
            connection,
            organization_id=str(row["organization_id"]),
            configuration_sha256=str(row["acceptance_configuration_sha256"]),
        )
        expected_limits = _canonical_agent_acceptance_limits_for_configuration(configuration)
        if limits != expected_limits:
            raise AuthorizationDeniedError(
                "agent acceptance limits differ from hosted configuration"
            )
        role = next(
            (item for item in configuration.roles if item.role == agent_role),
            None,
        )
        if role is None:
            raise AuthorizationDeniedError(
                "agent role is absent from the acceptance configuration set"
            )
        return AuthorizedAgentAcceptanceRoleConfiguration(
            organization_id=str(row["organization_id"]),
            run_id=run_id,
            acceptance_attempt_id=str(row["acceptance_attempt_id"]),
            configuration=configuration,
            role_configuration=role,
            generation_policy_sha256=str(row["acceptance_generation_policy_sha256"]),
            acceptance_context_sha256=str(row["acceptance_context_sha256"]),
            limits=limits,
            expires_at=row["acceptance_expires_at"],
        )

    @staticmethod
    def _validate_acceptance_parent(
        connection: Connection,
        *,
        authority: AuthorizedAgentAcceptanceRoleConfiguration,
        agent_role: AgentRole,
        parent_execution_id: str | None,
    ) -> None:
        version = str(authority.limits["schema_version"])
        if version == "1":
            parent_roles: Mapping[AgentRole, AgentRole | None] = {
                "orchestrator": None,
                "judge": "orchestrator",
                "documentation": "judge",
            }
        else:
            parent_roles = {
                "orchestrator": None,
                "red_team": "orchestrator",
                "judge": "red_team",
                "documentation": "judge",
            }
        try:
            expected_parent_role = parent_roles[agent_role]
        except KeyError as exc:
            raise AuthorizationDeniedError(
                "agent role is outside the live-acceptance allowlist"
            ) from exc
        if expected_parent_role is None:
            if parent_execution_id is not None:
                raise InvalidControlPlaneInput(
                    "acceptance planner must be the execution lineage root"
                )
            return
        if parent_execution_id is None:
            raise InvalidControlPlaneInput("acceptance child requires its exact parent")
        parent = (
            connection.execute(
                text(
                    "SELECT organization_id, campaign_run_id, attempt_id, agent_role "
                    "FROM agent_executions WHERE execution_id = :execution_id"
                ),
                {"execution_id": parent_execution_id},
            )
            .mappings()
            .one_or_none()
        )
        if (
            parent is None
            or parent["organization_id"] != authority.organization_id
            or parent["campaign_run_id"] != authority.run_id
            or parent["attempt_id"] != authority.acceptance_attempt_id
            or parent["agent_role"] != expected_parent_role
        ):
            raise InvalidControlPlaneInput("acceptance child requires its exact parent")

    @staticmethod
    def _assert_agent_acceptance_has_no_target_traffic(
        connection: Connection,
        *,
        organization_id: str,
        run_id: str,
    ) -> None:
        target_requests = connection.execute(
            text(
                "SELECT count(*) FROM outbound_http_requests "
                "WHERE organization_id = :org AND campaign_run_id = :run"
            ),
            {
                "org": organization_id,
                "run": run_id,
            },
        ).scalar_one()
        if target_requests:
            raise AuthorizationDeniedError("agent acceptance run has forbidden target traffic")

    @staticmethod
    def _assert_agent_acceptance_call_available(
        connection: Connection,
        *,
        authority: AuthorizedAgentAcceptanceRoleConfiguration,
    ) -> None:
        role_name = authority.role_configuration.role
        stats = (
            connection.execute(
                text(
                    "SELECT count(i.invocation_id) AS global_calls, "
                    "count(i.invocation_id) FILTER "
                    "(WHERE i.agent_role = :role) AS role_calls, "
                    "coalesce(sum(e.measured_cost_usd), 0) AS global_cost, "
                    "coalesce(sum(e.measured_cost_usd) FILTER "
                    "(WHERE i.agent_role = :role), 0) AS role_cost, "
                    "count(i.invocation_id) FILTER "
                    "(WHERE e.event_id IS NULL) AS open_calls, "
                    "count(e.event_id) FILTER "
                    "(WHERE e.cost_measurement_state <> 'measured') AS unknown_costs "
                    "FROM provider_call_invocations i "
                    "LEFT JOIN provider_call_events e "
                    "ON e.organization_id = i.organization_id "
                    "AND e.invocation_id = i.invocation_id "
                    "WHERE i.organization_id = :org AND i.campaign_run_id = :run"
                ),
                {
                    "org": authority.organization_id,
                    "run": authority.run_id,
                    "role": role_name,
                },
            )
            .mappings()
            .one()
        )
        limits = authority.limits
        if int(stats["open_calls"]) > 0:
            raise AuthorizationDeniedError("agent acceptance global concurrency cap is exhausted")
        if int(stats["unknown_costs"]) > 0:
            raise AuthorizationDeniedError("agent acceptance spend is no longer fully measurable")
        if int(stats["global_calls"]) >= int(limits["global_call_cap"]):
            raise AuthorizationDeniedError("agent acceptance global call cap is exhausted")
        if int(stats["role_calls"]) >= int(limits["role_call_caps"][role_name]):
            raise AuthorizationDeniedError(f"{role_name} acceptance call cap is exhausted")
        global_cost = Decimal(str(stats["global_cost"]))
        role_cost = Decimal(str(stats["role_cost"]))
        global_cap = Decimal(str(limits["global_usd_cap"]))
        role_cap = Decimal(str(limits["role_usd_caps"][role_name]))
        # Reserve the closed acceptance sub-envelope, not the reviewed campaign role's full
        # multi-call budget.  The staged configuration was already proven to contain this role
        # cap when the authority was created and again when it was loaded above.  Charging its
        # larger 34-call budget here would make the otherwise-valid one-call sub-envelope
        # impossible to enter.
        if global_cost + role_cap > global_cap:
            raise AuthorizationDeniedError(
                "agent acceptance global spend reservation exceeds its cap"
            )
        if role_cost + role_cap > role_cap:
            raise AuthorizationDeniedError(
                f"{role_name} acceptance spend reservation exceeds its cap"
            )

    @staticmethod
    def _stored_hosted_configuration(
        connection: Connection,
        *,
        organization_id: str,
        configuration_sha256: str,
        expected_release_sha256: str | None = None,
    ) -> HostedConfigurationSet:
        row = (
            connection.execute(
                text(
                    "SELECT payload, release_sha256 FROM hosted_configuration_sets "
                    "WHERE organization_id = :org "
                    "AND configuration_sha256 = :configuration"
                ),
                {
                    "org": organization_id,
                    "configuration": configuration_sha256,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise AuthorizationDeniedError("hosted configuration set is not staged")
        if expected_release_sha256 is not None and row["release_sha256"] != expected_release_sha256:
            raise AuthorizationDeniedError(
                "hosted configuration set belongs to a different reviewed release"
            )
        try:
            configuration = HostedConfigurationSet.from_payload(dict(row["payload"]))
            validate_hosted_configuration_set(configuration)
        except (TypeError, ValueError) as exc:
            raise AuthorizationDeniedError(
                "hosted configuration-set integrity check failed"
            ) from exc
        if configuration.configuration_sha256 != configuration_sha256:
            raise AuthorizationDeniedError(
                "hosted configuration-set identity differs from stored content"
            )
        return configuration

    def _authorized_hosted_role(
        self,
        connection: Connection,
        *,
        run_id: str,
        agent_role: AgentRole,
    ) -> AuthorizedHostedRoleConfiguration:
        if agent_role not in AGENT_ROLES:
            raise InvalidControlPlaneInput("hosted agent role is invalid")
        row = (
            connection.execute(
                text(
                    "SELECT r.organization_id, r.scope_hash, r.launcher_user_id, "
                    "q.scope_payload, d.decision, d.approver_user_id, "
                    "d.self_approval_override, "
                    "(q.expires_at > clock_timestamp()) AS authorization_live, "
                    "(SELECT state FROM campaign_run_events e "
                    "WHERE e.organization_id = r.organization_id "
                    "AND e.run_id = r.run_id ORDER BY e.id DESC LIMIT 1) AS state "
                    "FROM campaign_runs r "
                    "JOIN campaign_authorization_requests q "
                    "ON q.organization_id = r.organization_id "
                    "AND q.request_id = r.authorization_request_id "
                    "AND q.scope_hash = r.scope_hash "
                    "JOIN campaign_authorization_decisions d "
                    "ON d.organization_id = q.organization_id "
                    "AND d.request_id = q.request_id "
                    "AND d.scope_hash = q.scope_hash "
                    "WHERE r.run_id = :run_id"
                ),
                {"run_id": run_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("campaign run does not exist")
        if row["decision"] != "approved" or not row["authorization_live"]:
            raise AuthorizationDeniedError("campaign run authorization is not live")
        if row["approver_user_id"] == row["launcher_user_id"] or row["self_approval_override"]:
            raise AuthorizationDeniedError("campaign run violates two-person control")
        if row["state"] not in {"queued", "running"}:
            raise AuthorizationDeniedError("campaign run is not executable")
        try:
            scope = scope_from_payload(dict(row["scope_payload"]))
        except (TypeError, ValueError) as exc:
            raise AuthorizationDeniedError("campaign run scope is invalid") from exc
        if scope.scope_hash() != row["scope_hash"]:
            raise AuthorizationDeniedError("campaign run scope hash is invalid")
        self._validate_scope(connection, row["organization_id"], scope)
        if scope.hosted_run is None:
            raise AuthorizationDeniedError("campaign run has no hosted configuration authority")
        configuration = self._stored_hosted_configuration(
            connection,
            organization_id=str(row["organization_id"]),
            configuration_sha256=scope.hosted_run.configuration_set_sha256,
        )
        role = next(
            (item for item in configuration.roles if item.role == agent_role),
            None,
        )
        if role is None:
            raise AuthorizationDeniedError(
                "hosted role is absent from the approved configuration set"
            )
        return AuthorizedHostedRoleConfiguration(
            organization_id=str(row["organization_id"]),
            run_id=run_id,
            configuration=configuration,
            role_configuration=role,
            authorization=scope.hosted_run,
        )

    @staticmethod
    def _agent_assignment_from_row(row: Mapping[str, Any]) -> AgentAssignment:
        try:
            created_at = row["created_at"]
            return AgentAssignment(
                role=row["agent_role"],
                provider=row["provider"],
                model=row["model"],
                execution_mode=row["execution_mode"],
                activation_state=row["activation_state"],
                version=int(row["version"]),
                configuration_sha256=row["configuration_sha256"],
                configured_at=created_at.astimezone(datetime.UTC).isoformat()
                if isinstance(created_at, datetime.datetime)
                else str(created_at),
                configured_by=row["actor_user_id"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationDeniedError("agent assignment is malformed") from exc

    @classmethod
    def _agent_assignment(
        cls,
        connection: Connection,
        organization_id: str,
        agent_role: str,
        *,
        version: int,
    ) -> AgentAssignment:
        row = (
            connection.execute(
                text(
                    "SELECT * FROM agent_configuration_versions "
                    "WHERE organization_id = :org AND agent_role = :role "
                    "AND version = :version"
                ),
                {
                    "org": organization_id,
                    "role": agent_role,
                    "version": version,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("agent assignment does not exist")
        return cls._agent_assignment_from_row(row)

    @staticmethod
    def _aggregate_lock(connection: Connection, identity: str) -> None:
        connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:identity, 0))"),
            {"identity": identity},
        )

    def _begin_command(
        self,
        connection: Connection,
        principal: Principal,
        command_type: str,
        idempotency_key: str,
        document: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str]:
        if (
            not isinstance(idempotency_key, str)
            or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise InvalidControlPlaneInput("idempotency key is invalid")
        request_hash = content_hash(document)
        identity = (
            f"idempotency:{principal.organization_id}:{principal.user_id}:"
            f"{command_type}:{idempotency_key}"
        )
        self._aggregate_lock(connection, identity)
        row = (
            connection.execute(
                text(
                    "SELECT request_hash, response_payload FROM command_idempotency "
                    "WHERE organization_id = :org AND actor_user_id = :user "
                    "AND command_type = :command AND idempotency_key = :key"
                ),
                {
                    "org": principal.organization_id,
                    "user": principal.user_id,
                    "command": command_type,
                    "key": idempotency_key,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None, request_hash
        if row["request_hash"] != request_hash:
            raise IdempotencyConflictError("idempotency key names different immutable input")
        return dict(row["response_payload"]), request_hash

    @staticmethod
    def _finish_command(
        connection: Connection,
        principal: Principal,
        command_type: str,
        idempotency_key: str,
        request_hash: str,
        response: dict[str, Any],
    ) -> None:
        connection.execute(
            text(
                "INSERT INTO command_idempotency "
                "(organization_id, actor_user_id, command_type, idempotency_key, request_hash, "
                "response_payload) VALUES "
                "(:org, :user, :command, :key, :request_hash, CAST(:response AS jsonb))"
            ),
            {
                "org": principal.organization_id,
                "user": principal.user_id,
                "command": command_type,
                "key": idempotency_key,
                "request_hash": request_hash,
                "response": canonical_json(response),
            },
        )

    @staticmethod
    def _audit(
        connection: Connection,
        organization_id: str,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        principal: Principal | None,
        payload: dict[str, Any],
        *,
        actor_user_id: str | None = None,
        actor_session_id: str | None = None,
    ) -> None:
        user_id = principal.user_id if principal is not None else actor_user_id
        session_id = principal.session_id if principal is not None else actor_session_id
        connection.execute(
            text(
                "INSERT INTO audit_events "
                "(organization_id, event_type, aggregate_type, aggregate_id, actor_user_id, "
                "actor_session_id, payload) VALUES "
                "(:org, :event, :aggregate_type, :aggregate_id, :user, :session, "
                "CAST(:payload AS jsonb))"
            ),
            {
                "org": organization_id,
                "event": event_type,
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "user": user_id,
                "session": session_id,
                "payload": canonical_json(payload),
            },
        )

    def _target_snapshot(
        self, connection: Connection, organization_id: str, target_id: str, version: str
    ) -> TargetSnapshotRecord:
        row = (
            connection.execute(
                text(
                    "SELECT organization_id, target_id, version, content_hash, created_at "
                    "FROM target_definitions WHERE organization_id = :org "
                    "AND target_id = :target AND version = :version"
                ),
                {"org": organization_id, "target": target_id, "version": version},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("target definition does not exist")
        return TargetSnapshotRecord(**dict(row))

    def _surface_snapshot(
        self, connection: Connection, organization_id: str, surface_id: str, version: str
    ) -> SurfaceSnapshotRecord:
        row = (
            connection.execute(
                text(
                    "SELECT organization_id, target_id, target_version, surface_id, version, "
                    "content_hash, created_at FROM attack_surface_definitions "
                    "WHERE organization_id = :org AND surface_id = :surface AND version = :version"
                ),
                {"org": organization_id, "surface": surface_id, "version": version},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("surface definition does not exist")
        return SurfaceSnapshotRecord(**dict(row))

    def _load_target(
        self, connection: Connection, organization_id: str, target_id: str, version: str
    ) -> tuple[TargetDefinition, TargetDefinition, tuple[str, ...]]:
        row = (
            connection.execute(
                text(
                    "SELECT payload, content_hash FROM target_definitions "
                    "WHERE organization_id = :org "
                    "AND target_id = :target AND version = :version"
                ),
                {"org": organization_id, "target": target_id, "version": version},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("target definition does not exist")
        payload = dict(row["payload"])
        if content_hash(payload) != row["content_hash"]:
            raise AuthorizationDeniedError("target definition integrity check failed")
        base = target_from_payload(payload)
        events = tuple(
            connection.execute(
                text(
                    "SELECT to_lifecycle FROM target_lifecycle_events "
                    "WHERE organization_id = :org AND target_id = :target "
                    "AND target_version = :version ORDER BY id ASC"
                ),
                {"org": organization_id, "target": target_id, "version": version},
            ).scalars()
        )
        if not events or events[0] != TargetLifecycle.DRAFT.value:
            raise AuthorizationDeniedError("target lifecycle history is invalid")
        current = replace(base, lifecycle=TargetLifecycle(events[-1]))
        return base, current, events

    def _load_surface(
        self,
        connection: Connection,
        organization_id: str,
        target_id: str,
        surface_id: str,
        version: str,
    ) -> AttackSurfaceDefinition:
        row = (
            connection.execute(
                text(
                    "SELECT payload, content_hash FROM attack_surface_definitions "
                    "WHERE organization_id = :org AND target_id = :target "
                    "AND surface_id = :surface AND version = :version"
                ),
                {
                    "org": organization_id,
                    "target": target_id,
                    "surface": surface_id,
                    "version": version,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("surface definition does not exist")
        payload = dict(row["payload"])
        if content_hash(payload) != row["content_hash"]:
            raise AuthorizationDeniedError("surface definition integrity check failed")
        surface = surface_from_payload(payload)
        states = tuple(
            connection.execute(
                text(
                    "SELECT to_enabled FROM surface_state_events WHERE organization_id = :org "
                    "AND target_id = :target AND surface_id = :surface "
                    "AND surface_version = :version ORDER BY id ASC"
                ),
                {
                    "org": organization_id,
                    "target": target_id,
                    "surface": surface_id,
                    "version": version,
                },
            ).scalars()
        )
        if not states:
            raise AuthorizationDeniedError("surface state history is invalid")
        return replace(surface, enabled=bool(states[-1]))

    def _build_scope_from_database(
        self,
        connection: Connection,
        organization_id: str,
        target_id: str,
        target_version: str,
        surface_id: str,
        surface_version: str,
        corpus_hash: str,
        caps: SafetyCaps,
        run_nonce: str,
        corpus_id: str = "m11-seed-corpus-v1",
        execution_profile: ExecutionProfile = ExecutionProfile.LIVE,
        hosted_run: HostedRunBinding | None = None,
    ) -> AuthorizationScope:
        base, target, events = self._load_target(
            connection, organization_id, target_id, target_version
        )
        if target.environment.value != self._environment:
            raise AuthorizationDeniedError("target environment does not match this control plane")
        if self._environment != TargetEnvironment.LOCAL.value and target.adapter_kind == "fake":
            raise AuthorizationDeniedError("fake targets are local-test-only")
        surface = self._load_surface(
            connection, organization_id, target_id, surface_id, surface_version
        )
        try:
            registry = TargetRegistry()
            registry.register_target(base)
            registry.register_surface(surface)
            for lifecycle in events[1:]:
                registry.transition_target(target_id, target_version, TargetLifecycle(lifecycle))
            scope = AuthorizationScope.for_definitions(
                target=target,
                surface=surface,
                corpus_hash=corpus_hash,
                caps=caps,
                run_nonce=run_nonce,
                corpus_id=corpus_id,
                execution_profile=execution_profile,
                hosted_run=hosted_run,
            )
            registry.resolve(scope)
            return scope
        except (TargetRegistryError, ValueError) as exc:
            raise AuthorizationDeniedError("target/surface scope is not dispatchable") from exc

    def _validate_scope(
        self, connection: Connection, organization_id: str, scope: AuthorizationScope
    ) -> None:
        expected = self._build_scope_from_database(
            connection,
            organization_id,
            scope.target_id,
            scope.target_version,
            scope.surface_id,
            scope.surface_version,
            scope.corpus_hash,
            scope.caps,
            scope.run_nonce,
            scope.corpus_id,
            scope.execution_profile,
            scope.hosted_run,
        )
        if expected.canonical_bytes() != scope.canonical_bytes():
            raise AuthorizationDeniedError("authorization scope differs from registry state")
        if scope.hosted_run is not None:
            row = connection.execute(
                text(
                    "SELECT payload FROM hosted_configuration_sets "
                    "WHERE organization_id = :org AND configuration_sha256 = :configuration"
                ),
                {
                    "org": organization_id,
                    "configuration": scope.hosted_run.configuration_set_sha256,
                },
            ).scalar_one_or_none()
            if row is None:
                raise AuthorizationDeniedError("hosted configuration set is not staged")
            try:
                configuration = HostedConfigurationSet.from_payload(dict(row))
                validate_hosted_configuration_set(configuration)
            except (TypeError, ValueError) as exc:
                raise AuthorizationDeniedError(
                    "hosted configuration-set integrity check failed"
                ) from exc
            binding = scope.hosted_run
            if (
                configuration.configuration_sha256 != binding.configuration_set_sha256
                or configuration.global_limits.max_calls != binding.provider_model_call_limit
                or format(configuration.global_limits.max_usd, "f")
                != binding.provider_model_spend_limit_usd
                or configuration.global_limits.max_retries != binding.provider_max_retries
                or configuration.global_limits.max_concurrency != binding.provider_max_concurrency
            ):
                raise AuthorizationDeniedError(
                    "hosted authorization caps differ from the immutable configuration set"
                )
            if scope.auth_mode.value == "session" and (
                scope.credential_ref is None
                or not scope.credential_ref.endswith(f"/{binding.session_generation}")
            ):
                raise AuthorizationDeniedError(
                    "session generation differs from the target credential binding"
                )

    @staticmethod
    def _validate_work_unit_coordinate(
        attempt_id: str,
        turn_index: int,
        retry_index: int,
    ) -> None:
        if not isinstance(attempt_id, str) or not attempt_id or len(attempt_id) > 64:
            raise InvalidControlPlaneInput("campaign work-unit attempt identity is invalid")
        for field, value in (("turn index", turn_index), ("retry index", retry_index)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidControlPlaneInput(
                    f"campaign work-unit {field} must be a non-negative integer"
                )

    @staticmethod
    def _work_unit_lease_hash(lease_token: Any) -> str:
        if not isinstance(lease_token, str) or not lease_token:
            raise AuthorizationDeniedError("campaign queue lease token is unavailable")
        return hashlib.sha256(lease_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _locked_work_unit_context(connection: Connection, job: Any) -> Any:
        row = (
            connection.execute(
                text(
                    "SELECT j.job_id, j.queue, j.status, j.campaign_run_id, j.attempts, "
                    "j.worker_id, j.lease_token, "
                    "(j.lease_expires_at > clock_timestamp()) AS lease_live, "
                    "r.organization_id, r.scope_hash, r.launcher_user_id, q.scope_payload, "
                    "(q.expires_at > clock_timestamp()) AS authorization_live, "
                    "d.decision, d.approver_user_id, d.self_approval_override, "
                    "(SELECT state FROM campaign_run_events e "
                    "WHERE e.organization_id = r.organization_id AND e.run_id = r.run_id "
                    "ORDER BY e.id DESC LIMIT 1) AS run_state "
                    "FROM jobs j JOIN campaign_runs r ON r.run_id = j.campaign_run_id "
                    "JOIN campaign_authorization_requests q "
                    "ON q.organization_id = r.organization_id "
                    "AND q.request_id = r.authorization_request_id "
                    "AND q.scope_hash = r.scope_hash "
                    "JOIN campaign_authorization_decisions d "
                    "ON d.organization_id = q.organization_id "
                    "AND d.request_id = q.request_id AND d.scope_hash = q.scope_hash "
                    "WHERE j.job_id = :job_id FOR UPDATE OF j"
                ),
                {"job_id": getattr(job, "job_id", None)},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise AuthorizationDeniedError("campaign queue job is unavailable")
        if (
            str(row["queue"]) != "agent_work"
            or str(row["status"]) != "leased"
            or row["lease_live"] is not True
            or row["authorization_live"] is not True
            or row["decision"] != "approved"
            or bool(row["self_approval_override"])
            or row["approver_user_id"] == row["launcher_user_id"]
            or row["campaign_run_id"] != getattr(job, "campaign_run_id", None)
            or row["worker_id"] != getattr(job, "worker_id", None)
            or row["lease_token"] != getattr(job, "lease_token", None)
            or row["attempts"] != getattr(job, "attempts", None)
        ):
            raise AuthorizationDeniedError("runner lease ownership is stale")
        return row

    @staticmethod
    def _sanitize_plaintext_rationale(value: str) -> str:
        """Return bounded plain text with common credential shapes removed before persistence."""

        if not isinstance(value, str):
            raise InvalidControlPlaneInput("rationale must be plain text")
        normalized = "".join(
            character if character.isprintable() or character == "\n" else " "
            for character in value
        ).strip()
        if not normalized or len(normalized) > _RATIONALE_MAX_LENGTH:
            raise InvalidControlPlaneInput("rationale must contain 1 to 2000 characters")
        for pattern in (
            _BEARER_SECRET,
            _JWT_SECRET,
            _PROVIDER_SECRET,
            _COOKIE_SECRET,
            _LABELED_SECRET,
            _URL_USERINFO_SECRET,
        ):
            normalized = pattern.sub("***REDACTED***", normalized)
        if len(normalized) > _RATIONALE_MAX_LENGTH:
            raise InvalidControlPlaneInput("redacted rationale exceeds 2000 characters")
        return normalized

    @staticmethod
    def _normalize_expiry(value: datetime.datetime) -> datetime.datetime:
        if not isinstance(value, datetime.datetime) or value.tzinfo is None:
            raise InvalidControlPlaneInput("authorization expiry must be timezone-aware")
        return value.astimezone(datetime.UTC)

    def _authorization_request(
        self,
        connection: Connection,
        organization_id: str,
        request_id: str,
        *,
        for_update: bool = False,
    ) -> AuthorizationRequestRecord:
        suffix = " FOR UPDATE" if for_update else ""
        row = (
            connection.execute(
                text(
                    "SELECT * FROM campaign_authorization_requests WHERE organization_id = :org "
                    "AND request_id = :request_id" + suffix
                ),
                {"org": organization_id, "request_id": request_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("authorization request does not exist")
        payload = dict(row["scope_payload"])
        if scope_from_payload(payload).scope_hash() != row["scope_hash"]:
            raise AuthorizationDeniedError("authorization request scope integrity check failed")
        return AuthorizationRequestRecord(
            request_id=row["request_id"],
            organization_id=row["organization_id"],
            scope_hash=row["scope_hash"],
            scope_payload=payload,
            launcher_user_id=row["launcher_user_id"],
            launcher_session_id=row["launcher_session_id"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _authorization_decision(
        connection: Connection, organization_id: str, decision_id: str
    ) -> AuthorizationDecisionRecord:
        row = (
            connection.execute(
                text(
                    "SELECT * FROM campaign_authorization_decisions WHERE organization_id = :org "
                    "AND decision_id = :decision_id"
                ),
                {"org": organization_id, "decision_id": decision_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("authorization decision does not exist")
        return AuthorizationDecisionRecord(
            decision_id=row["decision_id"],
            organization_id=row["organization_id"],
            request_id=row["request_id"],
            scope_hash=row["scope_hash"],
            decision=row["decision"],
            approver_user_id=row["approver_user_id"],
            approver_session_id=row["approver_session_id"],
            self_approval_override=bool(row["self_approval_override"]),
            created_at=row["created_at"],
        )

    def _compose_campaign_report(
        self,
        connection: Connection,
        *,
        organization_id: str,
        run_id: str,
        run_state: str,
    ) -> str | None:
        """Write the one report that names this whole run, from durable rows only.

        Called inside the transaction that records a terminal state, so a run that reached one
        always has its report and a run that did not never has a partial one.

        Composed by projection, never by narration: every value here is read back from `verdict`,
        `finding`, `vuln_reports` and the attempt rows in this same transaction. Nothing is
        summarised by a model and nothing is carried from process memory, so recomposing from
        unchanged state yields identical bytes and a Runner restart cannot change what a completed
        run is said to have found.

        Aborted and failed runs get a report too. They examined only part of their corpus, which is
        exactly why a reviewer needs to see what they did find together with the fact that coverage
        was partial — `run_state` carries that, and migration 0032 keeps such a report
        unpublishable.
        """

        if run_state not in {"complete", "aborted", "failed"}:
            return None
        existing = connection.execute(
            text(
                "SELECT report_id FROM campaign_reports "
                "WHERE organization_id = :org AND campaign_run_id = :run_id"
            ),
            {"org": organization_id, "run_id": run_id},
        ).scalar_one_or_none()
        if existing is not None:
            # Idempotent: a re-entered terminal transition must not rewrite a run's own history.
            return str(existing)

        totals = (
            connection.execute(
                text(
                    "SELECT count(*) FILTER (WHERE state IN "
                    "  ('EXPLOIT_CONFIRMED','EXPLOIT_LIKELY','NO_EXPLOIT_OBSERVED')) AS decisive, "
                    "count(*) FILTER (WHERE state = 'INDETERMINATE') AS indeterminate, "
                    "count(*) FILTER (WHERE state = 'ERROR') AS operational_errors, "
                    "count(*) AS attempts "
                    "FROM verdict WHERE organization_id = :org AND campaign_run_id = :run_id"
                ),
                {"org": organization_id, "run_id": run_id},
            )
            .mappings()
            .one()
        )
        # Read from the run's own authorization scope, which exists for every run regardless of
        # how it ended. campaign_run_summaries carries it too but only after a clean completion,
        # so it is unavailable on exactly the aborted and failed paths that also need a report.
        profile = connection.execute(
            text(
                "SELECT q.scope_payload->>'execution_profile' FROM campaign_runs cr "
                "JOIN campaign_authorization_requests q "
                "ON q.organization_id = cr.organization_id "
                "AND q.request_id = cr.authorization_request_id "
                "WHERE cr.organization_id = :org AND cr.run_id = :run_id"
            ),
            {"org": organization_id, "run_id": run_id},
        ).scalar_one_or_none()
        # Ordered by case so the payload is stable across recomposition rather than following
        # whatever order the run happened to adjudicate in.
        finding_rows = (
            connection.execute(
                text(
                    "SELECT f.finding_id, f.state AS finding_state, f.severity, f.category, "
                    "a.case_id, v.state AS verdict_state, v.rationale, v.criteria_hits, "
                    "vr.report_id "
                    "FROM finding_evidence_links l "
                    "JOIN finding f ON f.organization_id = l.organization_id "
                    "AND f.finding_id = l.finding_id "
                    "JOIN verdict v ON v.id = l.verdict_id "
                    "JOIN campaign_attempts a ON a.organization_id = l.organization_id "
                    "AND a.run_id = l.campaign_run_id AND a.attempt_id = l.attempt_id "
                    # Prefer the finding's own report; fall back to the report already documenting
                    # this case. A candidate that re-found a known case reuses that document
                    # instead of minting a duplicate, so without the fallback the run's report
                    # would list the finding with no way to reach its evidence.
                    "LEFT JOIN LATERAL ("
                    "  SELECT r.report_id FROM vuln_reports r "
                    "  WHERE r.organization_id = l.organization_id "
                    "  AND (r.finding_id = l.finding_id "
                    "       OR r.contract_payload->>'source_case_id' = a.case_id) "
                    "  ORDER BY (r.finding_id = l.finding_id) DESC, r.created_at "
                    "  LIMIT 1"
                    ") vr ON true "
                    "WHERE l.organization_id = :org AND l.campaign_run_id = :run_id "
                    "ORDER BY a.case_id, f.finding_id"
                ),
                {"org": organization_id, "run_id": run_id},
            )
            .mappings()
            .all()
        )

        findings: list[dict[str, Any]] = []
        candidate_count = 0
        confirmed_count = 0
        for row in finding_rows:
            confirmation_status = (
                "confirmed"
                if row["verdict_state"] == "EXPLOIT_CONFIRMED"
                else "candidate_unconfirmed"
            )
            if confirmation_status == "confirmed":
                confirmed_count += 1
            else:
                candidate_count += 1
            entry: dict[str, Any] = {
                "finding_id": str(row["finding_id"]),
                "source_case_id": str(row["case_id"]),
                "severity": str(row["severity"]),
                "category": str(row["category"]),
                "confirmation_status": confirmation_status,
            }
            # Absent rather than empty when the platform has none: an invented blank reads as
            # "the evaluator said nothing", which is a different claim from "none was recorded".
            if row["criteria_hits"]:
                entry["criteria_hits"] = [str(hit) for hit in row["criteria_hits"]]
            if row["rationale"]:
                entry["rationale"] = str(row["rationale"])
            if row["report_id"]:
                entry["report_id"] = str(row["report_id"])
            findings.append(entry)

        report_id = (
            "CR-"
            + hashlib.sha256(
                f"campaign-report:v1\0{organization_id}\0{run_id}".encode()
            ).hexdigest()
        )
        publication_state = (
            "draft_unpublished"
            if candidate_count == 0 and run_state == "complete"
            else "blocked_pending_human_approval"
        )
        payload: dict[str, Any] = {
            "schema_version": "1",
            "report_id": report_id,
            "campaign_run_id": run_id,
            "run_state": run_state,
            "execution_profile": str(profile) if profile in {"synthetic", "live"} else "live",
            "totals": {
                "attempt_count": int(totals["attempts"]),
                "decisive_verdict_count": int(totals["decisive"]),
                "indeterminate_verdict_count": int(totals["indeterminate"]),
                "operational_error_count": int(totals["operational_errors"]),
                "confirmed_finding_count": confirmed_count,
                "candidate_finding_count": candidate_count,
            },
            "findings": findings,
            "publication_state": publication_state,
        }
        try:
            validate_contract("campaign_report", payload)
        except Exception as exc:
            raise InvalidControlPlaneInput(
                f"campaign report fails its published contract: {exc}"
            ) from exc
        connection.execute(
            text(
                "INSERT INTO campaign_reports "
                "(organization_id, report_id, campaign_run_id, run_state, publication_state, "
                "candidate_finding_count, confirmed_finding_count, contract_payload) VALUES "
                "(:org, :report, :run_id, :run_state, :publication, :candidates, :confirmed, "
                "CAST(:payload AS jsonb)) ON CONFLICT DO NOTHING"
            ),
            {
                "org": organization_id,
                "report": report_id,
                "run_id": run_id,
                "run_state": run_state,
                "publication": publication_state,
                "candidates": candidate_count,
                "confirmed": confirmed_count,
                "payload": canonical_json(payload),
            },
        )
        return report_id

    def _campaign_run(
        self, connection: Connection, organization_id: str, run_id: str
    ) -> CampaignRunRecord:
        row = (
            connection.execute(
                text(
                    "SELECT r.*, (SELECT state FROM campaign_run_events e "
                    "WHERE e.organization_id = r.organization_id AND e.run_id = r.run_id "
                    "ORDER BY e.id DESC LIMIT 1) AS state FROM campaign_runs r "
                    "WHERE r.organization_id = :org AND r.run_id = :run_id"
                ),
                {"org": organization_id, "run_id": run_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None or row["state"] is None:
            raise RecordNotFoundError("campaign run does not exist")
        return self._campaign_run_from_row(row)

    @staticmethod
    def _campaign_run_from_row(row: Any) -> CampaignRunRecord:
        return CampaignRunRecord(
            run_id=row["run_id"],
            organization_id=row["organization_id"],
            authorization_request_id=row["authorization_request_id"],
            scope_hash=row["scope_hash"],
            launcher_user_id=row["launcher_user_id"],
            launcher_session_id=row["launcher_session_id"],
            state=row["state"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _campaign_attempt_from_row(row: Any) -> CampaignAttemptRecord:
        return CampaignAttemptRecord(
            run_id=row["run_id"],
            organization_id=row["organization_id"],
            attempt_id=row["attempt_id"],
            ordinal=row["ordinal"],
            case_id=row["case_id"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _work_unit_reservation_from_row(row: Any) -> CampaignWorkUnitReservationRecord:
        return CampaignWorkUnitReservationRecord(
            organization_id=row["organization_id"],
            run_id=row["run_id"],
            attempt_id=row["attempt_id"],
            turn_index=row["turn_index"],
            retry_index=row["retry_index"],
            job_id=row["job_id"],
            job_attempt=row["job_attempt"],
            worker_id=row["worker_id"],
            reserved_at=row["reserved_at"],
            observed_at=row["observed_at"],
            observation_outcome=row["observation_outcome"],
        )

    @staticmethod
    def _finding_decision(
        connection: Connection, organization_id: str, decision_id: str
    ) -> FindingDecisionRecord:
        row = (
            connection.execute(
                text(
                    "SELECT * FROM finding_decision_events WHERE organization_id = :org "
                    "AND decision_id = :decision_id"
                ),
                {"org": organization_id, "decision_id": decision_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise RecordNotFoundError("finding decision does not exist")
        return FindingDecisionRecord(
            decision_id=row["decision_id"],
            organization_id=row["organization_id"],
            finding_id=row["finding_id"],
            decision=row["decision"],
            actor_user_id=row["actor_user_id"],
            actor_session_id=row["actor_session_id"],
            rationale=row["rationale"],
            reason_code=row["reason_code"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _enqueue_campaign_job(
        connection: Connection, run_id: str, authorization_request_id: str, scope_hash: str
    ) -> None:
        payload = {
            "authorization_request_id": authorization_request_id,
            "campaign_run_id": run_id,
            "scope_hash": scope_hash,
        }
        payload_json = canonical_json(payload)
        identity = f"m3-job:v1\0agent_work\0{run_id}\0{_CAMPAIGN_JOB_ATTEMPT_ID}"
        job_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        fingerprint_document = {
            "max_attempts": 3,
            "payload": payload,
            "payload_schema": _CAMPAIGN_PAYLOAD_SCHEMA,
            "payload_version": _CAMPAIGN_PAYLOAD_VERSION,
            "priority": 0,
            "run_after": "immediate",
        }
        fingerprint = hashlib.sha256(
            json.dumps(
                fingerprint_document,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        connection.execute(
            text(
                "INSERT INTO jobs "
                "(job_id, queue, campaign_run_id, attempt_id, payload_schema, payload_version, "
                "payload, enqueue_fingerprint, priority, max_attempts) VALUES "
                "(:job_id, 'agent_work'::job_queue, :run_id, :attempt_id, :schema, :version, "
                "CAST(:payload AS jsonb), :fingerprint, 0, 3)"
            ),
            {
                "job_id": job_id,
                "run_id": run_id,
                "attempt_id": _CAMPAIGN_JOB_ATTEMPT_ID,
                "schema": _CAMPAIGN_PAYLOAD_SCHEMA,
                "version": _CAMPAIGN_PAYLOAD_VERSION,
                "payload": payload_json,
                "fingerprint": fingerprint,
            },
        )


__all__ = [
    "AgentAcceptanceRunIdentity",
    "AuthorizedAgentAcceptanceRoleConfiguration",
    "ControlPlaneStore",
    "GovernedAcceptanceRunIdentity",
    "canonical_agent_acceptance_limits",
    "canonical_governed_acceptance_limits",
]
