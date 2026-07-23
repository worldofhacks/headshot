"""Transactional, organization-scoped persistence for M1d human control-plane commands."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from sqlalchemy import Connection, Engine, text

from agentforge.auth.permissions import (
    AUDIT_READ,
    CAMPAIGN_ABORT,
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    FINDINGS_APPROVE,
    FINDINGS_RESOLVE,
    ROLE_GODMODE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal
from agentforge.control_plane.errors import (
    AuthorizationDeniedError,
    IdempotencyConflictError,
    InvalidControlPlaneInput,
    RecordConflictError,
    RecordNotFoundError,
)
from agentforge.control_plane.records import (
    AuditEventRecord,
    AuthorizationDecisionRecord,
    AuthorizationRequestRecord,
    AuthorizedRunRecord,
    CampaignAttemptRecord,
    CampaignRunRecord,
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
from agentforge.policy.recorder import (
    PERSISTED_EVIDENCE_COLUMNS,
    EvidenceIntegrityError,
    ExecutionRecorder,
)
from agentforge.target.registry import TargetRegistry, TargetRegistryError
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthorizationScope,
    ExecutionProfile,
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
_URL_USERINFO_SECRET = re.compile(r"(?i)https://[^\s/@:]+:[^\s/@]+@")
_RATIONALE_MAX_LENGTH = 2_000
_MAX_AUTHORIZATION_LIFETIME = datetime.timedelta(hours=24)
_CAMPAIGN_JOB_ATTEMPT_ID = "campaign"
_CAMPAIGN_PAYLOAD_SCHEMA = "campaign.execute"
_CAMPAIGN_PAYLOAD_VERSION = 1
_SHA256 = re.compile(r"\A[a-f0-9]{64}\Z")
_CASE_CATEGORIES = frozenset({"prompt_injection", "data_exfiltration", "tool_misuse"})
_ATTACK_CLASSES = frozenset({"boundary", "invariant", "regression"})
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


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
            if request.expires_at <= datetime.datetime.now(datetime.UTC):
                raise AuthorizationDeniedError("authorization request is expired")
            self_approval_override = (
                decision == "approved"
                and principal.user_id == request.launcher_user_id
                and principal.organization_role == ROLE_GODMODE
            )
            if decision == "approved":
                if principal.user_id == request.launcher_user_id and not self_approval_override:
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
            if request.expires_at <= datetime.datetime.now(datetime.UTC):
                raise AuthorizationDeniedError("approved authorization is expired")
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
            scope = scope_from_payload(request.scope_payload)
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
            if row["decision"] != "approved" or row["expires_at"] <= datetime.datetime.now(
                datetime.UTC
            ):
                raise AuthorizationDeniedError("campaign run authorization is not live")
            same_person = row["approver_user_id"] == row["launcher_user_id"]
            if same_person and not row["self_approval_override"]:
                raise AuthorizationDeniedError("campaign run violates two-person control")
            if row["self_approval_override"] and not same_person:
                raise AuthorizationDeniedError("campaign self-approval override is invalid")
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
            )
        )
        if metadata_supplied:
            if (
                not isinstance(case_content_hash, str)
                or _SHA256.fullmatch(case_content_hash) is None
            ):
                raise InvalidControlPlaneInput("case content hash is invalid")
            if category not in _CASE_CATEGORIES:
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
        else:
            normalized_mappings = None
            normalized_fixture = None
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
                ):
                    raise RecordConflictError("attempt metadata differs from immutable case")
                return self._campaign_attempt_from_row(existing)
            row = (
                connection.execute(
                    text(
                        "INSERT INTO campaign_attempts "
                        "(organization_id, run_id, attempt_id, ordinal, case_id, "
                        "case_content_hash, category, severity, attack_class, owasp_mappings, "
                        "fixture_provenance) VALUES "
                        "(:org, :run_id, :attempt_id, :ordinal, :case_id, :case_hash, :category, "
                        ":severity, :attack_class, CAST(:owasp AS jsonb), CAST(:fixture AS jsonb)) "
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
                row["category"] not in _CASE_CATEGORIES
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
                            "organization_id, reason_codes, confirmation_source, error_code) "
                            "VALUES "
                            "(CAST(:state AS verdict_state), :confidence, :run_id, :attempt_id, "
                            ":org, CAST(:reasons AS jsonb), :source, :error) RETURNING id"
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

            finding_id: str | None = None
            if state == "EXPLOIT_CONFIRMED":
                finding_id = hashlib.sha256(
                    f"finding:v1\0{row['organization_id']}\0{run_id}\0{attempt_id}".encode()
                ).hexdigest()
                connection.execute(
                    text(
                        "INSERT INTO finding "
                        "(finding_id, state, severity, category, target_version, "
                        "organization_id, source_kind, execution_profile, published) VALUES "
                        "(:finding, 'judged'::finding_state, CAST(:severity AS finding_severity), "
                        ":category, :target_version, :org, 'campaign', :profile, false) "
                        "ON CONFLICT (finding_id) DO NOTHING"
                    ),
                    {
                        "finding": finding_id,
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
                    "publication_state": "unpublished",
                },
            )
            return finding_id

    def complete_campaign_job(
        self,
        *,
        job: Any,
        request_count: int,
        measured_cost: float,
    ) -> CampaignRunRecord:
        """Atomically persist the run summary, terminal state, audit event, and queue completion."""

        if (
            isinstance(request_count, bool)
            or not isinstance(request_count, int)
            or request_count < 0
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
                        "SELECT status, completion_worker_id, completion_lease_token FROM jobs "
                        "WHERE job_id = :job_id FOR UPDATE"
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
            attempt_count = connection.execute(
                text(
                    "SELECT count(*) FROM verdict WHERE organization_id = :org "
                    "AND campaign_run_id = :run_id"
                ),
                {"org": org, "run_id": run_id},
            ).scalar_one()
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
            connection.execute(
                text(
                    "INSERT INTO campaign_run_summaries "
                    "(organization_id, run_id, execution_profile, provenance, attempt_count, "
                    "request_count, confirmed_finding_count, measured_cost, started_at, ended_at) "
                    "VALUES (:org, :run_id, :profile, :provenance, :attempts, :requests, "
                    ":findings, :cost, :started, clock_timestamp())"
                ),
                {
                    "org": org,
                    "run_id": run_id,
                    "profile": scope.execution_profile.value,
                    "provenance": provenance,
                    "attempts": attempt_count,
                    "requests": request_count,
                    "findings": confirmed_count,
                    "cost": measured_cost,
                    "started": started_at,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events (organization_id, run_id, state) "
                    "VALUES (:org, :run_id, 'complete')"
                ),
                {"org": org, "run_id": run_id},
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
                    "request_count": request_count,
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
        elif decision in {"approved", "rejected"}:
            self._require_permission(principal, FINDINGS_APPROVE)
        else:
            raise InvalidControlPlaneInput("finding decision is invalid")
        if reason_code is not None and _REASON_CODE.fullmatch(reason_code) is None:
            raise InvalidControlPlaneInput("reason code is invalid")
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
            evidence = (
                connection.execute(
                    text(
                        "SELECT ar.*, l.evidence_content_hash FROM finding f "
                        "JOIN finding_evidence_links l ON l.organization_id = f.organization_id "
                        "AND l.finding_id = f.finding_id JOIN attempt_result ar "
                        "ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id WHERE f.organization_id = :org "
                        "AND f.finding_id = :finding"
                    ),
                    {"org": principal.organization_id, "finding": finding_id},
                )
                .mappings()
                .one_or_none()
            )
            if evidence is None:
                raise RecordNotFoundError("finding does not exist")
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
        )
        if expected.canonical_bytes() != scope.canonical_bytes():
            raise AuthorizationDeniedError("authorization scope differs from registry state")

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
        expiry = value.astimezone(datetime.UTC)
        now = datetime.datetime.now(datetime.UTC)
        if expiry <= now or expiry - now > _MAX_AUTHORIZATION_LIFETIME:
            raise InvalidControlPlaneInput(
                "authorization expiry must be future and within 24 hours"
            )
        return expiry

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


__all__ = ["ControlPlaneStore"]
