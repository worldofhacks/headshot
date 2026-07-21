"""PostgreSQL-backed v1 read models and command adapter."""

from __future__ import annotations

import datetime
import re
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Engine, create_engine, text

from agentforge.api.backend import ApiBackend, ApiBackendUnavailable, ApiConflict
from agentforge.api.read_models import validate_ready_data
from agentforge.api.schemas import CommandResult, EventBatch, ResourceResult
from agentforge.auth.errors import AuthorizationError
from agentforge.control_plane import ControlPlaneStore
from agentforge.control_plane.errors import (
    AuthorizationDeniedError,
    ControlPlaneError,
    IdempotencyConflictError,
    InvalidControlPlaneInput,
    RecordConflictError,
    RecordNotFoundError,
)
from agentforge.migration_config import normalize_psycopg_url
from agentforge.secrets import redact_mapping
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    OwaspMapping,
    SafetyCaps,
    TargetDefinition,
    TargetLifecycle,
)

_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PROVIDER_KEY = re.compile(r"\bsk-(?:ant-|or-|proj-)?[A-Za-z0-9_-]{8,}\b")
_AUTHORIZATION_HEADER = re.compile(r"(?im)\bauthorization\s*:\s*[^\r\n]+")
_COOKIE_HEADER = re.compile(r"(?im)\b(?:cookie|set-cookie)\s*:\s*[^\r\n]+")
_SESSION_COOKIE = re.compile(r"(?i)\b__session=[^\s;,]+")
_CREDENTIAL_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@[^\s]+")
_CREDENTIAL_REFERENCE = re.compile(r"(?i)\bsecretref://[A-Za-z0-9._~/-]+")
_LABELED_SECRET = re.compile(
    r"(?i)\b(?:access[_ -]?token|api[_ -]?key|authorization|bearer|cookie|credential|"
    r"password|refresh[_ -]?token|secret|session[_ -]?token)\b"
    r"\s*[:=]\s*[^\s;,]+"
)
_ALLOWED_LIFECYCLE_TRANSITIONS = {
    "draft": ["validating"],
    "validating": ["ready"],
    "ready": ["disabled"],
    "disabled": ["archived"],
    "archived": [],
}


def _safe(value: Any) -> Any:
    """JSON-safe, recursively redacted output for records and hostile evidence text."""

    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime.datetime):
        return value.astimezone(datetime.UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        redacted = redact_mapping(value)
        # This derived boolean intentionally discloses only whether a trusted reference
        # exists.  The generic key-based redactor conservatively masks every key containing
        # "credential", so restore this one non-secret projection after the real reference
        # has already been discarded.
        configured = value.get("credential_configured")
        if isinstance(configured, bool):
            redacted["credential_configured"] = configured
        return {str(key): _safe(item) for key, item in redacted.items()}
    if isinstance(value, (tuple, list, set)):
        return [_safe(item) for item in value]
    if isinstance(value, str):
        value = _AUTHORIZATION_HEADER.sub("Authorization: ***REDACTED***", value)
        value = _COOKIE_HEADER.sub("Cookie: ***REDACTED***", value)
        value = _SESSION_COOKIE.sub("__session=***REDACTED***", value)
        value = _CREDENTIAL_URL.sub("***REDACTED_CREDENTIAL_URL***", value)
        value = _CREDENTIAL_REFERENCE.sub("***REDACTED_CREDENTIAL_REFERENCE***", value)
        value = _LABELED_SECRET.sub("***REDACTED_LABELED_SECRET***", value)
        value = _BEARER.sub("Bearer ***REDACTED***", value)
        value = _JWT.sub("***REDACTED***", value)
        return _PROVIDER_KEY.sub("***REDACTED***", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _rows(connection, statement: str, parameters: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(text(statement), parameters).mappings().all()]


def _scope_projection(value: Any, *, target_base_url: Any = None) -> dict[str, Any]:
    """Return the reviewable authorization scope without its credential reference."""

    if not isinstance(value, Mapping):
        return {}
    projected = {
        key: value.get(key)
        for key in (
            "target_id",
            "target_version",
            "surface_id",
            "surface_version",
            "adapter_kind",
            "environment",
            "exact_host",
            "auth_mode",
            "explicit_no_auth",
            "protocol",
            "method",
            "relative_path",
            "corpus_hash",
            "caps",
            "run_nonce",
        )
    }
    protocol = projected.get("protocol")
    host = projected.get("exact_host")
    path = projected.get("relative_path")
    if all(isinstance(part, str) and part for part in (protocol, host, path, target_base_url)):
        parsed_base = urlsplit(target_base_url)
        if parsed_base.scheme == protocol and parsed_base.netloc == host:
            projected["endpoint"] = f"{target_base_url.rstrip('/')}/{path}"
    projected["auth_posture"] = (
        "explicit_no_auth"
        if projected.get("explicit_no_auth") is True
        else projected.get("auth_mode")
    )
    return projected


class PostgresApiBackend(ApiBackend):
    """Organization-scoped projections over the integrated schema."""

    def __init__(
        self,
        engine: Engine,
        *,
        environment: str,
        runner_available: bool = False,
    ) -> None:
        self._engine = engine
        self._store = ControlPlaneStore(engine, environment=environment)
        self._environment = environment
        self._runner_available = runner_available

    def read(self, resource, principal, *, identifiers=None):
        identifiers = dict(identifiers or {})
        if resource == "principal":
            return ResourceResult.ready(
                validate_ready_data(
                    "principal",
                    {
                        "user_id": principal.user_id,
                        "session_id": principal.session_id,
                        "organization_id": principal.organization_id,
                        "organization_role": principal.organization_role,
                        "organization_permissions": sorted(principal.organization_permissions),
                    },
                )
            )
        unavailable = {
            "findings": "finding_evidence_relation_missing",
            "finding": "finding_evidence_relation_missing",
            "coverage": "verified_coverage_projection_missing",
            "resilience": "regression_history_repository_missing",
            "traces": "persisted_trace_repository_missing",
            "costs": "measured_accounting_repository_missing",
            "configuration": "configuration_snapshot_repository_missing",
            "components": "component_heartbeat_repository_missing",
        }
        if resource in unavailable:
            return ResourceResult.unavailable(unavailable[resource])
        try:
            with self._engine.connect() as connection:
                if resource == "campaigns":
                    rows = _rows(
                        connection,
                        "SELECT r.run_id, r.authorization_request_id, r.scope_hash, "
                        "r.launcher_user_id, r.created_at, q.scope_payload, "
                        "(SELECT d.payload->>'base_url' FROM target_definitions d "
                        " WHERE d.organization_id = q.organization_id "
                        " AND d.target_id = q.scope_payload->>'target_id' "
                        " AND d.version = q.scope_payload->>'target_version' LIMIT 1) "
                        "AS target_base_url, "
                        "(SELECT e.state FROM campaign_run_events e "
                        " WHERE e.organization_id = r.organization_id AND e.run_id = r.run_id "
                        " ORDER BY e.id DESC LIMIT 1) AS state, "
                        "(SELECT count(*) FROM campaign_attempts a "
                        " WHERE a.organization_id = r.organization_id AND a.run_id = r.run_id) "
                        "AS attempt_count "
                        "FROM campaign_runs r JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "WHERE r.organization_id = :org ORDER BY r.created_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                elif resource == "campaign":
                    rows = _rows(
                        connection,
                        "SELECT r.run_id, r.authorization_request_id, r.scope_hash, "
                        "r.launcher_user_id, r.created_at, q.scope_payload, "
                        "(SELECT d.payload->>'base_url' FROM target_definitions d "
                        " WHERE d.organization_id = q.organization_id "
                        " AND d.target_id = q.scope_payload->>'target_id' "
                        " AND d.version = q.scope_payload->>'target_version' LIMIT 1) "
                        "AS target_base_url, "
                        "(SELECT e.state FROM campaign_run_events e "
                        " WHERE e.organization_id = r.organization_id AND e.run_id = r.run_id "
                        " ORDER BY e.id DESC LIMIT 1) AS state "
                        "FROM campaign_runs r JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "WHERE r.organization_id = :org AND r.run_id = :run_id",
                        {
                            "org": principal.organization_id,
                            "run_id": identifiers.get("campaign_id"),
                        },
                    )
                elif resource == "attempts":
                    rows = _rows(
                        connection,
                        "SELECT a.attempt_id, a.ordinal, a.case_id, a.created_at, "
                        "ar.content_hash, ar.executed_at, ar.trace_id, v.state AS verdict, "
                        "v.confidence FROM campaign_attempts a "
                        "LEFT JOIN attempt_result ar ON ar.organization_id = a.organization_id "
                        "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
                        "LEFT JOIN verdict v ON v.organization_id = a.organization_id "
                        "AND v.campaign_run_id = a.run_id AND v.attempt_id = a.attempt_id "
                        "WHERE a.organization_id = :org AND a.run_id = :run_id "
                        "ORDER BY a.ordinal ASC",
                        {
                            "org": principal.organization_id,
                            "run_id": identifiers.get("campaign_id"),
                        },
                    )
                elif resource == "evidence":
                    rows = _rows(
                        connection,
                        "SELECT ar.campaign_run_id, ar.attempt_id, ar.target_id, "
                        "ar.target_version, ar.surface_id, ar.surface_version, "
                        "ar.attack_attempt, ar.request_transcript, ar.response_transcript, "
                        "ar.policy_decision_id, ar.executed_at, ar.trace_id, ar.content_hash, "
                        "v.state AS verdict, v.confidence FROM attempt_result ar "
                        "LEFT JOIN verdict v ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE ar.organization_id = :org AND ar.attempt_id = :attempt_id",
                        {
                            "org": principal.organization_id,
                            "attempt_id": identifiers.get("attempt_id"),
                        },
                    )
                elif resource == "approvals":
                    rows = _rows(
                        connection,
                        "SELECT q.request_id, q.scope_hash, q.launcher_user_id, q.expires_at, "
                        "q.created_at, q.scope_payload, "
                        "(SELECT t.payload->>'base_url' FROM target_definitions t "
                        " WHERE t.organization_id = q.organization_id "
                        " AND t.target_id = q.scope_payload->>'target_id' "
                        " AND t.version = q.scope_payload->>'target_version' LIMIT 1) "
                        "AS target_base_url, d.decision, d.approver_user_id, "
                        "d.created_at AS decided_at FROM campaign_authorization_requests q "
                        "LEFT JOIN campaign_authorization_decisions d "
                        "ON d.organization_id = q.organization_id AND d.request_id = q.request_id "
                        "WHERE q.organization_id = :org ORDER BY q.created_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                elif resource in {"targets", "target"}:
                    where = "d.organization_id = :org"
                    parameters: dict[str, Any] = {"org": principal.organization_id}
                    if resource == "target":
                        where += " AND d.target_id = :target_id"
                        parameters["target_id"] = identifiers.get("target_id")
                    rows = _rows(
                        connection,
                        "SELECT d.target_id, d.version, d.content_hash, d.payload, d.created_at, "
                        "(SELECT e.to_lifecycle FROM target_lifecycle_events e "
                        " WHERE e.organization_id = d.organization_id "
                        " AND e.target_id = d.target_id AND e.target_version = d.version "
                        " ORDER BY e.id DESC LIMIT 1) AS lifecycle "
                        "FROM target_definitions d WHERE "
                        + where
                        + " ORDER BY d.target_id, d.created_at DESC",
                        parameters,
                    )
                    for row in rows:
                        payload = dict(row.pop("payload"))
                        row.update(
                            {
                                "name": payload.get("name"),
                                "adapter_kind": payload.get("adapter_kind"),
                                "environment": payload.get("environment"),
                                "base_url": payload.get("base_url"),
                                "auth_mode": payload.get("auth_mode"),
                                "credential_configured": bool(payload.get("credential_ref")),
                                "synthetic_data_only": payload.get("synthetic_data_only"),
                                "safety_caps": payload.get("safety_caps"),
                                "allowed_lifecycle_transitions": _ALLOWED_LIFECYCLE_TRANSITIONS.get(
                                    row.get("lifecycle"), []
                                ),
                            }
                        )
                        row["surfaces"] = _rows(
                            connection,
                            "SELECT s.surface_id, s.version, s.target_version, s.content_hash, "
                            "s.payload, s.created_at, "
                            "(SELECT e.to_enabled FROM surface_state_events e "
                            " WHERE e.organization_id = s.organization_id "
                            " AND e.surface_id = s.surface_id AND e.surface_version = s.version "
                            " ORDER BY e.id DESC LIMIT 1) AS enabled "
                            "FROM attack_surface_definitions s WHERE s.organization_id = :org "
                            "AND s.target_id = :target_id AND s.target_version = :version "
                            "ORDER BY s.surface_id, s.created_at DESC",
                            {
                                "org": principal.organization_id,
                                "target_id": row["target_id"],
                                "version": row["version"],
                            },
                        )
                        for surface in row["surfaces"]:
                            surface_payload = dict(surface.pop("payload"))
                            # The parent target/version already scopes this nested surface.
                            # Do not emit the internal duplicate parent key into the stable v1
                            # SurfaceReadModel.
                            surface_payload.pop("target_id", None)
                            surface.update(surface_payload)
                elif resource == "audit":
                    rows = _rows(
                        connection,
                        "SELECT cursor, event_type, aggregate_type, aggregate_id, actor_user_id, "
                        "payload, created_at FROM audit_events WHERE organization_id = :org "
                        "ORDER BY cursor DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                else:
                    return ResourceResult.unavailable("read_model_not_implemented")
        except Exception:
            return ResourceResult.unavailable("database_projection_unavailable")

        if resource in {"campaigns", "campaign", "approvals"}:
            for row in rows:
                row.update(
                    _scope_projection(
                        row.pop("scope_payload", None),
                        target_base_url=row.pop("target_base_url", None),
                    )
                )
                if resource == "approvals":
                    row["status"] = row.get("decision") or "pending"

        sanitized = _safe(rows)
        if resource in {"campaign", "evidence", "target"}:
            if not sanitized:
                return ResourceResult.empty()
            try:
                return ResourceResult.ready(validate_ready_data(resource, sanitized[0]))
            except Exception:
                return ResourceResult.unavailable("projection_schema_invalid")
        if not sanitized:
            return ResourceResult.empty()
        try:
            return ResourceResult.ready(validate_ready_data(resource, sanitized))
        except Exception:
            return ResourceResult.unavailable("projection_schema_invalid")

    def command(self, command, principal, payload, *, idempotency_key, identifiers=None):
        identifiers = dict(identifiers or {})
        try:
            if command in {"create_target", "revise_target"}:
                # Browser-supplied hosts, adapters, and credential references cannot create
                # server authority. The immutable store primitive remains available to a later
                # reviewed server-side catalog/provisioning workflow, but the public command
                # stays closed until that trusted source exists.
                return CommandResult.unavailable("trusted_target_authoring_catalog_missing")
            if command == "change_target_lifecycle":
                target = self._store.transition_target(
                    principal=principal,
                    target_id=identifiers.get("target_id", ""),
                    version=str(payload["version"]),
                    lifecycle=TargetLifecycle(str(payload["lifecycle"])),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(target.version, resource_id=target.target_id)
            if command in {"create_surface", "revise_surface"}:
                return CommandResult.unavailable("trusted_surface_authoring_catalog_missing")
            if command == "set_surface_state":
                surface = self._store.set_surface_enabled(
                    principal=principal,
                    target_id=identifiers.get("target_id", ""),
                    surface_id=identifiers.get("surface_id", ""),
                    version=str(payload["version"]),
                    enabled=bool(payload["enabled"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(surface.version, resource_id=surface.surface_id)
            if command == "request_campaign_authorization":
                caps = SafetyCaps(**dict(payload["caps"]))
                scope = self._store.build_scope(
                    principal=principal,
                    target_id=str(payload["target_id"]),
                    target_version=str(payload["target_version"]),
                    surface_id=str(payload["surface_id"]),
                    surface_version=str(payload["surface_version"]),
                    corpus_hash=str(payload["corpus_hash"]),
                    caps=caps,
                    run_nonce=str(payload["run_nonce"]),
                )
                expiry = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
                    seconds=int(payload["expires_in_seconds"])
                )
                record = self._store.request_campaign_authorization(
                    principal=principal,
                    scope=scope,
                    expires_at=expiry,
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(record.request_id, resource_id=record.request_id)
            if command == "decide_campaign_authorization":
                record = self._store.decide_campaign_authorization(
                    principal=principal,
                    request_id=identifiers.get("request_id", ""),
                    decision=str(payload["decision"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(record.decision_id, resource_id=record.request_id)
            if command == "launch_campaign":
                if not self._runner_available:
                    return CommandResult.unavailable("runner_execution_composition_missing")
                record = self._store.launch_campaign(
                    principal=principal,
                    request_id=str(payload["authorization_request_id"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.accepted(record.run_id, resource_id=record.run_id)
            if command == "abort_campaign":
                record = self._store.abort_campaign(
                    principal=principal,
                    run_id=identifiers.get("campaign_id", ""),
                    rationale=str(payload["reason"]),
                    reason_code="operator_abort",
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(record.run_id, resource_id=record.run_id)
            if command in {"decide_finding", "resolve_finding"}:
                # The integrated evidence schema has no authoritative finding-to-evidence
                # relation yet.  Persisting a human publication/resolution decision without
                # proving the reviewed evidence would manufacture authority, so this path
                # remains explicitly unavailable even though the append-only event primitive
                # is ready for the later relation-aware service.
                return CommandResult.unavailable("finding_evidence_relation_missing")
            if command == "request_live_probe_authorization":
                return CommandResult.unavailable("distinct_live_probe_workflow_missing")
            if command in {"validate_configuration", "publish_configuration"}:
                return CommandResult.unavailable("configuration_snapshot_repository_missing")
            return CommandResult.unavailable("command_not_implemented")
        except AuthorizationDeniedError as exc:
            raise AuthorizationError() from exc
        except (IdempotencyConflictError, RecordConflictError, RecordNotFoundError) as exc:
            raise ApiConflict("immutable control-plane conflict") from exc
        except (InvalidControlPlaneInput, ValueError, KeyError, TypeError) as exc:
            raise ApiConflict("invalid control-plane command") from exc
        except ControlPlaneError as exc:
            raise ApiBackendUnavailable("control-plane command unavailable") from exc

    def events(self, principal, *, after_cursor, limit):
        try:
            with self._engine.connect() as connection:
                oldest = connection.execute(
                    text("SELECT min(cursor) FROM audit_events WHERE organization_id = :org"),
                    {"org": principal.organization_id},
                ).scalar_one_or_none()
                rows = _rows(
                    connection,
                    "SELECT cursor, event_type, aggregate_type, aggregate_id, actor_user_id, "
                    "payload, created_at FROM audit_events WHERE organization_id = :org "
                    "AND cursor > :cursor ORDER BY cursor ASC LIMIT :limit",
                    {
                        "org": principal.organization_id,
                        "cursor": after_cursor,
                        "limit": min(limit, 100),
                    },
                )
        except Exception as exc:
            raise ApiBackendUnavailable("event repository unavailable") from exc
        oldest_cursor = int(oldest or max(after_cursor, 0))
        gap = after_cursor > 0 and oldest is not None and after_cursor < oldest_cursor - 1
        events = tuple(
            {
                "cursor": int(row["cursor"]),
                "type": str(row["event_type"]),
                "payload": _safe(
                    {
                        "aggregate_type": row["aggregate_type"],
                        "aggregate_id": row["aggregate_id"],
                        "actor_user_id": row["actor_user_id"],
                        "data": row["payload"],
                        "created_at": row["created_at"],
                    }
                ),
            }
            for row in rows
        )
        next_cursor = int(rows[-1]["cursor"]) if rows else after_cursor
        return EventBatch(
            events=events,
            next_cursor=next_cursor,
            oldest_cursor=oldest_cursor,
            gap=gap,
            terminal=False,
        )

    @staticmethod
    def _target(payload: Mapping[str, Any]) -> TargetDefinition:
        values = dict(payload)
        values["allowlisted_hosts"] = tuple(values["allowlisted_hosts"])
        values["canary_refs"] = tuple(values.get("canary_refs", ()))
        values["oracle_refs"] = tuple(values.get("oracle_refs", ()))
        values["safety_caps"] = SafetyCaps(**dict(values["safety_caps"]))
        return TargetDefinition(**values)

    @staticmethod
    def _surface(target_id: str, payload: Mapping[str, Any]) -> AttackSurfaceDefinition:
        values = dict(payload)
        values["target_id"] = target_id
        values["oracle_refs"] = tuple(values["oracle_refs"])
        values["owasp_mappings"] = tuple(
            OwaspMapping(
                framework=str(mapping["framework"]),
                version=str(mapping["version"]),
                identifier=str(mapping["identifier"]),
                name=str(mapping["name"]),
            )
            for mapping in values["owasp_mappings"]
        )
        return AttackSurfaceDefinition(**values)


def build_postgres_backend(
    database_url: str | None,
    *,
    environment: str,
    runner_available: bool = False,
) -> ApiBackend:
    if not database_url:
        from agentforge.api.backend import UnavailableApiBackend

        return UnavailableApiBackend()
    engine = create_engine(normalize_psycopg_url(database_url), pool_pre_ping=True, future=True)
    return PostgresApiBackend(
        engine,
        environment=environment,
        runner_available=runner_available,
    )


__all__ = ["PostgresApiBackend", "build_postgres_backend"]
