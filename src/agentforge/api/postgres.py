"""PostgreSQL-backed v1 read models and command adapter."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
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
from agentforge.campaign.corpus import AuthoredCorpus, load_mvp_corpus
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
from agentforge.policy.recorder import (
    PERSISTED_EVIDENCE_COLUMNS,
    EvidenceIntegrityError,
    ExecutionRecorder,
)
from agentforge.secrets import redact_mapping
from agentforge.target.catalog import SYNTHETIC_TARGET_ID, TrustedTargetCatalog
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
_REQUIRED_WEB = frozenset({"A01", "A03", "A04", "A06", "A07", "A09", "A10"})
_REQUIRED_LLM = frozenset({"LLM01", "LLM02", "LLM03", "LLM05", "LLM06"})
_REQUIRED_CATEGORIES = frozenset({"prompt_injection", "data_exfiltration", "tool_misuse"})


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


def _evidence_verified(row: Mapping[str, Any]) -> bool:
    fields: dict[str, Any] = {}
    for column in PERSISTED_EVIDENCE_COLUMNS:
        value = row.get(column)
        if isinstance(value, datetime.datetime):
            value = value.astimezone(datetime.UTC).isoformat()
        fields[column] = value
    fields["content_hash"] = row.get("content_hash")
    try:
        ExecutionRecorder().verify(fields)
    except (EvidenceIntegrityError, TypeError, ValueError):
        return False
    return True


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
            "corpus_id",
            "corpus_hash",
            "caps",
            "run_nonce",
            "execution_profile",
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
        corpus: AuthoredCorpus | None = None,
    ) -> None:
        self._engine = engine
        self._store = ControlPlaneStore(engine, environment=environment)
        self._environment = environment
        self._runner_available = runner_available
        self._corpus = corpus

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
        try:
            with self._engine.connect() as connection:
                if resource == "resilience":
                    rows = _rows(
                        connection,
                        "SELECT a.attempt_id AS regression_id, "
                        "concat(q.scope_payload->>'target_id', '@', "
                        "q.scope_payload->>'target_version') AS version, "
                        "coalesce(v.state::text, 'pending') AS status, "
                        "coalesce(v.created_at, a.created_at) AS recorded_at "
                        "FROM campaign_attempts a JOIN campaign_runs r "
                        "ON r.organization_id = a.organization_id AND r.run_id = a.run_id "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "LEFT JOIN verdict v ON v.organization_id = a.organization_id "
                        "AND v.campaign_run_id = a.run_id AND v.attempt_id = a.attempt_id "
                        "WHERE a.organization_id = :org AND a.attack_class = 'regression' "
                        "ORDER BY recorded_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                elif resource == "configuration":
                    published_at = connection.execute(
                        text(
                            "SELECT coalesce(max(created_at), clock_timestamp()) "
                            "FROM target_definitions WHERE organization_id = :org"
                        ),
                        {"org": principal.organization_id},
                    ).scalar_one()
                    configuration = {
                        "environment": self._environment,
                        "runner_composed": self._runner_available,
                        "corpus": {
                            "id": self._corpus.corpus_id if self._corpus else None,
                            "content_hash": self._corpus.content_hash if self._corpus else None,
                            "case_count": len(self._corpus.cases) if self._corpus else 0,
                        },
                        "langfuse": {
                            "adapter": "integrated",
                            "server_managed_auth": True,
                            "environment": self._environment,
                        },
                        "target_auth_material_browser_exposure": "none",
                    }
                    snapshot_id = hashlib.sha256(
                        json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    rows = [
                        {
                            "snapshot_id": snapshot_id,
                            "version": 1,
                            "status": "operational and evidenced",
                            "configuration": configuration,
                            "published_at": published_at,
                            "published_by": "trusted-server-composition",
                        }
                    ]
                elif resource == "components":
                    heartbeat_at = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
                    rows = [
                        {
                            "component_id": "web-api",
                            "name": "Operator console API",
                            "kind": "web",
                            "availability": "operational and evidenced",
                            "environment": self._environment,
                            "detail": "authenticated API and database projection responded",
                            "heartbeat_at": heartbeat_at,
                        },
                        {
                            "component_id": "postgres",
                            "name": "PostgreSQL system of record",
                            "kind": "database",
                            "availability": "operational and evidenced",
                            "environment": self._environment,
                            "detail": "organization-scoped projection query succeeded",
                            "heartbeat_at": heartbeat_at,
                        },
                    ]
                    persisted = _rows(
                        connection,
                        "SELECT component_id, name, kind, availability, environment, detail, "
                        "heartbeat_at FROM runtime_component_status "
                        "WHERE environment = :environment ORDER BY component_id",
                        {"environment": self._environment},
                    )
                    rows.extend(persisted)
                    present = {row["component_id"] for row in persisted}
                    for component_id, name, kind in (
                        ("runner", "Campaign runner", "worker"),
                        ("langfuse", "Langfuse tracing", "telemetry"),
                    ):
                        if component_id not in present:
                            rows.append(
                                {
                                    "component_id": component_id,
                                    "name": name,
                                    "kind": kind,
                                    "availability": "adapter integrated, execution deferred",
                                    "environment": self._environment,
                                    "detail": "awaiting first private-runner heartbeat",
                                    "heartbeat_at": heartbeat_at,
                                }
                            )
                elif resource == "campaigns":
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
                        "v.confidence, ar.execution_profile, ar.evidence_provenance "
                        "FROM campaign_attempts a "
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
                        "v.state AS verdict, v.confidence, ar.execution_profile, "
                        "ar.evidence_provenance FROM attempt_result ar "
                        "LEFT JOIN verdict v ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE ar.organization_id = :org AND ar.attempt_id = :attempt_id",
                        {
                            "org": principal.organization_id,
                            "attempt_id": identifiers.get("attempt_id"),
                        },
                    )
                elif resource in {"findings", "finding"}:
                    where = "f.organization_id = :org"
                    parameters = {"org": principal.organization_id}
                    if resource == "finding":
                        where += " AND f.finding_id = :finding_id"
                        parameters["finding_id"] = identifiers.get("finding_id")
                    source_rows = _rows(
                        connection,
                        "SELECT ar.*, f.finding_id AS linked_finding_id, f.state AS finding_state, "
                        "f.severity AS finding_severity, f.category AS finding_category, "
                        "f.target_version AS finding_target_version, f.source_kind, "
                        "f.execution_profile AS finding_execution_profile, f.published, "
                        "l.evidence_content_hash, l.provenance AS linked_provenance "
                        "FROM finding f JOIN finding_evidence_links l "
                        "ON l.organization_id = f.organization_id AND l.finding_id = f.finding_id "
                        "JOIN attempt_result ar ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id WHERE "
                        + where
                        + " ORDER BY f.created_at DESC",
                        parameters,
                    )
                    rows = []
                    for source in source_rows:
                        if source["content_hash"] != source[
                            "evidence_content_hash"
                        ] or not _evidence_verified(source):
                            return ResourceResult.unavailable("finding_evidence_integrity_failed")
                        history = _rows(
                            connection,
                            "SELECT decision, actor_user_id, rationale, created_at "
                            "FROM finding_decision_events WHERE organization_id = :org "
                            "AND finding_id = :finding ORDER BY created_at ASC",
                            {
                                "org": principal.organization_id,
                                "finding": source["linked_finding_id"],
                            },
                        )
                        latest = history[-1]["decision"] if history else None
                        publication_status = "blocked_pending_human_approval"
                        if source["published"]:
                            publication_status = "published"
                        elif latest == "approved":
                            publication_status = "approved_unpublished"
                        elif latest == "rejected":
                            publication_status = "rejected_unpublished"
                        elif latest == "resolved":
                            publication_status = "resolved_unpublished"
                        rows.append(
                            {
                                "finding_id": source["linked_finding_id"],
                                "state": "resolved"
                                if latest == "resolved"
                                else source["finding_state"],
                                "severity": source["finding_severity"],
                                "category": source["finding_category"],
                                "target_version": source["finding_target_version"],
                                "publication_status": publication_status,
                                "evidence_integrity": "verified",
                                "source_kind": source["source_kind"],
                                "execution_profile": source["finding_execution_profile"],
                                "evidence_provenance": source["linked_provenance"],
                                "campaign_run_id": source["campaign_run_id"],
                                "attempt_id": source["attempt_id"],
                                "evidence_content_hash": source["evidence_content_hash"],
                                "history": history,
                            }
                        )
                    tool_where = "organization_id = :org"
                    tool_parameters = {"org": principal.organization_id}
                    if resource == "finding":
                        tool_where += " AND finding_id = :finding_id"
                        tool_parameters["finding_id"] = identifiers.get("finding_id")
                    tool_rows = _rows(
                        connection,
                        "SELECT contract_payload, raw_artifact_sha256 "
                        "FROM security_tool_findings WHERE " + tool_where + " ORDER BY finding_id",
                        tool_parameters,
                    )
                    for source in tool_rows:
                        payload = source["contract_payload"]
                        reproduction = payload.get("reproduction_evidence", {})
                        rows.append(
                            {
                                "finding_id": payload["finding_id"],
                                "state": payload["validation_state"],
                                "severity": payload["severity"],
                                "category": reproduction.get("summary", "security tool finding"),
                                "target_version": payload["target_id"],
                                "publication_status": payload["human_publication_state"],
                                "evidence_integrity": "verified",
                                "source_kind": payload["source_kind"],
                                "execution_profile": "live"
                                if payload["scan_provenance"] == "live_target"
                                else "synthetic",
                                "evidence_provenance": payload["evidence_provenance"],
                                "campaign_run_id": None,
                                "attempt_id": None,
                                "evidence_content_hash": source["raw_artifact_sha256"],
                                "history": [],
                            }
                        )
                elif resource == "coverage":
                    source_rows = _rows(
                        connection,
                        "SELECT ar.*, a.case_id, a.category, a.attack_class, a.owasp_mappings, "
                        "a.fixture_provenance, v.state AS verdict_state, "
                        "v.created_at AS verdict_created_at FROM campaign_attempts a "
                        "JOIN attempt_result ar ON ar.organization_id = a.organization_id "
                        "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
                        "JOIN verdict v ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE ar.organization_id = :org ORDER BY v.created_at ASC",
                        {"org": principal.organization_id},
                    )
                    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
                    seen: set[tuple[str, str]] = set()
                    for source in source_rows:
                        identity = (source["campaign_run_id"], source["attempt_id"])
                        fixture = source.get("fixture_provenance")
                        mappings = source.get("owasp_mappings")
                        if (
                            identity in seen
                            or not _evidence_verified(source)
                            or source.get("category") not in _REQUIRED_CATEGORIES
                            or source.get("attack_class")
                            not in {"boundary", "invariant", "regression"}
                            or not isinstance(fixture, dict)
                            or fixture.get("classification") != "synthetic"
                            or fixture.get("contains_real_phi") is not False
                            or not isinstance(mappings, list)
                        ):
                            continue
                        seen.add(identity)
                        key = (
                            str(source["target_id"]),
                            str(source["target_version"]),
                            str(source["execution_profile"]),
                            str(source["evidence_provenance"]),
                        )
                        group = groups.setdefault(
                            key,
                            {
                                "attempts": set(),
                                "cases": set(),
                                "categories": set(),
                                "classifications": set(),
                                "web": set(),
                                "llm": set(),
                                "verdicts": {},
                                "as_of": source["verdict_created_at"],
                            },
                        )
                        group["attempts"].add(identity)
                        group["cases"].add(source["case_id"])
                        group["categories"].add(source["category"])
                        group["classifications"].add(source["attack_class"])
                        for mapping in mappings:
                            if not isinstance(mapping, dict):
                                continue
                            identifier = mapping.get("id")
                            if mapping.get("framework") == "OWASP Web" and isinstance(
                                identifier, str
                            ):
                                group["web"].add(identifier)
                            if mapping.get("framework") == "OWASP LLM" and isinstance(
                                identifier, str
                            ):
                                group["llm"].add(identifier)
                        verdict_state = str(source["verdict_state"])
                        group["verdicts"][verdict_state] = (
                            group["verdicts"].get(verdict_state, 0) + 1
                        )
                        group["as_of"] = max(group["as_of"], source["verdict_created_at"])
                    rows = []
                    for (target_id, target_version, profile, provenance), group in sorted(
                        groups.items()
                    ):
                        rows.append(
                            {
                                "target_version": f"{target_id}@{target_version}",
                                "verified_attempt_count": len(group["attempts"]),
                                "total_case_count": len(group["cases"]),
                                "category_count": len(group["categories"]),
                                "execution_profile": profile,
                                "evidence_provenance": provenance,
                                "classifications": sorted(group["classifications"]),
                                "owasp_web": sorted(group["web"]),
                                "owasp_llm": sorted(group["llm"]),
                                "verdict_counts": group["verdicts"],
                                "covered": (
                                    len(group["cases"]) == 9
                                    and group["categories"] == _REQUIRED_CATEGORIES
                                    and _REQUIRED_WEB.issubset(group["web"])
                                    and _REQUIRED_LLM.issubset(group["llm"])
                                ),
                                "as_of": group["as_of"],
                            }
                        )
                elif resource == "costs":
                    source_rows = _rows(
                        connection,
                        "SELECT s.run_id AS accounting_id, s.run_id AS campaign_id, "
                        "s.provenance AS provider, s.measured_cost, s.currency, s.request_count, "
                        "s.attempt_count, s.confirmed_finding_count, s.execution_profile, "
                        "s.started_at, s.ended_at, "
                        "extract(epoch FROM (s.ended_at - s.started_at)) * 1000 AS duration_ms, "
                        "s.created_at AS recorded_at, "
                        "CASE WHEN jsonb_typeof(q.scope_payload->'caps'->'budget_usd') = 'number' "
                        "THEN (q.scope_payload->'caps'->>'budget_usd')::double precision "
                        "ELSE NULL END AS budget_usd "
                        "FROM campaign_run_summaries s LEFT JOIN campaign_runs r "
                        "ON r.organization_id = s.organization_id AND r.run_id = s.run_id "
                        "LEFT JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "WHERE s.organization_id = :org ORDER BY s.created_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                    rows = []
                    for source in source_rows:
                        cost = source["measured_cost"]
                        rows.append(
                            {
                                "accounting_id": source["accounting_id"],
                                "campaign_id": source["campaign_id"],
                                "provider": source["provider"],
                                # measured_cost is a Numeric(14,6) -> Decimal; the console/pydantic
                                # contract requires a JSON number, so coerce it to float here rather
                                # than letting _safe stringify the Decimal.
                                "measured_cost": float(cost) if cost is not None else 0.0,
                                "currency": source["currency"],
                                "request_count": source["request_count"],
                                "attempt_count": source["attempt_count"],
                                "confirmed_finding_count": source["confirmed_finding_count"],
                                "average_cost_per_request": (
                                    float(cost) / source["request_count"]
                                    if cost is not None and source["request_count"]
                                    else 0.0
                                ),
                                "budget_usd": source["budget_usd"],
                                "budget_utilization": (
                                    float(cost) / source["budget_usd"]
                                    if cost is not None and source["budget_usd"]
                                    else None
                                ),
                                "duration_ms": float(source["duration_ms"] or 0.0),
                                "execution_profile": source["execution_profile"],
                                "started_at": source["started_at"],
                                "ended_at": source["ended_at"],
                                "recorded_at": source["recorded_at"],
                            }
                        )
                elif resource == "traces":
                    request_rows = _rows(
                        connection,
                        "SELECT request_id, trace_id, campaign_run_id AS campaign_id, attempt_id, "
                        "operation, provider, method, destination_host, relative_path, status, "
                        "status_code, error_code, started_at, finished_at, duration_ms, "
                        "request_bytes, response_bytes, measured_cost, currency, langfuse_status "
                        "FROM outbound_http_requests WHERE organization_id = :org "
                        "AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                    rows = [
                        {
                            **source,
                            "duration_ms": float(source["duration_ms"] or 0.0),
                            "measured_cost": float(source["measured_cost"] or 0.0),
                        }
                        for source in request_rows
                    ]
                    legacy_rows = _rows(
                        connection,
                        "SELECT ar.trace_id, ar.campaign_run_id AS campaign_id, ar.attempt_id, "
                        "ar.target_id, ar.target_version, ar.executed_at, ar.created_at, "
                        "v.state AS verdict_state, v.created_at AS verdict_created_at "
                        "FROM attempt_result ar LEFT JOIN verdict v "
                        "ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE ar.organization_id = :org AND ar.trace_id IS NOT NULL "
                        "AND NOT EXISTS (SELECT 1 FROM outbound_http_requests o "
                        "WHERE o.organization_id = ar.organization_id "
                        "AND o.trace_id = ar.trace_id) "
                        "ORDER BY ar.executed_at DESC NULLS LAST LIMIT 200",
                        {"org": principal.organization_id},
                    )
                    for source in legacy_rows:
                        started_at = source["executed_at"] or source["created_at"]
                        ended_at = source["verdict_created_at"] or started_at
                        rows.append(
                            {
                                "request_id": None,
                                "trace_id": source["trace_id"],
                                "campaign_id": source["campaign_id"],
                                "attempt_id": source["attempt_id"],
                                "operation": (
                                    f"attempt:{source['target_id']}@{source['target_version']}"
                                ),
                                "provider": source["target_id"] or "target",
                                "method": None,
                                "destination_host": None,
                                "relative_path": None,
                                "status": source["verdict_state"] or "recorded",
                                "status_code": None,
                                "error_code": None,
                                "started_at": started_at,
                                "finished_at": ended_at,
                                "duration_ms": max(
                                    0.0,
                                    (ended_at - started_at).total_seconds() * 1000.0,
                                ),
                                "request_bytes": 0,
                                "response_bytes": None,
                                "measured_cost": 0.0,
                                "currency": "USD",
                                "langfuse_status": "historical_not_instrumented",
                            }
                        )
                    summary_rows = _rows(
                        connection,
                        "SELECT run_id, execution_profile, provenance, request_count, "
                        "measured_cost, currency, started_at, ended_at "
                        "FROM campaign_run_summaries WHERE organization_id = :org "
                        "ORDER BY started_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                    for source in summary_rows:
                        rows.append(
                            {
                                "request_id": None,
                                "trace_id": hashlib.sha256(
                                    f"campaign:{source['run_id']}".encode()
                                ).hexdigest()[:32],
                                "campaign_id": source["run_id"],
                                "attempt_id": None,
                                "operation": "campaign.run",
                                "provider": source["provenance"],
                                "method": None,
                                "destination_host": None,
                                "relative_path": None,
                                "status": "complete",
                                "status_code": None,
                                "error_code": None,
                                "started_at": source["started_at"],
                                "finished_at": source["ended_at"],
                                "duration_ms": max(
                                    0.0,
                                    (source["ended_at"] - source["started_at"]).total_seconds()
                                    * 1000.0,
                                ),
                                "request_bytes": 0,
                                "response_bytes": None,
                                "measured_cost": float(source["measured_cost"] or 0.0),
                                "currency": source["currency"],
                                "langfuse_status": "historical_not_instrumented",
                            }
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
                        row["campaign_template"] = None
                        if self._corpus is not None and row["surfaces"]:
                            surface = row["surfaces"][0]
                            row["campaign_template"] = {
                                "target_id": row["target_id"],
                                "target_version": row["version"],
                                "surface_id": surface["surface_id"],
                                "surface_version": surface["version"],
                                "corpus_id": self._corpus.corpus_id,
                                "corpus_hash": self._corpus.content_hash,
                                "execution_profile": "synthetic"
                                if row["target_id"] == SYNTHETIC_TARGET_ID
                                else "live",
                                "maximum_caps": row["safety_caps"],
                            }
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
        if resource in {"campaign", "evidence", "target", "finding", "configuration"}:
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
                if self._corpus is not None:
                    if (
                        payload.get("corpus_id") != self._corpus.corpus_id
                        or payload.get("corpus_hash") != self._corpus.content_hash
                    ):
                        raise ApiConflict("campaign corpus differs from trusted content")
                    expected_profile = (
                        "synthetic" if payload.get("target_id") == SYNTHETIC_TARGET_ID else "live"
                    )
                    if payload.get("execution_profile") != expected_profile:
                        raise ApiConflict("campaign execution profile differs from trusted target")
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
                    corpus_id=str(payload["corpus_id"]),
                    execution_profile=str(payload["execution_profile"]),
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
                decision = str(payload["decision"]) if command == "decide_finding" else "resolved"
                record = self._store.record_finding_decision(
                    principal=principal,
                    finding_id=identifiers.get("finding_id", ""),
                    decision=decision,
                    rationale=str(payload["rationale"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(record.decision_id, resource_id=record.finding_id)
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
    corpus = load_mvp_corpus()
    required_org = os.environ.get("CLERK_REQUIRED_ORG_ID")
    if required_org:
        catalog = TrustedTargetCatalog.from_environment(environment)
        catalog.synchronize(
            ControlPlaneStore(engine, environment=environment),
            organization_id=required_org,
        )
    return PostgresApiBackend(
        engine,
        environment=environment,
        runner_available=runner_available,
        corpus=corpus,
    )


__all__ = ["PostgresApiBackend", "build_postgres_backend"]
