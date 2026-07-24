"""PostgreSQL-backed v1 read models and command adapter."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Engine, create_engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    preflight_hosted_configuration_set,
)
from agentforge.agents.runtime import AGENT_DEFINITIONS, default_assignment
from agentforge.api.backend import ApiBackend, ApiBackendUnavailable, ApiConflict
from agentforge.api.birdseye import build_birdseye_snapshot
from agentforge.api.read_models import validate_ready_data
from agentforge.api.schemas import CommandResult, EventBatch, ResourceResult
from agentforge.auth.errors import AuthorizationError
from agentforge.campaign.corpus import AuthoredCorpus, resolve_workload, verified_case_payload
from agentforge.contracts import validate as validate_contract
from agentforge.control_plane import ControlPlaneStore
from agentforge.control_plane.errors import (
    AuthorizationDeniedError,
    ControlPlaneError,
    IdempotencyConflictError,
    InvalidControlPlaneInput,
    RecordConflictError,
    RecordNotFoundError,
)
from agentforge.correlation import campaign_trace_id
from agentforge.migration_config import normalize_psycopg_url
from agentforge.policy.recorder import (
    PERSISTED_EVIDENCE_COLUMNS,
    EvidenceIntegrityError,
    ExecutionRecorder,
)
from agentforge.secrets import redact_mapping
from agentforge.security_tools.catalog import SECURITY_TOOL_CATALOG, security_tool_records
from agentforge.security_tools.scope import plan_tool_for_surface
from agentforge.security_tools.workbench import (
    inspect_sanitized_exchange,
    security_workbench_records,
)
from agentforge.target.catalog import SYNTHETIC_TARGET_ID, TrustedTargetCatalog
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    HostedRunBinding,
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
_DISPLAY_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|_)(?:sid|session_id|patient_id|patient_name|pid|mrn|ssn|"
    r"date_of_birth|birth_date|dob|address|email|phone)(?:$|_)"
)
_DISPLAY_SYNTHETIC_IDENTIFIER = re.compile(
    r"(?i)\bSYNTH-(?:PATIENT|PERSON|SUBJECT)-[A-Z0-9_-]+\b"
)
_DISPLAY_SYNTHETIC_CANARY = re.compile(r"(?i)\bSYNTH_CANARY_[A-Z0-9_-]+\b")
_DISPLAY_LABELED_IDENTIFIER = re.compile(
    r"(?i)\b(?:sid|session[_ -]?id|patient[_ -]?id|mrn|ssn|date[_ -]?of[_ -]?birth|dob)"
    r"\s*[:=]\s*[\"']?[A-Za-z0-9._:/@+-]+[\"']?"
)
_DISPLAY_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_DISPLAY_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
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
_RUNNER_HEARTBEAT_FRESHNESS_SECONDS = 30


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
        separate_authorization = value.get("requires_separate_authorization")
        if isinstance(separate_authorization, bool):
            redacted["requires_separate_authorization"] = separate_authorization
        # Aggregate model usage counters are non-secret accounting values. The generic
        # key-hint scrubber masks every key containing "token", so restore only these
        # explicitly typed counts after all credential-bearing structures were removed.
        for counter_key in ("input_tokens", "output_tokens", "token_observation_count"):
            if counter_key not in value:
                continue
            counter_value = value.get(counter_key)
            if counter_value is None or (
                isinstance(counter_value, int) and not isinstance(counter_value, bool)
            ):
                redacted[counter_key] = counter_value
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


def _evidence_hash_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for column in PERSISTED_EVIDENCE_COLUMNS:
        value = row.get(column)
        if isinstance(value, datetime.datetime):
            value = value.astimezone(datetime.UTC).isoformat()
        fields[column] = value
    fields["content_hash"] = row.get("content_hash")
    return fields


def _evidence_verified(row: Mapping[str, Any]) -> bool:
    try:
        ExecutionRecorder().verify(_evidence_hash_fields(row))
    except (EvidenceIntegrityError, TypeError, ValueError):
        return False
    return True


def _redact_evidence_display(value: Any) -> Any:
    """Redact patient/session identifiers from evidence after integrity verification."""

    if isinstance(value, Mapping):
        projected: dict[str, Any] = {}
        for key, item in value.items():
            label = str(key)
            projected[label] = (
                "***REDACTED_IDENTIFIER***"
                if _DISPLAY_SENSITIVE_KEY.search(label)
                else _redact_evidence_display(item)
            )
        return projected
    if isinstance(value, (tuple, list)):
        return [_redact_evidence_display(item) for item in value]
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if stripped[:1] in {"{", "["}:
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return json.dumps(
                _redact_evidence_display(parsed),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
    value = _DISPLAY_SYNTHETIC_IDENTIFIER.sub("SYNTH-PATIENT-[REDACTED]", value)
    value = _DISPLAY_SYNTHETIC_CANARY.sub("SYNTH_CANARY_[REDACTED]", value)
    value = _DISPLAY_LABELED_IDENTIFIER.sub("***REDACTED_IDENTIFIER***", value)
    value = _DISPLAY_EMAIL.sub("***REDACTED_EMAIL***", value)
    return _DISPLAY_SSN.sub("***REDACTED_SSN***", value)


def _reproduction_sha256(steps: Any) -> str | None:
    if not isinstance(steps, list) or not steps or not all(isinstance(step, str) for step in steps):
        return None
    canonical = json.dumps(
        steps,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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
    hosted_run = value.get("hosted_run")
    if isinstance(hosted_run, Mapping):
        projected["hosted_run"] = {
            key: hosted_run.get(key)
            for key in (
                "configuration_set_sha256",
                "generation_policy_sha256",
                "session_generation",
                "provider_model_call_limit",
                "provider_model_spend_limit_usd",
                "provider_max_retries",
                "provider_max_concurrency",
                "provider_timeout_seconds",
            )
        }
    else:
        projected["hosted_run"] = None
    return projected


class PostgresApiBackend(ApiBackend):
    """Organization-scoped projections over the integrated schema."""

    def __init__(
        self,
        engine: Engine,
        *,
        environment: str,
        runner_available: bool = False,
        hosted_runtime_available: bool = False,
        hosted_provider_bindings_verified: bool = False,
        corpus: AuthoredCorpus | None = None,
    ) -> None:
        self._engine = engine
        self._store = ControlPlaneStore(engine, environment=environment)
        self._environment = environment
        self._runner_available = runner_available
        self._hosted_runtime_available = hosted_runtime_available
        self._hosted_provider_bindings_verified = hosted_provider_bindings_verified
        self._corpus = corpus

    def _attack_case_evidence(self, source: Mapping[str, Any]) -> dict[str, Any]:
        case_id = str(source.get("case_id") or "unavailable")
        case_hash = source.get("case_content_hash")
        oracle_expectation = None
        corpus_reconciliation = "unavailable"
        if self._corpus is not None and isinstance(case_hash, str):
            authored = next(
                (
                    case
                    for case in self._corpus.cases
                    if case.payload.get("case_id") == case_id and case.content_hash == case_hash
                ),
                None,
            )
            if authored is not None:
                payload = verified_case_payload(authored)
                oracle_expectation = _redact_evidence_display(payload.get("oracle_expectation"))
                corpus_reconciliation = "verified"
        mappings = source.get("owasp_mappings")
        return {
            "case_id": case_id,
            "case_content_sha256": case_hash if isinstance(case_hash, str) else None,
            "category": source.get("case_category"),
            "attack_class": source.get("attack_class"),
            "owasp_mappings": mappings if isinstance(mappings, list) else [],
            "oracle_expectation": oracle_expectation,
            "corpus_reconciliation": corpus_reconciliation,
        }

    def _verification_projection(
        self,
        source: Mapping[str, Any],
    ) -> dict[str, Any]:
        finding_id = str(source.get("linked_finding_id") or source.get("finding_id") or "")
        content_hash = source.get("content_hash")
        linked_hash = source.get("evidence_content_hash")
        if (
            not isinstance(content_hash, str)
            or content_hash != linked_hash
            or not _evidence_verified(source)
        ):
            raise EvidenceIntegrityError("finding evidence cannot be verified")
        recomputed_hash = ExecutionRecorder().canonical_hash(_evidence_hash_fields(source))
        attack_attempt = source.get("attack_attempt")
        redacted_attempt = (
            _redact_evidence_display(attack_attempt)
            if isinstance(attack_attempt, Mapping)
            else None
        )
        input_sequence: list[str] = []
        if isinstance(redacted_attempt, Mapping):
            candidate = redacted_attempt.get("input_sequence")
            if isinstance(candidate, list) and all(isinstance(item, str) for item in candidate):
                input_sequence = candidate

        report_payload = source.get("report_payload")
        report_id = source.get("vuln_report_id")
        minimal_reproduction: list[str] = []
        reproduction_hash = None
        if isinstance(report_payload, Mapping):
            reproduction = report_payload.get("minimal_reproduction")
            if isinstance(reproduction, list) and all(
                isinstance(item, str) for item in reproduction
            ):
                minimal_reproduction = [
                    str(_redact_evidence_display(item)) for item in reproduction
                ]
            reproduction_hash = report_payload.get("reproduction_sha256")

        regression = None
        regression_payload = source.get("regression_payload")
        if isinstance(regression_payload, Mapping):
            regression = {
                "disposition_id": regression_payload.get("disposition_id"),
                "state": regression_payload.get("state"),
                "reason_codes": regression_payload.get("reason_codes", []),
                "reproduction_attempted": regression_payload.get("reproduction_attempted"),
                "deterministic_reproduction": regression_payload.get(
                    "deterministic_reproduction"
                ),
                "passes_for_right_reason": regression_payload.get("passes_for_right_reason"),
                "human_approved": regression_payload.get("human_approved"),
                "admitted": regression_payload.get("admitted"),
            }

        return {
            "availability": "ready",
            "reason_code": None,
            "finding_id": finding_id,
            "campaign_run_id": source.get("campaign_run_id"),
            "attempt_id": source.get("attempt_id"),
            "attack_case": self._attack_case_evidence(source),
            "attack_attempt": redacted_attempt,
            "input_sequence": input_sequence,
            "request_transcript": (
                _redact_evidence_display(source.get("request_transcript"))
                if isinstance(source.get("request_transcript"), Mapping)
                else None
            ),
            "response_transcript": (
                str(_redact_evidence_display(source.get("response_transcript")))
                if isinstance(source.get("response_transcript"), str)
                else None
            ),
            "policy_decision_id": source.get("policy_decision_id"),
            "executed_at": source.get("executed_at"),
            "trace_id": source.get("trace_id"),
            "judge": {
                "state": source.get("verdict_state"),
                "confidence": source.get("verdict_confidence"),
                "reason_codes": source.get("verdict_reason_codes") or [],
                "confirmation_source": source.get("verdict_confirmation_source"),
                "error_code": source.get("verdict_error_code"),
            },
            "report_id": report_id if isinstance(report_id, str) else None,
            "minimal_reproduction": minimal_reproduction,
            "reproduction_sha256": (
                reproduction_hash if isinstance(reproduction_hash, str) else None
            ),
            "regression": regression,
            "integrity": {
                "stored_content_sha256": content_hash,
                "finding_link_sha256": linked_hash,
                "recomputed_content_sha256": recomputed_hash,
                "evidence_record": "verified",
                "finding_link": "verified",
                "observability_reconciliation": "unavailable",
                "observability_detail": (
                    "No durable observability transcript hash is stored for this attempt."
                ),
            },
            "redaction_state": "synthetic_identifiers_redacted",
        }

    @staticmethod
    def _unavailable_verification(
        finding_id: str,
        *,
        reason_code: str,
    ) -> dict[str, Any]:
        return {
            "availability": "unavailable",
            "reason_code": reason_code,
            "finding_id": finding_id,
            "campaign_run_id": None,
            "attempt_id": None,
            "attack_case": None,
            "attack_attempt": None,
            "input_sequence": [],
            "request_transcript": None,
            "response_transcript": None,
            "policy_decision_id": None,
            "executed_at": None,
            "trace_id": None,
            "judge": None,
            "report_id": None,
            "minimal_reproduction": [],
            "reproduction_sha256": None,
            "regression": None,
            "integrity": None,
            "redaction_state": "synthetic_identifiers_redacted",
        }

    def read(self, resource, principal, *, identifiers=None):
        identifiers = dict(identifiers or {})
        if resource == "principal":
            return ResourceResult.ready(
                validate_ready_data(
                    "principal",
                    {
                        "user_id": principal.user_id,
                        "organization_id": principal.organization_id,
                        "organization_role": principal.organization_role,
                        "organization_permissions": sorted(principal.organization_permissions),
                    },
                )
            )
        if resource == "campaign_authorization_preflight":
            try:
                return self._campaign_authorization_preflight(
                    organization_id=principal.organization_id,
                    request_id=identifiers.get("request_id", ""),
                )
            except Exception:
                return ResourceResult.unavailable("campaign_preflight_unavailable")
        try:
            with self._engine.connect() as connection:
                if resource == "agents":
                    configuration_rows = _rows(
                        connection,
                        "SELECT * FROM agent_configuration_versions "
                        "WHERE organization_id = :org ORDER BY agent_role, version DESC",
                        {"org": principal.organization_id},
                    )
                    configurations: dict[str, list[dict[str, Any]]] = {}
                    for row in configuration_rows:
                        configurations.setdefault(row["agent_role"], []).append(row)
                    execution_rows = _rows(
                        connection,
                        "SELECT agent_role, count(*) AS execution_count, "
                        "count(*) FILTER (WHERE status = 'running') AS running_count, "
                        "count(*) FILTER (WHERE status = 'succeeded') AS succeeded_count, "
                        "count(*) FILTER (WHERE status = 'failed') AS failed_count, "
                        "count(*) FILTER (WHERE status = 'skipped') AS skipped_count, "
                        "coalesce(sum(measured_cost), 0) AS measured_cost, "
                        "sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens, "
                        "count(*) FILTER (WHERE input_tokens IS NOT NULL "
                        "OR output_tokens IS NOT NULL) AS token_observation_count, "
                        "avg(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) "
                        "AS average_duration_ms, "
                        "percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) "
                        "FILTER (WHERE duration_ms IS NOT NULL) AS p50_duration_ms, "
                        "percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) "
                        "FILTER (WHERE duration_ms IS NOT NULL) AS p95_duration_ms, "
                        "count(*) FILTER (WHERE langfuse_status = 'exported') "
                        "AS langfuse_exported_count, max(started_at) AS last_activity_at, "
                        "(array_agg(status ORDER BY started_at DESC))[1] AS last_status, "
                        "(array_agg(campaign_run_id ORDER BY started_at DESC))[1] "
                        "AS last_campaign_run_id, "
                        "(array_agg(attempt_id ORDER BY started_at DESC))[1] AS last_attempt_id "
                        "FROM agent_executions WHERE organization_id = :org GROUP BY agent_role",
                        {"org": principal.organization_id},
                    )
                    execution_by_role = {row["agent_role"]: row for row in execution_rows}

                    def assignment_record(source: Mapping[str, Any]) -> dict[str, Any]:
                        return {
                            "role": source["agent_role"]
                            if "agent_role" in source
                            else source["role"],
                            "provider": source["provider"],
                            "model": source["model"],
                            "execution_mode": source["execution_mode"],
                            "activation_state": source["activation_state"],
                            "version": source["version"],
                            "configuration_sha256": source["configuration_sha256"],
                            "configured_at": source.get("created_at")
                            or source.get("configured_at"),
                            "configured_by": source.get("actor_user_id")
                            or source.get("configured_by"),
                        }

                    rows = []
                    for definition in AGENT_DEFINITIONS:
                        definition_record = definition.public_record()
                        definition_record.pop("default_provider", None)
                        definition_record.pop("default_model", None)
                        definition_record.pop("default_execution_mode", None)
                        role_configurations = configurations.get(definition.role, [])
                        active = next(
                            (
                                row
                                for row in role_configurations
                                if row["activation_state"] == "active"
                            ),
                            None,
                        )
                        staged = next(
                            (
                                row
                                for row in role_configurations
                                if row["activation_state"] == "staged_pending_authorization"
                            ),
                            None,
                        )
                        active_assignment = (
                            assignment_record(active)
                            if active is not None
                            else default_assignment(definition.role).public_record()
                        )
                        stats = execution_by_role.get(definition.role, {})
                        rows.append(
                            {
                                **definition_record,
                                "active_assignment": active_assignment,
                                "staged_assignment": (
                                    assignment_record(staged) if staged is not None else None
                                ),
                                "execution_count": int(stats.get("execution_count", 0)),
                                "running_count": int(stats.get("running_count", 0)),
                                "succeeded_count": int(stats.get("succeeded_count", 0)),
                                "failed_count": int(stats.get("failed_count", 0)),
                                "skipped_count": int(stats.get("skipped_count", 0)),
                                "measured_cost": float(stats.get("measured_cost", 0.0)),
                                "currency": "USD",
                                "input_tokens": stats.get("input_tokens"),
                                "output_tokens": stats.get("output_tokens"),
                                "token_observation_count": int(
                                    stats.get("token_observation_count", 0)
                                ),
                                "average_duration_ms": (
                                    float(stats["average_duration_ms"])
                                    if stats.get("average_duration_ms") is not None
                                    else None
                                ),
                                "p50_duration_ms": (
                                    float(stats["p50_duration_ms"])
                                    if stats.get("p50_duration_ms") is not None
                                    else None
                                ),
                                "p95_duration_ms": (
                                    float(stats["p95_duration_ms"])
                                    if stats.get("p95_duration_ms") is not None
                                    else None
                                ),
                                "langfuse_exported_count": int(
                                    stats.get("langfuse_exported_count", 0)
                                ),
                                "last_activity_at": stats.get("last_activity_at"),
                                "last_status": stats.get("last_status"),
                                "last_campaign_run_id": stats.get("last_campaign_run_id"),
                                "last_attempt_id": stats.get("last_attempt_id"),
                            }
                        )
                elif resource in {
                    "hosted_configuration_set",
                    "hosted_configuration_preflight",
                }:
                    row = (
                        connection.execute(
                            text(
                                "SELECT configuration_sha256, schema_version, release_sha256, "
                                "payload, actor_user_id, created_at FROM hosted_configuration_sets "
                                "WHERE organization_id = :org "
                                "AND configuration_sha256 = :configuration"
                            ),
                            {
                                "org": principal.organization_id,
                                "configuration": identifiers.get("configuration_sha256", ""),
                            },
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        rows = []
                    else:
                        configuration = HostedConfigurationSet.from_payload(dict(row["payload"]))
                        if configuration.configuration_sha256 != row["configuration_sha256"]:
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        preflight = preflight_hosted_configuration_set(configuration)
                        public_roles = [
                            {
                                "role": role.role,
                                "provider": role.provider,
                                "model_id": role.model_id,
                                "upstream_provider": role.upstream_provider,
                                "prompt_sha256": role.prompt_sha256,
                                "policy_sha256": role.policy_sha256,
                                "prices": role.prices.canonical_payload(),
                                "limits": role.limits.canonical_payload(),
                                "provider_reference_bound": True,
                                "role_configuration_sha256": role.configuration_sha256,
                            }
                            for role in configuration.roles
                        ]
                        projection = {
                            "configuration_sha256": configuration.configuration_sha256,
                            "schema_version": configuration.schema_version,
                            "release_sha256": row["release_sha256"],
                            "activation_state": "staged_pending_authorization",
                            "runtime_available": self._hosted_runtime_available,
                            "runtime_reason": (
                                None
                                if self._hosted_runtime_available
                                else "hosted_runtime_not_composed"
                            ),
                            "global_limits": configuration.global_limits.canonical_payload(),
                            "roles": public_roles,
                            "configured_by": row["actor_user_id"],
                            "created_at": row["created_at"],
                        }
                        if resource == "hosted_configuration_preflight":
                            projection["preflight"] = {
                                "configuration_integrity": preflight.ok,
                                "role_count": len(preflight.roles),
                                "provider_bindings_distinct": True,
                                "provider_binding_readiness": (
                                    "runner_verified"
                                    if self._hosted_provider_bindings_verified
                                    else "runner_only_unverified"
                                ),
                                "authorization_required": preflight.authorization_required,
                                "runner_heartbeat_fresh": self._runner_heartbeat_is_fresh(),
                                "provider_calls_performed": 0,
                                "target_calls_performed": 0,
                            }
                        rows = [projection]
                elif resource == "agent_activity":
                    rows = _rows(
                        connection,
                        "SELECT execution_id, campaign_run_id, attempt_id, parent_execution_id, "
                        "agent_role, status, provider, model, execution_mode, "
                        "configuration_version, input_sha256, output_sha256, input_tokens, "
                        "output_tokens, measured_cost, currency, trace_id, langfuse_status, "
                        "detail, error_code, "
                        "started_at, finished_at, duration_ms FROM agent_executions "
                        "WHERE organization_id = :org ORDER BY id DESC LIMIT 1000",
                        {"org": principal.organization_id},
                    )
                    for row in rows:
                        row["measured_cost"] = float(row["measured_cost"] or 0.0)
                        row["duration_ms"] = (
                            float(row["duration_ms"]) if row["duration_ms"] is not None else None
                        )
                elif resource == "tooling":
                    surface_rows = _rows(
                        connection,
                        "SELECT t.target_id, t.version AS target_version, t.payload AS target, "
                        "s.surface_id, s.version AS surface_version, s.payload AS surface, "
                        "(SELECT e.to_lifecycle FROM target_lifecycle_events e "
                        "WHERE e.organization_id = t.organization_id "
                        "AND e.target_id = t.target_id AND e.target_version = t.version "
                        "ORDER BY e.id DESC LIMIT 1) AS target_lifecycle "
                        "FROM target_definitions t JOIN attack_surface_definitions s "
                        "ON s.organization_id = t.organization_id "
                        "AND s.target_id = t.target_id AND s.target_version = t.version "
                        "WHERE t.organization_id = :org ORDER BY t.target_id, s.surface_id",
                        {"org": principal.organization_id},
                    )
                    attempt_rows = _rows(
                        connection,
                        "SELECT source_tool, count(*) AS executed_attempt_count, "
                        "max(created_at) AS last_executed_at FROM campaign_attempts "
                        "WHERE organization_id = :org AND source_tool IS NOT NULL "
                        "GROUP BY source_tool",
                        {"org": principal.organization_id},
                    )
                    attempt_metrics = {row["source_tool"]: row for row in attempt_rows}
                    scan_rows = _rows(
                        connection,
                        "SELECT lower(r.tool_name) AS tool_id, count(DISTINCT r.run_id) "
                        "AS recorded_scan_count, count(f.finding_id) AS recorded_finding_count, "
                        "max(r.finished_at) AS last_executed_at FROM security_tool_runs r "
                        "LEFT JOIN security_tool_findings f "
                        "ON f.organization_id = r.organization_id AND f.run_id = r.run_id "
                        "WHERE r.organization_id = :org GROUP BY lower(r.tool_name)",
                        {"org": principal.organization_id},
                    )
                    scan_metrics = {row["tool_id"]: row for row in scan_rows}
                    candidate_counts = Counter(
                        case.source_tool
                        for case in (self._corpus.cases if self._corpus is not None else ())
                        if case.source_tool is not None
                    )
                    rows = []
                    for configured in surface_rows:
                        target = dict(configured["target"])
                        surface = dict(configured["surface"])
                        endpoint = (
                            f"{str(target.get('base_url', '')).rstrip('/')}/"
                            f"{str(surface.get('relative_path', '')).lstrip('/')}"
                        )
                        for tool in SECURITY_TOOL_CATALOG:
                            plan = plan_tool_for_surface(
                                tool,
                                surface_kind=str(surface.get("kind", "")),
                                protocol=str(surface.get("protocol", "")),
                                method=str(surface.get("method", "")),
                                relative_path=str(surface.get("relative_path", "")),
                            )
                            attempts = attempt_metrics.get(tool.tool_id, {})
                            scans = scan_metrics.get(tool.tool_id, {})
                            timestamps = [
                                value
                                for value in (
                                    attempts.get("last_executed_at"),
                                    scans.get("last_executed_at"),
                                )
                                if isinstance(value, datetime.datetime)
                            ]
                            rows.append(
                                {
                                    "tool_id": tool.tool_id,
                                    "name": tool.name,
                                    "version": tool.version,
                                    "kind": tool.kind,
                                    "availability": tool.availability,
                                    "target_access": tool.target_access,
                                    "target_id": configured["target_id"],
                                    "target_version": configured["target_version"],
                                    "target_lifecycle": configured["target_lifecycle"] or "draft",
                                    "surface_id": configured["surface_id"],
                                    "surface_version": configured["surface_version"],
                                    "surface_kind": surface.get("kind"),
                                    "endpoint": endpoint,
                                    **plan.public_record(),
                                    "capabilities": tool.capabilities,
                                    "owasp_llm": tool.owasp_llm,
                                    "owasp_web": tool.owasp_web,
                                    "reviewed_candidate_count": candidate_counts[tool.tool_id],
                                    "executed_attempt_count": int(
                                        attempts.get("executed_attempt_count", 0)
                                    ),
                                    "recorded_scan_count": int(scans.get("recorded_scan_count", 0)),
                                    "recorded_finding_count": int(
                                        scans.get("recorded_finding_count", 0)
                                    ),
                                    "last_executed_at": max(timestamps) if timestamps else None,
                                }
                            )
                elif resource == "resilience":
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
                        "hosted_runtime_composed": self._hosted_runtime_available,
                        "provider_bindings_runner_verified": (
                            self._hosted_provider_bindings_verified
                        ),
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
                        "security_tools": security_tool_records(),
                        "security_workbench": {
                            "name": "Headshot LLM Security Workbench",
                            "burp_suite_installed": False,
                            "capabilities": security_workbench_records(),
                        },
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
                elif resource == "birdseye":
                    rows = [
                        build_birdseye_snapshot(
                            connection,
                            organization_id=principal.organization_id,
                            environment=self._environment,
                        )
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
                            "version": "1",
                            "heartbeat_at": heartbeat_at,
                        },
                        {
                            "component_id": "postgres",
                            "name": "PostgreSQL system of record",
                            "kind": "database",
                            "availability": "operational and evidenced",
                            "environment": self._environment,
                            "detail": "organization-scoped projection query succeeded",
                            "version": "16",
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
                    for row in rows:
                        row.setdefault("version", "unreported")
                        row.setdefault("target_access", "none")
                        row.setdefault("capabilities", [])
                        row.setdefault("owasp_llm", [])
                        row.setdefault("owasp_web", [])
                        row.setdefault("operational_scope", [])
                        row.setdefault("adapter_only_scope", [])
                        row.setdefault("execution_evidence", [])
                    for tool in SECURITY_TOOL_CATALOG:
                        rows.append(
                            {
                                "component_id": f"security-tool:{tool.tool_id}",
                                "name": tool.name,
                                "kind": f"security-tool:{tool.kind}",
                                "availability": tool.availability,
                                "environment": "isolated-ci-tooling",
                                "detail": tool.detail,
                                "heartbeat_at": tool.last_verified_at,
                                "version": tool.version,
                                "target_access": tool.target_access,
                                "capabilities": list(tool.capabilities),
                                "owasp_llm": list(tool.owasp_llm),
                                "owasp_web": list(tool.owasp_web),
                                "operational_scope": list(tool.operational_scope),
                                "adapter_only_scope": list(tool.adapter_only_scope),
                                "execution_evidence": list(tool.execution_evidence),
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
                        "a.case_id, a.case_content_hash, a.category AS case_category, "
                        "a.attack_class, a.owasp_mappings, "
                        "v.state AS verdict_state, v.confidence AS verdict_confidence, "
                        "v.reason_codes AS verdict_reason_codes, "
                        "v.confirmation_source AS verdict_confirmation_source, "
                        "v.error_code AS verdict_error_code, "
                        "vr.report_id AS vuln_report_id, vr.contract_payload AS report_payload, "
                        "rd.contract_payload AS regression_payload, "
                        "l.evidence_content_hash, l.provenance AS linked_provenance "
                        "FROM finding f JOIN finding_evidence_links l "
                        "ON l.organization_id = f.organization_id AND l.finding_id = f.finding_id "
                        "JOIN attempt_result ar ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id "
                        "JOIN campaign_attempts a ON a.organization_id = l.organization_id "
                        "AND a.run_id = l.campaign_run_id AND a.attempt_id = l.attempt_id "
                        "JOIN verdict v ON v.id = l.verdict_id "
                        "LEFT JOIN vuln_reports vr "
                        "ON vr.organization_id = f.organization_id "
                        "AND vr.finding_id = f.finding_id "
                        "LEFT JOIN LATERAL (SELECT d.contract_payload "
                        "FROM regression_dispositions d "
                        "WHERE d.organization_id = f.organization_id "
                        "AND d.finding_id = f.finding_id "
                        "ORDER BY d.created_at DESC LIMIT 1) rd ON true WHERE "
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
                        projection = {
                                "finding_id": source["linked_finding_id"],
                                "state": "resolved"
                                if latest == "resolved"
                                else (
                                    "documented"
                                    if source["vuln_report_id"] is not None
                                    else source["finding_state"]
                                ),
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
                        if resource == "finding":
                            projection["verification"] = self._verification_projection(source)
                        rows.append(projection)
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
                        projection = {
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
                        if resource == "finding":
                            projection["verification"] = self._unavailable_verification(
                                payload["finding_id"],
                                reason_code="campaign_transcript_not_applicable",
                            )
                        rows.append(projection)
                elif resource in {"reports", "report"}:
                    where = "vr.organization_id = :org"
                    parameters = {"org": principal.organization_id}
                    if resource == "report":
                        where += " AND vr.report_id = :report_id"
                        parameters["report_id"] = identifiers.get("report_id")
                    source_rows = _rows(
                        connection,
                        "SELECT ar.*, f.finding_id AS linked_finding_id, "
                        "a.case_id, a.case_content_hash, a.category AS case_category, "
                        "a.attack_class, a.owasp_mappings, "
                        "v.state AS verdict_state, v.confidence AS verdict_confidence, "
                        "v.reason_codes AS verdict_reason_codes, "
                        "v.confirmation_source AS verdict_confirmation_source, "
                        "v.error_code AS verdict_error_code, "
                        "vr.report_id AS vuln_report_id, vr.contract_payload AS report_payload, "
                        "vr.created_at AS report_created_at, "
                        "rd.contract_payload AS regression_payload, "
                        "l.evidence_content_hash "
                        "FROM vuln_reports vr JOIN finding f "
                        "ON f.organization_id = vr.organization_id "
                        "AND f.finding_id = vr.finding_id "
                        "JOIN finding_evidence_links l "
                        "ON l.organization_id = f.organization_id AND l.finding_id = f.finding_id "
                        "JOIN attempt_result ar ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id "
                        "JOIN campaign_attempts a ON a.organization_id = l.organization_id "
                        "AND a.run_id = l.campaign_run_id AND a.attempt_id = l.attempt_id "
                        "JOIN verdict v ON v.id = l.verdict_id "
                        "LEFT JOIN LATERAL (SELECT d.contract_payload "
                        "FROM regression_dispositions d "
                        "WHERE d.organization_id = vr.organization_id "
                        "AND d.report_id = vr.report_id "
                        "ORDER BY d.created_at DESC LIMIT 1) rd ON true WHERE "
                        + where
                        + " ORDER BY vr.created_at DESC",
                        parameters,
                    )
                    rows = []
                    for source in source_rows:
                        report_payload = source.get("report_payload")
                        regression_payload = source.get("regression_payload")
                        try:
                            if not isinstance(report_payload, Mapping):
                                raise ValueError("report payload is absent")
                            report_payload = dict(report_payload)
                            validate_contract("vuln_report", report_payload)
                            if (
                                report_payload.get("report_id") != source["vuln_report_id"]
                                or report_payload.get("finding_id")
                                != source["linked_finding_id"]
                                or report_payload.get("campaign_run_id")
                                != source["campaign_run_id"]
                                or report_payload.get("attempt_id") != source["attempt_id"]
                                or _reproduction_sha256(
                                    report_payload.get("minimal_reproduction")
                                )
                                != report_payload.get("reproduction_sha256")
                                or f"evidence://sha256/{source['evidence_content_hash']}"
                                not in report_payload.get("evidence_references", [])
                            ):
                                raise ValueError("report correlation differs")
                            if regression_payload is not None:
                                if not isinstance(regression_payload, Mapping):
                                    raise ValueError("regression payload is invalid")
                                regression_payload = dict(regression_payload)
                                validate_contract(
                                    "regression_disposition",
                                    regression_payload,
                                )
                                if any(
                                    regression_payload.get(key) != report_payload.get(key)
                                    for key in (
                                        "finding_id",
                                        "report_id",
                                        "campaign_run_id",
                                        "attempt_id",
                                    )
                                ):
                                    raise ValueError("regression correlation differs")
                            verification = self._verification_projection(source)
                        except Exception:
                            return ResourceResult.unavailable("report_integrity_failed")
                        display_payload = _redact_evidence_display(report_payload)
                        regression = verification["regression"]
                        rows.append(
                            {
                                **display_payload,
                                "regression": regression,
                                "report_integrity": "verified",
                                "created_at": source["report_created_at"],
                                "verification": verification,
                            }
                        )
                elif resource == "coverage":
                    source_rows = _rows(
                        connection,
                        "SELECT ar.*, a.case_id, a.category, a.attack_class, a.owasp_mappings, "
                        "a.fixture_provenance, v.state AS verdict_state, "
                        "v.created_at AS verdict_created_at, "
                        "q.scope_payload->>'corpus_hash' AS authorized_corpus_hash "
                        "FROM campaign_attempts a JOIN campaign_runs r "
                        "ON r.organization_id = a.organization_id AND r.run_id = a.run_id "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
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
                                "authorized_case_counts": set(),
                                "as_of": source["verdict_created_at"],
                            },
                        )
                        group["attempts"].add(identity)
                        group["cases"].add(source["case_id"])
                        group["categories"].add(source["category"])
                        group["classifications"].add(source["attack_class"])
                        if (
                            self._corpus is not None
                            and source.get("authorized_corpus_hash") == self._corpus.content_hash
                        ):
                            group["authorized_case_counts"].add(len(self._corpus.cases))
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
                        total_case_count = max(
                            group["authorized_case_counts"] or {len(group["cases"])}
                        )
                        rows.append(
                            {
                                "target_version": f"{target_id}@{target_version}",
                                "verified_attempt_count": len(group["attempts"]),
                                "total_case_count": total_case_count,
                                "category_count": len(group["categories"]),
                                "execution_profile": profile,
                                "evidence_provenance": provenance,
                                "classifications": sorted(group["classifications"]),
                                "owasp_web": sorted(group["web"]),
                                "owasp_llm": sorted(group["llm"]),
                                "verdict_counts": group["verdicts"],
                                "covered": (
                                    len(group["cases"]) >= total_case_count
                                    and total_case_count >= 9
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
                                "agent_role": None,
                                "record_kind": "campaign",
                                # measured_cost is a Numeric(14,6) -> Decimal; the console/pydantic
                                # contract requires a JSON number, so coerce it to float here rather
                                # than letting _safe stringify the Decimal.
                                "measured_cost": float(cost) if cost is not None else 0.0,
                                "currency": source["currency"],
                                "request_count": source["request_count"],
                                "execution_count": 0,
                                "attempt_count": source["attempt_count"],
                                "confirmed_finding_count": source["confirmed_finding_count"],
                                "average_cost_per_request": (
                                    float(cost) / source["request_count"]
                                    if cost is not None and source["request_count"]
                                    else 0.0
                                ),
                                "input_tokens": None,
                                "output_tokens": None,
                                "token_observation_count": 0,
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
                    agent_cost_rows = _rows(
                        connection,
                        "SELECT e.campaign_run_id, e.agent_role, e.provider, e.model, "
                        "e.execution_mode, "
                        "sum(e.measured_cost) AS measured_cost, e.currency, "
                        "count(*) AS executions, "
                        "count(DISTINCT e.attempt_id) AS attempt_count, "
                        "sum(e.input_tokens) AS input_tokens, "
                        "sum(e.output_tokens) AS output_tokens, "
                        "count(*) FILTER (WHERE e.input_tokens IS NOT NULL "
                        "OR e.output_tokens IS NOT NULL) AS token_observation_count, "
                        "min(e.started_at) AS started_at, max(e.finished_at) AS ended_at, "
                        "extract(epoch FROM (max(e.finished_at) - min(e.started_at))) * 1000 "
                        "AS duration_ms, q.scope_payload->>'execution_profile' "
                        "AS execution_profile, "
                        "CASE WHEN jsonb_typeof(q.scope_payload->'caps'->'budget_usd') = 'number' "
                        "THEN (q.scope_payload->'caps'->>'budget_usd')::double precision "
                        "ELSE NULL END AS budget_usd "
                        "FROM agent_executions e JOIN campaign_runs r "
                        "ON r.organization_id = e.organization_id "
                        "AND r.run_id = e.campaign_run_id "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "WHERE e.organization_id = :org AND e.status <> 'running' "
                        "GROUP BY e.campaign_run_id, e.agent_role, e.provider, e.model, "
                        "e.currency, e.execution_mode, q.scope_payload "
                        "ORDER BY max(e.finished_at) DESC LIMIT 400",
                        {"org": principal.organization_id},
                    )
                    for source in agent_cost_rows:
                        cost = float(source["measured_cost"] or 0.0)
                        accounting_id = hashlib.sha256(
                            (
                                f"agent-cost:{source['campaign_run_id']}:"
                                f"{source['agent_role']}:{source['provider']}:{source['model']}:"
                                f"{source['execution_mode']}"
                            ).encode()
                        ).hexdigest()
                        rows.append(
                            {
                                "accounting_id": accounting_id,
                                "campaign_id": source["campaign_run_id"],
                                "provider": (
                                    f"agent:{source['agent_role']}:"
                                    f"{source['provider']}/{source['model']}"
                                ),
                                "agent_role": source["agent_role"],
                                "record_kind": "agent",
                                "measured_cost": cost,
                                "currency": source["currency"],
                                # Agent executions are logical spans, not physical provider
                                # requests. Until provider request IDs are durably correlated,
                                # never infer a request count from execution count.
                                "request_count": 0,
                                "execution_count": int(source["executions"]),
                                "attempt_count": int(source["attempt_count"]),
                                "confirmed_finding_count": 0,
                                "average_cost_per_request": 0.0,
                                "input_tokens": source["input_tokens"],
                                "output_tokens": source["output_tokens"],
                                "token_observation_count": int(source["token_observation_count"]),
                                "budget_usd": None,
                                "budget_utilization": None,
                                "duration_ms": float(source["duration_ms"] or 0.0),
                                "execution_profile": source["execution_profile"],
                                "started_at": source["started_at"],
                                "ended_at": source["ended_at"],
                                "recorded_at": source["ended_at"],
                            }
                        )
                elif resource == "traces":
                    request_rows = _rows(
                        connection,
                        "SELECT request_id, trace_id, campaign_run_id AS campaign_id, attempt_id, "
                        "operation, provider, method, destination_host, relative_path, status, "
                        "status_code, error_code, started_at, finished_at, duration_ms, "
                        "request_bytes, response_bytes, measured_cost, currency, langfuse_status, "
                        "request_payload, response_payload "
                        "FROM outbound_http_requests WHERE organization_id = :org "
                        "AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 200",
                        {"org": principal.organization_id},
                    )
                    rows = []
                    for source in request_rows:
                        request_payload = _safe(source.pop("request_payload"))
                        response_payload = _safe(source.pop("response_payload"))
                        duration_ms = float(source["duration_ms"] or 0.0)
                        inspection = inspect_sanitized_exchange(
                            request_payload=request_payload,
                            response_payload=(
                                response_payload if isinstance(response_payload, str) else None
                            ),
                            status_code=source["status_code"],
                            error_code=source["error_code"],
                            duration_ms=duration_ms,
                        )
                        rows.append(
                            {
                                **source,
                                **inspection,
                                "execution_id": None,
                                "parent_execution_id": None,
                                "agent_role": None,
                                "execution_mode": None,
                                "input_tokens": None,
                                "output_tokens": None,
                                "duration_ms": duration_ms,
                                "measured_cost": float(source["measured_cost"] or 0.0),
                            }
                        )
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
                                "execution_id": None,
                                "parent_execution_id": None,
                                "trace_id": source["trace_id"],
                                "campaign_id": source["campaign_id"],
                                "attempt_id": source["attempt_id"],
                                "operation": (
                                    f"attempt:{source['target_id']}@{source['target_version']}"
                                ),
                                "provider": source["target_id"] or "target",
                                "agent_role": None,
                                "execution_mode": None,
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
                                "input_tokens": None,
                                "output_tokens": None,
                                "langfuse_status": "historical_not_instrumented",
                                "request_preview": None,
                                "response_preview": None,
                                "request_sha256": None,
                                "response_sha256": None,
                                "inspection_flags": [],
                                "inspection_owasp_mappings": [],
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
                                "execution_id": None,
                                "parent_execution_id": None,
                                "trace_id": campaign_trace_id(source["run_id"]),
                                "campaign_id": source["run_id"],
                                "attempt_id": None,
                                "operation": "campaign.run",
                                "provider": source["provenance"],
                                "agent_role": None,
                                "execution_mode": None,
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
                                "input_tokens": None,
                                "output_tokens": None,
                                "langfuse_status": "historical_not_instrumented",
                                "request_preview": None,
                                "response_preview": None,
                                "request_sha256": None,
                                "response_sha256": None,
                                "inspection_flags": [],
                                "inspection_owasp_mappings": [],
                            }
                        )
                    agent_rows = _rows(
                        connection,
                        "SELECT execution_id, parent_execution_id, trace_id, campaign_run_id, "
                        "attempt_id, agent_role, status, provider, model, execution_mode, "
                        "input_sha256, output_sha256, input_tokens, output_tokens, error_code, "
                        "started_at, finished_at, duration_ms, measured_cost, currency, "
                        "langfuse_status "
                        "FROM agent_executions WHERE organization_id = :org "
                        "ORDER BY started_at DESC LIMIT 1000",
                        {"org": principal.organization_id},
                    )
                    for source in agent_rows:
                        rows.append(
                            {
                                "request_id": None,
                                "execution_id": source["execution_id"],
                                "parent_execution_id": source["parent_execution_id"],
                                "trace_id": source["trace_id"],
                                "campaign_id": source["campaign_run_id"],
                                "attempt_id": source["attempt_id"],
                                "operation": f"agent.{source['agent_role']}",
                                "provider": f"{source['provider']}/{source['model']}",
                                "agent_role": source["agent_role"],
                                "execution_mode": source["execution_mode"],
                                "method": None,
                                "destination_host": None,
                                "relative_path": None,
                                "status": source["status"],
                                "status_code": None,
                                "error_code": source["error_code"],
                                "started_at": source["started_at"],
                                "finished_at": source["finished_at"],
                                "duration_ms": (
                                    float(source["duration_ms"])
                                    if source["duration_ms"] is not None
                                    else None
                                ),
                                "request_bytes": 0,
                                "response_bytes": None,
                                "measured_cost": float(source["measured_cost"] or 0.0),
                                "currency": source["currency"],
                                "input_tokens": source["input_tokens"],
                                "output_tokens": source["output_tokens"],
                                "langfuse_status": source["langfuse_status"],
                                "request_preview": None,
                                "response_preview": None,
                                "request_sha256": source["input_sha256"],
                                "response_sha256": source["output_sha256"],
                                "inspection_flags": [],
                                "inspection_owasp_mappings": [],
                            }
                        )
                    rows.sort(key=lambda row: row["started_at"], reverse=True)
                elif resource in {"approvals", "approval"}:
                    approval_where = "q.organization_id = :org"
                    approval_parameters = {"org": principal.organization_id}
                    if resource == "approval":
                        approval_where += " AND q.request_id = :request_id"
                        approval_parameters["request_id"] = identifiers.get("request_id")
                    rows = _rows(
                        connection,
                        "SELECT q.request_id, q.scope_hash, q.launcher_user_id, q.expires_at, "
                        "q.created_at, q.scope_payload, "
                        "(SELECT t.payload->>'base_url' FROM target_definitions t "
                        " WHERE t.organization_id = q.organization_id "
                        " AND t.target_id = q.scope_payload->>'target_id' "
                        " AND t.version = q.scope_payload->>'target_version' LIMIT 1) "
                        "AS target_base_url, d.decision, d.approver_user_id, "
                        "coalesce(d.self_approval_override, false) AS self_approval_override, "
                        "d.created_at AS decided_at, "
                        "(q.expires_at <= clock_timestamp()) AS expired, "
                        "EXISTS (SELECT 1 FROM campaign_runs r "
                        "WHERE r.organization_id = q.organization_id "
                        "AND r.authorization_request_id = q.request_id) AS consumed "
                        "FROM campaign_authorization_requests q "
                        "LEFT JOIN campaign_authorization_decisions d "
                        "ON d.organization_id = q.organization_id AND d.request_id = q.request_id "
                        "WHERE "
                        + approval_where
                        + " ORDER BY q.created_at DESC LIMIT 200",
                        approval_parameters,
                    )
                    if resource == "approval" and rows:
                        row = rows[0]
                        run_id = connection.execute(
                            text(
                                "SELECT run_id FROM campaign_runs "
                                "WHERE organization_id = :org "
                                "AND authorization_request_id = :request_id "
                                "ORDER BY created_at DESC LIMIT 1"
                            ),
                            {
                                "org": principal.organization_id,
                                "request_id": row["request_id"],
                            },
                        ).scalar_one_or_none()
                        row["campaign_run_id"] = run_id
                        verification_rows = []
                        if isinstance(run_id, str):
                            verification_rows = _rows(
                                connection,
                                "SELECT ar.*, f.finding_id AS linked_finding_id, "
                                "a.case_id, a.case_content_hash, "
                                "a.category AS case_category, a.attack_class, a.owasp_mappings, "
                                "v.state AS verdict_state, "
                                "v.confidence AS verdict_confidence, "
                                "v.reason_codes AS verdict_reason_codes, "
                                "v.confirmation_source AS verdict_confirmation_source, "
                                "v.error_code AS verdict_error_code, "
                                "vr.report_id AS vuln_report_id, "
                                "vr.contract_payload AS report_payload, "
                                "rd.contract_payload AS regression_payload, "
                                "l.evidence_content_hash "
                                "FROM finding f JOIN finding_evidence_links l "
                                "ON l.organization_id = f.organization_id "
                                "AND l.finding_id = f.finding_id "
                                "JOIN attempt_result ar ON ar.organization_id = l.organization_id "
                                "AND ar.campaign_run_id = l.campaign_run_id "
                                "AND ar.attempt_id = l.attempt_id "
                                "JOIN campaign_attempts a ON a.organization_id = l.organization_id "
                                "AND a.run_id = l.campaign_run_id "
                                "AND a.attempt_id = l.attempt_id "
                                "JOIN verdict v ON v.id = l.verdict_id "
                                "LEFT JOIN vuln_reports vr "
                                "ON vr.organization_id = f.organization_id "
                                "AND vr.finding_id = f.finding_id "
                                "LEFT JOIN LATERAL (SELECT d.contract_payload "
                                "FROM regression_dispositions d "
                                "WHERE d.organization_id = f.organization_id "
                                "AND d.finding_id = f.finding_id "
                                "ORDER BY d.created_at DESC LIMIT 1) rd ON true "
                                "WHERE f.organization_id = :org "
                                "AND l.campaign_run_id = :run_id "
                                "ORDER BY f.created_at DESC",
                                {"org": principal.organization_id, "run_id": run_id},
                            )
                        try:
                            row["verification_chain"] = [
                                self._verification_projection(item)
                                for item in verification_rows
                            ]
                        except EvidenceIntegrityError:
                            return ResourceResult.unavailable(
                                "approval_evidence_integrity_failed"
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
                                "case_count": len(self._corpus.cases),
                                "tool_sources": list(self._corpus.tool_sources),
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

        if resource in {"campaigns", "campaign", "approvals", "approval"}:
            for row in rows:
                row.update(
                    _scope_projection(
                        row.pop("scope_payload", None),
                        target_base_url=row.pop("target_base_url", None),
                    )
                )
                if resource in {"approvals", "approval"}:
                    row["status"] = row.get("decision") or "pending"

        sanitized = _safe(rows)
        if resource in {
            "campaign",
            "evidence",
            "target",
            "finding",
            "approval",
            "report",
            "agent_prompt",
            "configuration",
            "birdseye",
            "hosted_configuration_set",
            "hosted_configuration_preflight",
        }:
            if not sanitized:
                return ResourceResult.empty()
            try:
                data = validate_ready_data(resource, sanitized[0])
                if resource == "hosted_configuration_preflight":
                    if not self._hosted_runtime_available:
                        return ResourceResult.degraded(
                            data,
                            "hosted_runtime_not_composed",
                        )
                    if not self._hosted_provider_bindings_verified:
                        return ResourceResult.degraded(
                            data,
                            "provider_credentials_runner_unverified",
                        )
                return ResourceResult.ready(data)
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
                    hosted_run=(
                        HostedRunBinding(**dict(payload["hosted_run"]))
                        if payload.get("hosted_run") is not None
                        else None
                    ),
                )
                with self._engine.connect() as connection:
                    database_now = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
                expiry = database_now + datetime.timedelta(
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
                requires_hosted_runtime = self._authorization_requires_hosted_runtime(
                    principal.organization_id,
                    str(payload["authorization_request_id"]),
                )
                if not self._hosted_runtime_available and requires_hosted_runtime:
                    return CommandResult.unavailable("hosted_runtime_not_composed")
                if not self._hosted_provider_bindings_verified and requires_hosted_runtime:
                    return CommandResult.unavailable("provider_credentials_runner_unverified")
                if not self._runner_heartbeat_is_fresh():
                    return CommandResult.unavailable("runner_heartbeat_stale")
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
            if command == "configure_agent":
                return CommandResult.unavailable("atomic_hosted_configuration_set_required")
            if command == "stage_hosted_configuration_set":
                configuration = HostedConfigurationSet.from_payload(dict(payload["configuration"]))
                configuration_sha256 = self._store.stage_hosted_configuration_set(
                    principal=principal,
                    configuration=configuration,
                    release_sha256=str(payload["release_sha256"]),
                    rationale=str(payload["rationale"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(
                    configuration_sha256,
                    resource_id=configuration_sha256,
                )
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

    def _runner_heartbeat_is_fresh(self) -> bool:
        """Use database time so Web/Runner host clock skew cannot widen launch authority."""

        with self._engine.connect() as connection:
            return bool(
                connection.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM runtime_component_status "
                        "WHERE environment = :environment AND component_id = 'runner' "
                        "AND availability = 'operational and evidenced' "
                        "AND heartbeat_at > clock_timestamp() "
                        "- make_interval(secs => :freshness_seconds))"
                    ),
                    {
                        "environment": self._environment,
                        "freshness_seconds": _RUNNER_HEARTBEAT_FRESHNESS_SECONDS,
                    },
                ).scalar_one()
            )

    def _campaign_authorization_preflight(
        self,
        *,
        organization_id: str,
        request_id: str,
    ) -> ResourceResult:
        """Project every launch gate without resolving a secret or making an external call."""

        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT q.scope_hash, q.scope_payload, q.launcher_user_id, q.expires_at, "
                        "d.decision, d.approver_user_id, clock_timestamp() AS database_now, "
                        "EXISTS (SELECT 1 FROM campaign_runs r "
                        "WHERE r.organization_id = q.organization_id "
                        "AND r.authorization_request_id = q.request_id) AS consumed "
                        "FROM campaign_authorization_requests q "
                        "LEFT JOIN campaign_authorization_decisions d "
                        "ON d.organization_id = q.organization_id AND d.request_id = q.request_id "
                        "WHERE q.organization_id = :org AND q.request_id = :request_id"
                    ),
                    {"org": organization_id, "request_id": request_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return ResourceResult.empty()
            scope = dict(row["scope_payload"])
            hosted = scope.get("hosted_run")
            hosted = dict(hosted) if isinstance(hosted, Mapping) else None
            target_state = (
                connection.execute(
                    text(
                        "SELECT "
                        "(SELECT e.to_lifecycle FROM target_lifecycle_events e "
                        "WHERE e.organization_id = t.organization_id "
                        "AND e.target_id = t.target_id AND e.target_version = t.version "
                        "ORDER BY e.id DESC LIMIT 1) AS lifecycle, "
                        "(SELECT e.to_enabled FROM surface_state_events e "
                        "WHERE e.organization_id = s.organization_id "
                        "AND e.surface_id = s.surface_id AND e.surface_version = s.version "
                        "ORDER BY e.id DESC LIMIT 1) AS surface_enabled, "
                        "(t.payload->>'synthetic_data_only')::boolean AS synthetic_data_only "
                        "FROM target_definitions t JOIN attack_surface_definitions s "
                        "ON s.organization_id = t.organization_id "
                        "AND s.target_id = t.target_id AND s.target_version = t.version "
                        "WHERE t.organization_id = :org AND t.target_id = :target "
                        "AND t.version = :target_version AND s.surface_id = :surface "
                        "AND s.version = :surface_version"
                    ),
                    {
                        "org": organization_id,
                        "target": scope.get("target_id", ""),
                        "target_version": scope.get("target_version", ""),
                        "surface": scope.get("surface_id", ""),
                        "surface_version": scope.get("surface_version", ""),
                    },
                )
                .mappings()
                .one_or_none()
            )
            runner_heartbeat_fresh = bool(
                connection.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM runtime_component_status "
                        "WHERE environment = :environment AND component_id = 'runner' "
                        "AND availability = 'operational and evidenced' "
                        "AND heartbeat_at > clock_timestamp() "
                        "- make_interval(secs => :freshness_seconds))"
                    ),
                    {
                        "environment": self._environment,
                        "freshness_seconds": _RUNNER_HEARTBEAT_FRESHNESS_SECONDS,
                    },
                ).scalar_one()
            )

            configuration_valid = False
            distinct_references = False
            caps_match = False
            if hosted is not None:
                payload = connection.execute(
                    text(
                        "SELECT payload FROM hosted_configuration_sets "
                        "WHERE organization_id = :org "
                        "AND configuration_sha256 = :configuration"
                    ),
                    {
                        "org": organization_id,
                        "configuration": hosted.get("configuration_set_sha256", ""),
                    },
                ).scalar_one_or_none()
                if payload is not None:
                    try:
                        configuration = HostedConfigurationSet.from_payload(dict(payload))
                        configuration_valid = configuration.configuration_sha256 == hosted.get(
                            "configuration_set_sha256"
                        )
                        distinct_references = len(
                            {role.credential_reference for role in configuration.roles}
                        ) == len(configuration.roles)
                        caps_match = (
                            configuration.global_limits.max_calls
                            == hosted.get("provider_model_call_limit")
                            and format(configuration.global_limits.max_usd, "f")
                            == hosted.get("provider_model_spend_limit_usd")
                            and configuration.global_limits.max_retries
                            == hosted.get("provider_max_retries")
                            and configuration.global_limits.max_concurrency
                            == hosted.get("provider_max_concurrency")
                        )
                    except (TypeError, ValueError):
                        pass

        database_now = row["database_now"]
        timeout_seconds = float(dict(scope.get("caps") or {}).get("run_timeout_seconds", 0))
        authorization_window_covers_run = row["expires_at"] > database_now + datetime.timedelta(
            seconds=timeout_seconds
        )
        two_person_approval = (
            row["decision"] == "approved"
            and isinstance(row["approver_user_id"], str)
            and row["approver_user_id"] != row["launcher_user_id"]
        )
        target_ready = bool(
            target_state is not None
            and target_state["lifecycle"] == "ready"
            and target_state["surface_enabled"] is True
            and target_state["synthetic_data_only"] is True
        )
        session_generation_bound = bool(
            hosted is not None
            and (
                scope.get("auth_mode") != "session"
                or (
                    isinstance(scope.get("credential_ref"), str)
                    and scope["credential_ref"].endswith(f"/{hosted.get('session_generation', '')}")
                )
            )
        )
        gates = {
            "target_ready": target_ready,
            "runner_heartbeat_fresh": runner_heartbeat_fresh,
            "two_person_approval": two_person_approval,
            "authorization_window_covers_run": authorization_window_covers_run,
            "approval_unconsumed": not bool(row["consumed"]),
            "hosted_runtime_composed": self._hosted_runtime_available,
            "configuration_integrity": configuration_valid,
            "configuration_caps_match": caps_match,
            "provider_bindings_distinct": distinct_references,
            "provider_bindings_runner_verified": self._hosted_provider_bindings_verified,
            "session_generation_bound": session_generation_bound,
            "synthetic_data_only": bool(
                target_state is not None and target_state["synthetic_data_only"] is True
            ),
        }
        reason_checks = (
            ("hosted_binding_missing", hosted is not None),
            ("hosted_runtime_not_composed", self._hosted_runtime_available),
            ("target_not_ready", target_ready),
            ("runner_heartbeat_stale", runner_heartbeat_fresh),
            ("two_person_approval_missing", two_person_approval),
            ("authorization_window_too_short", authorization_window_covers_run),
            ("approval_consumed", not bool(row["consumed"])),
            ("hosted_configuration_invalid", configuration_valid),
            ("hosted_configuration_caps_mismatch", caps_match),
            ("provider_credential_references_invalid", distinct_references),
            (
                "provider_credentials_runner_unverified",
                self._hosted_provider_bindings_verified,
            ),
            ("session_generation_mismatch", session_generation_bound),
        )
        reason = next(
            (code for code, passed in reason_checks if not passed),
            None,
        )
        projection = {
            "request_id": request_id,
            "scope_hash": row["scope_hash"],
            "configuration_set_sha256": (
                hosted.get("configuration_set_sha256") if hosted is not None else None
            ),
            "session_generation": (
                hosted.get("session_generation") if hosted is not None else None
            ),
            "gates": gates,
            "provider_calls_performed": 0,
            "target_calls_performed": 0,
            "checked_at": database_now.isoformat(),
        }
        if reason is None:
            return ResourceResult.ready(_safe(projection))
        return ResourceResult.degraded(_safe(projection), reason)

    def _authorization_requires_hosted_runtime(
        self,
        organization_id: str,
        request_id: str,
    ) -> bool:
        with self._engine.connect() as connection:
            value = connection.execute(
                text(
                    "SELECT scope_payload ? 'hosted_run' "
                    "FROM campaign_authorization_requests "
                    "WHERE organization_id = :org AND request_id = :request_id"
                ),
                {"org": organization_id, "request_id": request_id},
            ).scalar_one_or_none()
        return bool(value)

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
    hosted_runtime_available: bool = False,
    hosted_provider_bindings_verified: bool = False,
) -> ApiBackend:
    if not database_url:
        from agentforge.api.backend import UnavailableApiBackend

        return UnavailableApiBackend()
    engine = create_engine(normalize_psycopg_url(database_url), pool_pre_ping=True, future=True)
    corpus = resolve_workload()
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
        hosted_runtime_available=hosted_runtime_available,
        hosted_provider_bindings_verified=hosted_provider_bindings_verified,
        corpus=corpus,
    )


__all__ = ["PostgresApiBackend", "build_postgres_backend"]
