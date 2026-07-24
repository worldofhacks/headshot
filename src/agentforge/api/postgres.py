"""PostgreSQL-backed v1 read models and command adapter."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from decimal import Decimal
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Engine, create_engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    preflight_hosted_configuration_set,
    resolve_hosted_prompt,
)
from agentforge.agents.hosted_policy import (
    DEFAULT_HOSTED_GENERATION_POLICY,
    HostedGenerationPolicyError,
    resolve_hosted_generation_policy,
)
from agentforge.agents.prompts import PromptRegistryError, prompt_for_identity
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
from agentforge.control_plane.serialization import (
    content_hash,
    surface_payload,
    target_payload,
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
from agentforge.target.catalog import (
    SYNTHETIC_TARGET_ID,
    TargetCatalogError,
    TrustedTargetCatalog,
)
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
_DISPLAY_SYNTHETIC_IDENTIFIER = re.compile(r"(?i)\bSYNTH-(?:PATIENT|PERSON|SUBJECT)-[A-Z0-9_-]+\b")
_DISPLAY_SYNTHETIC_CANARY = re.compile(r"(?i)\bSYNTH_CANARY_[A-Z0-9_-]+\b")
_DISPLAY_LABELED_IDENTIFIER = re.compile(
    r"(?i)\b(?:sid|session[_ -]?id|patient[_ -]?id|mrn|ssn|date[_ -]?of[_ -]?birth|dob)"
    r"\s*[:=]\s*[\"']?[A-Za-z0-9._:/@+-]+[\"']?"
)
_DISPLAY_BARE_SESSION_ID = re.compile(r"(?i)\bsess_[-A-Za-z0-9._:]+\b")
_DISPLAY_LABELED_PHI = re.compile(
    r"(?i)\b(?:patient[_ -]?name|full[_ -]?name|phone(?:[_ -]?number)?|"
    r"(?:street[_ -]?)?address|date[_ -]?of[_ -]?birth|birth[_ -]?date|dob)\b"
    r"(?:\s*[:=]\s*|\s+)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n;]+)"
)
_DISPLAY_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_DISPLAY_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_DISPLAY_PHONE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}"
    r"(?![A-Za-z0-9])"
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
_RUNNER_HEARTBEAT_FRESHNESS_SECONDS = 30
# Hosted credential readiness is refreshed on a 30-second cadence. Give one missed refresh room
# without allowing an old Runner observation to become durable launch authority.
_HOSTED_RUNTIME_HEARTBEAT_FRESHNESS_SECONDS = 90
_SAFE_ACCOUNTING_COUNTERS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "token_observation_count",
        "physical_call_count",
        "physical_attempts",
        "role_physical_calls",
        "role_unresolved_physical_calls",
        "role_calls_remaining",
        "role_call_overrun",
        "global_physical_calls",
        "global_unresolved_physical_calls",
        "global_calls_remaining",
        "global_call_overrun",
        "oracle_comparison_count",
        "oracle_agreement_count",
    }
)


def _restore_safe_accounting_counters(redacted: Any, source: Any) -> None:
    """Restore only typed aggregate counters masked by generic deep secret redaction."""

    if isinstance(redacted, dict) and isinstance(source, Mapping):
        for key, source_value in source.items():
            if key in _SAFE_ACCOUNTING_COUNTERS and (
                source_value is None
                or (isinstance(source_value, int) and not isinstance(source_value, bool))
            ):
                redacted[key] = source_value
                continue
            if key in redacted:
                _restore_safe_accounting_counters(redacted[key], source_value)
        return
    if isinstance(redacted, list) and isinstance(source, (list, tuple)):
        for redacted_item, source_item in zip(redacted, source, strict=False):
            _restore_safe_accounting_counters(redacted_item, source_item)


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
        # Deep redaction masks keys containing "token" at any depth. Restore only explicitly
        # typed aggregate counters from the original shape; strings, booleans, and mappings stay
        # masked, so this cannot reintroduce credentials.
        _restore_safe_accounting_counters(redacted, value)
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


def _aggregate_cost_measurement_state(
    *,
    measured: int,
    partial: int,
    not_observed: int,
    invalid: int,
) -> str:
    total = measured + partial + not_observed + invalid
    if total == 0 or measured == total:
        return "measured"
    if partial > 0 or measured > 0:
        return "partial"
    if invalid > 0:
        return "invalid"
    return "not_observed"


def _accounting_status(cost_measurement_state: str, *, applicable: bool = True) -> str:
    if not applicable:
        return "not_applicable"
    return {
        "measured": "measured",
        "partial": "partial",
        "not_observed": "unavailable",
        "invalid": "unavailable",
    }[cost_measurement_state]


def _flatten_provider_event_ids(value: Any) -> list[str]:
    if value is None:
        return []
    flattened: list[str] = []
    for group in value:
        if isinstance(group, list):
            flattened.extend(str(item) for item in group)
    return flattened


def _provider_lineage_state(execution_mode: object, detail: object) -> str:
    if execution_mode != "hosted_advisory":
        return "not_applicable"
    state = detail.get("provider_lineage_state") if isinstance(detail, Mapping) else None
    if state not in {"canonical_physical", "historical_not_instrumented"}:
        raise ApiBackendUnavailable("persisted provider lineage state is invalid")
    return str(state)


def _unavailable_provider_budget() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "campaign_run_id": None,
        "configuration_set_sha256": None,
        "role_cost_measurement_state": None,
        "role_usd_cap": None,
        "role_usd_spent": 0.0,
        "role_unresolved_usd_exposure": 0.0,
        "role_usd_remaining": None,
        "role_usd_remaining_upper_bound": None,
        "role_usd_overrun": 0.0,
        "role_call_cap": None,
        "role_physical_calls": 0,
        "role_unresolved_physical_calls": 0,
        "role_call_count_state": None,
        "role_calls_remaining": None,
        "role_call_overrun": 0,
        "global_cost_measurement_state": None,
        "global_usd_cap": None,
        "global_usd_spent": 0.0,
        "global_unresolved_usd_exposure": 0.0,
        "global_usd_remaining": None,
        "global_usd_remaining_upper_bound": None,
        "global_usd_overrun": 0.0,
        "global_call_cap": None,
        "global_physical_calls": 0,
        "global_unresolved_physical_calls": 0,
        "global_call_count_state": None,
        "global_calls_remaining": None,
        "global_call_overrun": 0,
    }


def _provider_budget_projection(
    *,
    configuration: HostedConfigurationSet,
    role: str,
    campaign_run_id: str | None,
    campaign_state: str | None,
    role_spent: float,
    role_cost_measurement_state: str,
    role_physical_calls: int,
    role_unresolved_usd_exposure: float | None,
    role_unresolved_physical_calls: int | None,
    role_call_count_state: str,
    global_spent: float,
    global_cost_measurement_state: str,
    global_physical_calls: int,
    global_unresolved_usd_exposure: float | None,
    global_unresolved_physical_calls: int | None,
    global_call_count_state: str,
) -> dict[str, Any]:
    role_configuration = next(item for item in configuration.roles if item.role == role)
    role_cap = float(role_configuration.limits.max_usd)
    role_call_cap = role_configuration.limits.max_calls
    global_cap = float(configuration.global_limits.max_usd)
    global_call_cap = configuration.global_limits.max_calls
    role_available_usd = max(0.0, role_cap - role_spent)
    role_exposure = min(
        role_available_usd,
        (
            max(0.0, role_unresolved_usd_exposure)
            if role_unresolved_usd_exposure is not None
            else role_available_usd
        ),
    )
    role_available_calls = max(0, role_call_cap - role_physical_calls)
    role_unresolved_calls = min(
        role_available_calls,
        (
            max(0, role_unresolved_physical_calls)
            if role_unresolved_physical_calls is not None
            else role_available_calls
        ),
    )
    global_available_usd = max(0.0, global_cap - global_spent)
    global_exposure = min(
        global_available_usd,
        (
            max(0.0, global_unresolved_usd_exposure)
            if global_unresolved_usd_exposure is not None
            else global_available_usd
        ),
    )
    global_available_calls = max(0, global_call_cap - global_physical_calls)
    global_unresolved_calls = min(
        global_available_calls,
        (
            max(0, global_unresolved_physical_calls)
            if global_unresolved_physical_calls is not None
            else global_available_calls
        ),
    )
    status = (
        "staged_pending_authorization"
        if campaign_run_id is None
        else "active"
        if campaign_state in {"queued", "running"}
        else "historical"
    )
    return {
        "status": status,
        "campaign_run_id": campaign_run_id,
        "configuration_set_sha256": configuration.configuration_sha256,
        "role_cost_measurement_state": role_cost_measurement_state,
        "role_usd_cap": role_cap,
        "role_usd_spent": role_spent,
        "role_unresolved_usd_exposure": role_exposure,
        "role_usd_remaining": max(0.0, role_cap - role_spent - role_exposure),
        "role_usd_remaining_upper_bound": role_available_usd,
        "role_usd_overrun": max(0.0, role_spent - role_cap),
        "role_call_cap": role_call_cap,
        "role_physical_calls": role_physical_calls,
        "role_unresolved_physical_calls": role_unresolved_calls,
        "role_call_count_state": role_call_count_state,
        "role_calls_remaining": max(
            0,
            role_call_cap - role_physical_calls - role_unresolved_calls,
        ),
        "role_call_overrun": max(0, role_physical_calls - role_call_cap),
        "global_cost_measurement_state": global_cost_measurement_state,
        "global_usd_cap": global_cap,
        "global_usd_spent": global_spent,
        "global_unresolved_usd_exposure": global_exposure,
        "global_usd_remaining": max(0.0, global_cap - global_spent - global_exposure),
        "global_usd_remaining_upper_bound": global_available_usd,
        "global_usd_overrun": max(0.0, global_spent - global_cap),
        "global_call_cap": global_call_cap,
        "global_physical_calls": global_physical_calls,
        "global_unresolved_physical_calls": global_unresolved_calls,
        "global_call_count_state": global_call_count_state,
        "global_calls_remaining": max(
            0,
            global_call_cap - global_physical_calls - global_unresolved_calls,
        ),
        "global_call_overrun": max(0, global_physical_calls - global_call_cap),
    }


def _hosted_budget_usage(
    rows: list[dict[str, Any]],
    configurations: Mapping[str, HostedConfigurationSet],
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    """Reconcile observed usage plus conservative in-flight provider exposure."""

    by_run_role: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        run_id = str(row["campaign_run_id"])
        role = str(row["agent_role"])
        usage = by_run_role.setdefault(
            (run_id, role),
            {
                "measured_cost": 0.0,
                "physical_calls": 0,
                "unresolved_usd_exposure": 0.0,
                "unresolved_physical_calls": 0,
                "historical_lineage_count": 0,
                "measured_cost_count": 0,
                "partial_cost_count": 0,
                "not_observed_cost_count": 0,
                "invalid_cost_count": 0,
            },
        )
        usage["measured_cost"] = float(usage["measured_cost"]) + float(
            row.get("measured_cost") or 0
        )
        cost_state = str(row.get("cost_measurement_state") or "not_observed")
        state_counter = f"{cost_state}_cost_count"
        if state_counter in usage:
            usage[state_counter] = int(usage[state_counter]) + 1
        lineage_state = _provider_lineage_state(
            row.get("execution_mode"),
            row.get("detail"),
        )
        if lineage_state == "historical_not_instrumented":
            usage["historical_lineage_count"] = int(usage["historical_lineage_count"]) + 1
        observed_calls = int(row.get("physical_attempts") or 0)
        usage["physical_calls"] = int(usage["physical_calls"]) + observed_calls
        if lineage_state == "historical_not_instrumented":
            usage["unresolved_usd_exposure"] = None
            usage["unresolved_physical_calls"] = None
            continue
        configuration = configurations.get(str(row.get("configuration_set_sha256") or ""))
        if configuration is None:
            if row.get("status") == "running" or cost_state != "measured":
                usage["unresolved_usd_exposure"] = None
                usage["unresolved_physical_calls"] = None
            continue
        role_configuration = next(item for item in configuration.roles if item.role == role)
        maximum_attempts = 1 + min(
            role_configuration.limits.max_retries,
            configuration.global_limits.max_retries,
        )
        unresolved_calls = (
            max(0, maximum_attempts - observed_calls) if row.get("status") == "running" else 0
        )
        if usage["unresolved_physical_calls"] is not None:
            usage["unresolved_physical_calls"] = (
                int(usage["unresolved_physical_calls"]) + unresolved_calls
            )
        unresolved_cost_calls = (
            maximum_attempts
            if row.get("status") == "running"
            else observed_calls
            if cost_state != "measured"
            else 0
        )
        if unresolved_cost_calls == 0:
            continue
        try:
            policy = resolve_hosted_generation_policy(
                str(row.get("generation_policy_sha256") or "")
            )
            bounds = policy.call_bounds[role]
            prices = role_configuration.prices
            reservation = (
                prices.input_usd_per_million_tokens * bounds.input_tokens
                + prices.output_usd_per_million_tokens * bounds.output_tokens
                + max(
                    prices.output_usd_per_million_tokens,
                    prices.reasoning_usd_per_million_tokens,
                )
                * bounds.reasoning_tokens
            ) / Decimal(1_000_000)
        except (HostedGenerationPolicyError, KeyError):
            usage["unresolved_usd_exposure"] = None
        else:
            if usage["unresolved_usd_exposure"] is not None:
                usage["unresolved_usd_exposure"] = float(
                    Decimal(str(usage["unresolved_usd_exposure"]))
                    + reservation * unresolved_cost_calls
                )

    global_by_run: dict[str, dict[str, Any]] = {}
    for (run_id, _), usage in by_run_role.items():
        aggregate = global_by_run.setdefault(
            run_id,
            {
                "measured_cost": 0.0,
                "physical_calls": 0,
                "unresolved_usd_exposure": 0.0,
                "unresolved_physical_calls": 0,
                "historical_lineage_count": 0,
                "measured_cost_count": 0,
                "partial_cost_count": 0,
                "not_observed_cost_count": 0,
                "invalid_cost_count": 0,
            },
        )
        aggregate["measured_cost"] = float(aggregate["measured_cost"]) + float(
            usage["measured_cost"]
        )
        aggregate["physical_calls"] = int(aggregate["physical_calls"]) + int(
            usage["physical_calls"]
        )
        for field in (
            "unresolved_usd_exposure",
            "unresolved_physical_calls",
        ):
            if aggregate[field] is None or usage[field] is None:
                aggregate[field] = None
            else:
                aggregate[field] += usage[field]
        for field in (
            "historical_lineage_count",
            "measured_cost_count",
            "partial_cost_count",
            "not_observed_cost_count",
            "invalid_cost_count",
        ):
            aggregate[field] = int(aggregate[field]) + int(usage[field])
    return by_run_role, global_by_run


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


def _validated_verdict(row: Mapping[str, Any]) -> dict[str, Any] | None:
    """Validate the separately persisted Judge record; the attempt hash does not cover it."""

    if row.get("verdict_id") is None:
        return None
    verdict = {
        "schema_version": "1",
        "campaign_run_id": row.get("campaign_run_id"),
        "attempt_id": row.get("attempt_id"),
        "state": row.get("verdict_state"),
        "confidence": row.get("verdict_confidence"),
        "reason_codes": row.get("verdict_reason_codes"),
    }
    confirmation_source = row.get("verdict_confirmation_source")
    if confirmation_source is not None:
        verdict["confirmation_source"] = confirmation_source
    error_code = row.get("verdict_error_code")
    if error_code is not None:
        verdict["error_code"] = error_code
    try:
        validate_contract("verdict", verdict)
    except Exception as exc:
        raise EvidenceIntegrityError("verdict contract is invalid") from exc
    return verdict


def _trusted_report_verdict(row: Mapping[str, Any]) -> dict[str, Any]:
    """Require the durable deterministic Judge basis used by Documentation."""

    verdict = _validated_verdict(row)
    if verdict is None or verdict["state"] != "EXPLOIT_CONFIRMED":
        raise EvidenceIntegrityError("report requires a confirmed verdict")
    confirmation_source = verdict.get("confirmation_source")
    if confirmation_source not in {"oracle", "canary"}:
        raise EvidenceIntegrityError("report verdict source is not deterministic")
    reference_key = (
        "target_oracle_refs" if confirmation_source == "oracle" else "target_canary_refs"
    )
    references = row.get(reference_key)
    if (
        not isinstance(references, list)
        or not references
        or any(not isinstance(reference, str) or not reference for reference in references)
    ):
        raise EvidenceIntegrityError("report verdict lacks a durable configured basis")
    return verdict


def _validated_finding_lineage(row: Mapping[str, Any]) -> dict[str, Any]:
    """Reconcile a campaign finding with its attempt, case, evidence, and Judge record."""

    verdict = _validated_verdict(row)
    if verdict is None or verdict["state"] != "EXPLOIT_CONFIRMED":
        raise EvidenceIntegrityError("finding requires a confirmed verdict")
    if row.get("finding_source_kind") != "campaign":
        raise EvidenceIntegrityError("finding source kind differs from campaign lineage")
    bindings = (
        ("finding_target_version", "target_version"),
        ("finding_category", "case_category"),
        ("finding_severity", "case_severity"),
        ("finding_execution_profile", "execution_profile"),
        ("linked_provenance", "evidence_provenance"),
    )
    if any(row.get(finding_key) != row.get(source_key) for finding_key, source_key in bindings):
        raise EvidenceIntegrityError("finding metadata differs from its authoritative lineage")
    return verdict


def _report_evidence_references_verified(
    report_payload: Mapping[str, Any],
    *,
    content_hash: str,
) -> bool:
    """Accept only report references that this projection can reconcile durably."""

    expected_reference = f"evidence://sha256/{content_hash}"
    fix_validation = report_payload.get("fix_validation")
    return (
        report_payload.get("evidence_references") == [expected_reference]
        and isinstance(fix_validation, Mapping)
        and fix_validation.get("evidence_references") == []
    )


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
    value = _DISPLAY_BARE_SESSION_ID.sub("***REDACTED_SESSION_ID***", value)
    value = _DISPLAY_LABELED_IDENTIFIER.sub("***REDACTED_IDENTIFIER***", value)
    value = _DISPLAY_LABELED_PHI.sub("***REDACTED_PHI***", value)
    value = _DISPLAY_EMAIL.sub("***REDACTED_EMAIL***", value)
    value = _DISPLAY_SSN.sub("***REDACTED_SSN***", value)
    return _DISPLAY_PHONE.sub("***REDACTED_PHONE***", value)


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


def _security_tool_evidence_verified(row: Mapping[str, Any]) -> bool:
    """Reconcile one normalized tool finding with its run and sanitized artifact."""

    finding = row.get("finding_payload")
    artifact = row.get("artifact_payload")
    artifact_bytes = row.get("artifact_bytes")
    if (
        not isinstance(finding, Mapping)
        or not isinstance(artifact, Mapping)
        or not isinstance(artifact_bytes, (bytes, bytearray, memoryview))
        or row.get("matching_artifact_count") != 1
    ):
        return False
    finding = dict(finding)
    artifact = dict(artifact)
    run = {
        "schema_version": "1",
        "run_id": row.get("run_id"),
        "tool_name": row.get("run_tool_name"),
        "tool_version": row.get("run_tool_version"),
        "configuration_sha256": row.get("run_configuration_sha256"),
        "run_nonce": row.get("run_nonce"),
        "target_id": row.get("run_target_id"),
        "surface_id": row.get("run_surface_id"),
        "scan_provenance": row.get("run_scan_provenance"),
        "status": row.get("run_status"),
        "started_at": _safe(row.get("run_started_at")),
        "finished_at": _safe(row.get("run_finished_at")),
        "artifact_sha256": row.get("run_artifact_sha256"),
    }
    try:
        validate_contract("tool_finding", finding)
        validate_contract("security_tool_run", run)
        validate_contract("scan_artifact", artifact)
    except Exception:
        return False

    raw = bytes(artifact_bytes)
    digest = hashlib.sha256(raw).hexdigest()
    if (
        len(raw) != row.get("artifact_byte_length")
        or digest != row.get("artifact_sha256")
        or digest != artifact.get("sha256")
        or digest != finding.get("raw_artifact_sha256")
        or digest != run.get("artifact_sha256")
    ):
        return False

    finding_scalar_bindings = {
        "finding_id": "stored_finding_id",
        "run_id": "stored_finding_run_id",
        "raw_artifact_sha256": "stored_finding_artifact_sha256",
        "validation_state": "stored_finding_validation_state",
        "human_publication_state": "stored_finding_publication_state",
        "evidence_provenance": "stored_finding_provenance",
    }
    if any(
        finding.get(payload_key) != row.get(row_key)
        for payload_key, row_key in finding_scalar_bindings.items()
    ):
        return False

    run_bindings = (
        ("run_id", "run_id"),
        ("tool_name", "run_tool_name"),
        ("tool_version", "run_tool_version"),
        ("configuration_sha256", "run_configuration_sha256"),
        ("run_nonce", "run_nonce"),
        ("target_id", "run_target_id"),
        ("surface_id", "run_surface_id"),
        ("scan_provenance", "run_scan_provenance"),
    )
    if any(finding.get(finding_key) != row.get(row_key) for finding_key, row_key in run_bindings):
        return False

    artifact_scalar_bindings = {
        "artifact_id": "artifact_id",
        "run_id": "artifact_run_id",
        "sha256": "artifact_sha256",
        "media_type": "artifact_media_type",
        "byte_length": "artifact_byte_length",
        "artifact_locator": "artifact_locator",
    }
    if any(
        artifact.get(payload_key) != row.get(row_key)
        for payload_key, row_key in artifact_scalar_bindings.items()
    ):
        return False
    return (
        artifact.get("run_id") == run.get("run_id")
        and artifact.get("tool_name") == run.get("tool_name")
        and artifact.get("tool_version") == run.get("tool_version")
    )


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
        target_catalog: TrustedTargetCatalog | None = None,
    ) -> None:
        self._engine = engine
        self._store = ControlPlaneStore(engine, environment=environment)
        self._environment = environment
        self._runner_available = runner_available
        self._hosted_runtime_available = hosted_runtime_available
        self._hosted_provider_bindings_verified = hosted_provider_bindings_verified
        self._corpus = corpus
        self._target_catalog = target_catalog or TrustedTargetCatalog.from_environment(environment)

    @staticmethod
    def _target_session_generation(target_payload: Mapping[str, Any]) -> str:
        """Return only the non-secret immutable generation bound to a target credential."""

        credential_reference = target_payload.get("credential_ref")
        if credential_reference is None and target_payload.get("auth_mode") == "none":
            return "no-auth"
        if not isinstance(credential_reference, str):
            raise ValueError("target credential generation is unavailable")
        parsed = urlsplit(credential_reference)
        segments = tuple(segment for segment in parsed.path.split("/") if segment)
        if parsed.scheme != "secretref" or not segments:
            raise ValueError("target credential generation is invalid")
        return segments[-1]

    def _latest_hosted_run_binding(
        self,
        connection: Any,
        *,
        organization_id: str,
        target_payload: Mapping[str, Any],
    ) -> dict[str, object] | None:
        """Project the latest atomic set into a secret-free, server-derived run binding."""

        row = (
            connection.execute(
                text(
                    "SELECT configuration_sha256, payload FROM hosted_configuration_sets "
                    "WHERE organization_id = :org "
                    "ORDER BY created_at DESC, configuration_sha256 DESC LIMIT 1"
                ),
                {"org": organization_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        configuration = HostedConfigurationSet.from_payload(dict(row["payload"]))
        if configuration.configuration_sha256 != row["configuration_sha256"]:
            raise ValueError("hosted configuration-set integrity check failed")
        policy = DEFAULT_HOSTED_GENERATION_POLICY
        binding = HostedRunBinding(
            configuration_set_sha256=configuration.configuration_sha256,
            generation_policy_sha256=policy.policy_sha256,
            session_generation=self._target_session_generation(target_payload),
            provider_model_call_limit=configuration.global_limits.max_calls,
            provider_model_spend_limit_usd=format(configuration.global_limits.max_usd, "f"),
            provider_max_retries=configuration.global_limits.max_retries,
            provider_max_concurrency=configuration.global_limits.max_concurrency,
            provider_timeout_seconds=max(
                float(role.bounds.timeout_seconds) for role in policy.roles
            ),
        )
        return binding.canonical_payload()

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
        verdict = _validated_finding_lineage(source)
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
            _trusted_report_verdict(source)
            report_payload = dict(report_payload)
            try:
                validate_contract("vuln_report", report_payload)
            except Exception as exc:
                raise EvidenceIntegrityError("finding report contract is invalid") from exc
            if (
                report_payload.get("report_id") != report_id
                or report_payload.get("finding_id") != finding_id
                or report_payload.get("campaign_run_id") != source.get("campaign_run_id")
                or report_payload.get("attempt_id") != source.get("attempt_id")
                or report_payload.get("source_case_id") != source.get("case_id")
                or report_payload.get("severity") != source.get("finding_severity")
                or report_payload.get("category") != source.get("finding_category")
                or _reproduction_sha256(report_payload.get("minimal_reproduction"))
                != report_payload.get("reproduction_sha256")
                or not _report_evidence_references_verified(
                    report_payload,
                    content_hash=content_hash,
                )
            ):
                raise EvidenceIntegrityError("finding report correlation is invalid")
            reproduction = report_payload.get("minimal_reproduction")
            if isinstance(reproduction, list) and all(
                isinstance(item, str) for item in reproduction
            ):
                minimal_reproduction = [
                    str(_redact_evidence_display(item)) for item in reproduction
                ]
            reproduction_hash = report_payload.get("reproduction_sha256")
        elif report_id is not None:
            raise EvidenceIntegrityError("finding report payload is absent")

        regression = None
        regression_payload = source.get("regression_payload")
        if isinstance(regression_payload, Mapping):
            regression_payload = dict(regression_payload)
            try:
                validate_contract("regression_disposition", regression_payload)
            except Exception as exc:
                raise EvidenceIntegrityError("regression contract is invalid") from exc
            if any(
                regression_payload.get(key) != expected
                for key, expected in (
                    ("finding_id", finding_id),
                    ("report_id", report_id),
                    ("campaign_run_id", source.get("campaign_run_id")),
                    ("attempt_id", source.get("attempt_id")),
                )
            ):
                raise EvidenceIntegrityError("regression correlation is invalid")
            regression = {
                "disposition_id": regression_payload.get("disposition_id"),
                "state": regression_payload.get("state"),
                "reason_codes": regression_payload.get("reason_codes", []),
                "reproduction_attempted": regression_payload.get("reproduction_attempted"),
                "deterministic_reproduction": regression_payload.get("deterministic_reproduction"),
                "passes_for_right_reason": regression_payload.get("passes_for_right_reason"),
                "human_approved": regression_payload.get("human_approved"),
                "admitted": regression_payload.get("admitted"),
            }
        oracle_refs = source.get("target_oracle_refs")
        canary_refs = source.get("target_canary_refs")
        safe_oracle_refs = (
            [str(_redact_evidence_display(item)) for item in oracle_refs if isinstance(item, str)]
            if isinstance(oracle_refs, list)
            else []
        )
        safe_canary_refs = (
            [str(_redact_evidence_display(item)) for item in canary_refs if isinstance(item, str)]
            if isinstance(canary_refs, list)
            else []
        )

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
                "state": verdict["state"],
                "confidence": verdict["confidence"],
                "reason_codes": verdict["reason_codes"],
                "confirmation_source": verdict.get("confirmation_source"),
                "oracle_refs": safe_oracle_refs,
                "canary_refs": safe_canary_refs,
                "rationale": None,
                "rationale_availability": "unavailable",
                "rationale_detail": (
                    "This verdict contract stores typed reason codes, not free-form Judge prose."
                ),
                "error_code": verdict.get("error_code"),
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

    def _target_catalog_projection(
        self,
        connection: Any,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        """Project only non-authoritative catalog identity and registration state."""

        result: list[dict[str, Any]] = []
        for entry in self._target_catalog.entries:
            target = entry.target
            target_row = (
                connection.execute(
                    text(
                        "SELECT d.content_hash, "
                        "(SELECT e.to_lifecycle FROM target_lifecycle_events e "
                        " WHERE e.organization_id = d.organization_id "
                        " AND e.target_id = d.target_id AND e.target_version = d.version "
                        " ORDER BY e.id DESC LIMIT 1) AS lifecycle "
                        "FROM target_definitions d "
                        "WHERE d.organization_id = :org AND d.target_id = :target_id "
                        "AND d.version = :version"
                    ),
                    {
                        "org": organization_id,
                        "target_id": target.target_id,
                        "version": target.version,
                    },
                )
                .mappings()
                .one_or_none()
            )
            registration_state = "available"
            if target_row is not None:
                surface_rows = _rows(
                    connection,
                    "SELECT s.surface_id, s.version, s.content_hash "
                    "FROM attack_surface_definitions s "
                    "WHERE s.organization_id = :org AND s.target_id = :target_id "
                    "AND s.target_version = :version",
                    {
                        "org": organization_id,
                        "target_id": target.target_id,
                        "version": target.version,
                    },
                )
                expected_surfaces = {
                    (surface.surface_id, surface.version): content_hash(surface_payload(surface))
                    for surface in entry.surfaces
                }
                actual_surfaces = {
                    (str(row["surface_id"]), str(row["version"])): str(row["content_hash"])
                    for row in surface_rows
                }
                registration_state = (
                    "registered"
                    if target_row["content_hash"] == content_hash(target_payload(target))
                    and target_row["lifecycle"]
                    in {
                        TargetLifecycle.READY.value,
                        TargetLifecycle.DISABLED.value,
                        TargetLifecycle.ARCHIVED.value,
                    }
                    and actual_surfaces == expected_surfaces
                    else "conflict"
                )
            result.append(
                {
                    "target_id": target.target_id,
                    "version": target.version,
                    "name": target.name,
                    "environment": target.environment.value,
                    "synthetic_data_only": target.synthetic_data_only,
                    "surface_count": len(entry.surfaces),
                    "registration_state": registration_state,
                }
            )
        return result

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
                    hosted_rows = _rows(
                        connection,
                        "SELECT configuration_sha256, payload, actor_user_id, created_at "
                        "FROM hosted_configuration_sets WHERE organization_id = :org "
                        "ORDER BY created_at DESC",
                        {"org": principal.organization_id},
                    )
                    served_identity_rows = _rows(
                        connection,
                        "SELECT DISTINCT ON (agent_role, configuration_set_sha256) "
                        "agent_role, configuration_set_sha256, returned_model, "
                        "upstream_provider, provider_request_id, finished_at "
                        "FROM agent_executions WHERE organization_id = :org "
                        "AND status = 'succeeded' AND configuration_set_sha256 IS NOT NULL "
                        "AND returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
                        "AND provider_request_id IS NOT NULL "
                        "ORDER BY agent_role, configuration_set_sha256, finished_at DESC",
                        {"org": principal.organization_id},
                    )
                    served_identity_by_role_configuration = {
                        (row["agent_role"], row["configuration_set_sha256"]): row
                        for row in served_identity_rows
                    }
                    hosted_run_rows = _rows(
                        connection,
                        "SELECT DISTINCT ON "
                        "(q.scope_payload->'hosted_run'->>'configuration_set_sha256') "
                        "q.scope_payload->'hosted_run'->>'configuration_set_sha256' "
                        "AS configuration_sha256, r.run_id, r.created_at, "
                        "(SELECT state FROM campaign_run_events e "
                        "WHERE e.organization_id = r.organization_id "
                        "AND e.run_id = r.run_id ORDER BY e.id DESC LIMIT 1) "
                        "AS campaign_state "
                        "FROM campaign_runs r JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "AND q.scope_hash = r.scope_hash "
                        "WHERE r.organization_id = :org "
                        "AND q.scope_payload->'hosted_run'->>'configuration_set_sha256' "
                        "IS NOT NULL "
                        "ORDER BY "
                        "q.scope_payload->'hosted_run'->>'configuration_set_sha256', "
                        "r.created_at DESC",
                        {"org": principal.organization_id},
                    )
                    hosted_run_by_configuration = {
                        row["configuration_sha256"]: row
                        for row in hosted_run_rows
                        if isinstance(row.get("configuration_sha256"), str)
                    }
                    active_hosted_assignments: dict[str, dict[str, Any]] = {}
                    staged_hosted_assignments: dict[str, dict[str, Any]] = {}
                    hosted_configurations: dict[str, HostedConfigurationSet] = {}
                    for row in hosted_rows:
                        try:
                            configuration = HostedConfigurationSet.from_payload(
                                dict(row["payload"])
                            )
                        except (TypeError, ValueError):
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        if configuration.configuration_sha256 != row["configuration_sha256"]:
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        hosted_configurations[configuration.configuration_sha256] = configuration
                        activation = hosted_run_by_configuration.get(
                            configuration.configuration_sha256
                        )
                        activation_state = (
                            "active" if activation is not None else "staged_pending_authorization"
                        )
                        destination = (
                            active_hosted_assignments
                            if activation_state == "active"
                            else staged_hosted_assignments
                        )
                        for role in configuration.roles:
                            if activation is None and role.role in destination:
                                continue
                            try:
                                prompt = resolve_hosted_prompt(role.role, role.prompt_sha256)
                            except ValueError:
                                return ResourceResult.unavailable("hosted_prompt_integrity_failed")
                            served = served_identity_by_role_configuration.get(
                                (role.role, configuration.configuration_sha256)
                            )
                            candidate = {
                                "role": role.role,
                                "provider": role.provider,
                                "model": role.model_id,
                                "resolved_model": (
                                    served["returned_model"] if served is not None else None
                                ),
                                "upstream_provider": (
                                    served["upstream_provider"] if served is not None else None
                                ),
                                "prompt_sha256": prompt.sha256,
                                "prompt_version": prompt.version,
                                "execution_mode": "hosted_advisory",
                                "activation_state": activation_state,
                                "version": 1,
                                "configuration_sha256": configuration.configuration_sha256,
                                "configured_at": row["created_at"],
                                "configured_by": row["actor_user_id"],
                                "_activation_at": (
                                    activation["created_at"] if activation is not None else None
                                ),
                            }
                            previous = destination.get(role.role)
                            if (
                                previous is None
                                or activation is not None
                                and candidate["_activation_at"] > previous["_activation_at"]
                            ):
                                destination[role.role] = candidate
                    execution_rows = _rows(
                        connection,
                        "SELECT agent_role, count(*) AS execution_count, "
                        "count(*) FILTER (WHERE status = 'running') AS running_count, "
                        "count(*) FILTER (WHERE status = 'succeeded') AS succeeded_count, "
                        "count(*) FILTER (WHERE status = 'failed') AS failed_count, "
                        "count(*) FILTER (WHERE status = 'skipped') AS skipped_count, "
                        "sum(measured_cost) AS measured_cost, "
                        "sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens, "
                        "sum(reasoning_tokens) AS reasoning_tokens, "
                        "coalesce(sum(physical_attempts), 0) AS physical_call_count, "
                        "count(*) FILTER (WHERE execution_mode = 'hosted_advisory' "
                        "AND detail->>'provider_lineage_state' = "
                        "'historical_not_instrumented') AS historical_lineage_count, "
                        "count(*) FILTER (WHERE cost_measurement_state = 'measured') "
                        "AS measured_cost_count, "
                        "count(*) FILTER (WHERE cost_measurement_state = 'partial') "
                        "AS partial_cost_count, "
                        "count(*) FILTER (WHERE cost_measurement_state = 'not_observed') "
                        "AS not_observed_cost_count, "
                        "count(*) FILTER (WHERE cost_measurement_state = 'invalid') "
                        "AS invalid_cost_count, "
                        "array_agg(provider_event_ids ORDER BY id) AS provider_event_id_sets, "
                        "count(*) FILTER (WHERE input_tokens IS NOT NULL "
                        "OR output_tokens IS NOT NULL) AS token_observation_count, "
                        "count(*) FILTER (WHERE execution_mode = 'hosted_advisory') "
                        "AS hosted_execution_count, "
                        "avg(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) "
                        "AS average_duration_ms, "
                        "percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) "
                        "FILTER (WHERE duration_ms IS NOT NULL) AS p50_duration_ms, "
                        "percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) "
                        "FILTER (WHERE duration_ms IS NOT NULL) AS p95_duration_ms, "
                        "count(*) FILTER (WHERE langfuse_status = 'not_attempted') "
                        "AS langfuse_not_attempted_count, "
                        "count(*) FILTER (WHERE langfuse_status = 'disabled') "
                        "AS langfuse_disabled_count, "
                        "count(*) FILTER (WHERE langfuse_status = 'queued') "
                        "AS langfuse_queued_count, "
                        "count(*) FILTER (WHERE langfuse_status = 'exported') "
                        "AS langfuse_exported_count, "
                        "count(*) FILTER (WHERE langfuse_status = 'error') "
                        "AS langfuse_error_count, "
                        "count(*) FILTER (WHERE langfuse_verified_at IS NOT NULL) "
                        "AS langfuse_verified_count, "
                        "max(langfuse_verified_at) AS last_langfuse_verified_at, "
                        "max(started_at) AS last_activity_at, "
                        "(array_agg(status ORDER BY started_at DESC))[1] AS last_status, "
                        "(array_agg(campaign_run_id ORDER BY started_at DESC))[1] "
                        "AS last_campaign_run_id, "
                        "(array_agg(attempt_id ORDER BY started_at DESC))[1] AS last_attempt_id "
                        "FROM agent_executions WHERE organization_id = :org GROUP BY agent_role",
                        {"org": principal.organization_id},
                    )
                    execution_by_role = {row["agent_role"]: row for row in execution_rows}
                    hosted_budget_rows = _rows(
                        connection,
                        "SELECT campaign_run_id, agent_role, status, execution_mode, detail, "
                        "measured_cost, cost_measurement_state, physical_attempts, "
                        "configuration_set_sha256, "
                        "generation_policy_sha256, returned_model, upstream_provider, "
                        "provider_request_id, input_tokens, output_tokens, reasoning_tokens "
                        "FROM agent_executions WHERE organization_id = :org "
                        "AND configuration_set_sha256 IS NOT NULL",
                        {"org": principal.organization_id},
                    )
                    (
                        hosted_budget_by_run_role,
                        hosted_budget_global_by_run,
                    ) = _hosted_budget_usage(
                        hosted_budget_rows,
                        hosted_configurations,
                    )

                    def budget_record(
                        *,
                        role: str,
                        assignment: Mapping[str, Any] | None,
                    ) -> dict[str, Any]:
                        if (
                            assignment is None
                            or assignment.get("execution_mode") != "hosted_advisory"
                        ):
                            return _unavailable_provider_budget()
                        configuration_sha256 = str(assignment["configuration_sha256"])
                        configuration = hosted_configurations.get(configuration_sha256)
                        if configuration is None:
                            return budget_record(role=role, assignment=None)
                        run = hosted_run_by_configuration.get(configuration_sha256)
                        run_id = run["run_id"] if run is not None else None
                        role_usage = (
                            hosted_budget_by_run_role.get((run_id, role), {})
                            if run_id is not None
                            else {}
                        )
                        global_usage = (
                            hosted_budget_global_by_run.get(run_id, {})
                            if run_id is not None
                            else {}
                        )
                        role_cost_state = _aggregate_cost_measurement_state(
                            measured=int(role_usage.get("measured_cost_count", 0)),
                            partial=int(role_usage.get("partial_cost_count", 0)),
                            not_observed=int(role_usage.get("not_observed_cost_count", 0)),
                            invalid=int(role_usage.get("invalid_cost_count", 0)),
                        )
                        role_call_count_state = (
                            "lower_bound"
                            if int(role_usage.get("historical_lineage_count", 0)) > 0
                            else "exact"
                        )
                        global_cost_state = _aggregate_cost_measurement_state(
                            measured=int(global_usage.get("measured_cost_count", 0)),
                            partial=int(global_usage.get("partial_cost_count", 0)),
                            not_observed=int(global_usage.get("not_observed_cost_count", 0)),
                            invalid=int(global_usage.get("invalid_cost_count", 0)),
                        )
                        global_call_count_state = (
                            "lower_bound"
                            if int(global_usage.get("historical_lineage_count", 0)) > 0
                            else "exact"
                        )
                        return _provider_budget_projection(
                            configuration=configuration,
                            role=role,
                            campaign_run_id=run_id,
                            campaign_state=(
                                str(run["campaign_state"])
                                if run is not None and run.get("campaign_state") is not None
                                else None
                            ),
                            role_spent=float(role_usage.get("measured_cost", 0.0)),
                            role_cost_measurement_state=role_cost_state,
                            role_physical_calls=int(role_usage.get("physical_calls", 0)),
                            role_unresolved_usd_exposure=role_usage.get(
                                "unresolved_usd_exposure",
                                0.0,
                            ),
                            role_unresolved_physical_calls=role_usage.get(
                                "unresolved_physical_calls",
                                0,
                            ),
                            role_call_count_state=role_call_count_state,
                            global_spent=float(global_usage.get("measured_cost", 0.0)),
                            global_cost_measurement_state=global_cost_state,
                            global_physical_calls=int(global_usage.get("physical_calls", 0)),
                            global_unresolved_usd_exposure=global_usage.get(
                                "unresolved_usd_exposure",
                                0.0,
                            ),
                            global_unresolved_physical_calls=global_usage.get(
                                "unresolved_physical_calls",
                                0,
                            ),
                            global_call_count_state=global_call_count_state,
                        )

                    def assignment_record(source: Mapping[str, Any]) -> dict[str, Any]:
                        return {
                            "role": source["agent_role"]
                            if "agent_role" in source
                            else source["role"],
                            "provider": source["provider"],
                            "model": source["model"],
                            "resolved_model": source.get("resolved_model"),
                            "upstream_provider": source.get("upstream_provider"),
                            # Deterministic engines have no system prompt, and a per-role staged
                            # assignment is not an activated hosted configuration set. Keep prompt
                            # lineage explicitly unavailable instead of inventing it.
                            "prompt_sha256": source.get("prompt_sha256"),
                            "prompt_version": source.get("prompt_version"),
                            "execution_mode": source["execution_mode"],
                            "activation_state": source["activation_state"],
                            "version": source["version"],
                            "configuration_sha256": source["configuration_sha256"],
                            "configured_at": source.get("created_at")
                            or source.get("configured_at"),
                            "configured_by": source.get("actor_user_id")
                            or source.get("configured_by"),
                        }

                    def judge_calibration_record(
                        assignment: Mapping[str, Any],
                    ) -> dict[str, Any]:
                        unavailable = {
                            "state": "unavailable",
                            "calibration_id": None,
                            "decision_authority": "none",
                            "oracle_comparison_count": 0,
                            "oracle_agreement_count": 0,
                            "oracle_agreement_rate": None,
                            "status_label": "not yet measured",
                        }
                        if assignment.get("execution_mode") != "hosted_advisory":
                            return unavailable
                        configuration_sha256 = assignment.get("configuration_sha256")
                        latest = (
                            connection.execute(
                                text(
                                    "SELECT judge_calibration_id, judge_calibration_state "
                                    "FROM agent_executions WHERE organization_id = :org "
                                    "AND agent_role = 'judge' "
                                    "AND configuration_set_sha256 = :configuration "
                                    "AND judge_calibration_id IS NOT NULL "
                                    "AND judge_calibration_state IS NOT NULL "
                                    "ORDER BY started_at DESC, id DESC LIMIT 1"
                                ),
                                {
                                    "org": principal.organization_id,
                                    "configuration": configuration_sha256,
                                },
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if latest is None or latest["judge_calibration_state"] == "unavailable":
                            return unavailable
                        observations = (
                            connection.execute(
                                text(
                                    "SELECT count(*) FILTER "
                                    "(WHERE oracle_agreement IS NOT NULL) "
                                    "AS oracle_comparison_count, "
                                    "count(*) FILTER (WHERE oracle_agreement IS TRUE) "
                                    "AS oracle_agreement_count, "
                                    "(array_agg(decision_authority "
                                    "ORDER BY started_at DESC, id DESC) "
                                    "FILTER (WHERE decision_authority IS NOT NULL))[1] "
                                    "AS decision_authority "
                                    "FROM agent_executions WHERE organization_id = :org "
                                    "AND agent_role = 'judge' "
                                    "AND configuration_set_sha256 = :configuration "
                                    "AND judge_calibration_id = :calibration"
                                ),
                                {
                                    "org": principal.organization_id,
                                    "configuration": configuration_sha256,
                                    "calibration": latest["judge_calibration_id"],
                                },
                            )
                            .mappings()
                            .one()
                        )
                        comparison_count = int(observations["oracle_comparison_count"] or 0)
                        agreement_count = int(observations["oracle_agreement_count"] or 0)
                        authority = (
                            str(observations["decision_authority"] or "none")
                            if comparison_count
                            else "none"
                        )
                        return {
                            "state": latest["judge_calibration_state"],
                            "calibration_id": latest["judge_calibration_id"],
                            "decision_authority": authority,
                            "oracle_comparison_count": comparison_count,
                            "oracle_agreement_count": agreement_count,
                            "oracle_agreement_rate": (
                                agreement_count / comparison_count if comparison_count else None
                            ),
                            "status_label": (
                                "not yet measured"
                                if comparison_count == 0
                                else "live, model-decisive after calibration"
                                if authority == "model"
                                else "live, verified against oracle"
                            ),
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
                        active_hosted = active_hosted_assignments.get(definition.role)
                        hosted_activated_after_deterministic = active_hosted is not None and (
                            active is None or active_hosted["_activation_at"] > active["created_at"]
                        )
                        active_source = (
                            active_hosted
                            if hosted_activated_after_deterministic
                            else active
                            if active is not None
                            else default_assignment(definition.role).public_record()
                        )
                        active_assignment = assignment_record(active_source)
                        staged_source = staged_hosted_assignments.get(definition.role)
                        if staged_source is None:
                            staged_source = staged
                        staged_assignment = (
                            assignment_record(staged_source) if staged_source is not None else None
                        )
                        budget_assignment = (
                            active_assignment
                            if active_assignment["execution_mode"] == "hosted_advisory"
                            else staged_assignment
                        )
                        stats = execution_by_role.get(definition.role, {})
                        execution_count = int(stats.get("execution_count", 0))
                        cost_measurement_state = _aggregate_cost_measurement_state(
                            measured=int(stats.get("measured_cost_count", 0)),
                            partial=int(stats.get("partial_cost_count", 0)),
                            not_observed=int(stats.get("not_observed_cost_count", 0)),
                            invalid=int(stats.get("invalid_cost_count", 0)),
                        )
                        accounting_status = _accounting_status(
                            cost_measurement_state,
                            applicable=execution_count > 0,
                        )
                        judge_calibration = (
                            judge_calibration_record(active_assignment)
                            if definition.role == "judge"
                            else None
                        )
                        rows.append(
                            {
                                **definition_record,
                                "active_assignment": active_assignment,
                                "staged_assignment": staged_assignment,
                                "execution_count": execution_count,
                                "hosted_execution_count": int(
                                    stats.get("hosted_execution_count", 0)
                                ),
                                "running_count": int(stats.get("running_count", 0)),
                                "succeeded_count": int(stats.get("succeeded_count", 0)),
                                "failed_count": int(stats.get("failed_count", 0)),
                                "skipped_count": int(stats.get("skipped_count", 0)),
                                "measured_cost": (
                                    float(stats["measured_cost"])
                                    if stats.get("measured_cost") is not None
                                    else None
                                ),
                                "cost_measurement_state": (
                                    cost_measurement_state
                                    if execution_count > 0
                                    else "not_applicable"
                                ),
                                "accounting_status": accounting_status,
                                "provider_event_ids": _flatten_provider_event_ids(
                                    stats.get("provider_event_id_sets")
                                ),
                                "currency": "USD",
                                "input_tokens": stats.get("input_tokens"),
                                "output_tokens": stats.get("output_tokens"),
                                "reasoning_tokens": stats.get("reasoning_tokens"),
                                "token_observation_count": int(
                                    stats.get("token_observation_count", 0)
                                ),
                                "physical_call_count": int(stats.get("physical_call_count", 0)),
                                "physical_call_count_state": (
                                    "not_applicable"
                                    if int(stats.get("hosted_execution_count", 0)) == 0
                                    else (
                                        "lower_bound"
                                        if int(stats.get("historical_lineage_count", 0)) > 0
                                        else "exact"
                                    )
                                ),
                                "provider_budget": budget_record(
                                    role=definition.role,
                                    assignment=budget_assignment,
                                ),
                                "judge_calibration": judge_calibration,
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
                                "langfuse_not_attempted_count": int(
                                    stats.get("langfuse_not_attempted_count", 0)
                                ),
                                "langfuse_disabled_count": int(
                                    stats.get("langfuse_disabled_count", 0)
                                ),
                                "langfuse_queued_count": int(stats.get("langfuse_queued_count", 0)),
                                "langfuse_error_count": int(stats.get("langfuse_error_count", 0)),
                                "langfuse_verified_count": int(
                                    stats.get("langfuse_verified_count", 0)
                                ),
                                "last_langfuse_verified_at": stats.get("last_langfuse_verified_at"),
                                "last_activity_at": stats.get("last_activity_at"),
                                "last_status": stats.get("last_status"),
                                "last_campaign_run_id": stats.get("last_campaign_run_id"),
                                "last_attempt_id": stats.get("last_attempt_id"),
                            }
                        )
                elif resource == "agent_prompt":
                    agent_role = identifiers.get("agent_role", "")
                    prompt_version = identifiers.get("prompt_version", "")
                    prompt_sha256 = identifiers.get("prompt_sha256", "")
                    configuration_sha256 = identifiers.get("configuration_sha256", "")
                    configuration_row = (
                        connection.execute(
                            text(
                                "SELECT configuration_sha256, payload "
                                "FROM hosted_configuration_sets "
                                "WHERE organization_id = :org "
                                "AND configuration_sha256 = :configuration"
                            ),
                            {
                                "org": principal.organization_id,
                                "configuration": configuration_sha256,
                            },
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if configuration_row is None:
                        rows = []
                    else:
                        try:
                            configuration = HostedConfigurationSet.from_payload(
                                dict(configuration_row["payload"])
                            )
                        except (TypeError, ValueError):
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        if (
                            configuration.configuration_sha256
                            != configuration_row["configuration_sha256"]
                        ):
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        configured_role = next(
                            (
                                role
                                for role in configuration.roles
                                if role.role == agent_role and role.prompt_sha256 == prompt_sha256
                            ),
                            None,
                        )
                        try:
                            prompt = prompt_for_identity(
                                agent_role,
                                prompt_version,
                                prompt_sha256,
                            )
                        except PromptRegistryError:
                            rows = []
                        else:
                            if (
                                configured_role is None
                                or configured_role.prompt_version != prompt.version
                            ):
                                rows = []
                            else:
                                rows = [
                                    {
                                        "role": prompt.role,
                                        "prompt_version": prompt.version,
                                        "prompt_sha256": prompt.sha256,
                                        "system_prompt": prompt.content,
                                    }
                                ]
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
                        try:
                            configuration = HostedConfigurationSet.from_payload(
                                dict(row["payload"])
                            )
                        except (TypeError, ValueError):
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        if configuration.configuration_sha256 != row["configuration_sha256"]:
                            return ResourceResult.unavailable(
                                "hosted_configuration_integrity_failed"
                            )
                        preflight = preflight_hosted_configuration_set(configuration)
                        provider_bindings_verified = bool(
                            self._hosted_provider_bindings_verified
                            or self._hosted_provider_bindings_are_fresh(
                                configuration.configuration_sha256
                            )
                        )
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
                                "provider_reference_bound": provider_bindings_verified,
                                "role_configuration_sha256": role.configuration_sha256,
                            }
                            for role in configuration.roles
                        ]
                        projection = {
                            "configuration_sha256": configuration.configuration_sha256,
                            "schema_version": configuration.schema_version,
                            "release_sha256": row["release_sha256"],
                            "activation_state": "staged_pending_authorization",
                            "runtime_available": (
                                self._hosted_runtime_available and provider_bindings_verified
                            ),
                            "runtime_reason": (
                                (
                                    None
                                    if provider_bindings_verified
                                    else "provider_credentials_runner_unverified"
                                )
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
                                    if provider_bindings_verified
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
                        "agent_role, status, provider, model, returned_model, upstream_provider, "
                        "provider_request_id, execution_mode, configuration_version, "
                        "configuration_set_sha256, role_configuration_sha256, "
                        "generation_policy_sha256, input_sha256, output_sha256, input_tokens, "
                        "output_tokens, reasoning_tokens, physical_attempts, measured_cost, "
                        "cost_measurement_state, provider_event_ids, "
                        "currency, trace_id, langfuse_status, "
                        "langfuse_verified_at, "
                        "detail, judge_calibration_id, judge_calibration_state, "
                        "oracle_agreement, decision_authority, error_code, "
                        "provider_event_status, "
                        "started_at, finished_at, duration_ms FROM agent_executions "
                        "WHERE organization_id = :org ORDER BY id DESC LIMIT 1000",
                        {"org": principal.organization_id},
                    )
                    for row in rows:
                        row["model_substituted"] = row["provider_event_status"] == "model_mismatch"
                        row["measured_cost"] = (
                            float(row["measured_cost"])
                            if row["measured_cost"] is not None
                            else None
                        )
                        row["accounting_status"] = {
                            "measured": "measured",
                            "partial": "partial",
                            "not_observed": "unavailable",
                            "invalid": "unavailable",
                        }[row["cost_measurement_state"]]
                        row["provider_lineage_state"] = _provider_lineage_state(
                            row["execution_mode"],
                            row["detail"],
                        )
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
                        "SELECT a.source_tool AS tool_id, ar.target_id, ar.surface_id, "
                        "count(*) AS executed_attempt_count, "
                        "max(ar.executed_at) AS last_executed_at "
                        "FROM campaign_attempts a JOIN attempt_result ar "
                        "ON ar.organization_id = a.organization_id "
                        "AND ar.campaign_run_id = a.run_id "
                        "AND ar.attempt_id = a.attempt_id "
                        "WHERE a.organization_id = :org AND a.source_tool IS NOT NULL "
                        "GROUP BY a.source_tool, ar.target_id, ar.surface_id",
                        {"org": principal.organization_id},
                    )
                    attempt_metrics = {
                        (row["tool_id"], row["target_id"], row["surface_id"]): row
                        for row in attempt_rows
                    }
                    scan_rows = _rows(
                        connection,
                        "SELECT lower(r.tool_name) AS tool_id, r.target_id, r.surface_id, "
                        "count(DISTINCT r.run_id) AS recorded_scan_count, "
                        "count(DISTINCT f.finding_id) "
                        "AS recorded_finding_count, max(r.finished_at) AS last_executed_at, "
                        "(array_agg(r.status ORDER BY r.finished_at DESC))[1] "
                        "AS last_run_status, "
                        "(array_agg((SELECT e.code FROM tool_execution_errors e "
                        "WHERE e.organization_id = r.organization_id AND e.run_id = r.run_id "
                        "ORDER BY e.created_at DESC LIMIT 1) "
                        "ORDER BY r.finished_at DESC))[1] AS last_error_code "
                        "FROM security_tool_runs r "
                        "LEFT JOIN security_tool_findings f "
                        "ON f.organization_id = r.organization_id AND f.run_id = r.run_id "
                        "WHERE r.organization_id = :org "
                        "GROUP BY lower(r.tool_name), r.target_id, r.surface_id",
                        {"org": principal.organization_id},
                    )
                    scan_metrics = {
                        (row["tool_id"], row["target_id"], row["surface_id"]): row
                        for row in scan_rows
                    }
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
                            metric_key = (
                                tool.tool_id,
                                configured["target_id"],
                                configured["surface_id"],
                            )
                            attempts = attempt_metrics.get(metric_key, {})
                            scans = scan_metrics.get(metric_key, {})
                            executed_attempt_count = int(attempts.get("executed_attempt_count", 0))
                            recorded_scan_count = int(scans.get("recorded_scan_count", 0))
                            timestamps = [
                                value
                                for value in (
                                    attempts.get("last_executed_at"),
                                    scans.get("last_executed_at"),
                                )
                                if isinstance(value, datetime.datetime)
                            ]
                            attempt_at = attempts.get("last_executed_at")
                            scan_at = scans.get("last_executed_at")
                            scan_is_latest = isinstance(scan_at, datetime.datetime) and (
                                not isinstance(attempt_at, datetime.datetime)
                                or scan_at >= attempt_at
                            )
                            last_scan_status = scans.get("last_run_status")
                            if scan_is_latest and last_scan_status == "failed":
                                runtime_state = "error"
                                last_error_code = scans.get("last_error_code")
                            elif executed_attempt_count > 0 or recorded_scan_count > 0:
                                runtime_state = "evidenced"
                                last_error_code = None
                            else:
                                runtime_state = "idle"
                                last_error_code = None
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
                                    "executed_attempt_count": executed_attempt_count,
                                    "recorded_scan_count": recorded_scan_count,
                                    "recorded_finding_count": int(
                                        scans.get("recorded_finding_count", 0)
                                    ),
                                    "last_executed_at": max(timestamps) if timestamps else None,
                                    "runtime_state": runtime_state,
                                    "evidenced_finding_count": int(
                                        scans.get("recorded_finding_count", 0)
                                    ),
                                    "last_error_code": last_error_code,
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
                        "SELECT ar.*, v.id AS verdict_id, v.state AS verdict_state, "
                        "v.confidence AS verdict_confidence, "
                        "v.reason_codes AS verdict_reason_codes, "
                        "v.confirmation_source AS verdict_confirmation_source, "
                        "v.error_code AS verdict_error_code "
                        "FROM attempt_result ar "
                        "LEFT JOIN verdict v ON v.organization_id = ar.organization_id "
                        "AND v.campaign_run_id = ar.campaign_run_id "
                        "AND v.attempt_id = ar.attempt_id "
                        "WHERE ar.organization_id = :org AND ar.attempt_id = :attempt_id",
                        {
                            "org": principal.organization_id,
                            "attempt_id": identifiers.get("attempt_id"),
                        },
                    )
                    if len(rows) > 1:
                        return ResourceResult.unavailable("attempt_evidence_identifier_ambiguous")
                    if rows:
                        source = rows[0]
                        if not _evidence_verified(source):
                            return ResourceResult.unavailable("evidence_integrity_failed")
                        try:
                            verdict = _validated_verdict(source)
                        except EvidenceIntegrityError:
                            return ResourceResult.unavailable("verdict_integrity_failed")
                        rows = [
                            {
                                "campaign_run_id": source["campaign_run_id"],
                                "attempt_id": source["attempt_id"],
                                "target_id": source.get("target_id"),
                                "target_version": source.get("target_version"),
                                "surface_id": source.get("surface_id"),
                                "surface_version": source.get("surface_version"),
                                "attack_attempt": _redact_evidence_display(
                                    source.get("attack_attempt")
                                ),
                                "request_transcript": _redact_evidence_display(
                                    source.get("request_transcript")
                                ),
                                "response_transcript": _redact_evidence_display(
                                    source.get("response_transcript")
                                ),
                                "policy_decision_id": source.get("policy_decision_id"),
                                "executed_at": source.get("executed_at"),
                                "trace_id": source.get("trace_id"),
                                "content_hash": source["content_hash"],
                                # This Judge projection is separately contract-validated. The
                                # AttemptResult content hash authenticates only the evidence row.
                                "verdict": verdict["state"] if verdict is not None else None,
                                "confidence": (
                                    verdict["confidence"] if verdict is not None else None
                                ),
                                "execution_profile": source.get("execution_profile"),
                                "evidence_provenance": source.get("evidence_provenance"),
                            }
                        ]
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
                        "f.target_version AS finding_target_version, "
                        "f.source_kind AS finding_source_kind, "
                        "f.execution_profile AS finding_execution_profile, f.published, "
                        "a.case_id, a.case_content_hash, a.category AS case_category, "
                        "a.severity AS case_severity, "
                        "a.attack_class, a.owasp_mappings, "
                        "(SELECT t.payload->'oracle_refs' FROM target_definitions t "
                        "WHERE t.organization_id = ar.organization_id "
                        "AND t.target_id = ar.target_id AND t.version = ar.target_version "
                        "LIMIT 1) AS target_oracle_refs, "
                        "(SELECT t.payload->'canary_refs' FROM target_definitions t "
                        "WHERE t.organization_id = ar.organization_id "
                        "AND t.target_id = ar.target_id AND t.version = ar.target_version "
                        "LIMIT 1) AS target_canary_refs, "
                        "v.id AS verdict_id, "
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
                        "AND v.organization_id = l.organization_id "
                        "AND v.campaign_run_id = l.campaign_run_id "
                        "AND v.attempt_id = l.attempt_id "
                        "LEFT JOIN vuln_reports vr "
                        "ON vr.organization_id = f.organization_id "
                        "AND vr.finding_id = f.finding_id "
                        "AND vr.campaign_run_id = l.campaign_run_id "
                        "AND vr.attempt_id = l.attempt_id "
                        "LEFT JOIN LATERAL (SELECT d.contract_payload "
                        "FROM regression_dispositions d "
                        "WHERE d.organization_id = f.organization_id "
                        "AND d.finding_id = f.finding_id "
                        "AND d.report_id = vr.report_id "
                        "AND d.campaign_run_id = l.campaign_run_id "
                        "AND d.attempt_id = l.attempt_id "
                        "ORDER BY d.created_at DESC LIMIT 1) rd ON true WHERE "
                        + where
                        + " ORDER BY f.created_at DESC",
                        parameters,
                    )
                    finding_link_counts = Counter(
                        source["linked_finding_id"] for source in source_rows
                    )
                    if any(count != 1 for count in finding_link_counts.values()):
                        return ResourceResult.unavailable("finding_evidence_identifier_ambiguous")
                    rows = []
                    for source in source_rows:
                        try:
                            if source["content_hash"] != source[
                                "evidence_content_hash"
                            ] or not _evidence_verified(source):
                                raise EvidenceIntegrityError("finding evidence cannot be verified")
                            _validated_finding_lineage(source)
                        except EvidenceIntegrityError:
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
                        for event in history:
                            event["rationale"] = str(_redact_evidence_display(event["rationale"]))
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
                            "source_kind": source["finding_source_kind"],
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
                        "SELECT f.finding_id AS stored_finding_id, "
                        "f.run_id AS stored_finding_run_id, "
                        "f.raw_artifact_sha256 AS stored_finding_artifact_sha256, "
                        "f.validation_state AS stored_finding_validation_state, "
                        "f.human_publication_state AS stored_finding_publication_state, "
                        "f.evidence_provenance AS stored_finding_provenance, "
                        "f.contract_payload AS finding_payload, "
                        "r.run_id, r.tool_name AS run_tool_name, "
                        "r.tool_version AS run_tool_version, "
                        "r.configuration_sha256 AS run_configuration_sha256, "
                        "r.run_nonce, r.target_id AS run_target_id, "
                        "r.surface_id AS run_surface_id, "
                        "r.scan_provenance AS run_scan_provenance, "
                        "r.status AS run_status, r.started_at AS run_started_at, "
                        "r.finished_at AS run_finished_at, "
                        "r.artifact_sha256 AS run_artifact_sha256, "
                        "a.artifact_id, a.run_id AS artifact_run_id, "
                        "a.sha256 AS artifact_sha256, "
                        "a.media_type AS artifact_media_type, "
                        "a.byte_length AS artifact_byte_length, "
                        "a.artifact_locator, a.sanitized_payload AS artifact_bytes, "
                        "a.contract_payload AS artifact_payload, "
                        "(SELECT count(*) FROM scan_artifacts sa_count "
                        "WHERE sa_count.organization_id = f.organization_id "
                        "AND sa_count.run_id = f.run_id "
                        "AND sa_count.sha256 = f.raw_artifact_sha256) "
                        "AS matching_artifact_count "
                        "FROM security_tool_findings f "
                        "LEFT JOIN security_tool_runs r "
                        "ON r.organization_id = f.organization_id AND r.run_id = f.run_id "
                        "LEFT JOIN LATERAL (SELECT sa.* FROM scan_artifacts sa "
                        "WHERE sa.organization_id = f.organization_id "
                        "AND sa.run_id = f.run_id "
                        "AND sa.sha256 = f.raw_artifact_sha256 "
                        "ORDER BY sa.artifact_id LIMIT 1) a ON true WHERE "
                        + tool_where.replace("organization_id", "f.organization_id")
                        + " ORDER BY f.finding_id",
                        tool_parameters,
                    )
                    for source in tool_rows:
                        payload = source["finding_payload"]
                        try:
                            validate_contract("tool_finding", payload)
                        except Exception:
                            return ResourceResult.unavailable(
                                "security_tool_finding_contract_invalid"
                            )
                        evidence_verified = _security_tool_evidence_verified(source)
                        projection = {
                            "finding_id": payload["finding_id"],
                            "state": payload["validation_state"],
                            "severity": payload["severity"],
                            # ToolFinding has no normalized platform category or target-version
                            # field. Free-form summaries and target IDs are not substitutes.
                            "category": None,
                            "target_version": None,
                            "publication_status": payload["human_publication_state"],
                            "evidence_integrity": (
                                "verified" if evidence_verified else "unavailable"
                            ),
                            "source_kind": payload["source_kind"],
                            "execution_profile": "live"
                            if payload["scan_provenance"] == "live_target"
                            else "synthetic",
                            "evidence_provenance": payload["evidence_provenance"],
                            "campaign_run_id": None,
                            "attempt_id": None,
                            "evidence_content_hash": (
                                payload["raw_artifact_sha256"] if evidence_verified else None
                            ),
                            "history": [],
                        }
                        if resource == "finding":
                            projection["verification"] = self._unavailable_verification(
                                payload["finding_id"],
                                reason_code=(
                                    "campaign_transcript_not_applicable"
                                    if evidence_verified
                                    else "security_tool_evidence_integrity_failed"
                                ),
                            )
                        rows.append(projection)
                    projected_finding_counts = Counter(row["finding_id"] for row in rows)
                    if any(count != 1 for count in projected_finding_counts.values()):
                        return ResourceResult.unavailable("finding_evidence_identifier_ambiguous")
                elif resource in {"reports", "report"}:
                    where = "vr.organization_id = :org"
                    parameters = {"org": principal.organization_id}
                    if resource == "report":
                        where += " AND vr.report_id = :report_id"
                        parameters["report_id"] = identifiers.get("report_id")
                    source_rows = _rows(
                        connection,
                        "SELECT ar.*, f.finding_id AS linked_finding_id, "
                        "f.severity AS finding_severity, "
                        "f.category AS finding_category, "
                        "f.target_version AS finding_target_version, "
                        "f.source_kind AS finding_source_kind, "
                        "f.execution_profile AS finding_execution_profile, "
                        "a.case_id, a.case_content_hash, a.category AS case_category, "
                        "a.severity AS case_severity, "
                        "a.attack_class, a.owasp_mappings, "
                        "(SELECT t.payload->'oracle_refs' FROM target_definitions t "
                        "WHERE t.organization_id = ar.organization_id "
                        "AND t.target_id = ar.target_id AND t.version = ar.target_version "
                        "LIMIT 1) AS target_oracle_refs, "
                        "(SELECT t.payload->'canary_refs' FROM target_definitions t "
                        "WHERE t.organization_id = ar.organization_id "
                        "AND t.target_id = ar.target_id AND t.version = ar.target_version "
                        "LIMIT 1) AS target_canary_refs, "
                        "v.id AS verdict_id, "
                        "v.state AS verdict_state, v.confidence AS verdict_confidence, "
                        "v.reason_codes AS verdict_reason_codes, "
                        "v.confirmation_source AS verdict_confirmation_source, "
                        "v.error_code AS verdict_error_code, "
                        "vr.report_id AS vuln_report_id, vr.contract_payload AS report_payload, "
                        "vr.created_at AS report_created_at, "
                        "rd.contract_payload AS regression_payload, "
                        "l.evidence_content_hash, l.provenance AS linked_provenance "
                        "FROM vuln_reports vr JOIN finding f "
                        "ON f.organization_id = vr.organization_id "
                        "AND f.finding_id = vr.finding_id "
                        "JOIN finding_evidence_links l "
                        "ON l.organization_id = f.organization_id "
                        "AND l.finding_id = f.finding_id "
                        "AND l.campaign_run_id = vr.campaign_run_id "
                        "AND l.attempt_id = vr.attempt_id "
                        "JOIN attempt_result ar ON ar.organization_id = l.organization_id "
                        "AND ar.campaign_run_id = l.campaign_run_id "
                        "AND ar.attempt_id = l.attempt_id "
                        "JOIN campaign_attempts a ON a.organization_id = l.organization_id "
                        "AND a.run_id = l.campaign_run_id AND a.attempt_id = l.attempt_id "
                        "JOIN verdict v ON v.id = l.verdict_id "
                        "AND v.organization_id = l.organization_id "
                        "AND v.campaign_run_id = l.campaign_run_id "
                        "AND v.attempt_id = l.attempt_id "
                        "LEFT JOIN LATERAL (SELECT d.contract_payload "
                        "FROM regression_dispositions d "
                        "WHERE d.organization_id = vr.organization_id "
                        "AND d.report_id = vr.report_id "
                        "ORDER BY d.created_at DESC LIMIT 1) rd ON true WHERE "
                        + where
                        + " ORDER BY vr.created_at DESC",
                        parameters,
                    )
                    report_counts = Counter(source["vuln_report_id"] for source in source_rows)
                    if any(count != 1 for count in report_counts.values()):
                        return ResourceResult.unavailable("report_identifier_ambiguous")
                    rows = []
                    for source in source_rows:
                        report_payload = source.get("report_payload")
                        regression_payload = source.get("regression_payload")
                        try:
                            _trusted_report_verdict(source)
                            if not isinstance(report_payload, Mapping):
                                raise ValueError("report payload is absent")
                            report_payload = dict(report_payload)
                            validate_contract("vuln_report", report_payload)
                            if (
                                report_payload.get("report_id") != source["vuln_report_id"]
                                or report_payload.get("finding_id") != source["linked_finding_id"]
                                or report_payload.get("campaign_run_id")
                                != source["campaign_run_id"]
                                or report_payload.get("attempt_id") != source["attempt_id"]
                                or _reproduction_sha256(report_payload.get("minimal_reproduction"))
                                != report_payload.get("reproduction_sha256")
                                or not _report_evidence_references_verified(
                                    report_payload,
                                    content_hash=source["evidence_content_hash"],
                                )
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
                                "execution_mode": None,
                                # measured_cost is a Numeric(14,6) -> Decimal; the console/pydantic
                                # contract requires a JSON number, so coerce it to float here rather
                                # than letting _safe stringify the Decimal.
                                "measured_cost": float(cost) if cost is not None else None,
                                "cost_measurement_state": "measured",
                                "accounting_status": "measured",
                                "provider_event_ids": [],
                                "currency": source["currency"],
                                "request_count": source["request_count"],
                                "execution_count": 0,
                                "attempt_count": source["attempt_count"],
                                "confirmed_finding_count": source["confirmed_finding_count"],
                                "average_cost_per_request": (
                                    float(cost) / source["request_count"]
                                    if cost is not None and source["request_count"]
                                    else None
                                ),
                                "input_tokens": None,
                                "output_tokens": None,
                                "reasoning_tokens": None,
                                "token_observation_count": 0,
                                "physical_call_count": 0,
                                "physical_call_count_state": "not_applicable",
                                "provider_budget": None,
                                "p50_duration_ms": None,
                                "p95_duration_ms": None,
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
                        "WITH role_metrics AS ("
                        "SELECT organization_id, campaign_run_id, agent_role, "
                        "percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) "
                        "AS p50_duration_ms, "
                        "percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) "
                        "AS p95_duration_ms "
                        "FROM agent_executions WHERE organization_id = :org "
                        "AND status <> 'running' AND duration_ms IS NOT NULL "
                        "GROUP BY organization_id, campaign_run_id, agent_role"
                        ") "
                        "SELECT e.campaign_run_id, e.agent_role, e.provider, e.model, "
                        "e.execution_mode, "
                        "sum(e.measured_cost) AS measured_cost, e.currency, "
                        "count(*) FILTER (WHERE e.status <> 'running') AS executions, "
                        "count(DISTINCT e.attempt_id) AS attempt_count, "
                        "sum(e.input_tokens) AS input_tokens, "
                        "sum(e.output_tokens) AS output_tokens, "
                        "sum(e.reasoning_tokens) AS reasoning_tokens, "
                        "coalesce(sum(e.physical_attempts), 0) AS physical_call_count, "
                        "count(*) FILTER (WHERE e.detail->>'provider_lineage_state' = "
                        "'historical_not_instrumented') AS historical_lineage_count, "
                        "count(*) FILTER (WHERE e.cost_measurement_state = 'measured') "
                        "AS measured_cost_count, "
                        "count(*) FILTER (WHERE e.cost_measurement_state = 'partial') "
                        "AS partial_cost_count, "
                        "count(*) FILTER (WHERE e.cost_measurement_state = 'not_observed') "
                        "AS not_observed_cost_count, "
                        "count(*) FILTER (WHERE e.cost_measurement_state = 'invalid') "
                        "AS invalid_cost_count, "
                        "array_agg(e.provider_event_ids ORDER BY e.id) "
                        "AS provider_event_id_sets, "
                        "e.configuration_set_sha256, "
                        "count(*) FILTER (WHERE e.input_tokens IS NOT NULL "
                        "OR e.output_tokens IS NOT NULL) AS token_observation_count, "
                        "max(m.p50_duration_ms) AS p50_duration_ms, "
                        "max(m.p95_duration_ms) AS p95_duration_ms, "
                        "min(e.started_at) AS started_at, max(e.finished_at) AS ended_at, "
                        "statement_timestamp() AS recorded_at, "
                        "extract(epoch FROM ("
                        "max(coalesce(e.finished_at, statement_timestamp())) - min(e.started_at)"
                        ")) * 1000 "
                        "AS duration_ms, q.scope_payload->>'execution_profile' "
                        "AS execution_profile, run_state.state AS campaign_state, "
                        "CASE WHEN jsonb_typeof(q.scope_payload->'caps'->'budget_usd') = 'number' "
                        "THEN (q.scope_payload->'caps'->>'budget_usd')::double precision "
                        "ELSE NULL END AS budget_usd "
                        "FROM agent_executions e JOIN campaign_runs r "
                        "ON r.organization_id = e.organization_id "
                        "AND r.run_id = e.campaign_run_id "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "LEFT JOIN role_metrics m ON m.organization_id = e.organization_id "
                        "AND m.campaign_run_id = e.campaign_run_id "
                        "AND m.agent_role = e.agent_role "
                        "LEFT JOIN LATERAL (SELECT state FROM campaign_run_events event "
                        "WHERE event.organization_id = e.organization_id "
                        "AND event.run_id = e.campaign_run_id "
                        "ORDER BY event.id DESC LIMIT 1) run_state ON true "
                        "WHERE e.organization_id = :org "
                        "AND (e.status <> 'running' "
                        "OR e.configuration_set_sha256 IS NOT NULL) "
                        "GROUP BY e.campaign_run_id, e.agent_role, e.provider, e.model, "
                        "e.currency, e.execution_mode, e.configuration_set_sha256, "
                        "q.scope_payload, run_state.state "
                        "ORDER BY max(coalesce(e.finished_at, statement_timestamp())) DESC "
                        "LIMIT 400",
                        {"org": principal.organization_id},
                    )
                    cost_configuration_rows = _rows(
                        connection,
                        "SELECT configuration_sha256, payload FROM hosted_configuration_sets "
                        "WHERE organization_id = :org",
                        {"org": principal.organization_id},
                    )
                    cost_configurations: dict[str, HostedConfigurationSet] = {}
                    for configuration_row in cost_configuration_rows:
                        try:
                            configuration = HostedConfigurationSet.from_payload(
                                dict(configuration_row["payload"])
                            )
                        except (TypeError, ValueError):
                            continue
                        if (
                            configuration.configuration_sha256
                            == configuration_row["configuration_sha256"]
                        ):
                            cost_configurations[configuration.configuration_sha256] = configuration
                    hosted_cost_usage_rows = _rows(
                        connection,
                        "SELECT campaign_run_id, agent_role, status, execution_mode, detail, "
                        "measured_cost, cost_measurement_state, physical_attempts, "
                        "configuration_set_sha256, "
                        "generation_policy_sha256, returned_model, upstream_provider, "
                        "provider_request_id, input_tokens, output_tokens, reasoning_tokens "
                        "FROM agent_executions "
                        "WHERE organization_id = :org "
                        "AND configuration_set_sha256 IS NOT NULL",
                        {"org": principal.organization_id},
                    )
                    (
                        cost_usage_by_run_role,
                        global_cost_by_run,
                    ) = _hosted_budget_usage(
                        hosted_cost_usage_rows,
                        cost_configurations,
                    )
                    for source in agent_cost_rows:
                        role_usage = source
                        measured_cost = role_usage["measured_cost"]
                        cost = float(measured_cost) if measured_cost is not None else None
                        execution_count = int(role_usage["executions"])
                        physical_call_count = int(role_usage["physical_call_count"] or 0)
                        physical_call_count_state = (
                            "not_applicable"
                            if source["execution_mode"] == "deterministic"
                            else (
                                "lower_bound"
                                if int(role_usage["historical_lineage_count"] or 0) > 0
                                else "exact"
                            )
                        )
                        cost_measurement_state = _aggregate_cost_measurement_state(
                            measured=int(role_usage["measured_cost_count"]),
                            partial=int(role_usage["partial_cost_count"]),
                            not_observed=int(role_usage["not_observed_cost_count"]),
                            invalid=int(role_usage["invalid_cost_count"]),
                        )
                        accounting_status = _accounting_status(cost_measurement_state)
                        accounting_id = hashlib.sha256(
                            (
                                f"agent-cost:{source['campaign_run_id']}:"
                                f"{source['agent_role']}:{source['provider']}:{source['model']}:"
                                f"{source['execution_mode']}"
                            ).encode()
                        ).hexdigest()
                        configuration = cost_configurations.get(source["configuration_set_sha256"])
                        if configuration is None:
                            provider_budget = _unavailable_provider_budget()
                        else:
                            budget_role_usage = cost_usage_by_run_role.get(
                                (source["campaign_run_id"], source["agent_role"]),
                                {},
                            )
                            global_usage = global_cost_by_run.get(
                                source["campaign_run_id"],
                                {},
                            )
                            global_cost_measurement_state = _aggregate_cost_measurement_state(
                                measured=int(global_usage.get("measured_cost_count", 0)),
                                partial=int(global_usage.get("partial_cost_count", 0)),
                                not_observed=int(global_usage.get("not_observed_cost_count", 0)),
                                invalid=int(global_usage.get("invalid_cost_count", 0)),
                            )
                            provider_budget = _provider_budget_projection(
                                configuration=configuration,
                                role=source["agent_role"],
                                campaign_run_id=source["campaign_run_id"],
                                campaign_state=source["campaign_state"],
                                role_spent=float(
                                    budget_role_usage.get("measured_cost", cost or 0.0)
                                ),
                                role_cost_measurement_state=cost_measurement_state,
                                role_physical_calls=int(
                                    budget_role_usage.get(
                                        "physical_calls",
                                        physical_call_count,
                                    )
                                ),
                                role_unresolved_usd_exposure=budget_role_usage.get(
                                    "unresolved_usd_exposure",
                                    0.0,
                                ),
                                role_unresolved_physical_calls=budget_role_usage.get(
                                    "unresolved_physical_calls",
                                    0,
                                ),
                                role_call_count_state=physical_call_count_state,
                                global_spent=float(global_usage.get("measured_cost", 0.0)),
                                global_cost_measurement_state=(global_cost_measurement_state),
                                global_physical_calls=int(global_usage.get("physical_calls", 0)),
                                global_unresolved_usd_exposure=global_usage.get(
                                    "unresolved_usd_exposure",
                                    0.0,
                                ),
                                global_unresolved_physical_calls=global_usage.get(
                                    "unresolved_physical_calls",
                                    0,
                                ),
                                global_call_count_state=(
                                    "lower_bound"
                                    if int(global_usage.get("historical_lineage_count", 0)) > 0
                                    else "exact"
                                ),
                            )
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
                                "execution_mode": source["execution_mode"],
                                "measured_cost": cost,
                                "cost_measurement_state": cost_measurement_state,
                                "accounting_status": accounting_status,
                                "provider_event_ids": _flatten_provider_event_ids(
                                    role_usage["provider_event_id_sets"]
                                ),
                                "currency": source["currency"],
                                "request_count": physical_call_count,
                                "execution_count": execution_count,
                                "attempt_count": int(role_usage["attempt_count"]),
                                "confirmed_finding_count": 0,
                                "average_cost_per_request": (
                                    cost / physical_call_count
                                    if accounting_status == "measured"
                                    and cost is not None
                                    and physical_call_count
                                    and physical_call_count_state == "exact"
                                    else None
                                ),
                                "input_tokens": role_usage["input_tokens"],
                                "output_tokens": role_usage["output_tokens"],
                                "reasoning_tokens": role_usage["reasoning_tokens"],
                                "token_observation_count": int(
                                    role_usage["token_observation_count"]
                                ),
                                "physical_call_count": physical_call_count,
                                "physical_call_count_state": physical_call_count_state,
                                "provider_budget": provider_budget,
                                "p50_duration_ms": (
                                    float(source["p50_duration_ms"])
                                    if source["p50_duration_ms"] is not None
                                    else None
                                ),
                                "p95_duration_ms": (
                                    float(source["p95_duration_ms"])
                                    if source["p95_duration_ms"] is not None
                                    else None
                                ),
                                "budget_usd": None,
                                "budget_utilization": None,
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
                        "request_bytes, response_bytes, measured_cost, currency, langfuse_status, "
                        "langfuse_verified_at, request_payload, response_payload "
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
                                "requested_model": None,
                                "returned_model": None,
                                "model_substituted": False,
                                "provider_event_status": None,
                                "upstream_provider": None,
                                "provider_request_id": None,
                                "configuration_set_sha256": None,
                                "role_configuration_sha256": None,
                                "generation_policy_sha256": None,
                                "physical_attempts": None,
                                "input_tokens": None,
                                "output_tokens": None,
                                "reasoning_tokens": None,
                                "judge_calibration_id": None,
                                "judge_calibration_state": None,
                                "oracle_agreement": None,
                                "decision_authority": None,
                                "p50_duration_ms": None,
                                "p95_duration_ms": None,
                                "duration_ms": duration_ms,
                                "measured_cost": (
                                    float(source["measured_cost"])
                                    if source["measured_cost"] is not None
                                    else None
                                ),
                                "cost_measurement_state": "measured",
                                "accounting_status": "measured",
                                "provider_event_ids": [],
                                "provider_lineage_state": "not_applicable",
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
                                "model": None,
                                "agent_role": None,
                                "execution_mode": None,
                                "requested_model": None,
                                "returned_model": None,
                                "model_substituted": False,
                                "provider_event_status": None,
                                "upstream_provider": None,
                                "provider_request_id": None,
                                "configuration_set_sha256": None,
                                "role_configuration_sha256": None,
                                "generation_policy_sha256": None,
                                "physical_attempts": None,
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
                                "measured_cost": None,
                                "cost_measurement_state": "not_observed",
                                "accounting_status": "unavailable",
                                "provider_event_ids": [],
                                "provider_lineage_state": "not_applicable",
                                "currency": "USD",
                                "input_tokens": None,
                                "output_tokens": None,
                                "reasoning_tokens": None,
                                "judge_calibration_id": None,
                                "judge_calibration_state": None,
                                "oracle_agreement": None,
                                "decision_authority": None,
                                "p50_duration_ms": None,
                                "p95_duration_ms": None,
                                "langfuse_status": "historical_not_instrumented",
                                "langfuse_verified_at": None,
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
                                "model": None,
                                "agent_role": None,
                                "execution_mode": None,
                                "requested_model": None,
                                "returned_model": None,
                                "model_substituted": False,
                                "provider_event_status": None,
                                "upstream_provider": None,
                                "provider_request_id": None,
                                "configuration_set_sha256": None,
                                "role_configuration_sha256": None,
                                "generation_policy_sha256": None,
                                "physical_attempts": None,
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
                                "measured_cost": (
                                    float(source["measured_cost"])
                                    if source["measured_cost"] is not None
                                    else None
                                ),
                                "cost_measurement_state": "measured",
                                "accounting_status": "measured",
                                "provider_event_ids": [],
                                "provider_lineage_state": "not_applicable",
                                "currency": source["currency"],
                                "input_tokens": None,
                                "output_tokens": None,
                                "reasoning_tokens": None,
                                "judge_calibration_id": None,
                                "judge_calibration_state": None,
                                "oracle_agreement": None,
                                "decision_authority": None,
                                "p50_duration_ms": None,
                                "p95_duration_ms": None,
                                "langfuse_status": "historical_not_instrumented",
                                "langfuse_verified_at": None,
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
                        "WITH role_metrics AS ("
                        "SELECT organization_id, campaign_run_id, agent_role, "
                        "percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) "
                        "AS p50_duration_ms, "
                        "percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) "
                        "AS p95_duration_ms "
                        "FROM agent_executions WHERE organization_id = :org "
                        "AND status <> 'running' AND duration_ms IS NOT NULL "
                        "GROUP BY organization_id, campaign_run_id, agent_role"
                        ") "
                        "SELECT e.execution_id, e.parent_execution_id, e.trace_id, "
                        "e.campaign_run_id, "
                        "e.attempt_id, e.agent_role, e.status, e.provider, e.model, "
                        "e.returned_model, e.upstream_provider, e.provider_request_id, "
                        "e.execution_mode, e.configuration_set_sha256, "
                        "e.role_configuration_sha256, e.generation_policy_sha256, "
                        "e.physical_attempts, e.input_sha256, e.output_sha256, e.input_tokens, "
                        "e.output_tokens, e.reasoning_tokens, e.judge_calibration_id, "
                        "e.judge_calibration_state, e.oracle_agreement, e.decision_authority, "
                        "e.error_code, e.started_at, e.finished_at, "
                        "e.duration_ms, e.measured_cost, e.currency, e.langfuse_status, "
                        "e.cost_measurement_state, e.provider_event_ids, e.detail, "
                        "e.langfuse_verified_at, "
                        "e.provider_event_status, "
                        "m.p50_duration_ms, m.p95_duration_ms "
                        "FROM agent_executions e LEFT JOIN role_metrics m "
                        "ON m.organization_id = e.organization_id "
                        "AND m.campaign_run_id = e.campaign_run_id "
                        "AND m.agent_role = e.agent_role "
                        "WHERE e.organization_id = :org "
                        "ORDER BY e.started_at DESC LIMIT 1000",
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
                                "provider": source["provider"],
                                "model": source["model"],
                                "agent_role": source["agent_role"],
                                "execution_mode": source["execution_mode"],
                                "requested_model": source["model"],
                                "returned_model": source["returned_model"],
                                "model_substituted": (
                                    source["provider_event_status"] == "model_mismatch"
                                ),
                                "upstream_provider": source["upstream_provider"],
                                "provider_request_id": source["provider_request_id"],
                                "configuration_set_sha256": source["configuration_set_sha256"],
                                "role_configuration_sha256": source["role_configuration_sha256"],
                                "generation_policy_sha256": source["generation_policy_sha256"],
                                "physical_attempts": source["physical_attempts"],
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
                                "measured_cost": (
                                    float(source["measured_cost"])
                                    if source["measured_cost"] is not None
                                    else None
                                ),
                                "cost_measurement_state": source["cost_measurement_state"],
                                "accounting_status": _accounting_status(
                                    source["cost_measurement_state"]
                                ),
                                "provider_event_ids": source["provider_event_ids"],
                                "provider_event_status": source["provider_event_status"],
                                "provider_lineage_state": _provider_lineage_state(
                                    source["execution_mode"],
                                    source["detail"],
                                ),
                                "currency": source["currency"],
                                "input_tokens": source["input_tokens"],
                                "output_tokens": source["output_tokens"],
                                "reasoning_tokens": source["reasoning_tokens"],
                                "judge_calibration_id": source["judge_calibration_id"],
                                "judge_calibration_state": source["judge_calibration_state"],
                                "oracle_agreement": source["oracle_agreement"],
                                "decision_authority": source["decision_authority"],
                                "p50_duration_ms": (
                                    float(source["p50_duration_ms"])
                                    if source["p50_duration_ms"] is not None
                                    else None
                                ),
                                "p95_duration_ms": (
                                    float(source["p95_duration_ms"])
                                    if source["p95_duration_ms"] is not None
                                    else None
                                ),
                                "langfuse_status": source["langfuse_status"],
                                "langfuse_verified_at": source["langfuse_verified_at"],
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
                        "WHERE " + approval_where + " ORDER BY q.created_at DESC LIMIT 200",
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
                                "f.severity AS finding_severity, "
                                "f.category AS finding_category, "
                                "f.target_version AS finding_target_version, "
                                "f.source_kind AS finding_source_kind, "
                                "f.execution_profile AS finding_execution_profile, "
                                "a.case_id, a.case_content_hash, "
                                "a.category AS case_category, a.severity AS case_severity, "
                                "a.attack_class, a.owasp_mappings, "
                                "(SELECT t.payload->'oracle_refs' FROM target_definitions t "
                                "WHERE t.organization_id = ar.organization_id "
                                "AND t.target_id = ar.target_id "
                                "AND t.version = ar.target_version LIMIT 1) "
                                "AS target_oracle_refs, "
                                "(SELECT t.payload->'canary_refs' FROM target_definitions t "
                                "WHERE t.organization_id = ar.organization_id "
                                "AND t.target_id = ar.target_id "
                                "AND t.version = ar.target_version LIMIT 1) "
                                "AS target_canary_refs, "
                                "v.id AS verdict_id, v.state AS verdict_state, "
                                "v.confidence AS verdict_confidence, "
                                "v.reason_codes AS verdict_reason_codes, "
                                "v.confirmation_source AS verdict_confirmation_source, "
                                "v.error_code AS verdict_error_code, "
                                "vr.report_id AS vuln_report_id, "
                                "vr.contract_payload AS report_payload, "
                                "rd.contract_payload AS regression_payload, "
                                "l.evidence_content_hash, l.provenance AS linked_provenance "
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
                                "AND v.organization_id = l.organization_id "
                                "AND v.campaign_run_id = l.campaign_run_id "
                                "AND v.attempt_id = l.attempt_id "
                                "LEFT JOIN vuln_reports vr "
                                "ON vr.organization_id = f.organization_id "
                                "AND vr.finding_id = f.finding_id "
                                "AND vr.campaign_run_id = l.campaign_run_id "
                                "AND vr.attempt_id = l.attempt_id "
                                "LEFT JOIN LATERAL (SELECT d.contract_payload "
                                "FROM regression_dispositions d "
                                "WHERE d.organization_id = f.organization_id "
                                "AND d.finding_id = f.finding_id "
                                "AND d.report_id = vr.report_id "
                                "AND d.campaign_run_id = l.campaign_run_id "
                                "AND d.attempt_id = l.attempt_id "
                                "ORDER BY d.created_at DESC LIMIT 1) rd ON true "
                                "WHERE f.organization_id = :org "
                                "AND l.campaign_run_id = :run_id "
                                "ORDER BY f.created_at DESC",
                                {"org": principal.organization_id, "run_id": run_id},
                            )
                        approval_finding_counts = Counter(
                            item["linked_finding_id"] for item in verification_rows
                        )
                        if any(count != 1 for count in approval_finding_counts.values()):
                            return ResourceResult.unavailable(
                                "approval_evidence_identifier_ambiguous"
                            )
                        try:
                            row["verification_chain"] = [
                                self._verification_projection(item) for item in verification_rows
                            ]
                        except EvidenceIntegrityError:
                            return ResourceResult.unavailable("approval_evidence_integrity_failed")
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
                                "hosted_run": self._latest_hosted_run_binding(
                                    connection,
                                    organization_id=principal.organization_id,
                                    target_payload=payload,
                                ),
                            }
                elif resource == "target_catalog":
                    rows = self._target_catalog_projection(
                        connection,
                        organization_id=principal.organization_id,
                    )
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
                    if not bool(data.get("runtime_available")):
                        return ResourceResult.degraded(
                            data,
                            str(
                                data.get("runtime_reason")
                                or "provider_credentials_runner_unverified"
                            ),
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
            if command == "create_target":
                entry = self._target_catalog.register(
                    self._store,
                    principal=principal,
                    target_id=str(payload["target_id"]),
                    version=str(payload["version"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(
                    entry.target.version,
                    resource_id=entry.target.target_id,
                )
            if command == "revise_target":
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
                submitted_hosted_run = payload.get("hosted_run")
                if submitted_hosted_run is not None:
                    with self._engine.connect() as connection:
                        target_payload = connection.execute(
                            text(
                                "SELECT payload FROM target_definitions "
                                "WHERE organization_id = :org AND target_id = :target "
                                "AND version = :version"
                            ),
                            {
                                "org": principal.organization_id,
                                "target": str(payload["target_id"]),
                                "version": str(payload["target_version"]),
                            },
                        ).scalar_one_or_none()
                        expected_hosted_run = (
                            self._latest_hosted_run_binding(
                                connection,
                                organization_id=principal.organization_id,
                                target_payload=dict(target_payload),
                            )
                            if target_payload is not None
                            else None
                        )
                    if (
                        expected_hosted_run is None
                        or dict(submitted_hosted_run) != expected_hosted_run
                    ):
                        raise ApiConflict(
                            "hosted campaign binding differs from the server-owned active set"
                        )
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
                hosted_configuration_sha256 = self._authorization_hosted_configuration(
                    principal.organization_id,
                    str(payload["authorization_request_id"]),
                )
                requires_hosted_runtime = hosted_configuration_sha256 is not None
                if not self._hosted_runtime_available and requires_hosted_runtime:
                    return CommandResult.unavailable("hosted_runtime_not_composed")
                provider_bindings_verified = self._hosted_provider_bindings_verified or (
                    hosted_configuration_sha256 is not None
                    and self._hosted_provider_bindings_are_fresh(hosted_configuration_sha256)
                )
                if not provider_bindings_verified and requires_hosted_runtime:
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
                    reason_code=payload.get("reason_code"),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(record.decision_id, resource_id=record.finding_id)
            if command == "request_live_probe_authorization":
                return CommandResult.unavailable("distinct_live_probe_workflow_missing")
            if command == "configure_agent":
                if payload.get("execution_mode") != "deterministic":
                    return CommandResult.unavailable("atomic_hosted_configuration_set_required")
                assignment = self._store.configure_agent(
                    principal=principal,
                    agent_role=identifiers.get("agent_role", ""),
                    provider=str(payload["provider"]),
                    model=str(payload["model"]),
                    execution_mode=str(payload["execution_mode"]),
                    rationale=str(payload["rationale"]),
                    idempotency_key=idempotency_key,
                )
                return CommandResult.completed(
                    assignment.configuration_sha256,
                    resource_id=assignment.role,
                )
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
        except (
            InvalidControlPlaneInput,
            TargetCatalogError,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:
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
        provider_bindings_runner_verified = bool(
            self._hosted_provider_bindings_verified
            or (
                hosted is not None
                and isinstance(hosted.get("configuration_set_sha256"), str)
                and self._hosted_provider_bindings_are_fresh(
                    str(hosted["configuration_set_sha256"])
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
            "provider_bindings_runner_verified": provider_bindings_runner_verified,
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
                provider_bindings_runner_verified,
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

    def _authorization_hosted_configuration(
        self,
        organization_id: str,
        request_id: str,
    ) -> str | None:
        with self._engine.connect() as connection:
            value = connection.execute(
                text(
                    "SELECT scope_payload->'hosted_run'->>'configuration_set_sha256' "
                    "FROM campaign_authorization_requests "
                    "WHERE organization_id = :org AND request_id = :request_id"
                ),
                {"org": organization_id, "request_id": request_id},
            ).scalar_one_or_none()
        return str(value) if isinstance(value, str) and value else None

    def _hosted_provider_bindings_are_fresh(
        self,
        configuration_sha256: str,
    ) -> bool:
        """Read Runner-only sealed-binding readiness for one exact configuration."""

        with self._engine.connect() as connection:
            return bool(
                connection.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM runtime_component_status "
                        "WHERE environment = :environment "
                        "AND component_id = :configuration "
                        "AND name = 'OpenRouter hosted runtime' "
                        "AND kind = 'model-runtime' "
                        "AND availability = 'operational and evidenced' "
                        "AND heartbeat_at > clock_timestamp() "
                        "- make_interval(secs => :freshness_seconds))"
                    ),
                    {
                        "environment": self._environment,
                        "configuration": configuration_sha256,
                        "freshness_seconds": _HOSTED_RUNTIME_HEARTBEAT_FRESHNESS_SECONDS,
                    },
                ).scalar_one()
            )

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
    return PostgresApiBackend(
        engine,
        environment=environment,
        runner_available=runner_available,
        hosted_runtime_available=hosted_runtime_available,
        hosted_provider_bindings_verified=hosted_provider_bindings_verified,
        corpus=corpus,
    )


__all__ = ["PostgresApiBackend", "build_postgres_backend"]
