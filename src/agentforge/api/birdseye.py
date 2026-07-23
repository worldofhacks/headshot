"""Authoritative PostgreSQL projection for the live Birdseye war room.

The projection deliberately contains no demo topology. Runtime nodes come from the component
heartbeat registry plus the Web/PostgreSQL dependencies proven by the request that produced the
snapshot. Campaign, queue, cost, verdict, attention, and timeline values are read from their
durable source tables in the same database transaction.
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from sqlalchemy import text

from agentforge.agents.runtime import AGENT_DEFINITIONS, default_assignment
from agentforge.campaign.corpus import MVP_CATEGORIES
from agentforge.policy.recorder import (
    PERSISTED_EVIDENCE_COLUMNS,
    EvidenceIntegrityError,
    ExecutionRecorder,
)

_OPERATIONAL = "operational and evidenced"
_DEFERRED = "adapter integrated, execution deferred"
_REJECTED = "evaluated and rejected"
_BLOCKED = "blocked pending authorization"


def _rows(connection: Any, statement: str, parameters: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(text(statement), parameters).mappings().all()]


def _one(
    connection: Any,
    statement: str,
    parameters: Mapping[str, Any],
) -> dict[str, Any] | None:
    row = connection.execute(text(statement), parameters).mappings().one_or_none()
    return None if row is None else dict(row)


def _seconds_between(now: datetime.datetime, value: datetime.datetime) -> float:
    return max(0.0, (now - value.astimezone(datetime.UTC)).total_seconds())


def _trust_zone(component_id: str, kind: str) -> str:
    normalized = f"{component_id}:{kind}".lower()
    if component_id == "web-api":
        return "human"
    if component_id == "postgres" or "database" in normalized:
        return "data"
    if "langfuse" in normalized or "telemetry" in normalized or "observ" in normalized:
        return "observability"
    if "red-team" in normalized or "red_team" in normalized or "generator" in normalized:
        return "untrusted"
    if "judge" in normalized:
        return "evaluation"
    if (
        "documentation" in normalized
        or "regression" in normalized
        or "approv" in normalized
        or "human" in normalized
    ):
        return "governance"
    if (
        "runner" in normalized
        or "recorder" in normalized
        or "target" in normalized
        or "adapter" in normalized
    ):
        return "execution"
    if "policy" in normalized or "orchestrator" in normalized or "scheduler" in normalized:
        return "control"
    return "unclassified"


def _runtime_state(availability: str, *, fresh: bool, active: bool) -> str:
    if not fresh:
        return "stale"
    if availability == _REJECTED:
        return "error"
    if availability == _BLOCKED:
        return "waiting"
    if availability == _DEFERRED:
        return "unavailable"
    if availability != _OPERATIONAL:
        return "degraded"
    return "working" if active else "ready"


def _integrity_verified(row: Mapping[str, Any]) -> bool:
    candidate: dict[str, Any] = {}
    for column in PERSISTED_EVIDENCE_COLUMNS:
        value = row.get(column)
        if isinstance(value, datetime.datetime):
            value = value.astimezone(datetime.UTC).isoformat()
        candidate[column] = value
    candidate["content_hash"] = row.get("content_hash")
    try:
        ExecutionRecorder().verify(candidate)
    except (EvidenceIntegrityError, TypeError, ValueError):
        return False
    return True


def build_birdseye_snapshot(
    connection: Any,
    *,
    organization_id: str,
    environment: str,
) -> dict[str, Any]:
    """Build one consistent, organization-scoped Birdseye snapshot."""

    now = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
    parameters = {"org": organization_id}
    campaign_row = _one(
        connection,
        "SELECT r.run_id, r.scope_hash, r.created_at, q.scope_payload, e.state, "
        "(SELECT count(*) FROM campaign_attempts a WHERE a.organization_id = r.organization_id "
        "AND a.run_id = r.run_id) AS attempt_count "
        "FROM campaign_runs r JOIN campaign_authorization_requests q "
        "ON q.organization_id = r.organization_id "
        "AND q.request_id = r.authorization_request_id "
        "JOIN LATERAL (SELECT state, created_at FROM campaign_run_events cre "
        "WHERE cre.organization_id = r.organization_id AND cre.run_id = r.run_id "
        "ORDER BY cre.id DESC LIMIT 1) e ON true "
        "WHERE r.organization_id = :org "
        "ORDER BY CASE e.state WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END, "
        "r.created_at DESC LIMIT 1",
        parameters,
    )
    run_id = str(campaign_row["run_id"]) if campaign_row else None
    run_parameters = {"org": organization_id, "run_id": run_id}
    scope = dict(campaign_row.get("scope_payload") or {}) if campaign_row else {}
    caps = dict(scope.get("caps") or {})

    queue = _one(
        connection,
        "SELECT count(*) FILTER (WHERE j.status = 'queued'::job_status) AS queued, "
        "count(*) FILTER (WHERE j.status = 'leased'::job_status) AS leased, "
        "count(*) FILTER (WHERE j.status = 'dead_letter'::job_status) AS dead_letter, "
        "max(j.updated_at) AS last_activity_at FROM jobs j "
        "JOIN campaign_runs r ON r.run_id = j.campaign_run_id "
        "WHERE r.organization_id = :org "
        "AND (CAST(:run_id AS varchar) IS NULL OR j.campaign_run_id = :run_id)",
        run_parameters,
    ) or {"queued": 0, "leased": 0, "dead_letter": 0, "last_activity_at": None}
    queue_queued = int(queue["queued"] or 0)
    queue_leased = int(queue["leased"] or 0)
    queue_dead_letter = int(queue["dead_letter"] or 0)

    verdicts = _one(
        connection,
        "SELECT count(*) FILTER (WHERE state = 'EXPLOIT_CONFIRMED'::verdict_state) "
        "AS confirmed, count(*) FILTER (WHERE state = 'EXPLOIT_LIKELY'::verdict_state) "
        "AS likely, count(*) FILTER (WHERE state IN "
        "('INDETERMINATE'::verdict_state, 'ERROR'::verdict_state)) AS review "
        "FROM verdict WHERE organization_id = :org "
        "AND (CAST(:run_id AS varchar) IS NULL OR campaign_run_id = :run_id)",
        run_parameters,
    ) or {"confirmed": 0, "likely": 0, "review": 0}

    request_metrics = (
        _one(
            connection,
            "SELECT count(*) FILTER (WHERE langfuse_status = 'queued') AS export_queued, "
            "count(*) FILTER (WHERE langfuse_status = 'error') AS export_error, "
            "count(*) FILTER (WHERE langfuse_status = 'exported') AS export_complete, "
            "coalesce(sum(measured_cost), 0) AS measured_cost, "
            "percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) "
            "FILTER (WHERE duration_ms IS NOT NULL) AS p50_ms, "
            "percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) "
            "FILTER (WHERE duration_ms IS NOT NULL) AS p95_ms, "
            "min(started_at) AS first_activity_at, "
            "max(finished_at) AS last_activity_at FROM outbound_http_requests "
            "WHERE organization_id = :org "
            "AND (CAST(:run_id AS varchar) IS NULL OR campaign_run_id = :run_id)",
            run_parameters,
        )
        or {}
    )
    summary = (
        _one(
            connection,
            "SELECT measured_cost, attempt_count, started_at, ended_at "
            "FROM campaign_run_summaries "
            "WHERE organization_id = :org AND run_id = :run_id",
            run_parameters,
        )
        if run_id
        else None
    )
    measured_cost = float(
        summary["measured_cost"]
        if summary is not None
        else request_metrics.get("measured_cost") or 0
    )
    budget = max(0.0, float(caps.get("budget_usd") or 0))
    budget_utilization = measured_cost / budget if budget > 0 else 0.0
    scope_target_id = scope.get("target_id")
    if not isinstance(scope_target_id, str) or not scope_target_id:
        scope_target_id = None
    scope_target_version = scope.get("target_version")
    if not isinstance(scope_target_version, str) or not scope_target_version:
        scope_target_version = None
    scope_target_name = scope_target_id
    if scope_target_id is not None and scope_target_version is not None:
        registered_name = connection.execute(
            text(
                "SELECT payload->>'name' FROM target_definitions "
                "WHERE organization_id = :org AND target_id = :target_id "
                "AND version = :target_version LIMIT 1"
            ),
            {
                "org": organization_id,
                "target_id": scope_target_id,
                "target_version": scope_target_version,
            },
        ).scalar_one_or_none()
        if isinstance(registered_name, str) and registered_name:
            scope_target_name = registered_name

    # Security outcomes are projected from the same evidence-backed rows used by the Coverage
    # screen. Recomputing every content hash here keeps the outcome-first view from treating an
    # evidenceless or tampered verdict as a pass/fail signal.
    outcome_source_rows = _rows(
        connection,
        "SELECT ar.*, a.case_id, a.category, a.attack_class, "
        "v.state AS verdict_state, v.created_at AS verdict_at "
        "FROM campaign_attempts a JOIN attempt_result ar "
        "ON ar.organization_id = a.organization_id "
        "AND ar.campaign_run_id = a.run_id AND ar.attempt_id = a.attempt_id "
        "JOIN LATERAL (SELECT state, created_at FROM verdict candidate "
        "WHERE candidate.organization_id = ar.organization_id "
        "AND candidate.campaign_run_id = ar.campaign_run_id "
        "AND candidate.attempt_id = ar.attempt_id "
        "ORDER BY candidate.id DESC LIMIT 1) v ON true "
        "WHERE ar.organization_id = :org "
        "AND (CAST(:target_id AS varchar) IS NULL OR ar.target_id = :target_id) "
        "ORDER BY v.created_at ASC",
        {"org": organization_id, "target_id": scope_target_id},
    )
    verified_outcomes: list[dict[str, Any]] = []
    seen_outcomes: set[tuple[str, str]] = set()
    for row in outcome_source_rows:
        identity = (str(row["campaign_run_id"]), str(row["attempt_id"]))
        if (
            identity in seen_outcomes
            or row.get("category") not in MVP_CATEGORIES
            or not _integrity_verified(row)
        ):
            continue
        seen_outcomes.add(identity)
        verified_outcomes.append(row)

    category_groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "case_ids": set(),
            "attempt_count": 0,
            "held": 0,
            "exploited": 0,
            "review": 0,
            "as_of": None,
        }
    )
    for row in verified_outcomes:
        version = str(row.get("target_version") or "unattributed")
        category = str(row["category"])
        group = category_groups[(version, category)]
        group["case_ids"].add(str(row["case_id"]))
        group["attempt_count"] += 1
        verdict_state = str(row["verdict_state"])
        if verdict_state == "NO_EXPLOIT_OBSERVED":
            group["held"] += 1
        elif verdict_state in {"EXPLOIT_CONFIRMED", "EXPLOIT_LIKELY"}:
            group["exploited"] += 1
        else:
            group["review"] += 1
        group["as_of"] = row["verdict_at"]

    version_activity: dict[str, datetime.datetime] = {}
    for (version, _category), group in category_groups.items():
        at = group["as_of"]
        if at is not None and (version not in version_activity or at > version_activity[version]):
            version_activity[version] = at
    focus_version = scope_target_version
    if focus_version is None and version_activity:
        focus_version = max(version_activity, key=version_activity.__getitem__)
    selected_versions = sorted(
        version_activity,
        key=lambda version: version_activity[version],
        reverse=True,
    )[:4]
    if focus_version is not None:
        selected_versions = [focus_version, *[v for v in selected_versions if v != focus_version]][
            :4
        ]

    category_outcomes: list[dict[str, Any]] = []
    for version in selected_versions:
        for category in sorted(MVP_CATEGORIES):
            group = category_groups.get((version, category))
            if group is None and version != focus_version:
                continue
            category_outcomes.append(
                {
                    "target_version": version,
                    "category": category,
                    "verified_case_count": len(group["case_ids"]) if group is not None else 0,
                    "verified_attempt_count": (
                        int(group["attempt_count"]) if group is not None else 0
                    ),
                    "held_count": int(group["held"]) if group is not None else 0,
                    "exploited_count": int(group["exploited"]) if group is not None else 0,
                    "review_count": int(group["review"]) if group is not None else 0,
                    "last_evaluated_at": group["as_of"] if group is not None else None,
                }
            )

    focus_groups = {
        category: category_groups.get((focus_version, category))
        for category in MVP_CATEGORIES
        if focus_version is not None
    }
    tested_categories = sum(
        1 for group in focus_groups.values() if group is not None and group["attempt_count"] > 0
    )
    verified_case_count = sum(
        len(group["case_ids"]) for group in focus_groups.values() if group is not None
    )
    held_count = sum(int(group["held"]) for group in focus_groups.values() if group is not None)
    exploited_count = sum(
        int(group["exploited"]) for group in focus_groups.values() if group is not None
    )
    outcome_review_count = sum(
        int(group["review"]) for group in focus_groups.values() if group is not None
    )
    decisive_outcomes = held_count + exploited_count
    observed_hold_rate = held_count / decisive_outcomes if decisive_outcomes else None

    finding_rows_for_posture = _rows(
        connection,
        "SELECT state::text AS state, severity::text AS severity FROM finding "
        "WHERE organization_id = :org "
        "AND (CAST(:target_version AS varchar) IS NULL OR target_version = :target_version) "
        "AND (CAST(:target_id AS varchar) IS NULL OR EXISTS ("
        "SELECT 1 FROM finding_evidence_links fel JOIN attempt_result ar "
        "ON ar.organization_id = fel.organization_id "
        "AND ar.campaign_run_id = fel.campaign_run_id AND ar.attempt_id = fel.attempt_id "
        "WHERE fel.organization_id = finding.organization_id "
        "AND fel.finding_id = finding.finding_id AND ar.target_id = :target_id))",
        {
            "org": organization_id,
            "target_id": scope_target_id,
            "target_version": scope_target_version,
        },
    )
    tool_finding_rows = _rows(
        connection,
        "SELECT validation_state AS state, contract_payload->>'severity' AS severity "
        "FROM security_tool_findings WHERE organization_id = :org "
        "AND (CAST(:target_id AS varchar) IS NULL "
        "OR contract_payload->>'target_id' = :target_id)",
        {"org": organization_id, "target_id": scope_target_id},
    )
    finding_rows_for_posture.extend(tool_finding_rows)
    resolved_finding_states = {"resolved", "rejected"}
    validation_finding_states = {"remediated", "validated"}
    open_finding_count = sum(
        1
        for row in finding_rows_for_posture
        if str(row["state"]) not in resolved_finding_states | validation_finding_states
    )
    in_progress_finding_count = sum(
        1 for row in finding_rows_for_posture if str(row["state"]) in validation_finding_states
    )
    resolved_finding_count = sum(
        1 for row in finding_rows_for_posture if str(row["state"]) in resolved_finding_states
    )
    critical_open_finding_count = sum(
        1
        for row in finding_rows_for_posture
        if str(row["severity"]) == "critical" and str(row["state"]) not in resolved_finding_states
    )

    regression_groups: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"held": 0, "exploited": 0, "review": 0, "as_of": None}
    )
    for row in verified_outcomes:
        if row.get("attack_class") != "regression":
            continue
        version = str(row.get("target_version") or "unattributed")
        group = regression_groups[version]
        verdict_state = str(row["verdict_state"])
        if verdict_state == "NO_EXPLOIT_OBSERVED":
            group["held"] += 1
        elif verdict_state in {"EXPLOIT_CONFIRMED", "EXPLOIT_LIKELY"}:
            group["exploited"] += 1
        else:
            group["review"] += 1
        group["as_of"] = row["verdict_at"]
    ordered_regression_versions = sorted(
        regression_groups,
        key=lambda version: regression_groups[version]["as_of"],
        reverse=True,
    )
    current_regression_version = (
        focus_version
        if focus_version in regression_groups
        else (ordered_regression_versions[0] if ordered_regression_versions else None)
    )
    previous_regression_version = next(
        (
            version
            for version in ordered_regression_versions
            if version != current_regression_version
        ),
        None,
    )

    def regression_rate(version: str | None) -> float | None:
        if version is None:
            return None
        row = regression_groups[version]
        decisive = int(row["held"]) + int(row["exploited"])
        return int(row["held"]) / decisive if decisive else None

    current_regression_hold_rate = regression_rate(current_regression_version)
    previous_regression_hold_rate = regression_rate(previous_regression_version)
    resilience_delta = (
        current_regression_hold_rate - previous_regression_hold_rate
        if current_regression_hold_rate is not None and previous_regression_hold_rate is not None
        else None
    )
    resilience_direction = "unavailable"
    if resilience_delta is not None:
        if resilience_delta > 0.0001:
            resilience_direction = "improving"
        elif resilience_delta < -0.0001:
            resilience_direction = "degrading"
        else:
            resilience_direction = "steady"

    attempt_count_for_cost = int(
        summary["attempt_count"]
        if summary is not None
        else (campaign_row["attempt_count"] if campaign_row else 0) or 0
    )
    cost_per_attempt = (
        measured_cost / attempt_count_for_cost if attempt_count_for_cost > 0 else None
    )
    if summary is not None:
        elapsed_seconds = max(
            0.0,
            (
                summary["ended_at"].astimezone(datetime.UTC)
                - summary["started_at"].astimezone(datetime.UTC)
            ).total_seconds(),
        )
    elif request_metrics.get("first_activity_at") is not None:
        elapsed_seconds = _seconds_between(now, request_metrics["first_activity_at"])
    else:
        elapsed_seconds = 0.0
    cost_velocity = measured_cost / (elapsed_seconds / 60) if elapsed_seconds > 0 else None
    attempt_cap = int(caps.get("max_attempts_per_run") or 0)
    projected_cost_at_attempt_cap = (
        cost_per_attempt * attempt_cap if cost_per_attempt is not None and attempt_cap > 0 else None
    )

    orchestration_priority = (
        _one(
            connection,
            "SELECT payload, created_at FROM audit_events WHERE organization_id = :org "
            "AND aggregate_type = 'campaign_run' AND aggregate_id = :run_id "
            "AND event_type = 'campaign.orchestrated' ORDER BY cursor DESC LIMIT 1",
            run_parameters,
        )
        if run_id
        else None
    )
    priority_category: str | None = None
    priority_reason = "No active target context is available for prioritization."
    priority_source = "unavailable"
    priority_at = None
    if orchestration_priority is not None:
        priority_payload = dict(orchestration_priority.get("payload") or {})
        directive = dict(priority_payload.get("directive") or {})
        if directive.get("category") in MVP_CATEGORIES:
            priority_category = str(directive["category"])
            priority_reason = str(
                directive.get("coverage_goal")
                or priority_payload.get("priority_reason")
                or "Persisted Orchestrator decision"
            )
            priority_source = "orchestrator_decision"
            priority_at = orchestration_priority["created_at"]
    elif focus_version is not None:
        priority_category = min(
            MVP_CATEGORIES,
            key=lambda category: (
                int(focus_groups[category]["attempt_count"])
                if focus_groups.get(category) is not None
                else 0,
                category,
            ),
        )
        priority_reason = (
            "No Orchestrator decision is recorded; the server policy identifies the "
            "least-tested required category."
        )
        priority_source = "coverage_policy"

    agent_activity_rows = (
        _rows(
            connection,
            "SELECT recent.execution_id, recent.parent_execution_id, recent.agent_role, "
            "recent.status, recent.attempt_id, recent.phase, recent.error_code, "
            "recent.started_at, recent.finished_at, recent.duration_ms, a.category, "
            "v.state::text AS verdict_state, "
            "(SELECT fel.finding_id FROM finding_evidence_links fel "
            "WHERE fel.organization_id = recent.organization_id "
            "AND fel.campaign_run_id = recent.campaign_run_id "
            "AND fel.attempt_id = recent.attempt_id ORDER BY fel.created_at DESC LIMIT 1) "
            "AS finding_id FROM "
            "(SELECT e.*, e.detail->>'phase' AS phase FROM agent_executions e "
            "WHERE e.organization_id = :org AND e.campaign_run_id = :run_id "
            "ORDER BY e.id DESC LIMIT 24) recent "
            "LEFT JOIN campaign_attempts a ON a.organization_id = recent.organization_id "
            "AND a.run_id = recent.campaign_run_id AND a.attempt_id = recent.attempt_id "
            "LEFT JOIN LATERAL (SELECT state FROM verdict candidate "
            "WHERE candidate.organization_id = recent.organization_id "
            "AND candidate.campaign_run_id = recent.campaign_run_id "
            "AND candidate.attempt_id = recent.attempt_id "
            "ORDER BY candidate.id DESC LIMIT 1) v ON true ORDER BY recent.id ASC",
            run_parameters,
        )
        if run_id
        else []
    )
    agent_activity = [
        {
            "execution_id": str(row["execution_id"]),
            "parent_execution_id": (
                str(row["parent_execution_id"]) if row["parent_execution_id"] is not None else None
            ),
            "agent_role": str(row["agent_role"]),
            "status": str(row["status"]),
            "phase": str(row["phase"] or "agent_execution"),
            "attempt_id": str(row["attempt_id"]) if row["attempt_id"] is not None else None,
            "category": str(row["category"]) if row["category"] is not None else None,
            "verdict_state": (
                str(row["verdict_state"]) if row["verdict_state"] is not None else None
            ),
            "finding_id": str(row["finding_id"]) if row["finding_id"] is not None else None,
            "error_code": str(row["error_code"]) if row["error_code"] is not None else None,
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "duration_ms": (float(row["duration_ms"]) if row["duration_ms"] is not None else None),
        }
        for row in agent_activity_rows
    ]

    latest_attempt = _one(
        connection,
        "SELECT a.attempt_id, a.created_at, ar.executed_at, v.created_at AS verdict_at "
        "FROM campaign_attempts a LEFT JOIN attempt_result ar "
        "ON ar.organization_id = a.organization_id AND ar.campaign_run_id = a.run_id "
        "AND ar.attempt_id = a.attempt_id LEFT JOIN verdict v "
        "ON v.organization_id = a.organization_id AND v.campaign_run_id = a.run_id "
        "AND v.attempt_id = a.attempt_id WHERE a.organization_id = :org "
        "AND (CAST(:run_id AS varchar) IS NULL OR a.run_id = :run_id) "
        "ORDER BY a.ordinal DESC LIMIT 1",
        run_parameters,
    )
    pending_attempts = int(
        connection.execute(
            text(
                "SELECT count(*) FROM campaign_attempts a LEFT JOIN attempt_result ar "
                "ON ar.organization_id = a.organization_id AND ar.campaign_run_id = a.run_id "
                "AND ar.attempt_id = a.attempt_id WHERE a.organization_id = :org "
                "AND (CAST(:run_id AS varchar) IS NULL OR a.run_id = :run_id) "
                "AND ar.attempt_id IS NULL"
            ),
            run_parameters,
        ).scalar_one()
    )

    component_rows = [
        {
            "component_id": "web-api",
            "name": "Operator console API",
            "kind": "web",
            "availability": _OPERATIONAL,
            "detail": "Authenticated Birdseye projection responded",
            "heartbeat_at": now,
            "target_access": "none",
        },
        {
            "component_id": "postgres",
            "name": "PostgreSQL system of record",
            "kind": "database",
            "availability": _OPERATIONAL,
            "detail": "Organization-scoped snapshot transaction succeeded",
            "heartbeat_at": now,
            "target_access": "none",
        },
    ]
    persisted_components = _rows(
        connection,
        "SELECT component_id, name, kind, availability, detail, heartbeat_at "
        "FROM runtime_component_status WHERE environment = :environment "
        "ORDER BY component_id",
        {"environment": environment},
    )
    seen = {"web-api", "postgres"}
    for component in persisted_components:
        if component["component_id"] not in seen:
            component["target_access"] = (
                "policy-gated" if component["component_id"] == "runner" else "none"
            )
            component_rows.append(component)
            seen.add(component["component_id"])

    active_configurations = _rows(
        connection,
        "SELECT DISTINCT ON (agent_role) agent_role, provider, model, execution_mode, "
        "activation_state, version, created_at FROM agent_configuration_versions "
        "WHERE organization_id = :org AND activation_state = 'active' "
        "ORDER BY agent_role, version DESC",
        parameters,
    )
    configuration_by_role = {
        str(configuration["agent_role"]): configuration for configuration in active_configurations
    }
    latest_agent_executions = _rows(
        connection,
        "SELECT DISTINCT ON (agent_role) agent_role, status, provider, model, execution_mode, "
        "attempt_id, started_at, finished_at, duration_ms, error_code "
        "FROM agent_executions WHERE organization_id = :org "
        "AND (CAST(:run_id AS varchar) IS NULL OR campaign_run_id = :run_id) "
        "ORDER BY agent_role, id DESC",
        run_parameters,
    )
    execution_by_role = {
        str(execution["agent_role"]): execution for execution in latest_agent_executions
    }
    for definition in AGENT_DEFINITIONS:
        configuration = configuration_by_role.get(definition.role)
        if configuration is None:
            assignment = default_assignment(definition.role).public_record()
        else:
            assignment = configuration
        execution = execution_by_role.get(definition.role)
        component_rows.append(
            {
                "component_id": f"agent:{definition.role}",
                "name": definition.display_name,
                "kind": f"agent:{definition.role}",
                "availability": _OPERATIONAL,
                "detail": (
                    f"{assignment['provider']}/{assignment['model']} · "
                    f"{assignment['execution_mode']}"
                ),
                "heartbeat_at": (
                    execution.get("finished_at") or execution.get("started_at")
                    if execution is not None
                    else None
                ),
                "target_access": definition.target_access,
                "agent_role": definition.role,
                "agent_status": execution.get("status") if execution is not None else None,
                "agent_attempt_id": (
                    execution.get("attempt_id") if execution is not None else None
                ),
                "agent_error_code": (
                    execution.get("error_code") if execution is not None else None
                ),
            }
        )

    campaign_active = bool(campaign_row and campaign_row["state"] in {"queued", "running"})
    nodes: list[dict[str, Any]] = []
    for component in component_rows:
        component_id = str(component["component_id"])
        heartbeat_at = component["heartbeat_at"]
        freshness_limit = 600.0 if component_id == "langfuse" else 90.0
        freshness_seconds = (
            _seconds_between(now, heartbeat_at) if heartbeat_at is not None else None
        )
        fresh = freshness_seconds is not None and freshness_seconds <= freshness_limit
        availability = str(component["availability"])
        active = component_id == "runner" and campaign_active and (queue_queued + queue_leased) > 0
        agent_status = component.get("agent_status")
        if component.get("agent_role"):
            role_label = str(component["agent_role"]).replace("_", " ")
            if agent_status == "running":
                task = (
                    f"Running {role_label} for attempt {component['agent_attempt_id']}"
                    if component.get("agent_attempt_id")
                    else f"Running {role_label} campaign work"
                )
            elif agent_status is None:
                task = "Configured and ready; no execution is recorded for this campaign"
            else:
                task = (
                    f"Latest execution {agent_status}"
                    if not component.get("agent_error_code")
                    else f"Latest execution failed: {component['agent_error_code']}"
                )
            state = {
                "running": "working",
                "failed": "error",
                "succeeded": "ready",
                "skipped": "waiting",
                None: "ready",
            }.get(agent_status, "degraded")
        elif component_id == "web-api":
            task = "Serving the protected console snapshot"
        elif component_id == "postgres":
            task = "Maintaining the authoritative campaign and evidence record"
        elif component_id == "runner":
            task = (
                f"Processing {queue_leased} leased job(s)"
                if queue_leased
                else (f"Awaiting {queue_queued} queued job(s)" if queue_queued else "Queue clear")
            )
        elif component_id == "langfuse":
            export_queued = int(request_metrics.get("export_queued") or 0)
            task = (
                f"Exporting {export_queued} queued observation(s)"
                if export_queued
                else "Telemetry export queue clear"
            )
        else:
            task = str(component["detail"])
        if not component.get("agent_role"):
            state = _runtime_state(availability, fresh=fresh, active=active)
        nodes.append(
            {
                "component_id": component_id,
                "name": str(component["name"]),
                "kind": str(component["kind"]),
                "trust_zone": _trust_zone(component_id, str(component["kind"])),
                "availability": availability,
                "runtime_state": state,
                "detail": str(component["detail"]),
                "current_task": task,
                "heartbeat_at": heartbeat_at,
                "freshness_seconds": freshness_seconds,
                "is_fresh": fresh,
                "healthy_instances": (
                    1
                    if availability == _OPERATIONAL
                    and (component.get("agent_role") and state != "error" or fresh)
                    else 0
                ),
                "total_instances": 1,
                "p50_latency_ms": (
                    float(request_metrics["p50_ms"])
                    if component_id == "runner" and request_metrics.get("p50_ms") is not None
                    else None
                ),
                "p95_latency_ms": (
                    float(request_metrics["p95_ms"])
                    if component_id == "runner" and request_metrics.get("p95_ms") is not None
                    else None
                ),
                "queue_depth": (queue_queued + queue_leased if component_id == "runner" else None),
                "target_access": str(component["target_access"]),
            }
        )

    by_id = {node["component_id"]: node for node in nodes}
    edges: list[dict[str, Any]] = []

    def add_edge(
        edge_id: str,
        source: str,
        target: str,
        contract: str,
        state: str,
        detail: str,
        *,
        at: datetime.datetime | None = None,
    ) -> None:
        if source not in by_id or target not in by_id:
            return
        if by_id[source]["runtime_state"] == "stale" or by_id[target]["runtime_state"] == "stale":
            state = "stale"
        elif by_id[source]["runtime_state"] == "error" or by_id[target]["runtime_state"] == "error":
            state = "error"
        edges.append(
            {
                "edge_id": edge_id,
                "source_component_id": source,
                "target_component_id": target,
                "contract_name": contract,
                "state": state,
                "attempt_id": latest_attempt["attempt_id"] if latest_attempt else None,
                "last_event_at": at,
                "detail": detail,
            }
        )

    add_edge(
        "postgres-to-runner",
        "postgres",
        "runner",
        "CampaignDirective",
        "active" if queue_queued + queue_leased else "idle",
        "Durable exact-scope work delivery",
        at=queue.get("last_activity_at"),
    )
    add_edge(
        "runner-to-postgres",
        "runner",
        "postgres",
        "AttemptResult · Verdict",
        "active" if pending_attempts else ("complete" if latest_attempt else "idle"),
        "Append-only evidence and independent adjudication",
        at=(
            latest_attempt.get("verdict_at")
            or latest_attempt.get("executed_at")
            or latest_attempt.get("created_at")
            if latest_attempt
            else None
        ),
    )
    add_edge(
        "runner-to-langfuse",
        "runner",
        "langfuse",
        "TraceObservation",
        (
            "error"
            if int(request_metrics.get("export_error") or 0)
            else (
                "active"
                if int(request_metrics.get("export_queued") or 0)
                else ("complete" if int(request_metrics.get("export_complete") or 0) else "idle")
            )
        ),
        "Fail-soft export; PostgreSQL remains authoritative",
        at=request_metrics.get("last_activity_at"),
    )
    add_edge(
        "postgres-to-web",
        "postgres",
        "web-api",
        "ResourceEnvelope",
        "active",
        "Authenticated organization-scoped read projection",
        at=now,
    )

    def agent_contract_state(*component_ids: str) -> str:
        states = {
            by_id[component_id]["runtime_state"]
            for component_id in component_ids
            if component_id in by_id
        }
        if "error" in states:
            return "error"
        if "working" in states:
            return "active"
        return "complete" if latest_attempt else "idle"

    def latest_node_activity(*component_ids: str) -> datetime.datetime | None:
        values = [
            by_id[component_id]["heartbeat_at"]
            for component_id in component_ids
            if component_id in by_id and by_id[component_id]["heartbeat_at"] is not None
        ]
        return max(values) if values else None

    for edge_id, source, target, contract, detail in (
        (
            "postgres-to-orchestrator",
            "postgres",
            "agent:orchestrator",
            "OrchestrationSnapshot",
            "Verified coverage, finding, regression, queue, and budget signals",
        ),
        (
            "orchestrator-to-red-team",
            "agent:orchestrator",
            "agent:red_team",
            "CampaignDirective",
            "Authorized category and coverage goal; no target credentials",
        ),
        (
            "red-team-to-runner",
            "agent:red_team",
            "runner",
            "AttackAttempt",
            "Exact authorized corpus proposal crosses the Policy Gateway",
        ),
        (
            "runner-to-judge",
            "runner",
            "agent:judge",
            "EvidenceEnvelope",
            "Hash-verified evidence enters independent adjudication",
        ),
        (
            "judge-to-documentation",
            "agent:judge",
            "agent:documentation",
            "Verdict",
            "Only trusted confirmed verdicts may enter draft documentation",
        ),
        (
            "documentation-to-postgres",
            "agent:documentation",
            "postgres",
            "VulnReport draft",
            "Draft-only report remains blocked behind human publication approval",
        ),
    ):
        add_edge(
            edge_id,
            source,
            target,
            contract,
            agent_contract_state(source, target),
            detail,
            at=latest_node_activity(source, target),
        )

    attention: list[dict[str, Any]] = []
    evidence_rows = _rows(
        connection,
        "SELECT ar.* FROM attempt_result ar WHERE ar.organization_id = :org "
        "AND (CAST(:run_id AS varchar) IS NULL OR ar.campaign_run_id = :run_id) "
        "ORDER BY ar.executed_at DESC NULLS LAST LIMIT 100",
        run_parameters,
    )
    for row in evidence_rows:
        if _integrity_verified(row):
            continue
        attempt_id = str(row["attempt_id"])
        attention.append(
            {
                "attention_id": f"integrity:{attempt_id}",
                "priority": 0,
                "kind": "integrity",
                "title": "Evidence integrity verification failed",
                "detail": f"Attempt {attempt_id} is blocked from authoritative verdict use.",
                "continuation": "Evidence remains parked for review.",
                "record_type": "attempt",
                "record_id": attempt_id,
                "route": f"/live/{quote(attempt_id, safe='')}",
                "created_at": row.get("executed_at") or row.get("created_at") or now,
            }
        )

    approval_rows = _rows(
        connection,
        "SELECT q.request_id, q.created_at, q.expires_at FROM campaign_authorization_requests q "
        "LEFT JOIN campaign_authorization_decisions d "
        "ON d.organization_id = q.organization_id AND d.request_id = q.request_id "
        "WHERE q.organization_id = :org AND d.request_id IS NULL "
        "ORDER BY q.created_at ASC LIMIT 50",
        parameters,
    )
    for row in approval_rows:
        request_id = str(row["request_id"])
        attention.append(
            {
                "attention_id": f"approval:{request_id}",
                "priority": 1,
                "kind": "approval",
                "title": "Campaign authorization requires a decision",
                "detail": f"Exact-scope request {request_id} is pending a distinct approver.",
                "continuation": (
                    "Request expired; a new authorization is required."
                    if row["expires_at"] <= now
                    else "No live campaign may start before approval."
                ),
                "record_type": "approval",
                "record_id": request_id,
                "route": f"/approvals/{quote(request_id, safe='')}",
                "created_at": row["created_at"],
            }
        )

    finding_rows = _rows(
        connection,
        "SELECT finding_id, state, severity, created_at FROM finding "
        "WHERE organization_id = :org AND state NOT IN "
        "('resolved'::finding_state, 'validated'::finding_state) "
        "ORDER BY CASE severity WHEN 'critical'::finding_severity THEN 0 "
        "WHEN 'high'::finding_severity THEN 1 WHEN 'medium'::finding_severity THEN 2 ELSE 3 END, "
        "created_at ASC LIMIT 50",
        parameters,
    )
    for row in finding_rows:
        finding_id = str(row["finding_id"])
        attention.append(
            {
                "attention_id": f"finding:{finding_id}",
                "priority": 2,
                "kind": "finding",
                "title": f"{str(row['severity']).title()} finding requires review",
                "detail": f"Finding {finding_id} is {row['state']}.",
                "continuation": "Publication and remediation remain human-gated.",
                "record_type": "finding",
                "record_id": finding_id,
                "route": f"/findings/{quote(finding_id, safe='')}",
                "created_at": row["created_at"],
            }
        )

    for node in nodes:
        if node["runtime_state"] not in {"stale", "degraded", "error"}:
            continue
        attention.append(
            {
                "attention_id": f"component:{node['component_id']}",
                "priority": 3,
                "kind": "component",
                "title": f"{node['name']} is {node['runtime_state']}",
                "detail": node["detail"],
                "continuation": "Runtime claims remain unavailable until fresh evidence returns.",
                "record_type": "component",
                "record_id": node["component_id"],
                "route": "/live",
                "created_at": node["heartbeat_at"] or now,
            }
        )
    attention.sort(key=lambda item: (item["priority"], item["created_at"], item["attention_id"]))

    timeline_rows = _rows(
        connection,
        "SELECT cursor, event_type, aggregate_type, aggregate_id, actor_user_id, created_at "
        "FROM audit_events WHERE organization_id = :org ORDER BY cursor DESC LIMIT 50",
        parameters,
    )
    timeline = [
        {
            "cursor": int(row["cursor"]),
            "event_type": str(row["event_type"]),
            "actor": str(row["actor_user_id"] or "system"),
            "summary": str(row["event_type"]).replace(".", " · "),
            "aggregate_type": str(row["aggregate_type"]),
            "aggregate_id": str(row["aggregate_id"]),
            "created_at": row["created_at"],
        }
        for row in timeline_rows
    ]
    cursor = max((row["cursor"] for row in timeline), default=0)

    healthy_components = sum(node["healthy_instances"] for node in nodes)
    total_components = sum(node["total_instances"] for node in nodes)
    system_state = (
        "unavailable"
        if total_components == 0
        else ("nominal" if healthy_components == total_components else "degraded")
    )
    campaign = None
    if campaign_row:
        execution_profile = str(scope.get("execution_profile") or "")
        target_id = scope.get("target_id")
        target_version = scope.get("target_version")
        if (
            execution_profile in {"synthetic", "live"}
            and isinstance(target_id, str)
            and target_id
            and isinstance(target_version, str)
            and target_version
        ):
            campaign = {
                "run_id": str(campaign_row["run_id"]),
                "target_id": target_id,
                "target_name": scope_target_name or target_id,
                "target_version": target_version,
                "state": str(campaign_row["state"]),
                "execution_profile": execution_profile,
                "scope_hash": str(campaign_row["scope_hash"]),
                "attempt_count": int(campaign_row["attempt_count"] or 0),
            }

    return {
        "campaign": campaign,
        "instrumentation": {
            "budget_usd": budget,
            "measured_cost_usd": measured_cost,
            "budget_utilization": budget_utilization,
            "requests_per_second_cap": max(0.0, float(caps.get("target_requests_per_second") or 0)),
            "queue_queued": queue_queued,
            "queue_leased": queue_leased,
            "queue_dead_letter": queue_dead_letter,
            "confirmed_count": int(verdicts["confirmed"] or 0),
            "likely_count": int(verdicts["likely"] or 0),
            "review_count": int(verdicts["review"] or 0),
            "healthy_components": healthy_components,
            "total_components": total_components,
            "system_state": system_state,
        },
        "security_posture": {
            "tested_categories": tested_categories,
            "required_categories": len(MVP_CATEGORIES),
            "verified_case_count": verified_case_count,
            "held_count": held_count,
            "exploited_count": exploited_count,
            "review_count": outcome_review_count,
            "observed_hold_rate": observed_hold_rate,
            "open_finding_count": open_finding_count,
            "in_progress_finding_count": in_progress_finding_count,
            "resolved_finding_count": resolved_finding_count,
            "critical_open_finding_count": critical_open_finding_count,
            "resilience_direction": resilience_direction,
            "current_regression_hold_rate": current_regression_hold_rate,
            "previous_regression_hold_rate": previous_regression_hold_rate,
            "resilience_delta": resilience_delta,
            "cost_per_attempt_usd": cost_per_attempt,
            "cost_velocity_usd_per_minute": cost_velocity,
            "projected_cost_at_attempt_cap_usd": projected_cost_at_attempt_cap,
            "priority_category": priority_category,
            "priority_reason": priority_reason,
            "priority_source": priority_source,
            "priority_at": priority_at,
        },
        "category_outcomes": category_outcomes,
        "agent_activity": agent_activity,
        "nodes": nodes,
        "edges": edges,
        "attention": attention[:100],
        "timeline": timeline,
        "cursor": cursor,
        "as_of": now,
    }


__all__ = ["build_birdseye_snapshot"]
