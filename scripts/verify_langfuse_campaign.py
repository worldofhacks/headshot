#!/usr/bin/env python3
"""Verify one completed live campaign against PostgreSQL and Langfuse.

This is an acceptance probe for a deployed Runner. It never launches work, sends target traffic,
or uses a fixture. It polls Langfuse through the authenticated Public API until every durable
agent execution is query-visible with its typed agent/logical-runtime pair and native parentage,
every durable provider invocation is query-visible as one cost-bearing physical generation, and
every physical target request is query-visible with
content-addressed request/response lineage under its same-attempt Red Team agent. It also proves
the durable per-attempt Orchestrator -> Red Team -> Judge chain and one Judge -> Documentation
chain per finding evidence link. It is read-only unless the operator explicitly supplies
``--record-verification`` after a successful query-back. Acceptance is bound to the required
deployment environment and rejects any Runner configuration or observation environment mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import create_engine, text

from agentforge.agents.runtime import AGENT_ROLES
from agentforge.correlation import campaign_trace_id
from agentforge.telemetry.outbound import _LangfuseBridge

_BASE_REQUIRED_ROLES = frozenset({"orchestrator", "red_team", "judge"})
_DEPLOYED_ENVIRONMENTS = ("staging", "production")
_OBSERVATION_FIELDS = "core,basic,io,usage,metadata,model"
_MAX_OBSERVATION_PAGES = 100
_PROVIDER_OBSERVATION_NAME = "provider.openrouter.attempt"


def _database_url() -> str:
    value = os.environ.get("DATABASE_URL", "").strip()
    if not value:
        raise SystemExit("DATABASE_URL is required")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    return value


def _field(value: Any, *names: str) -> Any:
    for name in names:
        if isinstance(value, dict) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _decimal(value: Any, *, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise AssertionError(f"{label} is unavailable") from exc
    if not result.is_finite() or result < 0:
        raise AssertionError(f"{label} is invalid")
    return result


def _usage_value(observation: Any, key: str) -> int | None:
    usage = _field(observation, "usage_details", "usageDetails")
    if usage is None:
        return None
    if not isinstance(usage, dict):
        raise AssertionError("Langfuse usage details are invalid")
    if key not in usage:
        return None
    value = usage[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AssertionError(f"Langfuse {key} usage is invalid")
    return value


def _cost_value(observation: Any) -> Decimal | None:
    details = _field(observation, "cost_details", "costDetails")
    if details is None:
        return None
    if not isinstance(details, dict) or "total" not in details:
        raise AssertionError("Langfuse cost details are invalid")
    return _decimal(details["total"], label="Langfuse total cost")


def _metadata(observation: Any) -> dict[str, Any]:
    value = _field(observation, "metadata")
    return dict(value) if isinstance(value, dict) else {}


def _structured_io(observation: Any, field: str) -> Any:
    """Normalize v2 API IO, which may be returned as JSON text rather than decoded JSON."""

    value = _field(observation, field)
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _assert_environment_binding(expected_environment: str) -> None:
    """Bind acceptance to the exact deployed and Langfuse tracing environment."""

    for variable in ("AGENTFORGE_ENVIRONMENT", "LANGFUSE_TRACING_ENVIRONMENT"):
        configured_environment = os.environ.get(variable)
        if configured_environment != expected_environment:
            raise SystemExit(
                f"{variable} must exactly match --expected-environment {expected_environment!r}"
            )


def _assert_observation_environment(
    observation: Any,
    *,
    expected_environment: str,
    observation_label: str,
) -> None:
    metadata_environment = _metadata(observation).get("deployment.environment")
    if metadata_environment != expected_environment:
        raise AssertionError(
            f"{observation_label}: deployment environment does not reconcile (metadata): "
            f"expected {expected_environment!r}, observed {metadata_environment!r}"
        )
    native_environment = _field(observation, "environment")
    if native_environment != expected_environment:
        raise AssertionError(
            f"{observation_label}: native Langfuse environment does not reconcile: "
            f"expected {expected_environment!r}, observed {native_environment!r}"
        )


def _payload_digest(value: Any) -> tuple[str, int]:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _remote_observations(client: Any, trace_id: str) -> list[Any]:
    observations: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _page in range(_MAX_OBSERVATION_PAGES):
        parameters: dict[str, Any] = {
            "trace_id": trace_id,
            "limit": 1000,
            "fields": _OBSERVATION_FIELDS,
        }
        if cursor is not None:
            parameters["cursor"] = cursor
        response = client.api.observations.get_many(**parameters)
        data = _field(response, "data")
        if not isinstance(data, (list, tuple)):
            raise AssertionError("Langfuse observation page has no data array")
        observations.extend(data)

        meta = _field(response, "meta")
        next_cursor = _field(meta, "cursor")
        if next_cursor is None:
            return observations
        if not isinstance(next_cursor, str) or not next_cursor:
            raise AssertionError("Langfuse observation cursor is invalid")
        if next_cursor in seen_cursors:
            raise AssertionError("Langfuse observation pagination repeated a cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise AssertionError("Langfuse observation pagination exceeded the safety limit")


def _assert_durable_campaign(
    rows: list[dict[str, Any]],
    *,
    finding_evidence_exists: bool,
    trace_id: str,
) -> set[str]:
    if not rows:
        raise AssertionError("completed live campaign has no durable agent executions")

    execution_ids = [row["execution_id"] for row in rows]
    if len(execution_ids) != len(set(execution_ids)):
        raise AssertionError("durable agent execution IDs are duplicated")

    running = sorted(row["execution_id"] for row in rows if row["status"] == "running")
    if running:
        raise AssertionError(
            f"completed live campaign still has {len(running)} running agent execution(s)"
        )

    invalid_delivery = sorted(
        row["execution_id"] for row in rows if row["langfuse_status"] not in {"queued", "exported"}
    )
    if invalid_delivery:
        raise AssertionError(
            f"{len(invalid_delivery)} durable agent execution(s) are not awaiting or proven "
            "Langfuse delivery"
        )
    invalid_verification = sorted(
        row["execution_id"]
        for row in rows
        if (row["langfuse_status"] == "exported") != (row["langfuse_verified_at"] is not None)
    )
    if invalid_verification:
        raise AssertionError(
            f"{len(invalid_verification)} durable agent execution(s) have contradictory "
            "Langfuse delivery proof"
        )

    roles = {row["agent_role"] for row in rows}
    if not roles.issubset(set(AGENT_ROLES)):
        raise AssertionError(f"durable agent role is unknown: {sorted(roles)}")
    expected_roles = set(_BASE_REQUIRED_ROLES)
    if finding_evidence_exists:
        expected_roles.add("documentation")
    if roles != expected_roles:
        raise AssertionError(
            "durable agent role coverage is inconsistent with finding evidence: "
            f"expected {sorted(expected_roles)}, observed {sorted(roles)}"
        )

    if any(row["trace_id"] != trace_id for row in rows):
        raise AssertionError("durable agent trace correlation is inconsistent")

    rows_by_execution = {row["execution_id"]: row for row in rows}
    for row in rows:
        execution_id = row["execution_id"]
        parent_execution_id = row["parent_execution_id"]
        if parent_execution_id is not None and parent_execution_id not in rows_by_execution:
            raise AssertionError(f"{execution_id}: durable parent is outside the campaign")

    for row in rows:
        execution_id = row["execution_id"]
        ancestors: set[str] = set()
        cursor: str | None = execution_id
        while cursor is not None:
            if cursor in ancestors:
                raise AssertionError(f"{execution_id}: durable parent hierarchy contains a cycle")
            ancestors.add(cursor)
            parent = rows_by_execution[cursor]["parent_execution_id"]
            cursor = str(parent) if parent is not None else None
    return roles


def _assert_durable_requests(rows: list[dict[str, Any]], *, trace_id: str) -> None:
    if not rows:
        raise AssertionError("completed live campaign has no durable physical target requests")
    request_ids = [row["request_id"] for row in rows]
    if len(request_ids) != len(set(request_ids)):
        raise AssertionError("durable target request IDs are duplicated")
    for row in rows:
        request_id = row["request_id"]
        if row["status"] == "running" or row["finished_at"] is None or row["duration_ms"] is None:
            raise AssertionError(f"{request_id}: durable target request is not terminal")
        if row["langfuse_status"] not in {"queued", "exported"}:
            raise AssertionError(
                f"{request_id}: durable target request is not awaiting or proven Langfuse delivery"
            )
        if (row["langfuse_status"] == "exported") != (row["langfuse_verified_at"] is not None):
            raise AssertionError(
                f"{request_id}: durable target request has contradictory Langfuse delivery proof"
            )
        if row["trace_id"] != trace_id:
            raise AssertionError(f"{request_id}: durable target trace correlation is inconsistent")
        request_sha256, request_bytes = _payload_digest(row["request_payload"])
        if request_bytes != row["request_bytes"]:
            raise AssertionError(f"{request_id}: durable target request byte count is inconsistent")
        row["request_sha256"] = request_sha256
        if row["response_payload"] is None:
            row["response_sha256"] = None
        else:
            response = str(row["response_payload"]).encode("utf-8")
            if len(response) != row["response_bytes"]:
                raise AssertionError(
                    f"{request_id}: durable target response byte count is inconsistent"
                )
            row["response_sha256"] = hashlib.sha256(response).hexdigest()


def _assert_durable_provider_attempts(
    rows: list[dict[str, Any]],
    *,
    agent_rows: list[dict[str, Any]],
) -> None:
    """Reconcile append-only physical attempts with every logical hosted execution."""

    agents_by_execution = {row["execution_id"]: row for row in agent_rows}
    hosted_ids = {
        row["execution_id"] for row in agent_rows if row["execution_mode"] == "hosted_advisory"
    }
    rows_by_execution: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    invocation_ids: set[str] = set()
    event_ids: set[str] = set()
    for row in rows:
        invocation_id = row["invocation_id"]
        event_id = row["event_id"]
        execution_id = row["logical_execution_id"]
        if invocation_id in invocation_ids:
            raise AssertionError(f"{invocation_id}: durable provider invocation is duplicated")
        invocation_ids.add(invocation_id)
        if not isinstance(event_id, str) or not event_id:
            raise AssertionError(f"{invocation_id}: durable provider invocation is not terminal")
        if event_id in event_ids:
            raise AssertionError(f"{event_id}: durable provider event is duplicated")
        event_ids.add(event_id)
        agent = agents_by_execution.get(execution_id)
        if agent is None or execution_id not in hosted_ids:
            raise AssertionError(
                f"{invocation_id}: durable provider invocation has no hosted logical execution"
            )
        expected_identity = {
            "organization_id": agent["organization_id"],
            "campaign_run_id": agent["campaign_run_id"],
            "campaign_attempt_id": agent["attempt_id"],
            "parent_execution_id": agent["parent_execution_id"],
            "agent_role": agent["agent_role"],
            "requested_model": agent["model"],
        }
        for key, value in expected_identity.items():
            if row[key] != value:
                raise AssertionError(
                    f"{invocation_id}: durable provider {key} differs from logical execution"
                )
        if row["event_invocation_id"] != invocation_id:
            raise AssertionError(
                f"{invocation_id}: durable provider event identity is inconsistent"
            )
        if row["event_physical_sequence"] != row["physical_sequence"]:
            raise AssertionError(f"{invocation_id}: durable provider sequence is inconsistent")
        rows_by_execution[execution_id].append(row)

    for agent in agent_rows:
        execution_id = agent["execution_id"]
        physical_rows = rows_by_execution.get(execution_id, [])
        if agent["execution_mode"] != "hosted_advisory":
            if physical_rows:
                raise AssertionError(
                    f"{execution_id}: deterministic execution has physical provider attempts"
                )
            continue
        expected_count = agent["physical_attempts"]
        if (
            isinstance(expected_count, bool)
            or not isinstance(expected_count, int)
            or expected_count < 1
            or len(physical_rows) != expected_count
        ):
            raise AssertionError(
                f"{execution_id}: physical provider attempt count does not reconcile"
            )
        physical_rows.sort(key=lambda item: item["physical_sequence"])
        if [item["physical_sequence"] for item in physical_rows] != list(
            range(1, expected_count + 1)
        ):
            raise AssertionError(f"{execution_id}: physical provider sequence is not contiguous")
        if [item["event_id"] for item in physical_rows] != agent["provider_event_ids"]:
            raise AssertionError(f"{execution_id}: provider event order does not reconcile")

        observed_rows = [
            item
            for item in physical_rows
            if all(
                item[field] is not None
                for field in ("input_tokens", "output_tokens", "reasoning_tokens")
            )
        ]
        aggregate_tokens = {
            field: (sum(int(item[field]) for item in observed_rows) if observed_rows else None)
            for field in ("input_tokens", "output_tokens", "reasoning_tokens")
        }
        if any(agent[field] != value for field, value in aggregate_tokens.items()):
            raise AssertionError(
                f"{execution_id}: logical provider token projection does not reconcile"
            )
        measured_rows = [item for item in physical_rows if item["measured_cost_usd"] is not None]
        aggregate_cost = (
            sum(
                (
                    _decimal(
                        item["measured_cost_usd"],
                        label=f"{item['event_id']} durable provider cost",
                    )
                    for item in measured_rows
                ),
                Decimal(0),
            )
            if measured_rows
            else None
        )
        recorded_cost = (
            _decimal(agent["measured_cost"], label=f"{execution_id} logical provider cost")
            if agent["measured_cost"] is not None
            else None
        )
        if aggregate_cost != recorded_cost:
            raise AssertionError(
                f"{execution_id}: logical provider cost projection does not reconcile"
            )
        states = {str(item["cost_measurement_state"]) for item in physical_rows}
        expected_cost_state = (
            "measured"
            if len(measured_rows) == len(physical_rows) and states == {"measured"}
            else (
                "partial"
                if measured_rows
                else ("invalid" if "invalid" in states else "not_observed")
            )
        )
        if agent["cost_measurement_state"] != expected_cost_state:
            raise AssertionError(f"{execution_id}: logical provider cost state does not reconcile")


def _assert_canonical_causality(
    agent_rows: list[dict[str, Any]],
    request_rows: list[dict[str, Any]],
    finding_rows: list[dict[str, Any]],
) -> None:
    """Require one complete canonical agent chain for every attempted live case."""

    agents_by_execution = {row["execution_id"]: row for row in agent_rows}
    requests_by_attempt: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in request_rows:
        attempt_id = row["attempt_id"]
        if not isinstance(attempt_id, str) or not attempt_id:
            raise AssertionError(f"{row['request_id']}: durable target attempt identity is invalid")
        requests_by_attempt[attempt_id].append(row)

    attempted_ids = set(requests_by_attempt)
    red_team_rows = [row for row in agent_rows if row["agent_role"] == "red_team"]
    judge_rows = [row for row in agent_rows if row["agent_role"] == "judge"]
    orchestrator_rows = [row for row in agent_rows if row["agent_role"] == "orchestrator"]
    non_succeeded = sorted(
        row["execution_id"] for row in agent_rows if row["status"] != "succeeded"
    )
    if non_succeeded:
        raise AssertionError(
            "completed live campaign has a non-succeeded canonical agent execution"
        )
    for role, rows in (("Red Team", red_team_rows), ("Judge", judge_rows)):
        role_attempts = [row["attempt_id"] for row in rows]
        if any(not isinstance(attempt_id, str) or not attempt_id for attempt_id in role_attempts):
            raise AssertionError(f"{role} execution has no durable attempt identity")
        if set(role_attempts) != attempted_ids or len(role_attempts) != len(attempted_ids):
            raise AssertionError(
                f"each attempted target case must have exactly one {role} execution"
            )

    orchestrator_ids: set[str] = set()
    judges_by_attempt: dict[str, dict[str, Any]] = {}
    for attempt_id, requests in requests_by_attempt.items():
        red_team = next(row for row in red_team_rows if row["attempt_id"] == attempt_id)
        judge = next(row for row in judge_rows if row["attempt_id"] == attempt_id)
        parent_id = red_team["parent_execution_id"]
        orchestrator = agents_by_execution.get(parent_id)
        if orchestrator is None or orchestrator["agent_role"] != "orchestrator":
            raise AssertionError(f"{attempt_id}: Red Team is not a child of a durable Orchestrator")
        if (
            orchestrator["organization_id"] != red_team["organization_id"]
            or orchestrator["campaign_run_id"] != red_team["campaign_run_id"]
            or orchestrator["attempt_id"] not in {None, attempt_id}
        ):
            raise AssertionError(
                f"{attempt_id}: Orchestrator and Red Team correlation does not reconcile"
            )
        if judge["parent_execution_id"] != red_team["execution_id"]:
            raise AssertionError(f"{attempt_id}: Judge is not a child of its Red Team execution")
        for request in requests:
            if (
                request["organization_id"] != red_team["organization_id"]
                or request["campaign_run_id"] != red_team["campaign_run_id"]
            ):
                raise AssertionError(
                    f"{request['request_id']}: target request and agent tenant scope diverge"
                )
        orchestrator_ids.add(str(orchestrator["execution_id"]))
        judges_by_attempt[attempt_id] = judge

    if len(orchestrator_ids) != len(attempted_ids):
        raise AssertionError("each attempted target case must have its own Orchestrator execution")
    if {row["execution_id"] for row in orchestrator_rows} != orchestrator_ids:
        raise AssertionError("durable Orchestrator executions do not exactly cover attempted cases")

    finding_ids = [row["finding_id"] for row in finding_rows]
    if len(finding_ids) != len(set(finding_ids)):
        raise AssertionError("durable finding evidence identities are duplicated")
    finding_attempts = [row["attempt_id"] for row in finding_rows]
    if len(finding_attempts) != len(set(finding_attempts)):
        raise AssertionError("a canonical attempted case has more than one finding evidence link")
    if not set(finding_attempts).issubset(attempted_ids):
        raise AssertionError("finding evidence references a case with no durable target request")

    documentation_rows = [row for row in agent_rows if row["agent_role"] == "documentation"]
    matched_documentation_ids: set[str] = set()
    for finding in finding_rows:
        attempt_id = finding["attempt_id"]
        judge = judges_by_attempt.get(attempt_id)
        if (
            judge is None
            or finding["organization_id"] != judge["organization_id"]
            or finding["campaign_run_id"] != judge["campaign_run_id"]
        ):
            raise AssertionError(
                f"{finding['finding_id']}: finding evidence and Judge tenant scope diverge"
            )
        matches = [
            row
            for row in documentation_rows
            if row["attempt_id"] == attempt_id
            and isinstance(row["detail"], dict)
            and row["detail"].get("finding_id") == finding["finding_id"]
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"{finding['finding_id']}: expected exactly one matching Documentation execution"
            )
        documentation = matches[0]
        if documentation["parent_execution_id"] != judge["execution_id"]:
            raise AssertionError(
                f"{finding['finding_id']}: Documentation is not a child of the matching Judge"
            )
        matched_documentation_ids.add(str(documentation["execution_id"]))
    if {row["execution_id"] for row in documentation_rows} != matched_documentation_ids:
        raise AssertionError(
            "Documentation executions do not exactly reconcile with finding evidence links"
        )


def _assert_metadata(
    observation: Any,
    *,
    row: dict[str, Any],
    observation_label: str,
    expected_environment: str,
) -> dict[str, Any]:
    metadata = _metadata(observation)
    expected = {
        "organization_id": row["organization_id"],
        "campaign_run_id": row["campaign_run_id"],
        "attempt_id": row["attempt_id"],
        "parent_execution_id": row["parent_execution_id"],
        "agent.execution_id": row["execution_id"],
        "agent.role": row["agent_role"],
        "agent.provider": row["provider"],
        "agent.model": row["model"],
        "agent.execution_mode": row["execution_mode"],
        "agent.input_sha256": row["input_sha256"],
        "agent.output_sha256": row["output_sha256"],
        "agent.status": row["status"],
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise AssertionError(
                f"{row['execution_id']}: {observation_label} metadata {key} does not reconcile"
            )

    _assert_observation_environment(
        observation,
        expected_environment=expected_environment,
        observation_label=f"{row['execution_id']}: {observation_label}",
    )
    duration = _decimal(
        metadata.get("agent.duration_ms"),
        label=f"{row['execution_id']} Langfuse agent duration",
    )
    if duration != _decimal(
        row["duration_ms"],
        label=f"{row['execution_id']} durable agent duration",
    ):
        raise AssertionError(
            f"{row['execution_id']}: {observation_label} duration does not reconcile"
        )
    return metadata


def _assert_usage_and_cost(row: dict[str, Any], generation: Any) -> None:
    execution_id = row["execution_id"]
    remote_cost = _cost_value(generation)
    metadata = _metadata(generation)

    remote_tokens = {
        "input": _usage_value(generation, "input"),
        "output": _usage_value(generation, "output"),
        "reasoning": _usage_value(generation, "reasoning"),
    }
    usage_total = _usage_value(generation, "total")
    if row["execution_mode"] == "deterministic":
        recorded_cost = _decimal(row["measured_cost"], label="recorded agent cost")
        if (
            recorded_cost != 0
            or any(
                row[field] is not None
                for field in ("input_tokens", "output_tokens", "reasoning_tokens")
            )
            or any(value is not None for value in remote_tokens.values())
            or usage_total is not None
            or metadata.get("cost.source") != "deterministic_zero"
            or remote_cost != 0
        ):
            raise AssertionError(
                f"{execution_id}: deterministic zero-cost accounting does not reconcile"
            )
        return

    if (
        any(value is not None for value in remote_tokens.values())
        or usage_total is not None
        or remote_cost is not None
        or metadata.get("cost.source") != "provider_attempt_generations"
    ):
        raise AssertionError(
            f"{execution_id}: hosted logical runtime double-counts physical provider usage"
        )


def _assert_observations(
    rows: list[dict[str, Any]],
    observations: list[Any],
    *,
    expected_environment: str,
) -> None:
    rows_by_execution = {row["execution_id"]: row for row in rows}
    observations_by_execution: defaultdict[str, list[Any]] = defaultdict(list)
    observation_ids: set[str] = set()
    for observation in observations:
        observation_id = _field(observation, "id")
        if not isinstance(observation_id, str) or not observation_id:
            raise AssertionError("Langfuse observation ID is unavailable")
        if observation_id in observation_ids:
            raise AssertionError(f"Langfuse observation {observation_id} is duplicated")
        observation_ids.add(observation_id)

        metadata = _metadata(observation)
        if "agent.execution_id" not in metadata:
            if _field(observation, "type") == "AGENT" or str(
                _field(observation, "name") or ""
            ).startswith("agent."):
                raise AssertionError(
                    f"Langfuse agent observation {observation_id} has no execution identity"
                )
            continue
        execution_id = metadata["agent.execution_id"]
        if not isinstance(execution_id, str) or not execution_id:
            raise AssertionError(
                f"Langfuse observation {observation_id} has an invalid execution identity"
            )
        if execution_id not in rows_by_execution:
            raise AssertionError(
                f"Langfuse observation {observation_id} references an unknown execution"
            )
        if _field(observation, "name") == _PROVIDER_OBSERVATION_NAME:
            continue
        observations_by_execution[execution_id].append(observation)

    for row in rows:
        execution_id = row["execution_id"]
        expected_agent_name = f"agent.{row['agent_role']}"
        expected_generation_name = f"{expected_agent_name}.runtime"
        execution_observations = observations_by_execution[execution_id]
        signatures = [
            (_field(observation, "name"), _field(observation, "type"))
            for observation in execution_observations
        ]
        expected_signatures = [
            (expected_agent_name, "AGENT"),
            (expected_generation_name, "GENERATION"),
        ]
        if Counter(signatures) != Counter(expected_signatures):
            raise AssertionError(
                f"{execution_id}: expected exactly one typed agent/runtime observation pair"
            )
        agent = next(
            observation
            for observation in execution_observations
            if _field(observation, "type") == "AGENT"
        )
        generation = next(
            observation
            for observation in execution_observations
            if _field(observation, "type") == "GENERATION"
        )

        for label, observation in (("agent", agent), ("generation", generation)):
            if _field(observation, "trace_id", "traceId") != row["trace_id"]:
                raise AssertionError(f"{execution_id}: {label} trace does not reconcile")
            if _field(observation, "end_time", "endTime") is None:
                raise AssertionError(f"{execution_id}: {label} observation is not terminal")
            expected_status = row["error_code"] or row["status"]
            if _field(observation, "status_message", "statusMessage") != expected_status:
                raise AssertionError(f"{execution_id}: {label} terminal status does not reconcile")
            _assert_metadata(
                observation,
                row=row,
                observation_label=label,
                expected_environment=expected_environment,
            )
            if _structured_io(observation, "input") != {"sha256": row["input_sha256"]}:
                raise AssertionError(f"{execution_id}: {label} input hash does not reconcile")
            if _structured_io(observation, "output") != {"sha256": row["output_sha256"]}:
                raise AssertionError(f"{execution_id}: {label} output hash does not reconcile")

        agent_id = _field(agent, "id")
        generation_parent = _field(
            generation,
            "parent_observation_id",
            "parentObservationId",
        )
        if not agent_id or generation_parent != agent_id:
            raise AssertionError(f"{execution_id}: generation is not a child of its agent")

        parent_execution_id = row["parent_execution_id"]
        remote_parent = _field(
            agent,
            "parent_observation_id",
            "parentObservationId",
        )
        if parent_execution_id is None:
            if remote_parent is not None:
                raise AssertionError(f"{execution_id}: root agent has a remote parent")
        else:
            parent_observations = observations_by_execution[parent_execution_id]
            parent_agents = [
                observation
                for observation in parent_observations
                if _field(observation, "type") == "AGENT"
            ]
            if len(parent_agents) != 1 or remote_parent != _field(parent_agents[0], "id"):
                raise AssertionError(f"{execution_id}: native cross-agent parentage is incorrect")

        if _field(generation, "provided_model_name", "providedModelName") != row["model"]:
            raise AssertionError(f"{execution_id}: runtime generation model does not reconcile")
        _assert_usage_and_cost(row, generation)


def _assert_provider_observations(
    rows: list[dict[str, Any]],
    observations: list[Any],
    *,
    agent_rows: list[dict[str, Any]],
    expected_environment: str,
) -> None:
    """Require one exact, redacted Langfuse generation per durable provider event."""

    rows_by_invocation = {row["invocation_id"]: row for row in rows}
    agents_by_execution = {row["execution_id"]: row for row in agent_rows}
    remote_agents = {
        _metadata(observation).get("agent.execution_id"): observation
        for observation in observations
        if _field(observation, "type") == "AGENT"
        and isinstance(_metadata(observation).get("agent.execution_id"), str)
    }
    remote_by_invocation: dict[str, Any] = {}
    for observation in observations:
        metadata = _metadata(observation)
        invocation_id = metadata.get("provider.invocation_id")
        is_named_attempt = _field(observation, "name") == _PROVIDER_OBSERVATION_NAME
        if not is_named_attempt and invocation_id not in rows_by_invocation:
            continue
        if (
            not is_named_attempt
            or _field(observation, "type") != "GENERATION"
            or not isinstance(invocation_id, str)
            or not invocation_id
        ):
            raise AssertionError("Langfuse provider attempt has an invalid type, name, or identity")
        if invocation_id not in rows_by_invocation:
            raise AssertionError(
                f"Langfuse provider attempt references unknown invocation {invocation_id}"
            )
        if invocation_id in remote_by_invocation:
            raise AssertionError(f"{invocation_id}: provider attempt observation is duplicated")
        remote_by_invocation[invocation_id] = observation

    if set(remote_by_invocation) != set(rows_by_invocation):
        missing = sorted(set(rows_by_invocation) - set(remote_by_invocation))
        raise AssertionError(
            f"{len(missing)} durable provider attempt observation(s) are not query-visible"
        )

    for invocation_id, row in rows_by_invocation.items():
        observation = remote_by_invocation[invocation_id]
        execution_id = row["logical_execution_id"]
        agent = agents_by_execution[execution_id]
        expected_cost_source = {
            "measured": "provider_measured",
            "partial": "provider_partial_known",
            "not_observed": "not_observed",
            "invalid": "invalid",
        }[row["cost_measurement_state"]]
        expected_metadata = {
            "deployment.environment": expected_environment,
            "organization_id": row["organization_id"],
            "campaign_run_id": row["campaign_run_id"],
            "attempt_id": row["campaign_attempt_id"],
            "parent_execution_id": row["parent_execution_id"],
            "agent.execution_id": execution_id,
            "agent.role": row["agent_role"],
            "provider.name": "openrouter",
            "provider.invocation_id": invocation_id,
            "provider.event_id": row["event_id"],
            "provider.physical_sequence": row["physical_sequence"],
            "provider.retry_number": row["physical_sequence"] - 1,
            "provider.is_retry": row["physical_sequence"] > 1,
            "provider.requested_model": row["requested_model"],
            "provider.returned_model": row["returned_model"],
            "provider.configured_upstream": row["configured_upstream"],
            "provider.served_upstream": row["upstream_provider"],
            "provider.request_id": row["provider_request_id"],
            "provider.prompt_version": row["prompt_version"],
            "provider.prompt_sha256": row["prompt_sha256"],
            "provider.configuration_set_sha256": row["configuration_set_sha256"],
            "provider.role_configuration_sha256": row["role_configuration_sha256"],
            "provider.generation_policy_sha256": row["generation_policy_sha256"],
            "provider.status": row["status"],
            "provider.error_code": row["error_code"],
            "provider.duration_ms": None,
            "cost.source": expected_cost_source,
            "cost.measurement_state": row["cost_measurement_state"],
            "cost.usd": None,
        }
        metadata = _metadata(observation)
        if set(metadata) != set(expected_metadata):
            raise AssertionError(f"{invocation_id}: provider metadata field set does not reconcile")
        value_mismatches = sorted(
            key
            for key, expected in expected_metadata.items()
            if key not in {"provider.duration_ms", "cost.usd"} and metadata.get(key) != expected
        )
        if value_mismatches:
            raise AssertionError(
                f"{invocation_id}: provider metadata does not reconcile: {value_mismatches}"
            )
        if _decimal(
            metadata.get("provider.duration_ms"),
            label=f"{invocation_id} Langfuse provider duration",
        ) != _decimal(row["duration_ms"], label=f"{invocation_id} durable duration"):
            raise AssertionError(f"{invocation_id}: provider duration does not reconcile")
        expected_metadata_cost = (
            _decimal(
                row["measured_cost_usd"],
                label=f"{invocation_id} durable provider cost",
            )
            if row["measured_cost_usd"] is not None
            else None
        )
        remote_metadata_cost = (
            _decimal(
                metadata.get("cost.usd"),
                label=f"{invocation_id} Langfuse provider metadata cost",
            )
            if metadata.get("cost.usd") is not None
            else None
        )
        if remote_metadata_cost != expected_metadata_cost:
            mismatched = sorted(key for key in ("cost.usd",) if metadata.get(key) is not None)
            raise AssertionError(
                f"{invocation_id}: provider metadata does not reconcile: {mismatched}"
            )
        _assert_observation_environment(
            observation,
            expected_environment=expected_environment,
            observation_label=invocation_id,
        )
        if _field(observation, "trace_id", "traceId") != agent["trace_id"]:
            raise AssertionError(f"{invocation_id}: provider attempt trace does not reconcile")
        remote_agent = remote_agents.get(execution_id)
        if remote_agent is None or _field(
            observation,
            "parent_observation_id",
            "parentObservationId",
        ) != _field(remote_agent, "id"):
            raise AssertionError(
                f"{invocation_id}: provider attempt is not a native child of its role agent"
            )
        if _field(observation, "end_time", "endTime") is None:
            raise AssertionError(f"{invocation_id}: provider attempt observation is not terminal")
        expected_status = row["error_code"] or row["status"]
        if _field(observation, "status_message", "statusMessage") != expected_status:
            raise AssertionError(f"{invocation_id}: provider terminal status does not reconcile")
        expected_model = row["returned_model"] or row["requested_model"]
        if _field(observation, "provided_model_name", "providedModelName") != expected_model:
            raise AssertionError(f"{invocation_id}: provider model does not reconcile")
        expected_input = {
            "prompt_sha256": row["prompt_sha256"],
            "configuration_set_sha256": row["configuration_set_sha256"],
            "role_configuration_sha256": row["role_configuration_sha256"],
            "generation_policy_sha256": row["generation_policy_sha256"],
        }
        if _structured_io(observation, "input") != expected_input:
            raise AssertionError(f"{invocation_id}: provider input identities do not reconcile")
        if _structured_io(observation, "output") != {"provider_event_id": row["event_id"]}:
            raise AssertionError(f"{invocation_id}: provider output identity does not reconcile")

        expected_usage = {
            "input": row["input_tokens"],
            "output": row["output_tokens"],
            "reasoning": row["reasoning_tokens"],
        }
        remote_usage = {
            key: _usage_value(observation, key) for key in ("input", "output", "reasoning")
        }
        if remote_usage != expected_usage:
            raise AssertionError(f"{invocation_id}: provider token usage does not reconcile")
        expected_total = (
            sum(value for value in expected_usage.values() if value is not None)
            if any(value is not None for value in expected_usage.values())
            else None
        )
        if _usage_value(observation, "total") != expected_total:
            raise AssertionError(f"{invocation_id}: provider total usage does not reconcile")
        expected_cost = (
            _decimal(
                row["measured_cost_usd"],
                label=f"{invocation_id} durable provider cost",
            )
            if row["measured_cost_usd"] is not None
            else None
        )
        if _cost_value(observation) != expected_cost:
            raise AssertionError(f"{invocation_id}: provider cost does not reconcile")


def _assert_target_observations(
    rows: list[dict[str, Any]],
    observations: list[Any],
    *,
    agent_rows: list[dict[str, Any]],
    expected_environment: str,
) -> None:
    rows_by_request = {row["request_id"]: row for row in rows}
    red_team_by_attempt = {
        row["attempt_id"]: row for row in agent_rows if row["agent_role"] == "red_team"
    }
    remote_agents_by_execution: dict[str, Any] = {}
    remote_by_request: dict[str, Any] = {}
    for observation in observations:
        observation_metadata = _metadata(observation)
        execution_id = observation_metadata.get("agent.execution_id")
        if _field(observation, "type") == "AGENT" and isinstance(execution_id, str):
            remote_agents_by_execution[execution_id] = observation
        if (
            _field(observation, "name") != "target-http-request"
            and observation_metadata.get("request_id") not in rows_by_request
        ):
            continue
        if (
            _field(observation, "name") != "target-http-request"
            or _field(observation, "type") != "GENERATION"
        ):
            raise AssertionError("Langfuse target request observation has an invalid type or name")
        metadata = _metadata(observation)
        request_id = metadata.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise AssertionError("Langfuse target request observation has no request identity")
        if request_id not in rows_by_request:
            raise AssertionError(
                f"Langfuse target request observation references unknown request {request_id}"
            )
        if request_id in remote_by_request:
            raise AssertionError(f"{request_id}: target request observation is duplicated")
        remote_by_request[request_id] = observation

    if set(remote_by_request) != set(rows_by_request):
        missing = sorted(set(rows_by_request) - set(remote_by_request))
        raise AssertionError(
            f"{len(missing)} durable target request observation(s) are not query-visible"
        )

    for request_id, row in rows_by_request.items():
        observation = remote_by_request[request_id]
        metadata = _metadata(observation)
        red_team = red_team_by_attempt.get(row["attempt_id"])
        if red_team is None:
            raise AssertionError(
                f"{request_id}: matching durable Red Team execution is unavailable"
            )
        expected_metadata = {
            "organization_id": row["organization_id"],
            "campaign_run_id": row["campaign_run_id"],
            "attempt_id": row["attempt_id"],
            "case_id": row["case_id"],
            "attack_category": row["attack_category"],
            "target_id": row["target_id"],
            "target_version": row["target_version"],
            "surface_id": row["surface_id"],
            "surface_version": row["surface_version"],
            "execution_profile": "live",
            "target.provider": row["provider"],
            "http.method": row["method"],
            "http.request.body.size": row["request_bytes"],
            "http.request.body.sha256": row["request_sha256"],
            "http.response.body.size": row["response_bytes"],
            "http.response.body.sha256": row["response_sha256"],
            "transport.status": row["status"],
            "error_code": row["error_code"],
            "ledger.persisted": True,
            "red_team_execution_id": red_team["execution_id"],
        }
        for key, value in expected_metadata.items():
            if metadata.get(key) != value:
                raise AssertionError(
                    f"{request_id}: target request metadata {key} does not reconcile"
                )
        _assert_observation_environment(
            observation,
            expected_environment=expected_environment,
            observation_label=request_id,
        )
        if _field(observation, "trace_id", "traceId") != row["trace_id"]:
            raise AssertionError(f"{request_id}: target request trace does not reconcile")
        remote_red_team = remote_agents_by_execution.get(red_team["execution_id"])
        remote_parent = _field(
            observation,
            "parent_observation_id",
            "parentObservationId",
        )
        if remote_red_team is None or remote_parent != _field(remote_red_team, "id"):
            raise AssertionError(
                f"{request_id}: target request is not a native child of its Red Team agent"
            )
        if _field(observation, "end_time", "endTime") is None:
            raise AssertionError(f"{request_id}: target request observation is not terminal")
        if _field(observation, "provided_model_name", "providedModelName") != row["provider"]:
            raise AssertionError(f"{request_id}: target request provider does not reconcile")
        if _structured_io(observation, "input") != {
            "sha256": row["request_sha256"],
            "bytes": row["request_bytes"],
        }:
            raise AssertionError(f"{request_id}: target request input hash does not reconcile")
        expected_output = (
            None
            if row["response_sha256"] is None
            else {
                "sha256": row["response_sha256"],
                "bytes": row["response_bytes"],
            }
        )
        if _structured_io(observation, "output") != expected_output:
            raise AssertionError(f"{request_id}: target response hash does not reconcile")
        remote_cost = _cost_value(observation)
        if remote_cost != _decimal(row["measured_cost"], label="recorded target request cost"):
            raise AssertionError(f"{request_id}: target request cost does not reconcile")
        duration = _decimal(
            metadata.get("duration_ms"),
            label=f"{request_id} Langfuse target duration",
        )
        if duration != _decimal(
            row["duration_ms"],
            label=f"{request_id} durable target duration",
        ):
            raise AssertionError(f"{request_id}: target request duration does not reconcile")


def _exact_expected_ids(values: list[str], *, label: str) -> set[str]:
    if not values:
        raise AssertionError(f"{label} expected IDs are empty")
    if any(not isinstance(value, str) or not value for value in values):
        raise AssertionError(f"{label} expected IDs are invalid")
    expected = set(values)
    if len(expected) != len(values):
        raise AssertionError(f"{label} expected IDs are duplicated")
    return expected


def _exact_provider_pairs(
    values: list[tuple[str, str]],
) -> set[tuple[str, str]]:
    if any(
        not isinstance(invocation_id, str)
        or not invocation_id
        or not isinstance(event_id, str)
        or not event_id
        for invocation_id, event_id in values
    ):
        raise AssertionError("provider invocation/event expected identities are invalid")
    expected = set(values)
    if len(expected) != len(values):
        raise AssertionError("provider invocation/event expected identities are duplicated")
    return expected


def _record_queryback_verification(
    database_url: str,
    *,
    organization_id: str,
    campaign_run_id: str,
    agent_execution_ids: list[str],
    target_request_ids: list[str],
    provider_invocation_event_ids: list[tuple[str, str]],
) -> None:
    """Atomically persist successful remote query-back for the exact durable rows."""

    expected_agent_ids = _exact_expected_ids(
        agent_execution_ids,
        label="agent execution",
    )
    expected_request_ids = _exact_expected_ids(
        target_request_ids,
        label="target request",
    )
    expected_provider_pairs = _exact_provider_pairs(provider_invocation_event_ids)
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            recorded_provider_pairs = set(
                connection.execute(
                    text(
                        "SELECT i.invocation_id, e.event_id "
                        "FROM provider_call_invocations i "
                        "JOIN provider_call_events e "
                        "ON e.organization_id = i.organization_id "
                        "AND e.invocation_id = i.invocation_id "
                        "WHERE i.organization_id = :org AND i.campaign_run_id = :run_id"
                    ),
                    {
                        "org": organization_id,
                        "run_id": campaign_run_id,
                    },
                ).tuples()
            )
            if recorded_provider_pairs != expected_provider_pairs:
                missing = sorted(expected_provider_pairs - recorded_provider_pairs)
                unexpected = sorted(recorded_provider_pairs - expected_provider_pairs)
                raise AssertionError(
                    "provider verification persistence binding did not match expected IDs: "
                    f"missing={missing}, unexpected={unexpected}"
                )

            recorded_agent_ids = set(
                connection.execute(
                    text(
                        "UPDATE agent_executions SET langfuse_status = 'exported', "
                        "langfuse_verified_at = COALESCE(langfuse_verified_at, clock_timestamp()) "
                        "WHERE organization_id = :org AND campaign_run_id = :run_id "
                        "AND execution_id = ANY(:execution_ids) "
                        "AND langfuse_status IN ('queued', 'exported') RETURNING execution_id"
                    ),
                    {
                        "org": organization_id,
                        "run_id": campaign_run_id,
                        "execution_ids": list(expected_agent_ids),
                    },
                ).scalars()
            )
            if recorded_agent_ids != expected_agent_ids:
                missing = sorted(expected_agent_ids - recorded_agent_ids)
                unexpected = sorted(recorded_agent_ids - expected_agent_ids)
                raise AssertionError(
                    "agent execution verification persistence did not match expected IDs: "
                    f"missing={missing}, unexpected={unexpected}"
                )

            recorded_request_ids = set(
                connection.execute(
                    text(
                        "UPDATE outbound_http_requests SET langfuse_status = 'exported', "
                        "langfuse_verified_at = COALESCE(langfuse_verified_at, clock_timestamp()) "
                        "WHERE organization_id = :org AND campaign_run_id = :run_id "
                        "AND request_id = ANY(:request_ids) "
                        "AND langfuse_status IN ('queued', 'exported') RETURNING request_id"
                    ),
                    {
                        "org": organization_id,
                        "run_id": campaign_run_id,
                        "request_ids": list(expected_request_ids),
                    },
                ).scalars()
            )
            if recorded_request_ids != expected_request_ids:
                missing = sorted(expected_request_ids - recorded_request_ids)
                unexpected = sorted(recorded_request_ids - expected_request_ids)
                raise AssertionError(
                    "target request verification persistence did not match expected IDs: "
                    f"missing={missing}, unexpected={unexpected}"
                )
    finally:
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-run-id", required=True)
    parser.add_argument(
        "--expected-environment",
        required=True,
        choices=_DEPLOYED_ENVIRONMENTS,
        help=(
            "exact deployed environment expected in Runner configuration and every "
            "Langfuse observation"
        ),
    )
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument(
        "--record-verification",
        action="store_true",
        help=(
            "after complete Langfuse query-back, atomically mark only the verified "
            "durable rows; omitted by default for a read-only probe"
        ),
    )
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.poll_seconds <= 0:
        raise SystemExit("poll and timeout values must be positive")
    _assert_environment_binding(args.expected_environment)
    if not _LangfuseBridge.configured():
        raise SystemExit("safe HTTPS Langfuse credentials are required")

    database_url = _database_url()
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            campaign = (
                connection.execute(
                    text(
                        "SELECT r.organization_id, q.scope_payload->>'execution_profile' "
                        "AS execution_profile, EXISTS (SELECT 1 FROM campaign_run_summaries s "
                        "WHERE s.organization_id = r.organization_id AND s.run_id = r.run_id) "
                        "AS complete, EXISTS (SELECT 1 FROM finding_evidence_links fel "
                        "WHERE fel.organization_id = r.organization_id "
                        "AND fel.campaign_run_id = r.run_id) AS finding_evidence_exists "
                        "FROM campaign_runs r JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "WHERE r.run_id = :run_id"
                    ),
                    {"run_id": args.campaign_run_id},
                )
                .mappings()
                .one_or_none()
            )
            if campaign is None:
                raise SystemExit("campaign run does not exist")
            if campaign["execution_profile"] != "live" or not campaign["complete"]:
                raise SystemExit("campaign must be a completed live run")
            rows = [
                dict(row)
                for row in connection.execute(
                    text(
                        "SELECT execution_id, organization_id, campaign_run_id, attempt_id, "
                        "parent_execution_id, agent_role, provider, model, execution_mode, "
                        "configuration_version, status, error_code, duration_ms, input_sha256, "
                        "output_sha256, input_tokens, output_tokens, reasoning_tokens, "
                        "measured_cost, currency, trace_id, returned_model, upstream_provider, "
                        "provider_request_id, physical_attempts, cost_measurement_state, "
                        "provider_event_ids, langfuse_status, langfuse_verified_at, detail "
                        "FROM agent_executions WHERE organization_id = :org "
                        "AND campaign_run_id = :run_id ORDER BY id"
                    ),
                    {
                        "org": campaign["organization_id"],
                        "run_id": args.campaign_run_id,
                    },
                )
                .mappings()
                .all()
            ]
            finding_rows = [
                dict(row)
                for row in connection.execute(
                    text(
                        "SELECT organization_id, finding_id, campaign_run_id, attempt_id, "
                        "evidence_content_hash, verdict_id FROM finding_evidence_links "
                        "WHERE organization_id = :org AND campaign_run_id = :run_id "
                        "ORDER BY id"
                    ),
                    {
                        "org": campaign["organization_id"],
                        "run_id": args.campaign_run_id,
                    },
                )
                .mappings()
                .all()
            ]
            request_rows = [
                dict(row)
                for row in connection.execute(
                    text(
                        "SELECT o.request_id, o.organization_id, o.campaign_run_id, "
                        "o.attempt_id, o.trace_id, o.provider, o.method, o.status, "
                        "o.error_code, o.started_at, o.finished_at, o.duration_ms, "
                        "o.request_payload, o.response_payload, o.request_bytes, "
                        "o.response_bytes, o.measured_cost, o.currency, o.langfuse_status, "
                        "o.langfuse_verified_at, "
                        "q.scope_payload->>'target_id' AS target_id, "
                        "q.scope_payload->>'target_version' AS target_version, "
                        "q.scope_payload->>'surface_id' AS surface_id, "
                        "q.scope_payload->>'surface_version' AS surface_version, "
                        "a.case_id, a.category AS attack_category "
                        "FROM outbound_http_requests o JOIN campaign_runs r "
                        "ON r.organization_id = o.organization_id "
                        "AND r.run_id = o.campaign_run_id "
                        "JOIN campaign_authorization_requests q "
                        "ON q.organization_id = r.organization_id "
                        "AND q.request_id = r.authorization_request_id "
                        "LEFT JOIN campaign_attempts a "
                        "ON a.organization_id = o.organization_id "
                        "AND a.run_id = o.campaign_run_id "
                        "AND a.attempt_id = o.attempt_id "
                        "WHERE o.organization_id = :org "
                        "AND o.campaign_run_id = :run_id ORDER BY o.id"
                    ),
                    {
                        "org": campaign["organization_id"],
                        "run_id": args.campaign_run_id,
                    },
                )
                .mappings()
                .all()
            ]
            provider_rows = [
                dict(row)
                for row in connection.execute(
                    text(
                        "SELECT i.invocation_id, i.organization_id, i.campaign_run_id, "
                        "i.campaign_attempt_id, i.logical_execution_id, "
                        "i.parent_execution_id, i.agent_role, i.physical_sequence, "
                        "i.requested_model, i.configured_upstream, i.prompt_version, "
                        "i.prompt_sha256, i.configuration_set_sha256, "
                        "i.role_configuration_sha256, i.generation_policy_sha256, "
                        "i.started_at, e.event_id, e.invocation_id AS event_invocation_id, "
                        "e.physical_sequence AS event_physical_sequence, e.status, "
                        "e.returned_model, e.upstream_provider, e.provider_request_id, "
                        "e.input_tokens, e.output_tokens, e.reasoning_tokens, "
                        "e.cost_measurement_state, e.measured_cost_usd, e.error_code, "
                        "e.finished_at, e.duration_ms "
                        "FROM provider_call_invocations i "
                        "LEFT JOIN provider_call_events e "
                        "ON e.organization_id = i.organization_id "
                        "AND e.invocation_id = i.invocation_id "
                        "WHERE i.organization_id = :org AND i.campaign_run_id = :run_id "
                        "ORDER BY i.logical_execution_id, i.physical_sequence"
                    ),
                    {
                        "org": campaign["organization_id"],
                        "run_id": args.campaign_run_id,
                    },
                )
                .mappings()
                .all()
            ]
    finally:
        engine.dispose()

    trace_id = campaign_trace_id(args.campaign_run_id)
    try:
        roles = _assert_durable_campaign(
            rows,
            finding_evidence_exists=bool(campaign["finding_evidence_exists"]),
            trace_id=trace_id,
        )
        _assert_durable_requests(request_rows, trace_id=trace_id)
        _assert_durable_provider_attempts(provider_rows, agent_rows=rows)
        _assert_canonical_causality(rows, request_rows, finding_rows)
    except AssertionError as exc:
        raise SystemExit(str(exc)) from exc

    from langfuse import get_client

    client = get_client()
    deadline = time.monotonic() + args.timeout_seconds
    last_error = "Langfuse observations are not query-visible"
    while time.monotonic() < deadline:
        try:
            observations = _remote_observations(client, trace_id)
            _assert_observations(
                rows,
                observations,
                expected_environment=args.expected_environment,
            )
            _assert_provider_observations(
                provider_rows,
                observations,
                agent_rows=rows,
                expected_environment=args.expected_environment,
            )
            _assert_target_observations(
                request_rows,
                observations,
                agent_rows=rows,
                expected_environment=args.expected_environment,
            )
        except Exception as exc:
            last_error = str(exc)
            time.sleep(args.poll_seconds)
            continue
        if args.record_verification:
            try:
                _record_queryback_verification(
                    database_url,
                    organization_id=campaign["organization_id"],
                    campaign_run_id=args.campaign_run_id,
                    agent_execution_ids=[row["execution_id"] for row in rows],
                    target_request_ids=[row["request_id"] for row in request_rows],
                    provider_invocation_event_ids=[
                        (row["invocation_id"], row["event_id"]) for row in provider_rows
                    ],
                )
            except AssertionError as exc:
                raise SystemExit(f"Langfuse verification persistence failed: {exc}") from exc
            except Exception as exc:
                raise SystemExit(
                    "Langfuse verification persistence failed: database transaction failed"
                ) from exc
        print(
            json.dumps(
                {
                    "campaign_run_id": args.campaign_run_id,
                    "deployment_environment": args.expected_environment,
                    "trace_id": trace_id,
                    "agent_execution_count": len(rows),
                    "target_request_count": len(request_rows),
                    "provider_attempt_count": len(provider_rows),
                    "roles": sorted(roles),
                    "langfuse_observation_count": len(observations),
                    "status": "observed",
                    "verification_recorded": args.record_verification,
                },
                sort_keys=True,
            )
        )
        return 0
    raise SystemExit(f"Langfuse query-back verification failed: {last_error}")


if __name__ == "__main__":
    raise SystemExit(main())
