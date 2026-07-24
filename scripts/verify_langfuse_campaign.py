#!/usr/bin/env python3
"""Verify one completed live campaign against PostgreSQL and Langfuse.

This is an acceptance probe for a deployed Runner. It never launches work, sends target traffic,
or uses a fixture. It polls Langfuse through the authenticated Public API until every durable
agent execution is query-visible with its typed agent/generation pair, native parentage, terminal
latency, and exact recorded usage/cost.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import create_engine, text

from agentforge.agents.runtime import AGENT_ROLES
from agentforge.correlation import campaign_trace_id
from agentforge.telemetry.outbound import _LangfuseBridge


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
    if not isinstance(usage, dict) or key not in usage:
        return None
    value = usage[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AssertionError(f"Langfuse {key} usage is invalid")
    return int(value)


def _cost_value(observation: Any) -> Decimal | None:
    details = _field(observation, "cost_details", "costDetails")
    if not isinstance(details, dict) or "total" not in details:
        return None
    return _decimal(details["total"], label="Langfuse total cost")


def _metadata(observation: Any) -> dict[str, Any]:
    value = _field(observation, "metadata")
    return dict(value) if isinstance(value, dict) else {}


def _remote_observations(client: Any, trace_id: str) -> list[Any]:
    response = client.api.observations.get_many(
        trace_id=trace_id,
        limit=1000,
        fields="core,basic,usage,metadata",
    )
    data = _field(response, "data")
    return list(data) if isinstance(data, (list, tuple)) else []


def _assert_observations(rows: list[dict[str, Any]], observations: list[Any]) -> None:
    agents_by_execution: dict[str, Any] = {}
    generations_by_execution: dict[str, Any] = {}
    for observation in observations:
        metadata = _metadata(observation)
        execution_id = metadata.get("agent.execution_id")
        if not isinstance(execution_id, str):
            continue
        name = _field(observation, "name")
        if name == f"agent.{metadata.get('agent.role')}":
            agents_by_execution[execution_id] = observation
        elif name == f"agent.{metadata.get('agent.role')}.runtime":
            generations_by_execution[execution_id] = observation

    missing_agents = sorted(
        row["execution_id"] for row in rows if row["execution_id"] not in agents_by_execution
    )
    missing_generations = sorted(
        row["execution_id"] for row in rows if row["execution_id"] not in generations_by_execution
    )
    if missing_agents or missing_generations:
        raise AssertionError(
            "Langfuse observations are incomplete: "
            f"{len(missing_agents)} agent and {len(missing_generations)} generation rows missing"
        )

    for row in rows:
        execution_id = row["execution_id"]
        agent = agents_by_execution[execution_id]
        generation = generations_by_execution[execution_id]
        agent_id = _field(agent, "id")
        generation_parent = _field(
            generation,
            "parent_observation_id",
            "parentObservationId",
        )
        if not agent_id or generation_parent != agent_id:
            raise AssertionError(f"{execution_id}: generation is not a child of its agent")
        if _field(agent, "end_time", "endTime") is None:
            raise AssertionError(f"{execution_id}: agent observation is not terminal")
        if _field(generation, "end_time", "endTime") is None:
            raise AssertionError(f"{execution_id}: generation observation is not terminal")

        parent_execution_id = row["parent_execution_id"]
        if parent_execution_id is not None:
            parent = agents_by_execution.get(parent_execution_id)
            remote_parent = _field(
                agent,
                "parent_observation_id",
                "parentObservationId",
            )
            if parent is None or remote_parent != _field(parent, "id"):
                raise AssertionError(f"{execution_id}: native cross-agent parentage is incorrect")

        recorded_cost = _decimal(row["measured_cost"], label="recorded agent cost")
        remote_cost = _cost_value(generation)
        if row["execution_mode"] == "deterministic":
            if remote_cost != recorded_cost:
                raise AssertionError(f"{execution_id}: deterministic zero cost is not observable")
        elif remote_cost is None or remote_cost != recorded_cost:
            raise AssertionError(f"{execution_id}: hosted provider cost does not reconcile")

        for token_key, column in (("input", "input_tokens"), ("output", "output_tokens")):
            recorded_tokens = row[column]
            remote_tokens = _usage_value(generation, token_key)
            if recorded_tokens is not None and remote_tokens != recorded_tokens:
                raise AssertionError(f"{execution_id}: {token_key} usage does not reconcile")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-run-id", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.poll_seconds <= 0:
        raise SystemExit("poll and timeout values must be positive")
    if not _LangfuseBridge.configured():
        raise SystemExit("safe HTTPS Langfuse credentials are required")

    engine = create_engine(_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            campaign = (
                connection.execute(
                    text(
                        "SELECT r.organization_id, q.scope_payload->>'execution_profile' "
                        "AS execution_profile, EXISTS (SELECT 1 FROM campaign_run_summaries s "
                        "WHERE s.organization_id = r.organization_id AND s.run_id = r.run_id) "
                        "AS complete FROM campaign_runs r JOIN campaign_authorization_requests q "
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
                        "SELECT execution_id, parent_execution_id, agent_role, execution_mode, "
                        "input_tokens, output_tokens, measured_cost, trace_id "
                        "FROM agent_executions WHERE organization_id = :org "
                        "AND campaign_run_id = :run_id AND status <> 'running' ORDER BY id"
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

    roles = {row["agent_role"] for row in rows}
    if roles != set(AGENT_ROLES):
        raise SystemExit(f"durable agent role coverage is incomplete: {sorted(roles)}")
    trace_id = campaign_trace_id(args.campaign_run_id)
    if any(row["trace_id"] != trace_id for row in rows):
        raise SystemExit("durable agent trace correlation is inconsistent")
    if len(rows) * 2 > 1000:
        raise SystemExit("campaign exceeds the bounded Langfuse verification page")

    from langfuse import get_client

    client = get_client()
    deadline = time.monotonic() + args.timeout_seconds
    last_error = "Langfuse observations are not query-visible"
    while time.monotonic() < deadline:
        try:
            observations = _remote_observations(client, trace_id)
            _assert_observations(rows, observations)
        except Exception as exc:
            last_error = str(exc)
            time.sleep(args.poll_seconds)
            continue
        print(
            json.dumps(
                {
                    "campaign_run_id": args.campaign_run_id,
                    "trace_id": trace_id,
                    "agent_execution_count": len(rows),
                    "roles": sorted(roles),
                    "langfuse_observation_count": len(observations),
                    "status": "observed",
                },
                sort_keys=True,
            )
        )
        return 0
    raise SystemExit(f"Langfuse query-back verification failed: {last_error}")


if __name__ == "__main__":
    raise SystemExit(main())
