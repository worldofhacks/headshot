#!/usr/bin/env python3
"""Verify one completed agent-only acceptance run against Langfuse and canonical lineage."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import time
from typing import Any

from sqlalchemy import create_engine

from agentforge.agent_acceptance_verifier import (
    ACCEPTANCE_ROLES,
    OBSERVATION_FIELDS,
    assert_durable_acceptance,
    assert_remote_acceptance,
    load_acceptance_snapshot,
    record_queryback_verification,
)
from agentforge.config import Settings
from agentforge.telemetry.outbound import _LangfuseBridge

_MAX_OBSERVATION_PAGES = 100


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


def _remote_observations(client: Any, trace_id: str) -> list[Any]:
    observations: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _page in range(_MAX_OBSERVATION_PAGES):
        parameters: dict[str, Any] = {
            "trace_id": trace_id,
            "limit": 1000,
            "fields": OBSERVATION_FIELDS,
        }
        if cursor is not None:
            parameters["cursor"] = cursor
        response = client.api.observations.get_many(**parameters)
        data = _field(response, "data")
        if not isinstance(data, (list, tuple)):
            raise AssertionError("Langfuse observation page has no data array")
        observations.extend(data)
        next_cursor = _field(_field(response, "meta"), "cursor")
        if next_cursor is None:
            return observations
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
            raise AssertionError("Langfuse observation pagination cursor is invalid")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise AssertionError("Langfuse observation pagination exceeded the safety limit")


def _assert_environment_binding(settings: Settings, expected_environment: str) -> None:
    if settings.environment != expected_environment:
        raise SystemExit(
            "runtime environment must exactly match --expected-environment "
            f"{expected_environment!r}"
        )
    if os.environ.get("LANGFUSE_TRACING_ENVIRONMENT") != expected_environment:
        raise SystemExit(
            "LANGFUSE_TRACING_ENVIRONMENT must exactly match --expected-environment "
            f"{expected_environment!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--acceptance-run-id", required=True)
    parser.add_argument(
        "--expected-environment",
        required=True,
        choices=("local", "staging", "production"),
    )
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument(
        "--record-verification",
        action="store_true",
        help="atomically mark exactly the four reconciled agent rows exported",
    )
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.poll_seconds <= 0:
        raise SystemExit("poll and timeout values must be positive")

    settings = Settings.from_env()
    _assert_environment_binding(settings, args.expected_environment)
    if not _LangfuseBridge.configured():
        raise SystemExit("safe HTTPS Langfuse credentials are required")

    engine = create_engine(_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            snapshot = load_acceptance_snapshot(
                connection,
                run_id=args.acceptance_run_id,
            )
        try:
            by_role = assert_durable_acceptance(snapshot)
        except AssertionError as exc:
            raise SystemExit(str(exc)) from exc

        from langfuse import get_client

        client = get_client()
        deadline = time.monotonic() + args.timeout_seconds
        last_error = "Langfuse acceptance observations are not query-visible"
        evidence: dict[str, tuple[str, str]] | None = None
        while time.monotonic() < deadline:
            try:
                observations = _remote_observations(client, snapshot.trace_id)
                evidence = assert_remote_acceptance(
                    snapshot,
                    observations,
                    expected_environment=args.expected_environment,
                )
            except Exception as exc:
                last_error = str(exc)
                time.sleep(args.poll_seconds)
                continue
            break
        if evidence is None:
            raise SystemExit(f"Langfuse acceptance query-back failed: {last_error}")

        if args.record_verification:
            try:
                record_queryback_verification(
                    engine,
                    run_id=args.acceptance_run_id,
                    execution_ids=[str(row["execution_id"]) for row in snapshot.agents],
                )
            except AssertionError as exc:
                raise SystemExit(
                    f"Langfuse acceptance verification persistence failed: {exc}"
                ) from exc

        print(
            json.dumps(
                {
                    "acceptance_run_id": args.acceptance_run_id,
                    "acceptance_attempt_id": snapshot.run["acceptance_attempt_id"],
                    "organization_id": snapshot.run["organization_id"],
                    "deployment_environment": args.expected_environment,
                    "trace_id": snapshot.trace_id,
                    "target_request_count": snapshot.target_request_count,
                    "provider_event_count": len(snapshot.provider_calls),
                    "langfuse_observation_count": len(observations),
                    "verification_recorded": args.record_verification,
                    "status": "observed",
                    "roles": {
                        role: {
                            "execution_id": by_role[role]["execution_id"],
                            "returned_model": by_role[role]["returned_model"],
                            "upstream_provider": by_role[role]["upstream_provider"],
                            "input_tokens": by_role[role]["input_tokens"],
                            "output_tokens": by_role[role]["output_tokens"],
                            "reasoning_tokens": by_role[role]["reasoning_tokens"],
                            "measured_cost_usd": format(
                                by_role[role]["measured_cost"],
                                "f",
                            ),
                            "parent_execution_id": by_role[role]["parent_execution_id"],
                            "provider_event_id": by_role[role]["provider_event_ids"][0],
                            "langfuse_agent_observation_id": evidence[role][0],
                            "langfuse_generation_observation_id": evidence[role][1],
                        }
                        for role in ACCEPTANCE_ROLES
                    },
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        with contextlib.suppress(Exception):
            if "client" in locals():
                client.shutdown()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
