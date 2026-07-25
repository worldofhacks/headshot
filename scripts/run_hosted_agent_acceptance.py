#!/usr/bin/env python3
"""Execute one bounded, target-free live acceptance chain and print only safe identities."""

from __future__ import annotations

import argparse
import json
import os
import re

from sqlalchemy import create_engine

from agentforge.agent_acceptance import run_agent_acceptance
from agentforge.config import Settings

_ORGANIZATION_ID = re.compile(r"\Aorg_[A-Za-z0-9]+\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _database_url() -> str:
    value = os.environ.get("DATABASE_URL", "").strip()
    if not value:
        raise SystemExit("DATABASE_URL is required")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    return value


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run three target-free hosted agents against an existing human-staged "
            "four-role configuration."
        )
    )
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--configuration-set-sha256", required=True)
    parser.add_argument("--release-sha256", required=True)
    arguments = parser.parse_args()
    if _ORGANIZATION_ID.fullmatch(arguments.organization_id) is None:
        parser.error("--organization-id must be one Clerk organization ID")
    if _SHA256.fullmatch(arguments.configuration_set_sha256) is None:
        parser.error("--configuration-set-sha256 must be one lowercase SHA-256 digest")
    if _SHA256.fullmatch(arguments.release_sha256) is None:
        parser.error("--release-sha256 must be one lowercase SHA-256 digest")
    return arguments


def main() -> int:
    arguments = _arguments()
    settings = Settings.from_env()
    engine = create_engine(_database_url(), pool_pre_ping=True)
    try:
        result = run_agent_acceptance(
            engine=engine,
            environment=settings.environment,
            organization_id=arguments.organization_id,
            configuration_set_sha256=arguments.configuration_set_sha256,
            release_sha256=arguments.release_sha256,
        )
    finally:
        engine.dispose()
    print(
        json.dumps(
            {
                "run_id": result.run_id,
                "attempt_id": result.attempt_id,
                "organization_id": result.organization_id,
                "execution_ids": list(result.execution_ids),
                "trace_id": result.trace_id,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
