"""Railway config-as-code records exact process and migration commands."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _config(service: str) -> dict[str, object]:
    return json.loads((ROOT / "railway" / f"{service}.json").read_text(encoding="utf-8"))


def test_all_services_build_the_same_reviewed_dockerfile() -> None:
    for service in ("web", "runner", "scheduler"):
        build = _config(service)["build"]
        assert build == {"builder": "DOCKERFILE", "dockerfilePath": "Dockerfile"}


def test_web_alone_owns_migrations_readiness_and_public_process() -> None:
    deploy = _config("web")["deploy"]

    assert deploy["preDeployCommand"] == ["alembic upgrade head"]
    assert deploy["startCommand"] == "python -m agentforge.web"
    assert deploy["healthcheckPath"] == "/ready"


def test_private_processes_have_no_web_health_surface_or_migration_race() -> None:
    for service in ("runner", "scheduler"):
        deploy = _config(service)["deploy"]
        assert deploy["startCommand"] == f"python -m agentforge.{service}"
        assert "healthcheckPath" not in deploy
        assert "preDeployCommand" not in deploy
