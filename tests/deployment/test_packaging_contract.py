"""Static, deterministic checks for the production image boundary."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_dockerfile_is_a_three_stage_console_wheel_runtime_build() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert re.search(r"^FROM node:[^\n]+ AS console-build$", dockerfile, re.MULTILINE)
    assert re.search(r"^FROM python:[^\n]+ AS wheel-build$", dockerfile, re.MULTILINE)
    assert re.search(r"^FROM python:[^\n]+ AS runtime$", dockerfile, re.MULTILINE)
    assert "npm ci --ignore-scripts" in dockerfile
    assert "npm run build" in dockerfile
    assert "ARG VITE_CLERK_PUBLISHABLE_KEY" in dockerfile
    assert "python -m pip wheel" in dockerfile


def test_runtime_contains_only_built_console_assets_and_deploy_artifacts() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split(" AS runtime", maxsplit=1)[1]

    assert re.search(r"COPY --from=console-build .*?/dist /app/console", runtime)
    assert "COPY alembic.ini /app/alembic.ini" in runtime
    assert "COPY migrations /app/migrations" in runtime
    assert "COPY console" not in runtime
    assert "node_modules" not in runtime
    assert "CLERK_SECRET_KEY" not in dockerfile


def test_runtime_is_non_root_port_aware_and_has_liveness_only_healthcheck() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split(" AS runtime", maxsplit=1)[1]

    assert "USER app" in runtime
    assert 'CMD ["python", "-m", "agentforge.web"]' in runtime
    assert "PORT" in runtime
    healthcheck = next(line for line in runtime.splitlines() if "urllib.request.urlopen" in line)
    assert "/health" in healthcheck
    assert "/ready" not in healthcheck
    assert "curl" not in runtime


def test_docker_context_excludes_node_outputs_maps_and_local_render_artifacts() -> None:
    patterns = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "**/node_modules" in patterns
    assert "**/dist" in patterns
    assert "**/*.map" in patterns
    assert "tmp" in patterns


def test_local_compose_requires_the_public_clerk_build_identifier() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert "VITE_CLERK_PUBLISHABLE_KEY: ${VITE_CLERK_PUBLISHABLE_KEY:?required}" in compose


def test_local_compose_passes_only_explicit_web_auth_configuration() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    for name in (
        "CLERK_PUBLISHABLE_KEY",
        "CLERK_JWT_KEY",
        "CLERK_AUTHORIZED_PARTIES",
        "CLERK_REQUIRED_ORG_ID",
        "CLERK_FRONTEND_API_ORIGIN",
        "AGENTFORGE_MAX_REQUEST_BYTES",
        "PORT",
    ):
        assert f"{name}: ${{{name}:?required}}" in compose
    assert "AGENTFORGE_CONSOLE_DIR: /app/console" in compose
    assert "CLERK_SECRET_KEY" not in compose


def test_environment_template_documents_the_operational_web_contract() -> None:
    template = (ROOT / ".env.example").read_text(encoding="utf-8")

    for binding in (
        "PORT=8000",
        "AGENTFORGE_CONSOLE_DIR=console/dist",
        "AGENTFORGE_MAX_REQUEST_BYTES=1048576",
        "CLERK_FRONTEND_API_ORIGIN=",
        "CLERK_AUTHORIZED_PARTIES=http://localhost:8000",
    ):
        assert binding in template
    assert "future Vite console integration" not in template
    assert "future app integration" not in template
