"""Both CI systems must execute the full integration packaging gate."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _workflow(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_github_ci_runs_frontend_browser_bundle_and_audit_gates() -> None:
    workflow = _workflow(".github/workflows/ci.yml")
    for command in (
        "npm ci --ignore-scripts",
        "npm audit --audit-level=high",
        "npm run typecheck",
        "npm test",
        "npm run check:forbidden",
        "npm run build",
        "npm run check:bundle",
        "npm run test:browser",
    ):
        assert command in workflow


def test_github_ci_runs_in_image_migrations_runtime_and_secret_scan() -> None:
    workflow = _workflow(".github/workflows/ci.yml")
    assert "scripts/verify_runtime_image.sh" in workflow
    assert "scripts/verify_container_migrations.sh" in workflow
    assert "scripts/smoke_ready_container.sh" in workflow
    assert "scripts/smoke_runtime_container.sh" in workflow
    assert "gitleaks git . --redact --verbose" in workflow
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in workflow
    assert "sha256sum --check --strict" in workflow


def test_gitlab_ci_keeps_the_same_material_gates() -> None:
    workflow = _workflow(".gitlab-ci.yml")
    for command in (
        "npm ci --ignore-scripts",
        "npm audit --audit-level=high",
        "npm run test:browser",
        "scripts/verify_runtime_image.sh",
        "scripts/verify_container_migrations.sh",
        "scripts/smoke_ready_container.sh",
        "scripts/smoke_runtime_container.sh",
        "gitleaks git . --redact --verbose",
        "sha256sum --check --strict",
    ):
        assert command in workflow
