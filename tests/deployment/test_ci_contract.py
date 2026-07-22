"""Both CI systems must execute the full integration packaging gate."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Both CI systems must execute the same pinned security scanners. Each entry is a
# substring that only appears when that scanner is actually invoked; dropping the
# scanner from either workflow removes the substring and fails the parity test.
SECURITY_SCANNER_MARKERS = {
    "semgrep": "semgrep scan --config .semgrep.yml",
    "pip-audit": "pip-audit . --strict --progress-spinner=off",
    "promptfoo": "promptfoo@0.121.19 validate",
    "zap": "zap-baseline.py -t",
}
LLM_TOOL_RUNNER = "scripts/run_offline_llm_tools.sh"


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


def test_gitlab_ci_keeps_material_gates_on_the_unprivileged_runner() -> None:
    workflow = _workflow(".gitlab-ci.yml")
    for command in (
        "npm ci --ignore-scripts",
        "npm audit --audit-level=high",
        "npm run test:browser",
        "buildctl-daemonless.sh build",
        "Dockerfile.gitlab",
        "scripts/verify_container_archive.sh",
        "gitleaks git . --redact --verbose",
        "sha256sum --check --strict",
    ):
        assert command in workflow
    assert "docker:27.5.1-dind" not in workflow
    assert "DOCKER_HOST" not in workflow


def test_gitlab_daemonless_dockerfile_preserves_the_runtime_boundary() -> None:
    canonical = _workflow("Dockerfile")
    daemonless = _workflow("Dockerfile.gitlab")
    for marker in (
        "FROM python:3.12.11-slim-bookworm AS wheel-build",
        "python -m pip install --no-index --find-links=/wheels agentforge==0.1.0",
        "COPY alembic.ini /app/alembic.ini",
        "COPY migrations /app/migrations",
        "COPY evals /app/evals",
        "USER app",
        'CMD ["python", "-m", "agentforge.web"]',
    ):
        assert marker in canonical
        assert marker in daemonless


def test_github_ci_runs_every_pinned_security_scanner() -> None:
    workflow = _workflow(".github/workflows/ci.yml")
    for scanner, marker in SECURITY_SCANNER_MARKERS.items():
        assert marker in workflow, f"GitHub CI dropped the {scanner} scanner"
    assert LLM_TOOL_RUNNER in workflow


def test_gitlab_ci_runs_every_pinned_security_scanner() -> None:
    workflow = _workflow(".gitlab-ci.yml")
    for scanner, marker in SECURITY_SCANNER_MARKERS.items():
        assert marker in workflow, f"GitLab CI dropped the {scanner} scanner"
    assert LLM_TOOL_RUNNER in workflow


def test_both_ci_systems_pin_the_same_security_tool_versions() -> None:
    github = _workflow(".github/workflows/ci.yml")
    gitlab = _workflow(".gitlab-ci.yml")
    for pin in (
        "semgrep==1.170.0",
        "pip-audit==2.10.1",
        "promptfoo@0.121.19",
        "ghcr.io/zaproxy/zaproxy@sha256:"
        "c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a",
    ):
        assert pin in github, f"GitHub CI is missing pinned scanner version {pin}"
        assert pin in gitlab, f"GitLab CI is missing pinned scanner version {pin}"


def test_offline_llm_tool_runner_pins_native_tools_and_disables_remote_generation() -> None:
    runner = _workflow(LLM_TOOL_RUNNER)
    for marker in (
        "garak==0.15.1",
        "pyrit==0.14.0",
        "giskard_scan-1.0.0b3",
        "promptfoo@0.121.19 eval",
        "PROMPTFOO_DISABLE_REMOTE_GENERATION=true",
        "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true",
        "env -i",
        "security-tools/offline/validate_native_artifacts.py",
    ):
        assert marker in runner
