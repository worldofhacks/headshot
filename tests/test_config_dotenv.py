"""Settings.from_env() must load .env then .env.local (local overrides) so the config layer
resolves file-provided variables via os.environ. Secrets loaded this way are resolved by
reference at use time — never logged or inlined."""

import os

from agentforge.config import Settings


def test_from_env_loads_dotenv_with_local_override(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("AGENTFORGE_ENVIRONMENT=staging\nDOTENV_PROBE=from_env_file\n")
    (tmp_path / ".env.local").write_text(
        "AGENTFORGE_ENVIRONMENT=production\nDOTENV_PROBE_LOCAL=from_local\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AGENTFORGE_ENVIRONMENT", raising=False)
    monkeypatch.delenv("DOTENV_PROBE", raising=False)
    monkeypatch.delenv("DOTENV_PROBE_LOCAL", raising=False)

    settings = Settings.from_env()

    # .env.local overrides .env
    assert settings.environment == "production"
    # file-provided vars are resolvable via os.environ afterwards (reference resolution)
    assert os.environ.get("DOTENV_PROBE") == "from_env_file"
    assert os.environ.get("DOTENV_PROBE_LOCAL") == "from_local"


def test_from_env_without_dotenv_files_is_a_safe_noop(tmp_path, monkeypatch):
    # A production container sets env directly and ships no .env files; missing files must
    # not raise — from_env still reads the process environment.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "local")
    assert Settings.from_env().environment == "local"
