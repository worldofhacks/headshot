"""Env-isolated dotenv loading for ``Settings.from_env`` — the security-hardened behavior.

Written first (RED). Replaces the retired ``tests/test_config_dotenv.py``, whose assertions
encoded the OLD, WRONG behavior: it let a ``.env.local`` file set
``AGENTFORGE_ENVIRONMENT=production`` and thereby *promote* the deployment environment, and
it loaded dotenv files in every environment. Both are security defects.

Correct, security-hardened contract under test (see the ticket / config.py design):

* ``AGENTFORGE_ENVIRONMENT`` is read from the REAL process environment FIRST (``os.environ``),
  defaulting to ``"local"``, and is VALIDATED before any file is loaded — an unknown value
  raises ``ValueError`` and loads NOTHING.
* ``.env.local`` and ``.env`` are loaded ONLY when the process-level environment is
  ``"local"``. ``staging`` and ``production`` skip dotenv loading ENTIRELY.
* A dotenv file's ``AGENTFORGE_ENVIRONMENT`` MUST NEVER change the deployment environment — a
  file cannot elevate ``local`` -> ``staging``/``production``. The environment is decided by
  the process env alone.
* Precedence for every OTHER variable in local mode: process env > ``.env.local`` > ``.env``
  > defaults.
* Missing files are a safe no-op.

Every test uses ``tmp_path`` + ``monkeypatch.chdir`` + ``monkeypatch.delenv/setenv`` so the
REAL repo ``.env`` / ``.env.local`` files are never read or touched. Fake sentinel values
only — no real-looking secret ever appears here.

spec(M1a:AC-2)
"""

from __future__ import annotations

import os

import pytest

from agentforge.config import Settings

# A fake sentinel secret value — never a real-looking captured key.
FAKE_SECRET_SENTINEL = "sentinel-shh-123"


# ---------------------------------------------------------------------------
# local mode — dotenv files ARE loaded, with correct precedence
# ---------------------------------------------------------------------------


def test_local_mode_loads_env_and_env_local(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — in local mode a probe var from EACH file resolves via os.environ.

    ``.env`` and ``.env.local`` are both loaded; a probe unique to each file is resolvable
    through ``os.environ`` after ``from_env()``.
    """
    (tmp_path / ".env").write_text("PROBE_FROM_ENV=from_env_file\n")
    (tmp_path / ".env.local").write_text("PROBE_FROM_LOCAL=from_local_file\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "local")
    monkeypatch.delenv("PROBE_FROM_ENV", raising=False)
    monkeypatch.delenv("PROBE_FROM_LOCAL", raising=False)

    settings = Settings.from_env()

    assert settings.environment == "local"
    assert os.environ.get("PROBE_FROM_ENV") == "from_env_file"
    assert os.environ.get("PROBE_FROM_LOCAL") == "from_local_file"


def test_process_env_overrides_both_files(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — a real process env var WINS over both dotenv files.

    Precedence is process env > .env.local > .env; a value already present in the real
    process environment must survive dotenv loading unchanged.
    """
    (tmp_path / ".env").write_text("PROBE=file\n")
    (tmp_path / ".env.local").write_text("PROBE=file\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "local")
    monkeypatch.setenv("PROBE", "proc")

    Settings.from_env()

    assert os.environ.get("PROBE") == "proc"


def test_env_local_overrides_env_for_shared_var(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — .env.local overrides .env for a shared probe var (no process value).

    With no real process value set for the shared key, ``.env.local`` must win over
    ``.env``.
    """
    (tmp_path / ".env").write_text("SHARED_PROBE=from_env\n")
    (tmp_path / ".env.local").write_text("SHARED_PROBE=from_local\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "local")
    monkeypatch.delenv("SHARED_PROBE", raising=False)

    Settings.from_env()

    assert os.environ.get("SHARED_PROBE") == "from_local"


# ---------------------------------------------------------------------------
# staging / production — dotenv loading is SKIPPED entirely
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("deploy_env", ["staging", "production"])
def test_non_local_env_ignores_both_dotenv_files(
    deploy_env: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """spec(M1a:AC-2) — staging/production must NOT read .env or .env.local at all.

    The files are present with a probe var, but because the process environment is not
    ``local`` no dotenv loading happens: the probe is ABSENT from ``os.environ`` afterward
    and the environment is exactly the deployed value.
    """
    (tmp_path / ".env").write_text("PROBE_NONLOCAL=should_not_load\n")
    (tmp_path / ".env.local").write_text("PROBE_NONLOCAL=should_not_load\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", deploy_env)
    monkeypatch.delenv("PROBE_NONLOCAL", raising=False)

    settings = Settings.from_env()

    assert settings.environment == deploy_env
    assert os.environ.get("PROBE_NONLOCAL") is None


# ---------------------------------------------------------------------------
# a dotenv file can NEVER elevate the deployment environment
# ---------------------------------------------------------------------------


def test_dotenv_file_cannot_elevate_environment(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — a file's AGENTFORGE_ENVIRONMENT must NOT promote local -> production.

    With no process-level AGENTFORGE_ENVIRONMENT, the environment defaults to ``local``.
    A ``.env.local`` that tries to set ``AGENTFORGE_ENVIRONMENT=production`` must be ignored:
    the resolved environment stays ``local`` and the process env is NOT left set to
    ``production`` by the file. This is the exact defect the retired test encoded as correct.
    """
    (tmp_path / ".env.local").write_text("AGENTFORGE_ENVIRONMENT=production\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AGENTFORGE_ENVIRONMENT", raising=False)

    settings = Settings.from_env()

    assert settings.environment == "local"
    assert os.environ.get("AGENTFORGE_ENVIRONMENT") != "production"


@pytest.mark.parametrize("deploy_env", ["staging", "production"])
def test_dotenv_secret_absent_in_non_local_env(
    deploy_env: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """spec(M1a:AC-2) — a sentinel secret in a dotenv file is ABSENT in staging AND production.

    A non-local deployment must never absorb a dotenv-file secret; the fake sentinel placed
    in ``.env.local`` must not appear in ``os.environ`` after ``from_env()``.
    """
    (tmp_path / ".env.local").write_text(f"SECRET_SENTINEL={FAKE_SECRET_SENTINEL}\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", deploy_env)
    monkeypatch.delenv("SECRET_SENTINEL", raising=False)

    Settings.from_env()

    assert os.environ.get("SECRET_SENTINEL") is None


# ---------------------------------------------------------------------------
# missing files + unknown environment
# ---------------------------------------------------------------------------


def test_missing_dotenv_files_is_a_safe_noop(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — with NO dotenv files present, local from_env() works and does not raise."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "local")

    settings = Settings.from_env()

    assert settings.environment == "local"


def test_unknown_environment_raises_and_loads_nothing(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """spec(M1a:AC-2) — an unknown AGENTFORGE_ENVIRONMENT raises ValueError and loads NO file.

    Validation happens BEFORE any file is read, so a near-miss like ``"prod"`` raises and a
    probe var placed in a dotenv file is never loaded into ``os.environ``.
    """
    (tmp_path / ".env").write_text("UNKNOWN_ENV_PROBE=should_not_load\n")
    (tmp_path / ".env.local").write_text("UNKNOWN_ENV_PROBE=should_not_load\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "prod")  # near-miss for "production"
    monkeypatch.delenv("UNKNOWN_ENV_PROBE", raising=False)

    with pytest.raises(ValueError):
        Settings.from_env()

    assert os.environ.get("UNKNOWN_ENV_PROBE") is None
