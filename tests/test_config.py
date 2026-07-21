"""M1a tests — env-separated config model + the environment-isolation invariant.

Written first (RED). Targets the PUBLIC API only (ARCHITECTURE.md §12, O1):

    from agentforge.config import Settings, EnvironmentIsolationError

    Settings()                       -> environment defaults to "local"
    Settings(environment=...)        -> "local" | "staging" | "production"
    settings.resolve_target_credential(target_id) -> a secret *reference string* in
        production; MUST refuse (raise EnvironmentIsolationError) in local/staging.

These assert observable behavior, not internal attribute names, so a lazy implementation
that hardcodes one path cannot pass. The module does not exist yet, so import fails => RED.
"""

from __future__ import annotations

import pytest

# spec(M1a:AC-2) spec(M1a:AC-5/O1) — module under test does not exist yet (expected RED).
from agentforge.config import EnvironmentIsolationError, Settings

# ---------------------------------------------------------------------------
# AC-2 — config env separation
# ---------------------------------------------------------------------------


def test_default_environment_is_local() -> None:
    """spec(M1a:AC-2) — with no override, the environment defaults to ``local``."""
    assert Settings().environment == "local"


@pytest.mark.parametrize("env", ["local", "staging", "production"])
def test_each_environment_is_representable(env: str) -> None:
    """spec(M1a:AC-2) — every allowed environment can be constructed and round-trips."""
    assert Settings(environment=env).environment == env


def test_all_three_environments_are_distinct() -> None:
    """spec(M1a:AC-2) — local/staging/production are three separate values, not aliases.

    Guards against a lazy model that collapses everything to one environment.
    """
    envs = {Settings(environment=e).environment for e in ("local", "staging", "production")}
    assert envs == {"local", "staging", "production"}


def test_unknown_environment_is_rejected() -> None:
    """spec(M1a:AC-2) — the environment is an enumerated set, not free text.

    ``environment`` must be constrained to {local, staging, production}; an arbitrary
    value must not silently become a fourth environment. Any exception at construction
    (ValueError, validation error, etc.) satisfies this — we assert it is NOT accepted.
    """
    with pytest.raises(Exception):  # noqa: B017 - any construction-time rejection is acceptable
        Settings(environment="prod")  # near-miss for "production" must not be accepted


# ---------------------------------------------------------------------------
# AC-5 / O1 — environment isolation invariant (also covered in test_env_isolation.py)
# ---------------------------------------------------------------------------


def test_production_resolves_a_credential_reference_not_an_inline_secret() -> None:
    """spec(M1a:AC-5/O1) — in production, resolving a target credential yields a *reference*.

    The returned value must be a non-empty string reference (e.g. a secret-manager URI or
    env var name) and must NOT be an inline secret. We can't know the exact secret, but a
    reference must at least mention the requested target id, proving it is a lookup handle
    rather than a hardcoded constant.
    """
    settings = Settings(environment="production")
    ref = settings.resolve_target_credential("openemr-copilot")

    assert isinstance(ref, str)
    assert ref  # non-empty
    assert "openemr-copilot" in ref  # a reference to *this* target, not a fixed blob


def test_production_reference_differs_per_target() -> None:
    """spec(M1a:AC-5/O1) — the reference is derived from the target id, not a single constant.

    Two different targets must resolve to two different references — a hardcoded return
    value would fail this and is exactly the lazy implementation we want to block.
    """
    settings = Settings(environment="production")
    ref_a = settings.resolve_target_credential("openemr-copilot")
    ref_b = settings.resolve_target_credential("some-other-target")
    assert ref_a != ref_b


@pytest.mark.parametrize("env", ["local", "staging"])
def test_non_production_refuses_to_resolve_production_credentials(env: str) -> None:
    """spec(M1a:AC-5/O1) — INVARIANT: a local/staging config CANNOT resolve prod target creds.

    This is the non-deferrable O1 isolation invariant, mirrored here from
    tests/test_env_isolation.py so the config suite fails loudly if it regresses.
    """
    settings = Settings(environment=env)
    with pytest.raises(EnvironmentIsolationError):
        settings.resolve_target_credential("openemr-copilot")


def test_environment_isolation_error_is_an_exception_type() -> None:
    """spec(M1a:AC-5/O1) — the refusal is a dedicated, catchable error type."""
    assert isinstance(EnvironmentIsolationError, type)
    assert issubclass(EnvironmentIsolationError, Exception)
