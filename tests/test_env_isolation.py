"""M1a environment-isolation INVARIANT (O1) — the non-deferrable safety property.

spec(M1a:AC-5/O1)

The platform must NEVER let a non-production (local or staging) configuration resolve a
*production* target credential. This is an architectural invariant (ARCHITECTURE.md O1,
IMPLEMENTATION_PLAN.md M1a accept (e)), not a nice-to-have: a leaked prod live-target
credential from a dev box is exactly the failure mode the isolation boundary exists to
prevent. This file is the dedicated home of that invariant; test_config.py mirrors it.

The public contract under test:

    from agentforge.config import Settings, EnvironmentIsolationError

    Settings(environment="production").resolve_target_credential(tid) -> reference string
    Settings(environment="local"|"staging").resolve_target_credential(tid)
        -> raises EnvironmentIsolationError   (MUST refuse — never returns a secret/ref)

Module does not exist yet, so this errors on import (expected RED).
"""

from __future__ import annotations

import pytest

from agentforge.config import EnvironmentIsolationError, Settings

TARGET_ID = "openemr-copilot"  # the first target (a live prod system); see CLAUDE.md.

NON_PRODUCTION_ENVIRONMENTS = ["local", "staging"]


@pytest.mark.parametrize("env", NON_PRODUCTION_ENVIRONMENTS)
def test_non_production_config_cannot_resolve_production_credentials(env: str) -> None:
    """spec(M1a:AC-5/O1) — INVARIANT: staging/local MUST refuse prod target credentials.

    The refusal must be the dedicated EnvironmentIsolationError so callers can distinguish
    a policy refusal from an incidental bug.
    """
    settings = Settings(environment=env)
    with pytest.raises(EnvironmentIsolationError):
        settings.resolve_target_credential(TARGET_ID)


@pytest.mark.parametrize("env", NON_PRODUCTION_ENVIRONMENTS)
def test_refusal_leaks_no_reference_and_no_secret(env: str) -> None:
    """spec(M1a:AC-5/O1) — the refusal must return NOTHING, not a partial/degraded reference.

    A lazy implementation might return an empty string or ``None`` instead of raising; that
    would silently pass a call site expecting a truthy reference and defeats the invariant.
    We assert the call *raises* and never yields a value.
    """
    settings = Settings(environment=env)
    with pytest.raises(EnvironmentIsolationError):
        result = settings.resolve_target_credential(TARGET_ID)
        # Unreached if the invariant holds; if reached, the call returned instead of raising.
        pytest.fail(f"{env} config resolved a production credential: {result!r}")


def test_production_config_can_resolve_production_credentials() -> None:
    """spec(M1a:AC-5/O1) — the invariant is a *boundary*, not a blanket ban.

    Production MUST still resolve, or the isolation check is indistinguishable from a total
    outage. The resolved value is a reference string keyed to the target, never inline.
    """
    settings = Settings(environment="production")
    ref = settings.resolve_target_credential(TARGET_ID)
    assert isinstance(ref, str)
    assert ref
    assert TARGET_ID in ref


def test_isolation_is_decided_by_environment_not_by_target_id() -> None:
    """spec(M1a:AC-5/O1) — the SAME target id resolves in prod and refuses in staging/local.

    This pins the boundary to the *environment* dimension: identical inputs, opposite
    outcomes purely because the config's environment differs. Prevents an implementation
    from gating on target-id spelling instead of the environment.
    """
    assert Settings(environment="production").resolve_target_credential(TARGET_ID)

    for env in NON_PRODUCTION_ENVIRONMENTS:
        with pytest.raises(EnvironmentIsolationError):
            Settings(environment=env).resolve_target_credential(TARGET_ID)


def test_default_config_is_isolated() -> None:
    """spec(M1a:AC-5/O1) — the DEFAULT config (no env given) is local and therefore refuses.

    Fail-safe by default: an un-configured Settings must not be able to reach prod creds.
    """
    with pytest.raises(EnvironmentIsolationError):
        Settings().resolve_target_credential(TARGET_ID)
