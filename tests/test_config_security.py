"""M1a security/correctness fixes — target_id validation + Settings.from_env() wiring.

Written first (RED). These target NEW public API in ``agentforge.config`` that does not
exist yet, so import / attribute access fails => RED for the right reason.

Two confirmed M1a findings drive this file:

**(C1) target_id validation before secret-reference construction.**
    ``resolve_target_credential(target_id)`` must validate ``target_id`` against a strict
    identifier charset (DNS-label-ish: lowercase alnum + hyphen, no leading/trailing
    hyphen, length 1-63) **after** the environment gate. A malformed id in *production*
    raises a new ``agentforge.config.InvalidTargetIdError`` (a ``ValueError`` subclass) and
    leaks NO ``secretref://`` string. Defense-in-depth ordering: on a non-prod box the
    environment gate runs FIRST, so a malformed id still raises ``EnvironmentIsolationError``
    — a local/staging config never reasons about production id validity at all.

**(Important) Settings.from_env() wiring.**
    ``Settings.from_env()`` reads the ``AGENTFORGE_ENVIRONMENT`` env var so the isolation
    boundary is enforced from the *deployed* environment, not accidentally-everywhere.

We assert observable behavior (raised type, returned reference string), never internal
attribute names, so a lazy implementation cannot pass.

spec(M1a:AC-5) spec(M1a:AC-2)
"""

from __future__ import annotations

import pytest

# spec(M1a:AC-5) spec(M1a:AC-2) — InvalidTargetIdError / from_env do not exist yet (RED).
from agentforge.config import (
    EnvironmentIsolationError,
    InvalidTargetIdError,
    Settings,
)

# ---------------------------------------------------------------------------
# (C1) AC-5 — target_id validation, in PRODUCTION (env gate already passed)
# ---------------------------------------------------------------------------

# Well-formed, DNS-label-ish target ids (lowercase alnum + hyphen, no edge hyphen, 1-63).
WELL_FORMED_TARGET_IDS = [
    "openemr-copilot",
    "some-other-target",
    "a",  # minimal single-char id
    "target1",  # trailing digit
    "x" * 63,  # max length
]

# Malformed ids that must be REJECTED. Includes path-traversal, separators, empties,
# whitespace, newline, a control/NUL byte, and an over-length id.
MALFORMED_TARGET_IDS = [
    "../staging/other",  # path traversal into another env's secret space
    "a/b/c",  # path separators
    "..%2f..%2fadmin",  # url-encoded traversal
    "",  # empty
    "has space",  # whitespace
    "line\nbreak",  # embedded newline
    "\x00x",  # NUL / control char
    "a" * 64,  # over the 63-char limit
    "-leading",  # leading hyphen (not DNS-label-ish)
    "trailing-",  # trailing hyphen
    "UPPER",  # uppercase not allowed
]


@pytest.mark.parametrize("target_id", WELL_FORMED_TARGET_IDS)
def test_production_accepts_well_formed_target_id(target_id: str) -> None:
    """spec(M1a:AC-5) — a well-formed id in production resolves to a secret reference.

    The validation must be a *gate*, not a blanket ban: legitimate DNS-label-ish ids
    still produce ``secretref://production/<target_id>``.
    """
    ref = Settings(environment="production").resolve_target_credential(target_id)
    assert ref == f"secretref://production/{target_id}"


def test_production_reference_shape_for_known_targets() -> None:
    """spec(M1a:AC-5) — the two named targets resolve to their exact prod references."""
    settings = Settings(environment="production")
    assert (
        settings.resolve_target_credential("openemr-copilot")
        == "secretref://production/openemr-copilot"
    )
    assert (
        settings.resolve_target_credential("some-other-target")
        == "secretref://production/some-other-target"
    )


@pytest.mark.parametrize("bad_id", MALFORMED_TARGET_IDS)
def test_production_rejects_malformed_target_id(bad_id: str) -> None:
    """spec(M1a:AC-5) — in production, a malformed id raises InvalidTargetIdError.

    The error is raised BEFORE any secret reference is built, so the reference string is
    never constructed for an attacker-controlled id (path traversal, separators, etc.).
    """
    settings = Settings(environment="production")
    with pytest.raises(InvalidTargetIdError):
        settings.resolve_target_credential(bad_id)


def test_invalid_target_id_error_is_a_valueerror_subclass() -> None:
    """spec(M1a:AC-5) — InvalidTargetIdError is a dedicated ValueError subclass.

    A ValueError subclass so generic ``except ValueError`` call sites still catch it, while
    a dedicated type lets callers distinguish a malformed-id refusal from other failures.
    """
    assert isinstance(InvalidTargetIdError, type)
    assert issubclass(InvalidTargetIdError, ValueError)


@pytest.mark.parametrize("bad_id", MALFORMED_TARGET_IDS)
def test_production_leaks_no_secretref_for_malformed_id(bad_id: str) -> None:
    """spec(M1a:AC-5) — a malformed id must NEVER yield a ``secretref://`` string.

    Even if a future regression turned the raise into a return, we assert no secret
    reference leaks: the call must raise, and if it (wrongly) returns, the value must not
    be a secretref for the attacker-controlled id.
    """
    settings = Settings(environment="production")
    try:
        result = settings.resolve_target_credential(bad_id)
    except InvalidTargetIdError:
        return  # correct: refused before constructing any reference
    # If we got here the call returned instead of raising — that is a leak. Fail loudly.
    pytest.fail(f"malformed target_id {bad_id!r} was not rejected; leaked: {result!r}")


# ---------------------------------------------------------------------------
# (C1) AC-5 — ORDERING / defense-in-depth: env gate runs BEFORE id validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", ["local", "staging"])
def test_non_production_gate_precedes_target_id_validation(env: str) -> None:
    """spec(M1a:AC-5) — on a non-prod box, a MALFORMED id still raises EnvironmentIsolationError.

    Defense-in-depth ordering: the environment gate runs FIRST. A local/staging config must
    never even reason about whether a production target id is well-formed — it refuses on
    the environment dimension alone. If the id validation ran first, a malformed id would
    raise InvalidTargetIdError here instead, which would be the WRONG error.
    """
    settings = Settings(environment=env)
    with pytest.raises(EnvironmentIsolationError):
        settings.resolve_target_credential("../x")


@pytest.mark.parametrize("env", ["local", "staging"])
def test_non_production_refusal_is_not_invalid_target_id_error(env: str) -> None:
    """spec(M1a:AC-5) — the non-prod refusal is the ISOLATION error, not the id-validation error.

    Pins the ordering precisely: a malformed id in local/staging must NOT surface as
    InvalidTargetIdError. (InvalidTargetIdError is a ValueError subclass, so we assert the
    raised error is not the id error even though both are exceptions.)
    """
    settings = Settings(environment=env)
    with pytest.raises(EnvironmentIsolationError) as excinfo:
        settings.resolve_target_credential("..%2f..%2fadmin")
    assert not isinstance(excinfo.value, InvalidTargetIdError)


# ---------------------------------------------------------------------------
# (Important) AC-2 — Settings.from_env() reads AGENTFORGE_ENVIRONMENT
# ---------------------------------------------------------------------------


def test_from_env_defaults_to_local_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — with AGENTFORGE_ENVIRONMENT unset, from_env() yields local.

    Fail-safe default: an un-configured deployment is treated as local and therefore is
    isolated from production credentials.
    """
    monkeypatch.delenv("AGENTFORGE_ENVIRONMENT", raising=False)
    assert Settings.from_env().environment == "local"


def test_from_env_reads_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — AGENTFORGE_ENVIRONMENT=production wires a production Settings.

    And that production config can resolve a well-formed prod target credential — proving
    the isolation boundary is enforced from the *deployed* environment variable.
    """
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "production")
    settings = Settings.from_env()
    assert settings.environment == "production"
    assert (
        settings.resolve_target_credential("openemr-copilot")
        == "secretref://production/openemr-copilot"
    )


def test_from_env_reads_staging(monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — AGENTFORGE_ENVIRONMENT=staging wires a staging Settings.

    And a staging config refuses to resolve production credentials (O1 boundary held).
    """
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "staging")
    settings = Settings.from_env()
    assert settings.environment == "staging"
    with pytest.raises(EnvironmentIsolationError):
        settings.resolve_target_credential("openemr-copilot")


def test_from_env_rejects_unknown_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M1a:AC-2) — an unknown AGENTFORGE_ENVIRONMENT value is rejected.

    ``"prod"`` is a near-miss for ``"production"`` and must NOT silently become a fourth
    environment; from_env() surfaces the existing construction-time ValueError.
    """
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "prod")
    with pytest.raises(ValueError):
        Settings.from_env()
