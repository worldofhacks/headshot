"""M5 tests — the fail-closed, NETWORK-FREE activation preflight, written FIRST (RED).

spec(M5) — ARCHITECTURE.md §2/§5, DECISIONS.md D14/D16; PRD-01.

The preflight is PURE config validation: it makes ZERO network calls and resolves NO live
secret value. It produces TYPED errors — a distinct typed failure per rule — and, when a
config is fully valid, an EXPLICIT 'preflight_ok, authorization_required' result (setting the
URL is NOT permission to send traffic). THERE IS NO FALLBACK from a selected, misconfigured
live adapter to the P9 fake — a config failure is a typed error, never a silent switch.

No live URL, no live credential, no PHI, no socket anywhere in this file. The preflight is
handed a config object built from Settings/env values; every field here is a fake sentinel.

Rules under test (each a DISTINCT typed failure):
  1. URL present + valid https:// (empty / http:// / malformed -> typed error)
  2. EXACT-host allowlisting (off-allowlist host, incl. subdomain/suffix -> typed error)
  3. auth mode in {none, bearer, session, oauth}   (else -> typed error)
  4. EXACTLY the creds the mode requires present, no others missing (missing -> typed error)
  5. CONFLICTING auth (creds for a different mode set -> typed error)
  6. SYNTHETIC-only requirement (synthetic-off -> typed error)
  7. CANARY set OR explicit no-canary declared (silently-absent -> typed error)
  8. secrets by REFERENCE only; O1 (local/staging cannot resolve a live credential)
  9. a fully-valid config PASSES but returns authorization_required (URL set != authorized)
"""

from __future__ import annotations

import socket

import pytest

from agentforge.config import Settings
from agentforge.secrets import Secret
from agentforge.target.preflight import (
    PreflightConfig,
    PreflightResult,
    TargetPreflightError,
    run_preflight,
)

# ---- fake sentinel values — never real-looking captured secrets ------------
FAKE_BEARER = "sentinel-bearer-abc123"
FAKE_SESSION_COOKIE = "sentinel-session-cookie-xyz"
FAKE_OAUTH_CLIENT_ID = "sentinel-client-id"
FAKE_OAUTH_CLIENT_SECRET = "sentinel-client-secret"
FAKE_OAUTH_TOKEN_URL = "https://openemr.example.test/oauth/token"
FAKE_CANARY = "CANARY-do-not-store-7f3a"

ALLOWED_HOST = "openemr.example.test"
VALID_URL = f"https://{ALLOWED_HOST}"


def _valid_config(**overrides) -> PreflightConfig:
    """A fully-valid bearer-mode config with an EXACT-host allowlist and synthetic-only ON.

    Every keyword override lets a test perturb exactly one field to isolate one rule.
    """
    base = {
        "target_id": "openemr",
        "base_url": VALID_URL,
        "allowed_host": ALLOWED_HOST,
        "auth_mode": "bearer",
        "bearer_token": Secret(FAKE_BEARER),
        "session_cookie": None,
        "oauth_client_id": None,
        "oauth_client_secret": None,
        "oauth_token_url": None,
        "synthetic_only": True,
        "canary_value": FAKE_CANARY,
        "canary_explicitly_unavailable": False,
        "settings": Settings(environment="local"),
    }
    base.update(overrides)
    return PreflightConfig(**base)


# ---------------------------------------------------------------------------
# (d) / rule 9 — a fully-valid config PASSES but requires explicit authorization
# ---------------------------------------------------------------------------


def test_valid_config_is_preflight_ok_but_authorization_required() -> None:
    """spec(M5) — a fully-valid config passes preflight, but the result EXPLICITLY does not
    authorize traffic: setting the URL is not permission. Activation still needs a separate,
    explicit authorization."""
    result = run_preflight(_valid_config())

    assert isinstance(result, PreflightResult)
    assert result.ok is True
    assert result.authorization_required is True
    # Passing preflight is NOT the same as being authorized to send.
    assert getattr(result, "authorized", False) is False


# ---------------------------------------------------------------------------
# rule 1 — URL present + a valid https:// URL
# ---------------------------------------------------------------------------


def test_empty_url_is_a_typed_error_not_a_noop_or_fallback() -> None:
    """spec(M5) — an empty URL is a TYPED config error, NOT a no-op and NOT a fake fallback."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(base_url=""))


def test_http_url_is_a_typed_error() -> None:
    """spec(M5) — a plaintext http:// URL is refused (https:// only)."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(base_url=f"http://{ALLOWED_HOST}"))


def test_malformed_url_is_a_typed_error() -> None:
    """spec(M5) — a malformed URL (no scheme/host) is a typed error."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(base_url="not-a-url", allowed_host="not-a-url"))


# ---------------------------------------------------------------------------
# rule 2 — EXACT-host allowlisting (no subdomain/suffix/wildcard match)
# ---------------------------------------------------------------------------


def test_off_allowlist_host_is_a_typed_error() -> None:
    """spec(M5) — a URL whose host is not the allowlisted host EXACTLY is refused."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(base_url="https://evil.example.test"))


def test_subdomain_of_allowlisted_host_is_rejected() -> None:
    """spec(M5) — EXACT match only: a subdomain of the allowlisted host is NOT admitted."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(base_url=f"https://sub.{ALLOWED_HOST}"))


def test_suffix_lookalike_host_is_rejected() -> None:
    """spec(M5) — a suffix/lookalike host (ending with the allowlisted host) is NOT admitted."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(base_url=f"https://not-{ALLOWED_HOST}"))


# ---------------------------------------------------------------------------
# rule 3 — auth mode must be one of {none, bearer, session, oauth}
# ---------------------------------------------------------------------------


def test_bad_auth_mode_is_a_typed_error() -> None:
    """spec(M5) — an auth mode outside the enumerated set is refused."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(auth_mode="basic", bearer_token=None))


# ---------------------------------------------------------------------------
# rule 4 — EXACTLY the creds the chosen mode requires are present
# ---------------------------------------------------------------------------


def test_bearer_mode_missing_token_is_a_typed_error() -> None:
    """spec(M5) — bearer mode with no bearer token is a typed missing-credential error."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(auth_mode="bearer", bearer_token=None))


def test_session_mode_missing_cookie_is_a_typed_error() -> None:
    """spec(M5) — session mode with no session cookie is a typed missing-credential error."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(auth_mode="session", bearer_token=None, session_cookie=None))


def test_oauth_mode_missing_fields_is_a_typed_error() -> None:
    """spec(M5) — oauth mode missing any of client_id/client_secret/token_url is a typed error."""
    with pytest.raises(TargetPreflightError):
        run_preflight(
            _valid_config(
                auth_mode="oauth",
                bearer_token=None,
                oauth_client_id=Secret(FAKE_OAUTH_CLIENT_ID),
                oauth_client_secret=Secret(FAKE_OAUTH_CLIENT_SECRET),
                oauth_token_url=None,  # missing
            )
        )


def test_none_mode_with_no_creds_is_accepted() -> None:
    """spec(M5) — 'none' mode requires NO creds; a clean none-mode config passes preflight."""
    result = run_preflight(_valid_config(auth_mode="none", bearer_token=None))
    assert result.ok is True
    assert result.authorization_required is True


# ---------------------------------------------------------------------------
# rule 5 — CONFLICTING auth (creds for a DIFFERENT mode than the selected one)
# ---------------------------------------------------------------------------


def test_conflicting_auth_is_a_typed_error() -> None:
    """spec(M5) — bearer selected but oauth fields ALSO populated is an ambiguous multi-mode
    config and is refused (no silent precedence)."""
    with pytest.raises(TargetPreflightError):
        run_preflight(
            _valid_config(
                auth_mode="bearer",
                bearer_token=Secret(FAKE_BEARER),
                oauth_client_id=Secret(FAKE_OAUTH_CLIENT_ID),
                oauth_client_secret=Secret(FAKE_OAUTH_CLIENT_SECRET),
                oauth_token_url=FAKE_OAUTH_TOKEN_URL,
            )
        )


def test_none_mode_with_a_credential_set_is_conflicting() -> None:
    """spec(M5) — 'none' mode must carry NO creds; a stray credential is a conflicting-auth
    typed error."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(auth_mode="none", bearer_token=Secret(FAKE_BEARER)))


# ---------------------------------------------------------------------------
# rule 6 — SYNTHETIC-only requirement (no real PHI, ever)
# ---------------------------------------------------------------------------


def test_synthetic_off_is_a_typed_error() -> None:
    """spec(M5) — HEADSHOT_SYNTHETIC_ONLY must be true; synthetic-off is refused (no PHI)."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(synthetic_only=False))


# ---------------------------------------------------------------------------
# rule 7 — CANARY set OR an explicit no-canary state declared
# ---------------------------------------------------------------------------


def test_silently_absent_canary_is_a_typed_error() -> None:
    """spec(M5) — a silently-absent canary (no value, not explicitly declared unavailable) is
    refused: the canary must be a deliberate decision."""
    with pytest.raises(TargetPreflightError):
        run_preflight(_valid_config(canary_value=None, canary_explicitly_unavailable=False))


def test_explicit_no_canary_state_is_accepted() -> None:
    """spec(M5) — an EXPLICIT no-canary declaration is a deliberate decision and passes."""
    result = run_preflight(_valid_config(canary_value=None, canary_explicitly_unavailable=True))
    assert result.ok is True
    assert result.authorization_required is True


# ---------------------------------------------------------------------------
# rule 8 — secrets by REFERENCE; O1 (local/staging cannot resolve a live credential)
# ---------------------------------------------------------------------------


def test_preflight_does_not_echo_a_raw_secret() -> None:
    """spec(M5) — the raw secret value never appears in the preflight result's rendering."""
    result = run_preflight(_valid_config())
    assert FAKE_BEARER not in repr(result)
    assert FAKE_BEARER not in str(result)


@pytest.mark.parametrize("deploy_env", ["local", "staging"])
def test_non_production_cannot_resolve_a_live_credential(deploy_env: str) -> None:
    """spec(M5, O1) — a non-production preflight reports config-SHAPE validity, but a LIVE
    credential is NOT resolvable there. resolve_target_credential must raise off-production,
    so the result must signal the credential is unresolved (not resolved to a value)."""
    result = run_preflight(_valid_config(settings=Settings(environment=deploy_env)))
    # Shape can still be valid; but the live credential is NOT resolved off-production.
    assert result.credential_resolvable is False


# ---------------------------------------------------------------------------
# (c) NO fallback to the P9 fake — a failure is a typed error, not a FakeAdapter
# ---------------------------------------------------------------------------


def test_misconfig_never_returns_a_fake_adapter() -> None:
    """spec(M5) — when OpenEMR is selected and misconfigured, preflight raises a typed error;
    it does NOT silently hand back a FakeTargetAdapter."""
    from agentforge.target.fake_adapter import FakeTargetAdapter

    with pytest.raises(TargetPreflightError) as excinfo:
        run_preflight(_valid_config(base_url=""))
    assert not isinstance(excinfo.value, FakeTargetAdapter)


# ---------------------------------------------------------------------------
# (e) NO network/socket call occurs in preflight — the client is patched to RAISE
# ---------------------------------------------------------------------------


def test_preflight_makes_no_socket_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M5) — preflight is NETWORK-FREE. Break socket construction; a passing preflight
    over a valid config then proves it opened ZERO sockets."""

    def boom(*_args, **_kwargs):
        raise AssertionError("preflight attempted network I/O (opened a socket)")

    monkeypatch.setattr(socket, "socket", boom)

    result = run_preflight(_valid_config())  # must not touch the network

    assert result.ok is True
    assert result.authorization_required is True


def test_preflight_never_constructs_the_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """spec(M5) — preflight resolves no live secret and builds no HTTP client. If httpx is
    importable, patch its Client to RAISE on construction and assert preflight still passes —
    proving preflight never instantiates the transport."""
    try:
        import httpx
    except ImportError:  # pragma: no cover — httpx optional at preflight time
        pytest.skip("httpx not installed; preflight is client-free regardless")

    def boom(*_args, **_kwargs):
        raise AssertionError("preflight constructed an HTTP client (would reach the network)")

    monkeypatch.setattr(httpx, "Client", boom)

    result = run_preflight(_valid_config())

    assert result.ok is True
    assert result.authorization_required is True


def test_production_malformed_target_id_is_a_typed_preflight_error() -> None:
    """spec(M5) — every preflight failure stays inside the typed taxonomy. In production a
    malformed target id makes Settings.resolve_target_credential raise InvalidTargetIdError;
    preflight must convert it to a typed MalformedTargetIdError, never leak the raw ValueError
    subtype out of run_preflight."""
    from agentforge.target.preflight import MalformedTargetIdError, TargetPreflightError

    with pytest.raises(TargetPreflightError) as exc:
        run_preflight(
            _valid_config(settings=Settings(environment="production"), target_id="../etc/passwd")
        )
    assert isinstance(exc.value, MalformedTargetIdError)
    assert exc.value.reason.value == "malformed-target-id"
