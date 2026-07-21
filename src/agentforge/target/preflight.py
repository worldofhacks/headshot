"""Fail-closed, NETWORK-FREE activation preflight for a live target (target #1: OpenEMR).

spec(M5) — ARCHITECTURE.md §2/§5, DECISIONS.md D14/D16; PRD-01.

The preflight is PURE config validation. It makes ZERO network calls, constructs NO HTTP
client, resolves NO live secret value, and opens NO socket — it only inspects the shape of the
config assembled from ``Settings``/env. Each rule is a DISTINCT typed failure (a
:class:`TargetPreflightError` subtype carrying an enumerated ``reason``), so a caller can tell
*which* gate refused activation.

Fail-closed means: an empty/insecure/malformed URL, an off-allowlist host, a bad auth mode, a
missing-or-conflicting credential, synthetic-mode-off, or a silently-absent canary each RAISE a
typed error — never a no-op, and NEVER a silent fallback to the P9 fake. There is no path from
a selected, misconfigured live adapter to :class:`FakeTargetAdapter`.

A fully-valid config PASSES but returns a :class:`PreflightResult` that EXPLICITLY does not
authorize traffic: ``ok=True`` with ``authorization_required=True`` and ``authorized=False``.
Setting the URL is not permission — activation still needs a separate, explicit authorization.

O1: off production, a live credential is NOT resolvable. ``resolve_target_credential`` raises in
local/staging, so the result reports ``credential_resolvable=False`` there (shape can still be
valid). No raw secret is ever echoed into the result's rendering.

Framework-neutral (D10): imports config/secrets only — no web framework, no httpx.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from agentforge.config import EnvironmentIsolationError, InvalidTargetIdError, Settings
from agentforge.secrets import Secret

# The enumerated auth modes a live target may use. Anything outside this set is a typed error.
_VALID_AUTH_MODES: frozenset[str] = frozenset({"none", "bearer", "session", "oauth"})


class PreflightReason(StrEnum):
    """Enumerated, distinct reasons a preflight can fail — one per rule."""

    EMPTY_URL = "empty-url"
    INSECURE_URL = "insecure-url"
    MALFORMED_URL = "malformed-url"
    OFF_ALLOWLIST_HOST = "off-allowlist-host"
    BAD_AUTH_MODE = "bad-auth-mode"
    MISSING_CREDENTIAL = "missing-credential"
    CONFLICTING_AUTH = "conflicting-auth"
    SYNTHETIC_OFF = "synthetic-off"
    ABSENT_CANARY = "absent-canary"
    MALFORMED_TARGET_ID = "malformed-target-id"


class TargetPreflightError(Exception):
    """Base of the typed preflight-error taxonomy. ``reason`` names the exact rule that failed.

    A dedicated, catchable base so a caller can distinguish a *fail-closed refusal* (the
    preflight doing its job) from an incidental bug, and the ``reason`` enum tells it precisely
    which gate refused activation.
    """

    reason: PreflightReason

    def __init__(self, message: str, *, reason: PreflightReason) -> None:
        super().__init__(message)
        self.reason = reason


class EmptyUrlError(TargetPreflightError):
    def __init__(self, message: str = "target base URL is empty") -> None:
        super().__init__(message, reason=PreflightReason.EMPTY_URL)


class InsecureUrlError(TargetPreflightError):
    def __init__(self, message: str = "target base URL must use https://") -> None:
        super().__init__(message, reason=PreflightReason.INSECURE_URL)


class MalformedUrlError(TargetPreflightError):
    def __init__(self, message: str = "target base URL is malformed") -> None:
        super().__init__(message, reason=PreflightReason.MALFORMED_URL)


class OffAllowlistHostError(TargetPreflightError):
    _DEFAULT = "target host is not the allowlisted host (exact match)"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.OFF_ALLOWLIST_HOST)


class BadAuthModeError(TargetPreflightError):
    _DEFAULT = "auth mode is not one of {none, bearer, session, oauth}"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.BAD_AUTH_MODE)


class MissingCredentialError(TargetPreflightError):
    _DEFAULT = "a credential the selected auth mode requires is missing"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.MISSING_CREDENTIAL)


class ConflictingAuthError(TargetPreflightError):
    _DEFAULT = "credentials for a mode other than the selected one are set"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.CONFLICTING_AUTH)


class SyntheticOffError(TargetPreflightError):
    _DEFAULT = "synthetic-only mode must be enabled (no real PHI, ever)"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.SYNTHETIC_OFF)


class AbsentCanaryError(TargetPreflightError):
    _DEFAULT = "canary is silently absent; set a value or declare it explicitly unavailable"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.ABSENT_CANARY)


class MalformedTargetIdError(TargetPreflightError):
    _DEFAULT = "target id is malformed (fails the strict identifier grammar)"

    def __init__(self, message: str = _DEFAULT) -> None:
        super().__init__(message, reason=PreflightReason.MALFORMED_TARGET_ID)


@dataclass(frozen=True)
class PreflightConfig:
    """The config a preflight validates — assembled from ``Settings``/env, all by reference.

    Secrets are :class:`Secret` wrappers (never raw strings), so no rendering of this config or
    the resulting :class:`PreflightResult` can echo a raw credential. Every field is a pure
    config value; the preflight never dereferences a live secret from any of them.
    """

    target_id: str
    base_url: str
    allowed_host: str
    auth_mode: str
    bearer_token: Secret | None = None
    session_cookie: Secret | None = None
    oauth_client_id: Secret | None = None
    oauth_client_secret: Secret | None = None
    oauth_token_url: str | None = None
    synthetic_only: bool = False
    canary_value: str | None = None
    canary_explicitly_unavailable: bool = False
    settings: Settings = Settings(environment="local")


@dataclass(frozen=True)
class PreflightResult:
    """The result of a PASSING preflight — shape is valid, but traffic is NOT authorized.

    ``ok`` is always ``True`` here (a failing preflight RAISES a typed error instead of
    returning). ``authorization_required`` is always ``True`` and ``authorized`` always
    ``False``: passing preflight is necessary but not sufficient — sending traffic still needs a
    separate, explicit authorization. ``credential_resolvable`` reflects O1: it is only ``True``
    in production, where ``resolve_target_credential`` can produce a secret *reference*; in
    local/staging it is ``False`` (a live credential is not resolvable off-production).

    ``__repr__``/``__str__`` never render a raw secret — the config holds only :class:`Secret`
    wrappers, and this result stores no raw credential at all.
    """

    ok: bool
    authorization_required: bool
    authorized: bool
    credential_resolvable: bool
    auth_mode: str
    target_id: str


def run_preflight(config: PreflightConfig) -> PreflightResult:
    """Validate ``config`` fail-closed and NETWORK-FREE; raise a typed error or return a result.

    Runs every rule in order; the FIRST breach raises its distinct
    :class:`TargetPreflightError` subtype. A fully-valid config returns a
    :class:`PreflightResult` that explicitly does NOT authorize traffic. Makes zero network
    calls, builds no HTTP client, and resolves no live secret value.
    """
    _check_url(config)  # rule 1: present + valid https://
    _check_host_allowlist(config)  # rule 2: exact-host match
    _check_auth_mode(config)  # rule 3: enumerated auth mode
    _check_required_credentials(config)  # rule 4: exactly the required creds present
    _check_conflicting_auth(config)  # rule 5: no creds for a different mode
    _check_synthetic_only(config)  # rule 6: synthetic-only ON
    _check_canary(config)  # rule 7: canary set OR explicitly unavailable

    # rule 8 / O1: a live credential is resolvable ONLY in production. This is a pure config
    # check on Settings.resolve_target_credential — it raises off-production (never a network
    # call, never a resolved raw secret). We swallow the value: only the boolean is kept.
    credential_resolvable = _credential_resolvable(config)

    # rule 9: passing preflight NEVER authorizes traffic — surface the explicit
    # "preflight_ok, authorization_required" state.
    return PreflightResult(
        ok=True,
        authorization_required=True,
        authorized=False,
        credential_resolvable=credential_resolvable,
        auth_mode=config.auth_mode,
        target_id=config.target_id,
    )


# --------------------------------------------------------------------------- rules


def _check_url(config: PreflightConfig) -> None:
    """Rule 1 — URL present and a VALID ``https://`` URL. Each failure is a distinct type."""
    url = config.base_url
    if not url:
        raise EmptyUrlError(
            "target base URL is empty — a live target requires an explicit https:// URL "
            "(empty is a typed error, never a no-op or a fake fallback)"
        )
    parts = urlsplit(url)
    if parts.scheme != "https":
        # http:// (or any non-https scheme) is refused: plaintext transport is never allowed.
        raise InsecureUrlError(
            f"target base URL {url!r} must use https:// (scheme was {parts.scheme or '(none)'!r})"
        )
    if not parts.hostname:
        raise MalformedUrlError(f"target base URL {url!r} is malformed — it has no host")


def _check_host_allowlist(config: PreflightConfig) -> None:
    """Rule 2 — the URL host must equal the allowlisted host EXACTLY (no subdomain/suffix)."""
    host = urlsplit(config.base_url).hostname
    # Exact, case-insensitive host equality only — no subdomain, no suffix, no wildcard.
    if host is None or host.lower() != config.allowed_host.lower():
        raise OffAllowlistHostError(
            f"target host {host!r} is not the allowlisted host {config.allowed_host!r} "
            "(EXACT match required — a subdomain or suffix lookalike is NOT admitted)"
        )


def _check_auth_mode(config: PreflightConfig) -> None:
    """Rule 3 — auth mode must be one of {none, bearer, session, oauth}."""
    if config.auth_mode not in _VALID_AUTH_MODES:
        allowed = ", ".join(sorted(_VALID_AUTH_MODES))
        raise BadAuthModeError(f"auth mode {config.auth_mode!r} is not one of: {allowed}")


def _check_required_credentials(config: PreflightConfig) -> None:
    """Rule 4 — EXACTLY the credential fields the chosen mode requires must be present."""
    mode = config.auth_mode
    if mode == "none":
        return  # 'none' requires no creds (a stray one is caught by rule 5)
    if mode == "bearer":
        if config.bearer_token is None:
            raise MissingCredentialError(
                "bearer mode requires a bearer token (OPENEMR_BEARER_TOKEN / credential ref)"
            )
        return
    if mode == "session":
        if config.session_cookie is None:
            raise MissingCredentialError(
                "session mode requires a session cookie (OPENEMR_SESSION_COOKIE)"
            )
        return
    if mode == "oauth":
        missing = [
            field_name
            for field_name, value in (
                ("oauth_client_id", config.oauth_client_id),
                ("oauth_client_secret", config.oauth_client_secret),
                ("oauth_token_url", config.oauth_token_url),
            )
            if value is None
        ]
        if missing:
            raise MissingCredentialError(
                f"oauth mode requires client_id + client_secret + token_url; missing: {missing}"
            )
        return


def _check_conflicting_auth(config: PreflightConfig) -> None:
    """Rule 5 — no credentials for a mode OTHER than the selected one may be set.

    A multi-mode config is ambiguous: refuse it rather than pick a silent precedence.
    """
    present = _present_credential_modes(config)
    # A mode is "in play" if any of its credential fields are populated. If any populated mode
    # is not the selected one, the config is conflicting.
    conflicting = present - {config.auth_mode}
    if conflicting:
        raise ConflictingAuthError(
            f"auth mode {config.auth_mode!r} selected, but credentials for other mode(s) "
            f"{sorted(conflicting)} are also set — ambiguous multi-mode config is refused"
        )


def _check_synthetic_only(config: PreflightConfig) -> None:
    """Rule 6 — synthetic-only mode must be enabled (no real PHI, ever)."""
    if not config.synthetic_only:
        raise SyntheticOffError(
            "HEADSHOT_SYNTHETIC_ONLY must be true — real PHI is never permitted; "
            "synthetic fixtures only"
        )


def _check_canary(config: PreflightConfig) -> None:
    """Rule 7 — a canary must be set OR explicitly declared unavailable (a deliberate decision).

    A silently-absent canary (no value AND not explicitly declared unavailable) is refused: the
    canary is a deliberate decision, never an accidental omission.
    """
    has_canary = bool(config.canary_value)
    if not has_canary and not config.canary_explicitly_unavailable:
        raise AbsentCanaryError(
            "canary is silently absent — set HEADSHOT_CANARY_VALUE or explicitly declare the "
            "no-canary state; a silently-missing canary is refused"
        )


# --------------------------------------------------------------------------- helpers


def _present_credential_modes(config: PreflightConfig) -> set[str]:
    """Return the set of auth modes for which ANY credential field is populated.

    'none' never appears here (it owns no credential fields), so a stray credential under
    'none' surfaces as a conflict with whichever real mode the credential belongs to.
    """
    present: set[str] = set()
    if config.bearer_token is not None:
        present.add("bearer")
    if config.session_cookie is not None:
        present.add("session")
    if any(
        value is not None
        for value in (
            config.oauth_client_id,
            config.oauth_client_secret,
            config.oauth_token_url,
        )
    ):
        present.add("oauth")
    return present


def _credential_resolvable(config: PreflightConfig) -> bool:
    """Rule 8 / O1 — is a live credential resolvable in this environment? (pure config check).

    Delegates to :meth:`Settings.resolve_target_credential`, which raises
    :class:`EnvironmentIsolationError` off production (local/staging) and only in production
    returns a secret *reference* string. We keep ONLY the boolean — the reference value is never
    stored or echoed, and this makes NO network call and dereferences NO live secret. The O1
    isolation refusal maps to ``False``; a malformed target id (only reachable in production,
    where the id is actually validated) becomes a TYPED :class:`MalformedTargetIdError` so every
    preflight failure stays inside the typed taxonomy (never a leaked ``InvalidTargetIdError``).
    """
    try:
        config.settings.resolve_target_credential(config.target_id)
    except EnvironmentIsolationError:
        # O1: a non-production box cannot resolve a live credential — report unresolved.
        return False
    except InvalidTargetIdError as exc:
        # Keep the fail-closed contract typed: a bad target id is a preflight refusal, not a
        # leaked ValueError subtype escaping run_preflight.
        raise MalformedTargetIdError(f"malformed target id: {exc}") from exc
    return True
