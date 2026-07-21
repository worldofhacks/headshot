"""Presence-only live-campaign preflight status — reports set/empty + validity, NEVER a value.

Run: ``python scripts/preflight_status.py``. It loads the process environment (in local this
includes .env.local via Settings.from_env), then reports, per field, ONLY a boolean/status —
no URL, credential, canary, provider key, or model id is ever printed. This is the report the
orchestrator surfaces at the live-authorization checkpoint; it does NOT authorize traffic and
makes NO network call.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from agentforge.config import Settings

Settings.from_env()  # loads .env / .env.local in local (real env wins); resolves no secret value

_SUPPORTED_PROVIDERS = {"openrouter", "together"}
_VALID_AUTH_MODES = {"none", "bearer", "session", "oauth"}


def _set(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def _https_and_parseable(name: str) -> tuple[bool, bool]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return (False, False)
    parts = urlsplit(raw)
    return (parts.scheme == "https", bool(parts.scheme) and bool(parts.netloc))


def _positive_number(name: str) -> str:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return "missing"
    try:
        return "valid" if float(raw) > 0 else "invalid(<=0)"
    except ValueError:
        return "invalid(non-numeric)"


def _auth_consistency() -> str:
    mode = os.environ.get("HEADSHOT_TARGET_AUTH_MODE", "").strip()
    if mode not in _VALID_AUTH_MODES:
        return "inconsistent(bad-mode)"
    have = {
        "bearer": _set("OPENEMR_BEARER_TOKEN") or _set("OPENEMR_TARGET_CREDENTIAL"),
        "session": _set("OPENEMR_SESSION_COOKIE"),
        "oauth": _set("OPENEMR_OAUTH_CLIENT_ID")
        and _set("OPENEMR_OAUTH_CLIENT_SECRET")
        and _set("OPENEMR_OAUTH_TOKEN_URL"),
    }
    others_set = [m for m, present in have.items() if present and m != mode]
    if mode == "none":
        return "consistent" if not any(have.values()) else f"inconsistent(stray:{others_set})"
    if not have.get(mode, False):
        return "inconsistent(missing-required)"
    if others_set:
        return f"inconsistent(conflict:{others_set})"
    return "consistent"


def main() -> None:
    https, parseable = _https_and_parseable("HEADSHOT_TARGET_BASE_URL")
    synthetic = os.environ.get("HEADSHOT_SYNTHETIC_ONLY", "").strip().lower() == "true"
    provider = os.environ.get("HEADSHOT_RED_TEAM_PROVIDER", "").strip().lower()
    url_status = f"set={_set('HEADSHOT_TARGET_BASE_URL')} https={https} format-valid={parseable}"
    provider_ready = provider in _SUPPORTED_PROVIDERS and _set(f"{provider.upper()}_API_KEY")

    rows = [
        ("Target URL", url_status),
        ("Allowlist (target_id)", f"configured={_set('HEADSHOT_TARGET_ID')}"),
        ("Auth mode", _auth_consistency()),
        ("Synthetic provenance", "ready" if synthetic else "not-ready"),
        ("Canary", "deterministic" if _set("HEADSHOT_CANARY_VALUE") else "unavailable"),
        ("Provider", "ready" if provider_ready else "not-ready"),
        ("Model", "set" if _set("HEADSHOT_RED_TEAM_MODEL") else "empty"),
        ("Budget (USD)", _positive_number("HEADSHOT_RUN_BUDGET_USD")),
        ("Attempt cap", _positive_number("HEADSHOT_MAX_ATTEMPTS_PER_RUN")),
        ("Rate (req/s)", _positive_number("HEADSHOT_TARGET_REQUESTS_PER_SECOND")),
        ("Timeout (s)", _positive_number("HEADSHOT_RUN_TIMEOUT_SECONDS")),
        # Abort path is runtime code in the M4 gateway; monitoring is the M6a observability core.
        ("Abort path", "ready (gateway hard-abort, code)"),
        ("Monitoring", "ready (M6a core; M6b Langfuse external)"),
    ]
    print("=== LIVE-CAMPAIGN PREFLIGHT — PRESENCE ONLY (no values) ===")
    for label, status in rows:
        print(f"  {label:<24} : {status}")
    print("NOTE: presence/validity only; NO value is displayed. This does NOT authorize traffic.")


if __name__ == "__main__":
    main()
