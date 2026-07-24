"""RED tests for WP-18A private, per-attempt OAST (out-of-band application security testing).

SSRF and blind data-exfiltration are proven by an out-of-band callback. AgentForge runs its OWN
private OAST — never a public collaborator service (that would exfiltrate to a third party). Each
attempt mints a fresh, unpredictable, nonce-derived callback subdomain on an authorized *private*
domain; a received callback correlates to exactly the attempt that minted it. A callback to an
unminted label or an unauthorized domain is an escape and fails closed.

Offline: no DNS, no listener — these pin the minting, correlation, and escape logic only.
"""

from __future__ import annotations

import pytest

from agentforge.security_tools.active_authorization import ActiveScanCaps, ActiveScanScope
from agentforge.security_tools.oast import OastEscape, PrivateOastRegistry


def _scope(*, callback_domains: tuple[str, ...] = ("oast.agentforge.internal",)) -> ActiveScanScope:
    return ActiveScanScope(
        origin="https://copilot.example-hospital.test",
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot/*",),
        principals=("synthetic-clinician-a",),
        image_sha256="a" * 64,
        addon_sha256s=("b" * 64,),
        rule_sha256s=("c" * 64,),
        callback_domains=callback_domains,
        caps=ActiveScanCaps.parse(
            max_requests=100,
            requests_per_second=10.0,
            max_duration_seconds=600.0,
            max_findings=200,
        ),
        scope_nonce="nonce-0123456789ab",
    )


def test_registry_refuses_a_public_or_target_callback_domain() -> None:
    for public in ("oast.example.com", "burpcollaborator.net", "copilot.example-hospital.test"):
        with pytest.raises(OastEscape, match="private"):
            PrivateOastRegistry(_scope(callback_domains=(public,)))


def test_mint_produces_a_fresh_per_attempt_callback_on_an_authorized_private_domain() -> None:
    reg = PrivateOastRegistry(_scope())
    a = reg.mint("attempt-1")
    b = reg.mint("attempt-2")
    assert a.callback_host.endswith(".oast.agentforge.internal")
    assert a.callback_url.startswith("https://") and "/cb/" in a.callback_url
    assert a.callback_host != b.callback_host, "each attempt gets a distinct OAST label"
    assert a.attempt_id == "attempt-1"


def test_mint_refuses_a_domain_the_scope_did_not_authorize() -> None:
    reg = PrivateOastRegistry(_scope())
    with pytest.raises(OastEscape, match="not authorized"):
        reg.mint("attempt-1", domain="other.agentforge.internal")


def test_label_is_nonce_derived_and_unpredictable_without_the_nonce() -> None:
    same = PrivateOastRegistry(_scope()).mint("attempt-1")
    again = PrivateOastRegistry(_scope()).mint("attempt-1")
    assert same.callback_host == again.callback_host, "deterministic for the same scope+attempt"

    other_scope = _scope()
    object.__setattr__(other_scope, "scope_nonce", "nonce-ffffffffffff")
    diff = PrivateOastRegistry(other_scope).mint("attempt-1")
    assert diff.callback_host != same.callback_host, "an attacker cannot guess the label"


def test_observe_callback_correlates_to_the_minting_attempt() -> None:
    reg = PrivateOastRegistry(_scope())
    token_a = reg.mint("attempt-1")
    reg.mint("attempt-2")
    hit = reg.observe_callback(f"https://{token_a.callback_host}/cb/attempt-1")
    assert hit.attempt_id == "attempt-1"
    assert reg.confirmed_attempts() == ("attempt-1",)


def test_observe_unminted_label_is_an_escape() -> None:
    reg = PrivateOastRegistry(_scope())
    reg.mint("attempt-1")
    with pytest.raises(OastEscape, match="unrecognized|unminted"):
        reg.observe_callback("https://deadbeef.oast.agentforge.internal/cb/x")


def test_observe_callback_off_the_authorized_domain_is_an_escape() -> None:
    reg = PrivateOastRegistry(_scope())
    token = reg.mint("attempt-1")
    label = token.callback_host.split(".", 1)[0]
    with pytest.raises(OastEscape, match="domain"):
        reg.observe_callback(f"https://{label}.evil.example.test/cb/x")
