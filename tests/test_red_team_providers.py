"""M8 — Red Team PROVIDER RED tests (written first, NO src/ code).

Anchors: ARCHITECTURE.md §3/§8/§16 (F2/F7), PRD-14/17; .env.example RED-TEAM block
(HEADSHOT_RED_TEAM_PROVIDER / HEADSHOT_RED_TEAM_MODEL / OPENROUTER_API_KEY / TOGETHER_API_KEY).

A ``RedTeamProvider`` generates variant AttackAttempts. Two families:

  * FakeProvider / CassetteProvider — DETERMINISTIC, OFFLINE, zero network. A recorded cassette
    replays fixture responses; a REFUSAL / EMPTY generation is retried or switched to another
    cassette/strategy — never a silent stall. Used by the offline slice AND by every test here.
  * HostedProvider — the OpenRouter/Together boundary. Guarded by a provider/model VALIDATION
    preflight: the provider must be supported, ``HEADSHOT_RED_TEAM_MODEL`` must be non-empty, and
    a credential reference must be present. If the model is UNSET the hosted path typed-FAILS
    preflight while fake/cassette/seed stay fully usable. Even a passing preflight still requires
    EXPLICIT authorization to run — it never auto-fires. Its SDK import is LAZY and it is NEVER
    invoked in a test: we patch the network/SDK to RAISE and assert it is never reached.

Every test pins an edge/error. Until ``agentforge.agents.red_team.providers`` exists, every
import below fails and this module RED-collects for the right reason.
"""

from __future__ import annotations

import socket

import pytest

# The RT provider surface under test (does not exist yet -> RED by import error).
from agentforge.agents.red_team.providers import (  # noqa: E402
    CassetteProvider,
    FakeProvider,
    HostedProvider,
    HostedProviderConfig,
    ProviderAuthorizationError,
    ProviderPreflightError,
    preflight_hosted_provider,
)

# The canonical env keys (from .env.example). HEADSHOT_RED_TEAM_MODEL is THE model setting —
# there is deliberately no provider-specific alias (no OPENROUTER_MODEL).
_PROVIDER_ENV = "HEADSHOT_RED_TEAM_PROVIDER"
_MODEL_ENV = "HEADSHOT_RED_TEAM_MODEL"


def _seed_attempt(case_ref: str = "AF-M11-PI-001", category: str = "prompt_injection") -> dict:
    """A minimal, credential-free, partial-success AttackAttempt to mutate from."""
    return {
        "schema_version": "1",
        "case_ref": case_ref,
        "input_sequence": ["seed turn one"],
        "category": category,
    }


# ===========================================================================
# FAKE / CASSETTE — deterministic, offline, no network
# ===========================================================================
def test_fake_provider_generates_deterministic_variants() -> None:
    """The FakeProvider is a pure function of its input: two generate() calls over the same
    seed + count yield identical variants (deterministic offline generation, no model)."""
    provider = FakeProvider()
    seed = _seed_attempt()

    first = provider.generate(seed, count=3, category="prompt_injection")
    second = provider.generate(seed, count=3, category="prompt_injection")

    assert len(first) == 3
    assert first == second  # deterministic — no randomness


def test_cassette_provider_replays_recorded_responses_offline() -> None:
    """A CassetteProvider replays recorded fixture responses — no live generation. The replayed
    variants are exactly what the cassette holds, in order."""
    cassette = {
        "prompt_injection": ["variant A", "variant B"],
    }
    provider = CassetteProvider(cassette=cassette)

    variants = provider.generate(_seed_attempt(), count=2, category="prompt_injection")

    assert len(variants) == 2
    assert [v["input_sequence"][-1] for v in variants] == ["variant A", "variant B"]


# ===========================================================================
# (e) a REFUSAL / EMPTY response is retried/switched — NEVER a silent stall
# ===========================================================================
def test_refusal_response_is_retried_or_switched_not_stalled() -> None:
    """A cassette whose first strategy REFUSES must not silently stall: the provider retries or
    switches to another strategy and still returns a usable, non-empty variant."""
    cassette = {
        # strategy 0 refuses; strategy 1 succeeds — the provider must switch, not give up.
        "prompt_injection": ["__REFUSAL__", "recovered variant"],
    }
    provider = CassetteProvider(cassette=cassette)

    variants = provider.generate(_seed_attempt(), count=1, category="prompt_injection")

    assert variants, "a refusal was silently stalled instead of retried/switched"
    # The refusal sentinel must NOT be surfaced as a real variant.
    assert all("__REFUSAL__" not in v["input_sequence"][-1] for v in variants)


def test_empty_generation_is_retried_or_switched_not_stalled() -> None:
    """An EMPTY generation is likewise retried/switched — an empty first response is recovered,
    never returned as a silent zero-length stall."""
    cassette = {
        "prompt_injection": ["", "non-empty recovery"],
    }
    provider = CassetteProvider(cassette=cassette)

    variants = provider.generate(_seed_attempt(), count=1, category="prompt_injection")

    assert variants
    assert all(v["input_sequence"][-1] for v in variants), "an empty variant slipped through"


def test_persistent_refusal_raises_not_silent_stall() -> None:
    """If EVERY strategy refuses/empties, the provider must fail LOUDLY (a typed error), never
    return silently — a stall is a bug, an exhausted retry is an explicit signal."""
    cassette = {"prompt_injection": ["__REFUSAL__", "__REFUSAL__", ""]}
    provider = CassetteProvider(cassette=cassette)

    with pytest.raises((ProviderPreflightError, RuntimeError, ValueError)):
        provider.generate(_seed_attempt(), count=1, category="prompt_injection")


# ===========================================================================
# (g) HOSTED provider/model VALIDATION preflight — model UNSET typed-fails
# ===========================================================================
def test_hosted_preflight_typed_fails_when_model_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """HEADSHOT_RED_TEAM_MODEL UNSET -> the hosted preflight raises a TYPED
    ProviderPreflightError. The hosted path is unusable without a model; no network is touched.
    """
    monkeypatch.setenv(_PROVIDER_ENV, "openrouter")
    monkeypatch.delenv(_MODEL_ENV, raising=False)  # model UNSET

    config = HostedProviderConfig(
        provider="openrouter", model="", credential_ref="env:OPENROUTER_API_KEY"
    )

    with pytest.raises(ProviderPreflightError):
        preflight_hosted_provider(config)


def test_hosted_preflight_typed_fails_on_unsupported_provider() -> None:
    """An UNSUPPORTED provider fails the same typed preflight — only the allowlisted providers
    (openrouter / together) may pass, even with a model set."""
    config = HostedProviderConfig(
        provider="definitely-not-a-provider",
        model="some/model",
        credential_ref="env:OPENROUTER_API_KEY",
    )
    with pytest.raises(ProviderPreflightError):
        preflight_hosted_provider(config)


def test_hosted_preflight_typed_fails_when_credential_ref_missing() -> None:
    """A missing credential reference fails preflight — a hosted call with no key is refused
    up front, never attempted."""
    config = HostedProviderConfig(provider="openrouter", model="qwen/qwen-2.5", credential_ref="")
    with pytest.raises(ProviderPreflightError):
        preflight_hosted_provider(config)


def test_fake_and_cassette_still_work_when_hosted_preflight_would_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With HEADSHOT_RED_TEAM_MODEL unset (hosted would typed-fail), the OFFLINE fake/cassette
    modes remain FULLY usable — the offline slice never depends on the hosted path."""
    monkeypatch.delenv(_MODEL_ENV, raising=False)

    fake = FakeProvider().generate(_seed_attempt(), count=2, category="prompt_injection")
    cassette = CassetteProvider(cassette={"prompt_injection": ["x", "y"]}).generate(
        _seed_attempt(), count=2, category="prompt_injection"
    )

    assert len(fake) == 2
    assert len(cassette) == 2


# ===========================================================================
# (g) supported provider + non-empty model + credential ref -> preflight OK, but STILL not
#      auto-run; running requires EXPLICIT authorization
# ===========================================================================
def test_hosted_preflight_ok_for_supported_provider_model_and_credential() -> None:
    """A supported provider + non-empty model + present credential ref PASSES preflight.
    Preflight is a validation gate only — passing it does NOT dispatch anything."""
    config = HostedProviderConfig(
        provider="openrouter",
        model="qwen/qwen-2.5-72b-instruct",
        credential_ref="env:OPENROUTER_API_KEY",
    )
    result = preflight_hosted_provider(config)  # must not raise

    assert result.ok is True
    # Passing preflight is NOT permission to run: explicit authorization is still required.
    assert result.authorization_required is True


def test_hosted_generate_refuses_without_explicit_authorization() -> None:
    """Even with a passing preflight, the HostedProvider must NOT run without explicit
    authorization — generate() without authorization raises ProviderAuthorizationError and
    NEVER reaches an SDK / the network."""
    config = HostedProviderConfig(
        provider="openrouter",
        model="qwen/qwen-2.5-72b-instruct",
        credential_ref="env:OPENROUTER_API_KEY",
    )
    provider = HostedProvider(config=config)

    with pytest.raises(ProviderAuthorizationError):
        # authorized defaults to False -> a hosted run is refused BEFORE any SDK/network use.
        provider.generate(_seed_attempt(), count=1, category="prompt_injection")


def test_hosted_generate_typed_fails_preflight_when_model_unset_even_if_authorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit authorization does NOT bypass the model-unset preflight: an authorized hosted
    generate() with no model still typed-fails preflight and dispatches nothing."""
    monkeypatch.delenv(_MODEL_ENV, raising=False)
    config = HostedProviderConfig(
        provider="openrouter", model="", credential_ref="env:OPENROUTER_API_KEY"
    )
    provider = HostedProvider(config=config, authorized=True)

    with pytest.raises(ProviderPreflightError):
        provider.generate(_seed_attempt(), count=1, category="prompt_injection")


# ===========================================================================
# (h) NO network/socket and NO hosted-provider SDK call in ANY test — patch to RAISE
# ===========================================================================
def test_no_socket_opened_across_provider_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Break socket construction, then exercise the offline providers + every hosted refusal
    path — none may open a socket. The hosted provider is authorization/preflight-gated, so it
    never reaches the transport."""

    def boom(*_args, **_kwargs):
        raise AssertionError("a provider attempted network I/O (opened a socket)")

    monkeypatch.setattr(socket, "socket", boom)

    # Offline providers do real (offline) work with no socket.
    FakeProvider().generate(_seed_attempt(), count=2, category="prompt_injection")
    CassetteProvider(cassette={"prompt_injection": ["a", "b"]}).generate(
        _seed_attempt(), count=2, category="prompt_injection"
    )

    # Hosted provider is gated: an unauthorized run refuses BEFORE any socket.
    config = HostedProviderConfig(
        provider="openrouter",
        model="qwen/qwen-2.5-72b-instruct",
        credential_ref="env:OPENROUTER_API_KEY",
    )
    with pytest.raises(ProviderAuthorizationError):
        HostedProvider(config=config).generate(
            _seed_attempt(), count=1, category="prompt_injection"
        )
    # Preflight itself is network-free.
    assert preflight_hosted_provider(config).ok is True


def test_hosted_provider_never_imports_a_provider_sdk_at_module_load() -> None:
    """The provider SDK import must be LAZY — inside the hosted call path only. Importing the
    providers module (already done at collection) must NOT have imported an OpenRouter/Together/
    OpenAI SDK. If none is installed, the property holds trivially; if one is, it must be absent
    from ``sys.modules`` purely from importing the RT providers."""
    import sys

    import agentforge.agents.red_team.providers as providers_module  # noqa: F401

    # The RT provider module import alone must not have pulled in a hosted SDK.
    for sdk in ("openai", "together", "openrouter"):
        assert sdk not in sys.modules, (
            f"{sdk!r} was imported at RT-providers module load — the SDK import must be lazy, "
            "inside the hosted call path, never at package import (and never in a test)"
        )


def test_hosted_sdk_call_boundary_raises_if_ever_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    """Belt-and-suspenders: patch the hosted provider's lazy SDK-client factory to RAISE, then
    prove the authorization/preflight gates fire FIRST so the factory is never called."""
    config = HostedProviderConfig(
        provider="openrouter",
        model="qwen/qwen-2.5-72b-instruct",
        credential_ref="env:OPENROUTER_API_KEY",
    )
    provider = HostedProvider(config=config)  # unauthorized

    # If the hosted provider exposes a lazy client factory, break it so any real call explodes.
    if hasattr(provider, "_build_client"):

        def boom(*_args, **_kwargs):
            raise AssertionError("hosted provider constructed an SDK client (would hit network)")

        monkeypatch.setattr(provider, "_build_client", boom)

    with pytest.raises(ProviderAuthorizationError):
        provider.generate(_seed_attempt(), count=1, category="prompt_injection")
