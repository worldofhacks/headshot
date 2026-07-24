"""M8 — HostedProvider live-generation unit tests (injected fake OpenAI-wire client, NO network).

Anchors: ARCHITECTURE.md §3/§8/§16 (F2/F7), PRD-14/17; .env.example RED-TEAM block.

These exercise :meth:`HostedProvider._generate_via_client` directly with an INJECTED fake client
that mimics the OpenAI/OpenRouter chat-completions surface. No SDK is imported and no socket is
opened — the fake stands in for the transport. They pin two behaviours the task requires:

  * PARSING — a strict-JSON ``{"variants": [...]}`` response is parsed into the SAME
    ``{"input_sequence": [...seed turns..., continuation]}`` variant shape the offline providers
    return, and the bounded model/timeout/output-token caps are passed on the call.
  * EXHAUSTED / FAIL-CLOSED — an empty, unparseable, transport-erroring, or insufficient response
    raises a typed :class:`ProviderExhaustedError` instead of silently short-returning.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import pytest

from agentforge.agents.red_team.providers import (
    HOSTED_MAX_OUTPUT_TOKENS,
    HOSTED_REQUEST_TIMEOUT_S,
    HostedProvider,
    HostedProviderConfig,
    ProviderExhaustedError,
)

_MODEL = "deepseek/deepseek-chat"


def _config() -> HostedProviderConfig:
    return HostedProviderConfig(
        provider="openrouter", model=_MODEL, credential_ref="env:OPENROUTER_API_KEY"
    )


def _seed(case_ref: str = "AF-M11-PI-001") -> dict[str, Any]:
    """A minimal, credential-free seed AttackAttempt to generate continuations from."""
    return {
        "schema_version": "1",
        "case_ref": case_ref,
        "input_sequence": ["seed turn one"],
        "category": "prompt_injection",
    }


# --- Fake OpenAI-wire client -------------------------------------------------------------------
class _FakeMessage:
    def __init__(self, content: Any) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: Any) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: Any) -> None:
        self.choices = [_FakeChoice(content)]


class _FakeCompletions:
    def __init__(self, content: Any, calls: list[dict[str, Any]]) -> None:
        self._content = content
        self._calls = calls

    def create(self, **kwargs: Any) -> _FakeResponse:
        self._calls.append(kwargs)
        if isinstance(self._content, Exception):
            raise self._content
        return _FakeResponse(self._content)


class _FakeChat:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.completions = completions


class _FakeOpenAIClient:
    """Mimics ``client.chat.completions.create(...)`` and records every call's kwargs.

    ``content`` is returned (wrapped in the OpenAI response shape) on EVERY create call; if it is
    an ``Exception`` it is raised instead, modelling a transport/SDK failure.
    """

    def __init__(self, content: Any) -> None:
        self.calls: list[dict[str, Any]] = []
        self.chat = _FakeChat(_FakeCompletions(content, self.calls))


# --- PARSING -----------------------------------------------------------------------------------
def test_parses_strict_json_into_offline_variant_shape() -> None:
    """A valid ``{"variants": [...]}`` response parses into the exact shape FakeProvider returns:
    each variant's ``input_sequence`` is the seed's turns with the continuation appended last."""
    client = _FakeOpenAIClient(json.dumps({"variants": ["adversarial one", "adversarial two"]}))
    provider = HostedProvider(config=_config(), authorized=True)

    variants = provider._generate_via_client(client, _seed(), count=2, category="prompt_injection")

    assert variants == [
        {"input_sequence": ["seed turn one", "adversarial one"]},
        {"input_sequence": ["seed turn one", "adversarial two"]},
    ]


def test_generation_call_honors_model_and_bounded_caps() -> None:
    """The hosted call carries the canonical model id and the bounded timeout / output-token caps
    (a slow or runaway model can never overrun unbounded)."""
    client = _FakeOpenAIClient(json.dumps({"variants": ["a", "b"]}))
    provider = HostedProvider(config=_config(), authorized=True)

    provider._generate_via_client(client, _seed(), count=2, category="prompt_injection")

    assert client.calls, "the hosted client was never called"
    call = client.calls[0]
    assert call["model"] == _MODEL
    assert call["timeout"] == HOSTED_REQUEST_TIMEOUT_S
    assert call["max_tokens"] == HOSTED_MAX_OUTPUT_TOKENS


def test_generation_via_injected_client_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Break socket construction, then generate through the injected client — the parsing path
    touches no transport of its own (the fake client is the only boundary)."""

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("hosted generation attempted real network I/O (opened a socket)")

    monkeypatch.setattr(socket, "socket", boom)
    client = _FakeOpenAIClient(json.dumps({"variants": ["a", "b"]}))

    out = HostedProvider(config=_config(), authorized=True)._generate_via_client(
        client, _seed(), count=2, category="prompt_injection"
    )

    assert len(out) == 2


# --- EXHAUSTED / FAIL-CLOSED -------------------------------------------------------------------
def test_empty_variants_fails_closed() -> None:
    """An empty ``variants`` array is a refusal/empty: it raises ProviderExhaustedError, never a
    silent zero-length return."""
    client = _FakeOpenAIClient(json.dumps({"variants": []}))
    provider = HostedProvider(config=_config(), authorized=True)

    with pytest.raises(ProviderExhaustedError):
        provider._generate_via_client(client, _seed(), count=2, category="prompt_injection")


def test_unparseable_response_fails_closed() -> None:
    """A non-JSON (e.g. natural-language refusal) response fails closed — it cannot masquerade as
    a usable variant."""
    client = _FakeOpenAIClient("I'm sorry, I can't help with that.")
    provider = HostedProvider(config=_config(), authorized=True)

    with pytest.raises(ProviderExhaustedError):
        provider._generate_via_client(client, _seed(), count=1, category="prompt_injection")


def test_transport_error_fails_closed() -> None:
    """A transport/SDK failure surfaces as a typed ProviderExhaustedError (fail closed), never a
    leaked raw exception path or a silent stall."""
    client = _FakeOpenAIClient(RuntimeError("connection reset by peer"))
    provider = HostedProvider(config=_config(), authorized=True)

    with pytest.raises(ProviderExhaustedError):
        provider._generate_via_client(client, _seed(), count=1, category="prompt_injection")


def test_insufficient_variants_fails_closed_not_short_return() -> None:
    """Fewer usable variants than ``count`` fails loudly rather than silently short-returning."""
    client = _FakeOpenAIClient(json.dumps({"variants": ["only one usable"]}))
    provider = HostedProvider(config=_config(), authorized=True)

    with pytest.raises(ProviderExhaustedError):
        provider._generate_via_client(client, _seed(), count=3, category="prompt_injection")


def test_refusal_and_empty_entries_are_skipped_then_exhausts() -> None:
    """Refusal-sentinel and empty entries are skipped (never surfaced); if too few usable remain,
    it fails closed."""
    client = _FakeOpenAIClient(json.dumps({"variants": ["__REFUSAL__", "", "  "]}))
    provider = HostedProvider(config=_config(), authorized=True)

    with pytest.raises(ProviderExhaustedError):
        provider._generate_via_client(client, _seed(), count=1, category="prompt_injection")
