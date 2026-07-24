"""Red Team providers — offline generators + the guarded hosted boundary (M8).

ARCHITECTURE.md §3/§8/§16 (F2/F7), PRD-14/17; .env.example RED-TEAM block
(HEADSHOT_RED_TEAM_PROVIDER / HEADSHOT_RED_TEAM_MODEL / OPENROUTER_API_KEY / TOGETHER_API_KEY).

A ``RedTeamProvider`` turns a seed attempt into ``count`` variant *continuations* (each a last
turn to append). Two families:

* :class:`FakeProvider` / :class:`CassetteProvider` — DETERMINISTIC, OFFLINE, zero network. A
  cassette replays recorded fixture responses; a REFUSAL (the ``__REFUSAL__`` sentinel) or an
  EMPTY generation is retried/switched to the next strategy — never a silent stall. If EVERY
  strategy refuses/empties, generation fails LOUDLY with a typed :class:`ProviderExhaustedError`.
  These power the offline slice and every test.
* :class:`HostedProvider` — the OpenRouter / Together boundary. It is guarded by a provider/model
  VALIDATION preflight (:func:`preflight_hosted_provider`): the provider must be supported,
  ``HEADSHOT_RED_TEAM_MODEL`` (carried on the config) must be non-empty, and a credential
  reference must be present. A passing preflight is NOT permission to run — the hosted provider
  additionally requires EXPLICIT authorization, and even then dispatches through the SAME trusted
  gateway. Its provider-SDK import is LAZY (inside :meth:`HostedProvider._build_client` only,
  never at module load) and is never reached in a test.

``HEADSHOT_RED_TEAM_MODEL`` is the single canonical model setting — there is deliberately no
provider-specific alias (no ``OPENROUTER_MODEL``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

# The env keys (from .env.example) that select and configure the hosted provider. Read only for
# reference/validation here; the gateway (M4) stays authoritative over budget/rate/timeout.
PROVIDER_ENV = "HEADSHOT_RED_TEAM_PROVIDER"
MODEL_ENV = "HEADSHOT_RED_TEAM_MODEL"

# The ONLY hosted providers the preflight admits. An unsupported provider fails preflight even
# with a model set — the boundary is allowlisted, not open.
SUPPORTED_HOSTED_PROVIDERS: frozenset[str] = frozenset({"openrouter", "together"})

# The sentinel a cassette uses to model a provider REFUSAL. It must never surface as a variant;
# it triggers a retry/switch to the next recorded strategy instead.
REFUSAL_SENTINEL = "__REFUSAL__"


class ProviderPreflightError(RuntimeError):
    """The hosted provider/model validation preflight failed (typed, fail-closed).

    Raised when the provider is unsupported, ``HEADSHOT_RED_TEAM_MODEL`` is unset/empty, or the
    credential reference is missing. A ``RuntimeError`` subclass so a broad ``except`` still
    catches it, while the dedicated type lets a caller distinguish a validation refusal from an
    incidental bug. The offline fake/cassette/seed modes never raise this — only the hosted path.
    """


class ProviderAuthorizationError(RuntimeError):
    """A hosted generation was attempted without EXPLICIT authorization (typed, fail-closed).

    Raised by :meth:`HostedProvider.generate` when ``authorized`` is not True — BEFORE any SDK is
    built or any network is touched. Passing the preflight is a validation gate only; running the
    hosted provider is a separate, deliberate authorization.
    """


class ProviderExhaustedError(RuntimeError):
    """Every generation strategy refused or came back empty (typed, fail-closed).

    Raised instead of returning a silent zero-length result: an exhausted retry is an EXPLICIT
    signal, a silent stall is a bug. A ``RuntimeError`` subclass so the retry/switch tests can
    catch it broadly.
    """


@runtime_checkable
class RedTeamProvider(Protocol):
    """A generator of variant continuations for a seed attempt.

    ``generate`` returns ``count`` variant dicts, each carrying an ``input_sequence`` whose last
    turn is the newly generated continuation appended to the seed's own turns (so a multi-turn
    attack stays first-class). A provider produces PROPOSED input only — never a credential and
    never evidence.
    """

    def generate(
        self, seed: dict[str, Any], *, count: int, category: str
    ) -> list[dict[str, Any]]: ...


def _variant_from_continuation(seed: dict[str, Any], continuation: str) -> dict[str, Any]:
    """Build a variant dict by appending ``continuation`` as a new final turn to the seed's turns.

    The variant carries only proposed input (``input_sequence``); ``mutation.mutate`` wraps it
    into a full, lineage-tagged, schema-valid AttackAttempt. No trusted field is ever attached.
    """
    turns = list(seed.get("input_sequence", []))
    turns.append(continuation)
    return {"input_sequence": turns}


def _collect_usable(
    seed: dict[str, Any], strategies: list[str], count: int
) -> list[dict[str, Any]]:
    """Walk ``strategies`` in order, SKIPPING refusals/empties, until ``count`` usable variants.

    A ``__REFUSAL__`` sentinel or an empty string is a refusal/empty response: it is retried by
    switching to the NEXT strategy, never surfaced as a variant and never a silent stall. If the
    strategies are exhausted before ``count`` usable variants are found, a typed
    :class:`ProviderExhaustedError` is raised (loud failure, not a silent short return).
    """
    variants: list[dict[str, Any]] = []
    for continuation in strategies:
        if continuation == REFUSAL_SENTINEL or continuation == "":
            continue  # refusal/empty -> switch to the next strategy (retry, not stall)
        variants.append(_variant_from_continuation(seed, continuation))
        if len(variants) == count:
            return variants
    raise ProviderExhaustedError(
        f"every generation strategy refused or came back empty ({len(strategies)} tried); "
        f"could not produce {count} usable variant(s) — failing loudly, not stalling silently"
    )


@dataclass
class FakeProvider:
    """A pure-function, offline generator: variant text is a deterministic function of the input.

    Two ``generate`` calls over the same seed + count + category yield IDENTICAL variants (no
    randomness, no model, no network). It never refuses and never returns empty, so the offline
    slice and every test have a stable, network-free generator.
    """

    def generate(self, seed: dict[str, Any], *, count: int, category: str) -> list[dict[str, Any]]:
        case_ref = seed.get("case_ref", "seed")
        # Deterministic, non-refusal, non-empty continuations derived from the seed + index.
        strategies = [f"mutation::{category}::{case_ref}::v{i}" for i in range(count)]
        return _collect_usable(seed, strategies, count)


@dataclass
class CassetteProvider:
    """Replays RECORDED fixture responses per category — offline, no live generation.

    ``cassette`` maps a category to an ordered list of recorded continuations. Replay walks that
    list in order; a ``__REFUSAL__`` or empty entry is retried/switched to the next entry, never
    surfaced. If the recorded strategies are exhausted before ``count`` usable variants are found,
    a typed :class:`ProviderExhaustedError` is raised — a stall is a bug, an exhausted retry is an
    explicit signal.
    """

    cassette: dict[str, list[str]]

    def generate(self, seed: dict[str, Any], *, count: int, category: str) -> list[dict[str, Any]]:
        strategies = list(self.cassette.get(category, []))
        return _collect_usable(seed, strategies, count)


@dataclass(frozen=True)
class HostedProviderConfig:
    """The hosted provider selection: provider adapter, canonical model id, credential reference.

    ``model`` is the value of ``HEADSHOT_RED_TEAM_MODEL`` (the single canonical model setting).
    ``credential_ref`` is a REFERENCE to the key (e.g. ``env:OPENROUTER_API_KEY``), never an
    inline secret.
    """

    provider: str
    model: str
    credential_ref: str


@dataclass(frozen=True)
class PreflightResult:
    """The outcome of a hosted provider/model validation preflight.

    ``ok`` is True only when provider + model + credential ref all validate.
    ``authorization_required`` is always True on a passing preflight — validating the config is
    NOT permission to run; a hosted run still needs explicit authorization.
    """

    ok: bool
    authorization_required: bool
    provider: str
    model: str


def preflight_hosted_provider(config: HostedProviderConfig) -> PreflightResult:
    """Validate a hosted provider/model/credential triple BEFORE any network is touched.

    Fails closed with a typed :class:`ProviderPreflightError` when the provider is unsupported,
    ``HEADSHOT_RED_TEAM_MODEL`` (``config.model``) is unset/empty, or the credential reference is
    missing. On success returns a :class:`PreflightResult` with ``ok=True`` and
    ``authorization_required=True`` — a passing preflight validates the config but does NOT
    dispatch anything and does NOT authorize a run. This function is entirely network-free.
    """
    provider = (config.provider or "").strip().lower()
    if provider not in SUPPORTED_HOSTED_PROVIDERS:
        supported = ", ".join(sorted(SUPPORTED_HOSTED_PROVIDERS))
        raise ProviderPreflightError(
            f"unsupported hosted provider {config.provider!r} "
            f"({PROVIDER_ENV}); expected one of: {supported}"
        )
    if not (config.model or "").strip():
        raise ProviderPreflightError(
            f"{MODEL_ENV} is unset/empty; the hosted path is unusable without a model id "
            "(fake/cassette/seed modes remain fully usable)"
        )
    if not (config.credential_ref or "").strip():
        raise ProviderPreflightError(
            f"no credential reference for hosted provider {provider!r}; a hosted call with no "
            "key is refused up front, never attempted"
        )
    return PreflightResult(
        ok=True, authorization_required=True, provider=provider, model=config.model
    )


@dataclass
class HostedProvider:
    """The OpenRouter / Together boundary — preflight- AND authorization-gated, SDK import lazy.

    :meth:`generate` runs the validation preflight FIRST (so a model-unset config typed-fails even
    if authorized), then refuses unless ``authorized`` is explicitly True, raising
    :class:`ProviderAuthorizationError` BEFORE any SDK is built or any socket is opened. Only past
    both gates is the lazy provider SDK constructed (via :meth:`_build_client`) and a real hosted
    call made — a path this M8 slice never exercises in a test, and which itself dispatches
    generated attempts through the SAME trusted gateway (budget/rate/abort) as every other attempt.
    """

    config: HostedProviderConfig
    authorized: bool = False

    def generate(self, seed: dict[str, Any], *, count: int, category: str) -> list[dict[str, Any]]:
        # (1) Validation preflight first — a bad provider/model/credential fails closed here,
        # even when the caller has already granted authorization (authorization never bypasses
        # validation).
        preflight_hosted_provider(self.config)

        # (2) Explicit authorization gate — a passing preflight is NOT permission to run. This
        # refuses BEFORE any SDK is built or any network is reached.
        if not self.authorized:
            raise ProviderAuthorizationError(
                "hosted generation requires EXPLICIT authorization; preflight passed but the "
                "provider is not authorized to run (no SDK built, no network touched)"
            )

        # (3) Only past both gates is the lazy SDK constructed and a real hosted call made. This
        # branch is never reached in a test (the gates fire first) and dispatches through the
        # SAME trusted gateway as every other attempt.
        client = self._build_client()  # pragma: no cover - lazy SDK boundary, never hit in tests
        return self._generate_via_client(  # pragma: no cover - real hosted call, gated + lazy
            client, seed, count=count, category=category
        )

    def _build_client(self) -> Any:  # pragma: no cover - lazy SDK import, never hit in tests
        """Lazily construct the provider SDK client — imported INSIDE this method only.

        The provider SDK import lives here so importing this module never pulls an
        OpenRouter/Together/OpenAI SDK into ``sys.modules``. This method is reached only after the
        preflight and authorization gates pass, so a test (which never authorizes a hosted run)
        never triggers the import or a network connection.
        """
        provider = self.config.provider.strip().lower()
        if provider == "together":
            from together import Together  # noqa: PLC0415 - lazy, boundary-only import

            return Together()
        # Default supported provider: OpenRouter speaks the OpenAI wire protocol.
        from openai import OpenAI  # noqa: PLC0415 - lazy, boundary-only import

        return OpenAI()

    def _generate_via_client(  # pragma: no cover - real hosted call, never hit in tests
        self, client: Any, seed: dict[str, Any], *, count: int, category: str
    ) -> list[dict[str, Any]]:
        """Perform the real hosted generation through an already-built SDK client.

        Never reached in a test — the preflight/authorization gates fire first. Left as the
        explicit real-call boundary so the gated path is legible.
        """
        raise NotImplementedError(
            "the live hosted generation path is intentionally unexercised in this slice; it is "
            "reached only under explicit authorization and dispatches via the trusted gateway"
        )
