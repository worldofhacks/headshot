"""Provider-neutral tracing core (ARCHITECTURE.md §9 the six questions, S6/S9/O3/O7; §6 O6
correlation IDs; §13 the O7 fallback). STDLIB-ONLY — this is the LOCAL, framework-neutral
observability core the M6b OTEL SDK + Langfuse exporter drop into with **zero
re-instrumentation** (the exporter is a swappable protocol).

EXTERNAL-OUT invariant: this module imports NO ``opentelemetry`` and NO ``langfuse`` (they
are M6b) and touches NO network. It reads from the Postgres System-of-Record (O7 fallback)
and redacts secrets through :mod:`agentforge.secrets` before any exporter output.

The design (M6a ticket):

  * :class:`Span` — a name + attribute map + parent link + start/end taken from an INJECTABLE
    clock (never the wall clock, so a test is deterministic).
  * :class:`Tracer` — opens exactly ONE root span per request (one request == one trace) and
    child spans for the four agents {red_team, gateway, judge, documentation}. Every span it
    opens is stamped with the O6 correlation IDs and the §9 tag set.
  * :class:`CorrelationContext` — carries campaign_id / attempt_id / finding_id (O6) plus the
    §9 tags {agent, attack_category, owasp_web, owasp_llm, system_version, verdict}, which the
    Tracer stamps onto every span.
  * :class:`NoOpExporter` / :class:`ConsoleExporter` — the two local exporters. Console output
    is redacted (a :class:`~agentforge.secrets.Secret` never reaches the log verbatim).
  * :func:`derive_coverage_fallback` — the O7 fallback: with Langfuse unavailable, coverage is
    still computed from Postgres, deterministically (never random, never blocked).
"""

from __future__ import annotations

import itertools
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from agentforge.secrets import Secret, looks_like_provider_key, redact_mapping

# ---------------------------------------------------------------------------
# S6 sanity gate: the minimum distinct hash-verified attempts before a target_version may be
# flagged 'covered'. Exposed as a module constant so the frozen coverage view AND the test
# suite pin to ONE number (never a magic literal on either side). Kept in sync with
# coverage_view.sql's threshold below.
# ---------------------------------------------------------------------------
MIN_ATTEMPTS_FOR_COVERAGE = 2

# The four child agents that hang off the Orchestrator's root span (§9).
CHILD_AGENTS = ("red_team", "gateway", "judge", "documentation")

# The §9 tag set every span must carry (defaulted so a span is never missing a key).
_SPAN_TAG_KEYS = (
    "agent",
    "attack_category",
    "owasp_web",
    "owasp_llm",
    "system_version",
    "verdict",
)

# The durable O6 correlation IDs propagated onto every span.
_CORRELATION_KEYS = ("campaign_id", "attempt_id", "finding_id")

_logger = logging.getLogger("agentforge.observability.tracing")


# ---------------------------------------------------------------------------
# CorrelationContext — the O6 durable IDs + the §9 tag set, stamped onto every span.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CorrelationContext:
    """Durable correlation IDs (O6) plus the §9 span tags, carried across one request/trace.

    The three IDs (``campaign_id`` / ``attempt_id`` / ``finding_id``) are the durable keys the
    Tracer stamps IDENTICALLY onto the root and every child span, so a whole trace is
    correlatable back to its campaign/attempt/finding even after the fact. The §9 tags default
    to ``""`` so a span always carries the full key set (a missing tag is an empty string, not
    an absent key) — the test asserts on key presence.
    """

    campaign_id: str
    attempt_id: str
    finding_id: str
    agent: str = ""
    attack_category: str = ""
    owasp_web: str = ""
    owasp_llm: str = ""
    system_version: str = ""
    verdict: str = ""

    def base_tags(self) -> dict[str, Any]:
        """The full {correlation IDs + §9 tags} mapping stamped onto a freshly opened span."""
        tags: dict[str, Any] = {key: getattr(self, key) for key in _CORRELATION_KEYS}
        for key in _SPAN_TAG_KEYS:
            tags[key] = getattr(self, key)
        return tags


# ---------------------------------------------------------------------------
# Span — a node in the trace tree. start/end come from the injected clock, never wall-clock.
# ---------------------------------------------------------------------------
@dataclass
class Span:
    """One span in a trace. ``attributes`` carries the O6 IDs + §9 tags + any set attribute.

    ``start_time`` / ``end_time`` are opaque clock ticks from the Tracer's INJECTED clock — an
    integer counter in tests, so the span never reads the wall clock. ``parent`` is ``None`` on
    the single root span and the root :class:`Span` on each child (one request == one trace).
    """

    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    parent: Span | None = None
    start_time: int | None = None
    end_time: int | None = None

    def set_attribute(self, key: str, value: Any) -> None:
        """Attach an attribute to this span. A :class:`Secret` is stored as-is and redacted at
        export time — it is never stringified into the attribute map (its own dunders redact,
        and the ConsoleExporter redacts again as belt-and-suspenders)."""
        self.attributes[key] = value


# ---------------------------------------------------------------------------
# Exporter protocol + the two local exporters (NoOp, Console). The protocol is the seam M6b
# swaps the real OTEL SDK / Langfuse exporter into with zero re-instrumentation.
# ---------------------------------------------------------------------------
@runtime_checkable
class SpanExporter(Protocol):
    """The swappable export seam. M6b drops the OTEL/Langfuse exporter in behind this."""

    def export(self, spans: list[Span]) -> None: ...


class NoOpExporter:
    """Discards spans (the test default). Never raises, never touches the network."""

    def export(self, spans: list[Span]) -> None:  # noqa: D102 - trivial
        return None


def backstop_provider_keys(value: Any) -> Any:
    """Mask a BARE, unwrapped provider-key string at any depth (the secondary backstop).

    :func:`agentforge.secrets.redact_mapping` catches a :class:`Secret` value and any value
    under a sensitive-looking key, but by its own documented limitation it cannot catch a raw
    provider-key STRING sitting under an innocuous key (e.g. a stray ``sk-…`` token in a free
    ``notes`` attribute). This applies :func:`agentforge.secrets.looks_like_provider_key` to
    every remaining string so such a token never reaches the console verbatim — defense in
    depth on top of the type/key-based redaction, so no single miss leaks a credential.
    """
    if isinstance(value, str) and looks_like_provider_key(value):
        return "***REDACTED***"
    if isinstance(value, Mapping):
        return {k: backstop_provider_keys(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        masked = [backstop_provider_keys(item) for item in value]
        return tuple(masked) if isinstance(value, tuple) else masked
    return value


class ConsoleExporter:
    """Writes a redacted, single-line summary of each span via stdlib logging + print.

    Redaction is defense-in-depth: every attribute mapping is passed through
    :func:`agentforge.secrets.redact_mapping` (masks a :class:`~agentforge.secrets.Secret` and
    any value under a sensitive-looking key), THEN through the provider-key backstop
    (:func:`backstop_provider_keys`, which masks a bare unwrapped ``sk-…``-style token under an
    innocuous key). So no secret — wrapped, keyed, or bare — is ever printed verbatim. No network.
    """

    def export(self, spans: list[Span]) -> None:
        for span in spans:
            safe_attrs = backstop_provider_keys(redact_mapping(span.attributes))
            line = (
                f"span name={span.name!r} parent="
                f"{span.parent.name if span.parent else None!r} "
                f"start={span.start_time} end={span.end_time} attrs={safe_attrs}"
            )
            _logger.info(line)
            # print() so the test's capsys sees it even without logging configuration; the
            # line is already redacted, so no raw secret can reach stdout.
            print(line)


# ---------------------------------------------------------------------------
# Tracer — one root span per request, child spans for the four agents. Every span it opens is
# stamped with the correlation IDs + §9 tags from the CorrelationContext.
# ---------------------------------------------------------------------------
class Tracer:
    """Opens one root span per request (one request == one trace) + child spans per agent.

    The ``clock`` is injected (a zero-arg callable returning a monotonically increasing tick);
    the Tracer never calls the wall clock, so a test is deterministic. The ``exporter`` is the
    swappable seam (:class:`SpanExporter`); :meth:`export` flushes every span opened this trace
    through it. Spans are retained on the Tracer so a single :meth:`export` sends the whole
    trace.
    """

    def __init__(
        self,
        exporter: SpanExporter | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._exporter: SpanExporter = exporter if exporter is not None else NoOpExporter()
        self._clock: Callable[[], int] = clock if clock is not None else itertools.count().__next__
        self._spans: list[Span] = []
        self._correlation: CorrelationContext | None = None

    def _open_span(self, name: str, parent: Span | None, correlation: CorrelationContext) -> Span:
        """Build + register a span, stamped with the correlation IDs + §9 tags, clock-started."""
        span = Span(
            name=name,
            attributes=dict(correlation.base_tags()),
            parent=parent,
            start_time=self._clock(),
        )
        self._spans.append(span)
        return span

    def root_span(self, name: str, *, correlation: CorrelationContext) -> _SpanScope:
        """Open THE root span for a request (parent is None). Use as a context manager.

        Exactly one root per request — closing the context stamps the end tick. The
        correlation context is retained so :meth:`child_span` inherits the same IDs + tags.
        """
        self._correlation = correlation
        span = self._open_span(name, parent=None, correlation=correlation)
        return _SpanScope(self, span)

    def child_span(self, agent: str, *, parent: Span) -> Span:
        """Open a child span for one of the four agents, parented on the root (§9).

        Inherits the SAME correlation IDs + §9 tags as the root (O6 durability) and overrides
        the ``agent`` tag with this child's agent name. The child is closed with an end tick at
        creation-return time so a bare ``child_span(...)`` call is a complete, exported span.
        """
        if self._correlation is None:  # pragma: no cover - guarded by root_span always first
            raise RuntimeError("child_span requires an open root_span/correlation context")
        span = self._open_span(agent, parent=parent, correlation=self._correlation)
        span.attributes["agent"] = agent
        span.end_time = self._clock()
        return span

    def close(self, span: Span) -> None:
        """Stamp a span's end tick from the injected clock (idempotent-safe)."""
        span.end_time = self._clock()

    def export(self) -> None:
        """Flush every span opened this trace through the exporter (no-raise for both exporters)."""
        self._exporter.export(list(self._spans))


class _SpanScope:
    """Context manager that closes its span (stamps the end tick) on exit."""

    def __init__(self, tracer: Tracer, span: Span) -> None:
        self._tracer = tracer
        self._span = span

    def __enter__(self) -> Span:
        return self._span

    def __exit__(self, *_exc: object) -> bool:
        self._tracer.close(self._span)
        return False


# ---------------------------------------------------------------------------
# O7 fallback — coverage derived from the Postgres SoR when Langfuse is unavailable.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CoverageRow:
    """One row of the Postgres-derived coverage signal: a target_version + its verified count."""

    target_version: str
    attempt_count: int
    covered: bool


@dataclass(frozen=True)
class CoverageResult:
    """The O7 fallback result: coverage rows read from the Postgres SoR (never random).

    ``langfuse_available`` records the branch taken (False on the fallback path). ``rows`` are
    the ``coverage_metric`` view rows — the SAME hash-verified, nonce-deduped signal the online
    path would surface, so an observability outage never changes the number.
    """

    rows: tuple[CoverageRow, ...]
    langfuse_available: bool


def derive_coverage_fallback(engine: Any, *, langfuse_available: bool) -> CoverageResult:
    """O7: compute coverage from the Postgres SoR — even (especially) with Langfuse unavailable.

    Reads the ``coverage_metric`` view (S6: hash-verified, nonce-deduped verdicts only — NEVER
    raw spans) and returns a structured, DETERMINISTIC result. With ``langfuse_available=False``
    the computation is identical: the number comes from Postgres, never from the observability
    backend, so an outage never blocks priority/coverage and never randomizes it. Ordered by
    ``target_version`` so two derivations over the same DB state are byte-identical.
    """
    # Imported here (not at module top) so the framework-neutral core stays SQLAlchemy-free at
    # import time (D10) — mirrors the migration/env lazy-import discipline.
    from sqlalchemy import text

    rows: list[CoverageRow] = []
    with engine.connect() as conn:
        result = conn.execute(
            text(
                "SELECT target_version, attempt_count, covered "
                "FROM coverage_metric ORDER BY target_version"
            )
        )
        for r in result.mappings().all():
            rows.append(
                CoverageRow(
                    target_version=r["target_version"],
                    attempt_count=int(r["attempt_count"]),
                    covered=bool(r["covered"]),
                )
            )
    return CoverageResult(rows=tuple(rows), langfuse_available=langfuse_available)


__all__ = [
    "MIN_ATTEMPTS_FOR_COVERAGE",
    "CHILD_AGENTS",
    "CorrelationContext",
    "Span",
    "SpanExporter",
    "NoOpExporter",
    "ConsoleExporter",
    "backstop_provider_keys",
    "Tracer",
    "CoverageRow",
    "CoverageResult",
    "derive_coverage_fallback",
    "Secret",
]
