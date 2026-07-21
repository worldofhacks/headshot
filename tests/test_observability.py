"""M6a — provider-neutral observability-core tests (RED until agentforge.observability.*
and migration 0003's coverage view exist).

Test-Agent-owned. Pins the CONTRACT for the M6a observability core (ARCHITECTURE.md §9
the six questions + S6/S9/O3/O7, §13 the O7 fallback, §6 the O6 correlation IDs) as
described in the M6a ticket DESIGN. Nothing here is app-layer stubbed:

  * the tracing / reconcile / alerts tests import ``agentforge.observability.*`` — which do
    not exist yet, so this module fails to import and EVERY test errors at collection (RED
    for the right reason);
  * the coverage-view / reconcile DB tests use the shared ``migrated_db`` fixture
    (tests/conftest.py) — a REAL per-session Postgres migrated with ``alembic upgrade head``.
    Migration 0003 (the ``coverage_metric`` view) does not exist yet, so those tests go RED
    either at the fixture's ``alembic upgrade head`` (once 0003 lands the view appears) or on
    the missing view / missing ``agentforge.observability`` import.

EXTERNAL-OUT invariant (asserted below): the core is stdlib-only — NO ``opentelemetry``
module may be imported. The real OTEL SDK + Langfuse exporter are M6b, not M6a.

Determinism: an INJECTABLE clock (never wall-clock) and an in-memory CapturingAlertChannel
(never a real webhook/network). Synthetic data only — no PHI (S… / PRD).

The module + symbol names below are the FROZEN contract the Implementation Agent builds to.
"""

from __future__ import annotations

import itertools
import sys

import pytest
from sqlalchemy import Engine, text

# ---------------------------------------------------------------------------
# The M6a observability core (does not exist yet — importing it is the primary RED).
# Kept at module top so a missing module surfaces as a clean collection error, not a
# per-test AttributeError.
# ---------------------------------------------------------------------------
from agentforge.observability import alerts as alerts_mod
from agentforge.observability import reconcile as reconcile_mod
from agentforge.observability import tracing as tracing_mod

# ---------------------------------------------------------------------------
# Deterministic clock — a monotonically increasing counter, injected into the Tracer so a
# span's start/end never touch the wall clock.
# ---------------------------------------------------------------------------


class FakeClock:
    """A deterministic, injectable clock: each call returns the next integer tick."""

    def __init__(self, start: int = 0) -> None:
        self._counter = itertools.count(start)

    def __call__(self) -> int:
        return next(self._counter)


# The tag set every span must carry (ARCHITECTURE §9 "one request = one trace").
EXPECTED_SPAN_TAGS = frozenset(
    {
        "agent",
        "attack_category",
        "owasp_web",
        "owasp_llm",
        "system_version",
        "verdict",
    }
)

# The durable correlation IDs (O6) that propagate onto every span.
CORRELATION_KEYS = frozenset({"campaign_id", "attempt_id", "finding_id"})

# The four child agents that hang off the Orchestrator's root span (§9).
CHILD_AGENTS = ("red_team", "gateway", "judge", "documentation")


def _make_correlation() -> object:
    """Build a synthetic CorrelationContext carrying the O6 IDs (no PHI, synthetic only)."""
    return tracing_mod.CorrelationContext(
        campaign_id="camp-synthetic-0001",
        attempt_id="att-synthetic-0001",
        finding_id="find-synthetic-0001",
    )


def _make_tracer() -> object:
    """A Tracer wired to the deterministic clock and the no-op exporter (test default)."""
    return tracing_mod.Tracer(
        exporter=tracing_mod.NoOpExporter(),
        clock=FakeClock(),
    )


def _span_tags(span: object) -> dict:
    """The attribute/tag mapping a span exposes (``.attributes`` is the frozen name)."""
    return dict(span.attributes)


# ===========================================================================
# AC-1 — one request = one trace, with child spans; NoOp + Console exporters both work.
# ===========================================================================
def test_root_span_opens_one_trace_with_child_spans() -> None:
    """One request opens exactly one ROOT span; the four agents are CHILD spans of it (§9)."""
    tracer = _make_tracer()
    corr = _make_correlation()

    with tracer.root_span("request", correlation=corr) as root:
        children = [tracer.child_span(agent, parent=root) for agent in CHILD_AGENTS]

    # Exactly one root; every child's parent is that root (one request == one trace).
    assert root.parent is None
    assert len(children) == len(CHILD_AGENTS)
    for child in children:
        assert child.parent is root


def test_every_span_carries_correlation_ids_and_full_tag_set() -> None:
    """Correlation IDs (O6) AND the §9 tag set are stamped on EVERY span — root and child."""
    tracer = _make_tracer()
    corr = _make_correlation()

    with tracer.root_span("request", correlation=corr) as root:
        child = tracer.child_span("judge", parent=root)

        for span in (root, child):
            tags = _span_tags(span)
            missing_tags = EXPECTED_SPAN_TAGS - tags.keys()
            missing_ids = CORRELATION_KEYS - tags.keys()
            assert not missing_tags, f"{span} missing §9 tags: {sorted(missing_tags)}"
            assert not missing_ids, f"{span} missing O6 correlation IDs: {sorted(missing_ids)}"
            # The IDs must be the synthetic values we injected, not blanks.
            assert tags["campaign_id"] == "camp-synthetic-0001"
            assert tags["attempt_id"] == "att-synthetic-0001"
            assert tags["finding_id"] == "find-synthetic-0001"


def test_span_uses_injected_clock_not_wall_clock() -> None:
    """A span's start/end come from the INJECTED clock — deterministic, never the wall clock."""
    clock = FakeClock(start=100)
    tracer = tracing_mod.Tracer(exporter=tracing_mod.NoOpExporter(), clock=clock)
    corr = _make_correlation()

    with tracer.root_span("request", correlation=corr) as root:
        pass

    # First tick opened the span, a later tick closed it — both from the fake clock's range.
    assert root.start_time >= 100
    assert root.end_time >= root.start_time
    assert root.end_time < 1_000_000  # a real wall-clock epoch would be ~1.7e9 — proves fake.


def test_noop_and_console_exporters_both_accept_a_trace() -> None:
    """Both the NoOp and Console exporters export a finished trace without raising (AC-1)."""
    corr = _make_correlation()
    for exporter in (tracing_mod.NoOpExporter(), tracing_mod.ConsoleExporter()):
        tracer = tracing_mod.Tracer(exporter=exporter, clock=FakeClock())
        with tracer.root_span("request", correlation=corr) as root:
            tracer.child_span("red_team", parent=root)
        # Explicit flush/export path must be a no-raise for both exporters.
        tracer.export()


def test_console_exporter_redacts_secrets_never_raw(capsys: pytest.CaptureFixture[str]) -> None:
    """The ConsoleExporter output redacts a secret-shaped value — never prints it raw (§5, D…)."""
    from agentforge.secrets import Secret

    raw = "sk-supersecret-DO-NOT-LEAK-abcdef0123456789"
    tracer = tracing_mod.Tracer(exporter=tracing_mod.ConsoleExporter(), clock=FakeClock())
    corr = _make_correlation()

    with tracer.root_span("request", correlation=corr) as root:
        child = tracer.child_span("gateway", parent=root)
        # A secret sneaking into a span attribute must NOT reach the console verbatim.
        child.set_attribute("api_key", Secret(raw))
    tracer.export()

    out = capsys.readouterr()
    combined = out.out + out.err
    assert raw not in combined, "ConsoleExporter leaked a raw secret value"


def test_console_exporter_redacts_a_bare_provider_key_under_an_innocuous_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A BARE, unwrapped provider-key string under a NON-sensitive attribute key (e.g. 'notes')
    is masked by the exporter's provider-key backstop — redact_mapping alone (Secret-type / key-
    name based) would miss it, so without the backstop a stray token would print verbatim."""
    raw = "sk-ant-FAKE-not-real-DO-NOT-LEAK-000"
    tracer = tracing_mod.Tracer(exporter=tracing_mod.ConsoleExporter(), clock=FakeClock())
    corr = _make_correlation()
    with tracer.root_span("request", correlation=corr) as root:
        child = tracer.child_span("gateway", parent=root)
        child.set_attribute("notes", raw)  # bare token under an INNOCUOUS key
    tracer.export()
    out = capsys.readouterr()
    assert raw not in (out.out + out.err), "ConsoleExporter leaked a bare provider-key token"


# ===========================================================================
# AC-1 (external-out) — NO opentelemetry, NO langfuse, NO network in the core.
# ===========================================================================
def test_no_opentelemetry_module_is_imported() -> None:
    """The M6a core is stdlib-only: importing it must NOT drag in the opentelemetry SDK."""
    otel = [
        name for name in sys.modules if name == "opentelemetry" or name.startswith("opentelemetry.")
    ]
    assert not otel, f"opentelemetry must NOT be imported by the M6a core; found: {sorted(otel)}"


def test_no_langfuse_module_is_imported() -> None:
    """Langfuse is M6b (external). The local core must not import it (external-out)."""
    lf = [name for name in sys.modules if name == "langfuse" or name.startswith("langfuse.")]
    assert not lf, f"langfuse must NOT be imported by the M6a core; found: {sorted(lf)}"


@pytest.mark.parametrize("module", ["tracing", "reconcile", "alerts"])
def test_observability_module_source_has_no_otel_or_langfuse_import(module: str) -> None:
    """No observability source file imports opentelemetry/langfuse (static, source-level check)."""
    import importlib
    import inspect

    mod = importlib.import_module(f"agentforge.observability.{module}")
    src = inspect.getsource(mod)
    assert "import opentelemetry" not in src
    assert "from opentelemetry" not in src
    assert "import langfuse" not in src
    assert "from langfuse" not in src


# ===========================================================================
# AC-2 — durable correlation IDs propagate across spans.
# ===========================================================================
def test_correlation_ids_propagate_identically_across_all_spans() -> None:
    """The SAME campaign/attempt/finding IDs appear on the root and every child (O6 durability)."""
    tracer = _make_tracer()
    corr = _make_correlation()

    seen: list[tuple] = []
    with tracer.root_span("request", correlation=corr) as root:
        seen.append(_id_triple(root))
        for agent in CHILD_AGENTS:
            child = tracer.child_span(agent, parent=root)
            seen.append(_id_triple(child))

    # Every span shares one identical (campaign_id, attempt_id, finding_id) triple.
    assert len(set(seen)) == 1
    assert seen[0] == ("camp-synthetic-0001", "att-synthetic-0001", "find-synthetic-0001")


def _id_triple(span: object) -> tuple:
    tags = dict(span.attributes)
    return (tags.get("campaign_id"), tags.get("attempt_id"), tags.get("finding_id"))


# ===========================================================================
# AC-4 (S9 invariant) — evidence-hash reconciliation. Match → ok; mismatch/missing → degraded.
# ===========================================================================
def test_reconcile_matching_hash_is_ok() -> None:
    """When the span's transcript_hash equals the authoritative content_hash → ``ok``."""
    h = "a" * 64
    status = reconcile_mod.reconcile(h, h)
    assert status == reconcile_mod.ReconcileStatus.OK


def test_reconcile_mismatched_hash_is_degraded() -> None:
    """S9 INVARIANT: a diverging span transcript_hash marks the run DEGRADED (not trusted)."""
    authoritative = "a" * 64
    divergent = "b" * 64
    status = reconcile_mod.reconcile(authoritative, divergent)
    assert status == reconcile_mod.ReconcileStatus.DEGRADED


@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-hash"])
def test_reconcile_missing_or_malformed_hash_fails_closed_to_degraded(bad: object) -> None:
    """Fail-closed: a missing/malformed hash on EITHER side → DEGRADED, never silently ok."""
    good = "a" * 64
    assert reconcile_mod.reconcile(good, bad) == reconcile_mod.ReconcileStatus.DEGRADED
    assert reconcile_mod.reconcile(bad, good) == reconcile_mod.ReconcileStatus.DEGRADED


def test_reconcile_degraded_is_not_blocked_status() -> None:
    """A divergence DEGRADES the run (it is still readable) — it does not 'block'/erase it (§9)."""
    members = {m.name for m in reconcile_mod.ReconcileStatus}
    # The status enum expresses ok vs degraded — divergence is detectable, not a hard block.
    assert "OK" in members
    assert "DEGRADED" in members
    assert "BLOCKED" not in members


def test_reconcile_accepts_an_attempt_result_row(migrated_db: Engine) -> None:
    """reconcile() reads the authoritative content_hash from a real attempt_result row (S9).

    Uses the M2 ``migrated_db`` (real Postgres). RED now: migration 0003 / the observability
    module do not exist yet. Once landed, a row whose span hash diverges must be ``degraded``.
    """
    run_id, attempt_id = "run-recon-0001", "att-recon-0001"
    authoritative = "c" * 64
    _insert_attempt_result(migrated_db, run_id, attempt_id, content_hash=authoritative)

    row = _fetch_attempt_result_row(migrated_db, run_id, attempt_id)

    # Same hash on the span → ok; a divergent span hash → degraded (fail-closed by construction).
    assert reconcile_mod.reconcile(row, authoritative) == reconcile_mod.ReconcileStatus.OK
    assert reconcile_mod.reconcile(row, "d" * 64) == reconcile_mod.ReconcileStatus.DEGRADED


# ===========================================================================
# AC-3 / AC-5 (S6 invariant) — the Postgres SoR coverage view.
#   Coverage from HASH-VERIFIED, NONCE-DEDUPED verdicts only; a duplicate pair counts once;
#   'covered' requires ≥N distinct verified attempts AND ≥1 oracle/decisive case; NEVER raw
#   spans. The grouping dimension is ``target_version`` (a real attempt_result column) — the
#   only coverage axis derivable within the view-only scope of migration 0003 (the base tables
#   attempt_result/verdict are frozen; 0003 may add a VIEW, never a column). The S6 "oracle /
#   human-spot-checked" anchor is derived from a DECISIVE verdict state (EXPLOIT_CONFIRMED,
#   the deterministic-oracle disposition) vs a non-decisive/LLM-only one (EXPLOIT_LIKELY).
# ===========================================================================
def test_coverage_metric_view_exists_after_migration(migrated_db: Engine) -> None:
    """AC-3: migration 0003 creates the ``coverage_metric`` view (a VIEW, not a raw table)."""
    with migrated_db.connect() as conn:
        row = conn.execute(
            text(
                "SELECT table_type FROM information_schema.tables "
                "WHERE table_name = 'coverage_metric'"
            )
        ).first()
    assert row is not None, "migration 0003 did not create the coverage_metric relation"
    assert row[0] == "VIEW", "coverage_metric must be a Postgres VIEW over the SoR, not a table"


def test_coverage_view_exposes_the_sor_grouping_and_gate_columns(migrated_db: Engine) -> None:
    """The view surfaces the S6 contract columns: the grouping key, the count, the gate flag."""
    with migrated_db.connect() as conn:
        cols = {
            r[0]
            for r in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'coverage_metric'"
                )
            ).all()
        }
    for required in ("target_version", "attempt_count", "covered"):
        assert required in cols, (
            f"coverage_metric view is missing column {required!r}: {sorted(cols)}"
        )


def test_coverage_counts_distinct_pairs_only_a_duplicate_counts_once(migrated_db: Engine) -> None:
    """S6: coverage counts DISTINCT (campaign_run_id, attempt_id) pairs — a duplicate counts once.

    We insert TWO verified verdicts over the SAME (run, attempt) evidence pair (a replay-shaped
    duplicate). The view's attempt count for that target_version must be 1, never 2.
    """
    tv = "coverage-dup-v1"
    run_id, attempt_id = "run-dup-0001", "att-dup-0001"
    _insert_verified_attempt(
        migrated_db, run_id, attempt_id, target_version=tv, verdict_state="EXPLOIT_CONFIRMED"
    )
    # A second verdict over the SAME evidence pair — must NOT double-count.
    _insert_verdict(migrated_db, run_id, attempt_id, verdict_state="EXPLOIT_CONFIRMED")

    n = _coverage_attempt_count(migrated_db, tv)
    assert n == 1, f"duplicate (run, attempt) pair double-counted: got {n}"


def test_coverage_ignores_unverified_evidenceless_verdicts(migrated_db: Engine) -> None:
    """S6: coverage only surfaces verdicts joined to real attempt_result evidence — never raw.

    The verdict→attempt_result FK means a verdict cannot even exist without evidence, so the
    view's join can never count an evidenceless (raw-span-only) record. A legitimately verified
    attempt is counted exactly once; nothing phantom is added.
    """
    tv = "coverage-verified-only-v1"
    _insert_verified_attempt(
        migrated_db,
        "run-ok-0002",
        "att-ok-0002",
        target_version=tv,
        verdict_state="EXPLOIT_CONFIRMED",
    )
    assert _coverage_attempt_count(migrated_db, tv) == 1


def test_covered_flag_requires_min_verified_and_oracle(migrated_db: Engine) -> None:
    """S6 gate: 'covered' is TRUE only with ≥N distinct verified attempts AND ≥1 decisive case.

    A single non-decisive (LLM-only, EXPLOIT_LIKELY) verified attempt must NOT flip the
    target_version to covered — the sanity gate (§9) forbids 'covered' without the
    deterministic-oracle/human anchor AND without enough distinct verified attempts.
    """
    tv = "coverage-undercovered-v1"
    # One non-decisive verified attempt: below N and with no oracle/decisive anchor.
    _insert_verified_attempt(
        migrated_db,
        "run-uc-0001",
        "att-uc-0001",
        target_version=tv,
        verdict_state="EXPLOIT_LIKELY",
    )
    assert _coverage_covered_flag(migrated_db, tv) is False, (
        "a single non-decisive verified attempt must NOT flip to 'covered' (S6)"
    )


def test_covered_flag_false_without_the_oracle_anchor_even_at_volume(migrated_db: Engine) -> None:
    """S6 gate: ≥N distinct verified attempts but ZERO decisive/oracle case → still NOT covered."""
    tv = "coverage-volume-no-oracle-v1"
    for i in range(_MIN_ATTEMPTS_FOR_COVERAGE + 1):
        # Every verdict is non-decisive (EXPLOIT_LIKELY) — the oracle anchor is absent.
        _insert_verified_attempt(
            migrated_db,
            f"run-vno-{i:04d}",
            f"att-vno-{i:04d}",
            target_version=tv,
            verdict_state="EXPLOIT_LIKELY",
        )
    assert _coverage_covered_flag(migrated_db, tv) is False, (
        "volume alone must NOT satisfy 'covered' without an oracle/decisive anchor (S6)"
    )


def test_covered_flag_true_only_with_full_evidence(migrated_db: Engine) -> None:
    """S6 gate (positive): ≥N verified attempts + ≥1 decisive/oracle case → covered TRUE."""
    tv = "coverage-well-covered-v1"
    # N distinct verified attempts; at least one carries a DECISIVE (oracle-grade) verdict.
    for i in range(_MIN_ATTEMPTS_FOR_COVERAGE):
        _insert_verified_attempt(
            migrated_db,
            f"run-wc-{i:04d}",
            f"att-wc-{i:04d}",
            target_version=tv,
            verdict_state="EXPLOIT_CONFIRMED" if i == 0 else "EXPLOIT_LIKELY",
        )
    assert _coverage_covered_flag(migrated_db, tv) is True, (
        "≥N distinct verified attempts + a decisive case must satisfy the S6 'covered' gate"
    )


# ===========================================================================
# AC-6 (O3) — each alert kind fires, tied to the DURABLE source, deterministically.
# ===========================================================================
# The six O3 alert kinds (ARCHITECTURE §9 alerting).
O3_ALERT_KINDS = (
    "human_approval_pending",
    "regression_detected",
    "budget_circuit_breaker_tripped",
    "target_unreachable",
    "queue_depth_over_threshold",
    "emission_failure",
)


def test_all_o3_alert_kinds_are_enumerated() -> None:
    """Every mandated O3 alert kind is a first-class enumerated kind (no free-form strings)."""
    kinds = {k.value if hasattr(k, "value") else k for k in alerts_mod.AlertKind}
    missing = set(O3_ALERT_KINDS) - kinds
    assert not missing, f"AlertKind is missing O3 kinds: {sorted(missing)}"


@pytest.mark.parametrize("kind", O3_ALERT_KINDS)
def test_each_o3_alert_kind_fires_to_the_capturing_channel(kind: str) -> None:
    """AC-6: each alert kind fires deterministically into the in-memory channel (no network)."""
    channel = alerts_mod.CapturingAlertChannel()
    alert = alerts_mod.Alert(
        kind=alerts_mod.AlertKind(kind),
        source="exploit_db",  # the DURABLE source, not Langfuse
        payload={"detail": "synthetic", "sla_seconds": 3600},
    )
    channel.emit(alert)

    captured = channel.captured
    assert len(captured) == 1
    fired = captured[0]
    fired_kind = fired.kind.value if hasattr(fired.kind, "value") else fired.kind
    assert fired_kind == kind
    # Tied to the durable source — an observability outage must not silence it.
    assert fired.source != "langfuse"


def test_alert_channel_is_deterministic_and_in_memory() -> None:
    """The CapturingAlertChannel records EXACTLY what was emitted, in order, no side effects."""
    channel = alerts_mod.CapturingAlertChannel()
    kinds = ["human_approval_pending", "regression_detected", "emission_failure"]
    for k in kinds:
        channel.emit(
            alerts_mod.Alert(kind=alerts_mod.AlertKind(k), source="exploit_db", payload={})
        )
    got = [(c.kind.value if hasattr(c.kind, "value") else c.kind) for c in channel.captured]
    assert got == kinds


def test_emission_failure_alert_is_tied_to_durable_source_not_langfuse() -> None:
    """O3: even an EMISSION-FAILURE alert routes through the durable source, so it is never lost."""
    channel = alerts_mod.CapturingAlertChannel()
    channel.emit(
        alerts_mod.Alert(
            kind=alerts_mod.AlertKind("emission_failure"),
            source="exploit_db",
            payload={"backend": "langfuse", "reason": "unreachable"},
        )
    )
    assert len(channel.captured) == 1
    assert channel.captured[0].source == "exploit_db"


def test_alert_channel_redacts_secrets_and_bare_tokens_in_the_payload() -> None:
    """§5: raw secrets / adversarial content are NEVER rendered into an alert. The channel
    redacts, before storing, a Secret value, a token under a sensitive key, AND a bare provider-
    key string under an innocuous key — so an alert payload can never leak a credential even
    though an alert routes to a durable, human-facing sink."""
    from agentforge.secrets import Secret

    channel = alerts_mod.CapturingAlertChannel()
    channel.emit(
        alerts_mod.Alert(
            kind=alerts_mod.AlertKind("emission_failure"),
            source="exploit_db",
            payload={
                "wrapped": Secret("sentinel-shh-999"),
                "api_key": "sk-or-FAKE-not-real-111",  # sensitive key
                "notes": "sk-ant-FAKE-not-real-222",  # bare token under an innocuous key
            },
        )
    )
    blob = str(channel.captured[0].payload)
    assert "sentinel-shh-999" not in blob
    assert "sk-or-FAKE-not-real-111" not in blob
    assert "sk-ant-FAKE-not-real-222" not in blob
    assert "REDACTED" in blob


# ===========================================================================
# AC-7 (O7) — with the 'Langfuse' exporter unavailable, coverage/priority still compute
#             from Postgres (never random, never blocked).
# ===========================================================================
def test_langfuse_out_fallback_derives_coverage_from_postgres(migrated_db: Engine) -> None:
    """O7: with Langfuse unavailable, coverage is derived from the Postgres SoR, deterministically.

    We insert a verified attempt, then compute coverage through the fallback path with the
    observability backend explicitly UNAVAILABLE — it must return the Postgres-derived value,
    never random and never a blocked/empty error.
    """
    tv = "fallback-v1"
    _insert_verified_attempt(
        migrated_db,
        "run-fb-0001",
        "att-fb-0001",
        target_version=tv,
        verdict_state="EXPLOIT_CONFIRMED",
    )

    coverage = tracing_mod.derive_coverage_fallback(migrated_db, langfuse_available=False)
    # A structured Postgres-derived signal — not None/random/blocked.
    assert coverage is not None
    counts = _coverage_rows_by_target_version(coverage)
    assert counts.get(tv, 0) >= 1


def test_langfuse_out_fallback_is_not_random(migrated_db: Engine) -> None:
    """O7: two fallback derivations over the SAME DB state return the SAME value (not random)."""
    tv = "determinism-v1"
    _insert_verified_attempt(
        migrated_db,
        "run-det-0001",
        "att-det-0001",
        target_version=tv,
        verdict_state="EXPLOIT_CONFIRMED",
    )
    a = tracing_mod.derive_coverage_fallback(migrated_db, langfuse_available=False)
    b = tracing_mod.derive_coverage_fallback(migrated_db, langfuse_available=False)
    assert _coverage_rows_by_target_version(a) == _coverage_rows_by_target_version(b)


# ===========================================================================
# AC-8 — synthetic data only. (Guardrail: none of the fixtures above carry PHI.)
# ===========================================================================
def test_fixtures_are_synthetic_no_phi(migrated_db: Engine) -> None:
    """AC-8: every seeded attempt_result response transcript is synthetic — no PHI markers."""
    _insert_attempt_result(migrated_db, "run-phi-0001", "att-phi-0001", content_hash="e" * 64)
    with migrated_db.connect() as conn:
        rows = conn.execute(text("SELECT response_transcript FROM attempt_result")).all()
    blob = " ".join(str(r[0]) for r in rows if r[0] is not None).lower()
    for phi_marker in ("ssn", "mrn", "date of birth", "patient name"):
        assert phi_marker not in blob, f"PHI-shaped marker {phi_marker!r} leaked into a fixture"


# ---------------------------------------------------------------------------
# DB seeding + coverage-read helpers.
#
# These target the M2 schema (attempt_result, verdict) that already exists AND the 0003
# coverage_metric view + the observability read API that do NOT exist yet. Every helper is
# below the tests so a missing symbol fails inside a test body (clear RED), not at import.
# ---------------------------------------------------------------------------

# The S6 sanity gate's minimum distinct verified attempts before a target_version may be
# 'covered'. The exact N is the impl's to set; the coverage read API MUST expose it as
# ``MIN_ATTEMPTS_FOR_COVERAGE`` so this test is pinned to the impl's own threshold, not a
# magic number. Absent now (module import itself is RED); resolved once the impl lands.
try:  # pragma: no cover - resolved once the impl lands
    _MIN_ATTEMPTS_FOR_COVERAGE = tracing_mod.MIN_ATTEMPTS_FOR_COVERAGE
except AttributeError:  # observability module exists but symbol not yet defined
    _MIN_ATTEMPTS_FOR_COVERAGE = 2


def _insert_attempt_result(
    engine: Engine,
    campaign_run_id: str,
    attempt_id: str,
    *,
    content_hash: str,
    target_version: str = "v-synthetic",
) -> None:
    """Insert one synthetic authoritative attempt_result row (the S9 evidence spine)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO attempt_result "
                "(campaign_run_id, attempt_id, target_version, response_transcript, content_hash) "
                "VALUES (:run, :att, :tv, :resp, :h)"
            ),
            {
                "run": campaign_run_id,
                "att": attempt_id,
                "tv": target_version,
                "resp": "synthetic response — no PHI",
                "h": content_hash,
            },
        )


def _insert_verdict(
    engine: Engine, campaign_run_id: str, attempt_id: str, *, verdict_state: str
) -> None:
    """Insert a verdict over an existing (run, attempt) evidence pair (FK-checked)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO verdict (state, campaign_run_id, attempt_id) "
                "VALUES (CAST(:s AS verdict_state), :run, :att)"
            ),
            {"s": verdict_state, "run": campaign_run_id, "att": attempt_id},
        )


def _insert_verified_attempt(
    engine: Engine,
    campaign_run_id: str,
    attempt_id: str,
    *,
    target_version: str,
    verdict_state: str,
) -> None:
    """Insert a hash-verified attempt: an attempt_result (evidence) + a verdict over it.

    Uses ONLY columns the frozen M2 schema already has — ``attempt_result.target_version``
    (the view's grouping dimension) and ``verdict.state`` (from which the coverage view
    DERIVES the S6 oracle/decisive anchor: EXPLOIT_CONFIRMED = decisive, EXPLOIT_LIKELY =
    non-decisive/LLM-only). No new base-table column is required, so migration 0003 stays a
    VIEW-only, scope-legal change. The verdict→attempt_result FK guarantees the evidence
    exists before the verdict — i.e. the verdict is verifiable.
    """
    _insert_attempt_result(
        engine,
        campaign_run_id,
        attempt_id,
        content_hash=f"{campaign_run_id}:{attempt_id}:hash",
        target_version=target_version,
    )
    _insert_verdict(engine, campaign_run_id, attempt_id, verdict_state=verdict_state)


def _fetch_attempt_result_row(engine: Engine, campaign_run_id: str, attempt_id: str) -> object:
    """Fetch the attempt_result row (a mapping) reconcile() reads the authoritative hash from."""
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT * FROM attempt_result "
                    "WHERE campaign_run_id = :run AND attempt_id = :att"
                ),
                {"run": campaign_run_id, "att": attempt_id},
            )
            .mappings()
            .first()
        )
    assert row is not None
    return dict(row)


def _coverage_attempt_count(engine: Engine, target_version: str) -> int:
    """The coverage view's DISTINCT-verified-attempt count for a target_version (S6)."""
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT attempt_count FROM coverage_metric WHERE target_version = :tv"),
            {"tv": target_version},
        ).first()
    return int(row[0]) if row is not None else 0


def _coverage_covered_flag(engine: Engine, target_version: str) -> bool:
    """The coverage view's 'covered' boolean for a target_version (the S6 sanity gate result)."""
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT covered FROM coverage_metric WHERE target_version = :tv"),
            {"tv": target_version},
        ).first()
    return bool(row[0]) if row is not None else False


def _coverage_rows_by_target_version(coverage: object) -> dict:
    """Normalize a fallback-coverage result into {target_version: attempt_count} for comparison."""
    rows = coverage.rows if hasattr(coverage, "rows") else coverage
    result: dict = {}
    for r in rows:
        if isinstance(r, dict):
            result[r["target_version"]] = r.get("attempt_count", 0)
        else:
            result[r.target_version] = getattr(r, "attempt_count", 0)
    return result
