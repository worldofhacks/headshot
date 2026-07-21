"""M1a readiness composition + local target-isolation — black-box coverage.

Test-Agent-owned (companion to the frozen tests/test_health.py, tests/test_config.py,
tests/test_env_isolation.py). These exercise behavior the frozen suite deliberately leaves
to a fake-injected callable: the REAL composition of the ``/ready`` readiness check.

Contract under test (to be provided by the Implementation Agent — ARCHITECTURE.md §12,
IMPLEMENTATION_PLAN.md M1a accept (c)/(e)/(f)):

    from agentforge.app import build_app

    build_app(database_url: str | None, schema_check: Callable[[], bool]) -> FastAPI

``build_app`` composes TWO independent readiness signals and hands the composite to the
FROZEN ``agentforge.health.create_app(readiness_check=...)`` factory (single-callable
contract — unchanged):

  1. a REAL Postgres-connectivity check — connects to ``database_url`` and runs a trivial
     query (e.g. ``SELECT 1``); and
  2. the pluggable ``schema_check`` — "migrations/schema current" (falsy => not ready).

``/ready`` is 200 only when BOTH pass; otherwise 503. ``/health`` stays liveness-only and
must NEVER consult Postgres or the schema check.

``build_app`` does not exist yet, so importing it fails at collection => the non-gated
tests here (T-R1, T-R3, T-R6) go RED for the RIGHT reason (missing composition, not a
missing driver). The Postgres-backed tests (T-R2, T-R4, T-R5) are integration tests gated
on ``DATABASE_URL`` — they SKIP locally and run in CI against its ephemeral Postgres. The
Postgres driver (``psycopg``) is imported lazily inside those gated tests only, so its
absence never masks the real "missing build_app" RED signal on the non-gated tests.

spec(M1a:AC-3) spec(M1a:AC-5/O1) spec(M1a:AC-6)
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# A database_url that resolves to a closed port on loopback: connecting MUST fail fast, so
# the real DB-connectivity check reports "not reachable" without needing a live Postgres.
UNREACHABLE_DATABASE_URL = "postgresql://x:x@127.0.0.1:1/none"

# The first (and, locally, only) target: a live production system reached by reference in
# production and refused everywhere else (CLAUDE.md, ARCHITECTURE.md O1).
TARGET_ID = "openemr-copilot"

# Gate for the integration tests that need a genuinely reachable Postgres (CI provides one
# via DATABASE_URL against its ephemeral service). Locally these SKIP.
_DATABASE_URL = os.environ.get("DATABASE_URL")
requires_postgres = pytest.mark.skipif(
    not _DATABASE_URL,
    reason="needs a reachable Postgres via DATABASE_URL (CI ephemeral service)",
)


def _build_app(database_url, schema_check):
    """Import + call ``agentforge.app.build_app`` LAZILY, inside the test body.

    Deferring the import means the "feature not built yet" state surfaces as a clean test
    FAILURE naming the missing ``build_app`` — not a module-level collection ERROR that
    would abort the whole session and hide the (green) frozen suite. The DATABASE_URL-gated
    tests are skipped before their body runs, so they never trip this while the feature is
    absent. Once the Implementation Agent lands ``build_app``, this import just succeeds.
    """
    from agentforge.app import build_app

    return build_app(database_url=database_url, schema_check=schema_check)


# ---------------------------------------------------------------------------
# T-R1 — /health is liveness-only: never consults Postgres or the schema check
# ---------------------------------------------------------------------------
def test_health_never_consults_postgres_or_schema_check() -> None:
    """spec(M1a:AC-3) — T-R1: the REAL app serves /health -> 200 {"status": "alive"}
    WITHOUT touching Postgres.

    We compose the app with an UNREACHABLE database_url (so any DB touch would be visible
    as latency/failure) and a schema_check that FAILS the test if it is ever called. A
    liveness probe that reached for the DB or the schema check would trip one of these.
    """
    schema_calls: list[int] = []

    def schema_check() -> bool:
        schema_calls.append(1)  # /health must never reach this
        return True

    app = _build_app(database_url=UNREACHABLE_DATABASE_URL, schema_check=schema_check)
    resp = TestClient(app).get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}
    assert schema_calls == []  # liveness did not consult the readiness composition


# ---------------------------------------------------------------------------
# T-R2 — /ready is 200 when BOTH Postgres is reachable AND schema_check is truthy
# ---------------------------------------------------------------------------
@requires_postgres
def test_ready_200_when_postgres_reachable_and_schema_current() -> None:
    """spec(M1a:AC-3) — T-R2 (integration): DB reachable + schema current -> 200 ready.

    Uses the real DATABASE_URL so the DB-connectivity half is genuinely exercised against
    CI's ephemeral Postgres; schema_check returns True so the composite is truthy.
    """
    app = _build_app(database_url=_DATABASE_URL, schema_check=lambda: True)
    resp = TestClient(app).get("/ready")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


# ---------------------------------------------------------------------------
# T-R3 — /ready is 503 when Postgres is unreachable (no DB needed; runs everywhere)
# ---------------------------------------------------------------------------
def test_ready_503_when_postgres_unreachable() -> None:
    """spec(M1a:AC-3) — T-R3: DB unreachable -> 503 not_ready, even when schema_check True.

    Points build_app at a closed loopback port. The composite must fail CLOSED on the DB
    half regardless of the schema half — a lazy composition that only consults schema_check
    (or that treats a connection error as ready) fails this. Needs no live database.
    """
    app = _build_app(database_url=UNREACHABLE_DATABASE_URL, schema_check=lambda: True)
    resp = TestClient(app).get("/ready")

    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


# ---------------------------------------------------------------------------
# T-R4 — /ready is 503 when Postgres is reachable but schema_check is falsy
# ---------------------------------------------------------------------------
@requires_postgres
def test_ready_503_when_schema_stale_despite_reachable_postgres() -> None:
    """spec(M1a:AC-3) — T-R4 (integration): DB reachable but schema stale -> 503 not_ready.

    Proves the schema half is a real gate: with a genuinely reachable Postgres, a falsy
    schema_check (stale/missing revision) must still force 503. A composition that only
    checked DB connectivity would wrongly report ready here.
    """
    app = _build_app(database_url=_DATABASE_URL, schema_check=lambda: False)
    resp = TestClient(app).get("/ready")

    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


# ---------------------------------------------------------------------------
# T-R5 — CI-connectivity proof: a real connection + trivial query actually succeeds
# ---------------------------------------------------------------------------
@requires_postgres
def test_ci_postgres_is_genuinely_reachable() -> None:
    """spec(M1a:AC-3) — T-R5 (integration): open a REAL connection to DATABASE_URL and
    assert ``SELECT 1`` returns 1.

    This proves CI genuinely REACHES its ephemeral Postgres (not merely starts a container),
    so a green T-R2 reflects real connectivity rather than a stubbed check. psycopg is
    imported lazily here so its absence never masks the non-gated RED signal above.
    """
    import psycopg  # lazy: only the DATABASE_URL-gated path needs the driver

    with psycopg.connect(_DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1")
        row = cur.fetchone()

    assert row is not None
    assert row[0] == 1


# ---------------------------------------------------------------------------
# T-R6 — local target-isolation: the fake adapter is the only target; no live creds/URL
# ---------------------------------------------------------------------------
def test_local_config_refuses_live_target_credentials() -> None:
    """spec(M1a:AC-6) spec(M1a:AC-5/O1) — T-R6: a ``local`` config cannot resolve a live
    target credential.

    accept (f): locally the P9 fake TargetAdapter is the only target — no live URL, no live
    credential, no hosted-model secret. A ``local`` Settings must refuse to resolve a live
    target credential, raising the dedicated EnvironmentIsolationError (the O1 boundary),
    never returning a degraded/empty reference.
    """
    from agentforge.config import EnvironmentIsolationError, Settings

    settings = Settings(environment="local")
    with pytest.raises(EnvironmentIsolationError):
        settings.resolve_target_credential(TARGET_ID)


def test_local_config_exposes_no_live_target_url() -> None:
    """spec(M1a:AC-6) — T-R6: a ``local`` config exposes no live target URL.

    Locally the ONLY reachable target is the deterministic P9 fake (no network). So a local
    Settings must not surface any live target URL: no attribute/mapping on the config may
    hand back an ``http(s)://`` endpoint for a target. We scan the config's own public
    surface and any target-listing helper it exposes; finding a live URL fails the test.
    """
    from agentforge.config import Settings

    settings = Settings(environment="local")

    def _looks_live(value: object) -> bool:
        return isinstance(value, str) and value.startswith(("http://", "https://"))

    # 1) No public attribute value on the config is a live http(s) URL.
    for name in dir(settings):
        if name.startswith("_"):
            continue
        try:
            value = getattr(settings, name)
        except Exception:
            continue
        if callable(value):
            continue
        assert not _looks_live(value), f"local config exposed a live target URL via {name!r}"

    # 2) Any target-listing helper the config offers must not enumerate a live URL either;
    #    locally the fake adapter is the only target. Absence of such a helper is also fine.
    for helper in ("target_urls", "list_target_urls", "live_target_urls"):
        fn = getattr(settings, helper, None)
        if callable(fn):
            urls = fn()
            assert not any(_looks_live(u) for u in urls), (
                f"local config's {helper}() enumerated a live target URL: {urls!r}"
            )
