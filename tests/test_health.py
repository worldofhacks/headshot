"""M1a health/readiness probes (AC-3) — liveness vs. readiness, via an app factory.

spec(M1a:AC-3)

Public contract under test (ARCHITECTURE.md §12; IMPLEMENTATION_PLAN.md M1a accept (c)):

    from agentforge.health import create_app

    app = create_app(readiness_check=<callable>)  -> a FastAPI app exposing:
        GET /health -> 200 {"status": "alive"}     (process liveness; NO DB)
        GET /ready  -> 200 {"status": "ready"}      when readiness_check() is truthy
                    -> 503 {"status": "not_ready"}  when it is falsy OR raises

``readiness_check`` models "DB connectivity + migrations-current"; the test injects a fake
callable so no real database is required. The factory + FastAPI/httpx do not exist yet, so
this errors at import/collection (expected RED — missing deps + missing module).
"""

from __future__ import annotations

import pytest

# fastapi is not installed yet and agentforge.health does not exist -> RED at import time.
from fastapi.testclient import TestClient

from agentforge.health import create_app


def _client(readiness_check) -> TestClient:
    return TestClient(create_app(readiness_check=readiness_check))


# ---------------------------------------------------------------------------
# Liveness — /health — must be independent of readiness / DB state
# ---------------------------------------------------------------------------


def test_health_is_alive_regardless_of_readiness() -> None:
    """spec(M1a:AC-3) — /health reports process liveness only; a failing readiness check
    must NOT drag /health down. Inject a readiness check that raises to prove independence.
    """

    def dead_db() -> bool:
        raise RuntimeError("db down")

    resp = _client(dead_db).get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}


def test_health_does_not_invoke_the_readiness_check() -> None:
    """spec(M1a:AC-3) — liveness must be cheap: it must NOT touch the DB-readiness probe.

    We fail the test if /health ever calls the injected readiness check.
    """
    calls: list[int] = []

    def spy() -> bool:
        calls.append(1)
        return True

    resp = _client(spy).get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}
    assert calls == []  # /health never ran the readiness probe


# ---------------------------------------------------------------------------
# Readiness — /ready — reflects the injected DB/migration check
# ---------------------------------------------------------------------------


def test_ready_returns_200_when_check_truthy() -> None:
    """spec(M1a:AC-3) — DB reachable + migrations current -> 200 {"status": "ready"}."""
    resp = _client(lambda: True).get("/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


def test_ready_returns_503_when_check_falsy() -> None:
    """spec(M1a:AC-3) — readiness check returns falsy -> 503 {"status": "not_ready"}."""
    resp = _client(lambda: False).get("/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


def test_ready_returns_503_when_check_raises() -> None:
    """spec(M1a:AC-3) — a readiness probe that RAISES (e.g. DB connection error) must be
    treated as not-ready (503), never a 500 and never a false 'ready'. Fail-closed.
    """

    def boom() -> bool:
        raise ConnectionError("cannot reach postgres")

    resp = _client(boom).get("/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


@pytest.mark.parametrize("falsy", [False, None, 0, "", []])
def test_ready_treats_any_falsy_result_as_not_ready(falsy: object) -> None:
    """spec(M1a:AC-3) — readiness is truthiness-based; any falsy return means not_ready.

    Blocks a lazy ``== True`` check that would mishandle e.g. a ``None`` or ``0`` return.
    """
    resp = _client(lambda: falsy).get("/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


def test_ready_actually_consults_the_check_each_request() -> None:
    """spec(M1a:AC-3) — readiness is evaluated per-request, not cached at app build.

    A DB that recovers between requests must flip /ready from 503 back to 200; a hardcoded
    response cannot satisfy both assertions.
    """
    state = {"ok": False}
    client = _client(lambda: state["ok"])

    first = client.get("/ready")
    assert first.status_code == 503
    assert first.json() == {"status": "not_ready"}

    state["ok"] = True
    second = client.get("/ready")
    assert second.status_code == 200
    assert second.json() == {"status": "ready"}


def test_create_app_returns_a_fastapi_app() -> None:
    """spec(M1a:AC-3) — the factory yields a real FastAPI application instance."""
    from fastapi import FastAPI

    app = create_app(readiness_check=lambda: True)
    assert isinstance(app, FastAPI)
