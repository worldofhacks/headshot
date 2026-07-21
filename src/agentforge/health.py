"""Liveness + readiness probes behind an app factory.

spec(M1a:AC-3)

``create_app(readiness_check=...)`` returns a FastAPI app exposing two probes with
distinct semantics (ARCHITECTURE.md §12; IMPLEMENTATION_PLAN.md M1a accept (c)):

* ``GET /health`` — process **liveness**. Always ``200 {"status": "alive"}`` as long as
  the process can serve a request. It must NOT touch the database / readiness check, so a
  broken dependency never makes the orchestrator kill an otherwise-live pod.
* ``GET /ready`` — **readiness**. Consults the injected ``readiness_check`` *per request*
  (models "DB reachable + migrations current"). Truthy -> ``200 {"status": "ready"}``;
  falsy **or raising** -> ``503 {"status": "not_ready"}`` (fail-closed).

This module is the only place in the platform that imports a web framework; the
framework-neutral core (``agentforge.config`` etc.) stays dependency-free (D10).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse


def create_app(readiness_check: Callable[[], Any]) -> FastAPI:
    """Build the health/readiness FastAPI app.

    ``readiness_check`` is a zero-arg callable returning a truthiness-y value (e.g. a DB
    ping). It is injected so tests — and production — can swap the real dependency check
    without a live database.
    """
    app = FastAPI(title="AgentForge health", docs_url=None, redoc_url=None)

    @app.get("/health")
    def health() -> JSONResponse:
        # Liveness only: never consult readiness_check — a dead DB must not fail liveness.
        return JSONResponse(status_code=200, content={"status": "alive"})

    @app.get("/ready")
    def ready() -> JSONResponse:
        # Fail-closed: any exception is treated as not-ready, never a 500 or a false ready.
        try:
            ok = readiness_check()
        except Exception:
            ok = False
        if ok:
            return JSONResponse(status_code=200, content={"status": "ready"})
        return JSONResponse(status_code=503, content={"status": "not_ready"})

    return app
