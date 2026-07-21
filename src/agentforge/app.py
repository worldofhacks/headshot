"""ASGI entrypoint for the deployment/health surface.

spec(M1a:AC-3)

This is the module the container runs under uvicorn (``agentforge.app:app``). It wires the
health app factory (:func:`agentforge.health.create_app`) to a REAL, composed readiness
check via :func:`build_app`.

``/ready`` is 200 only when BOTH halves pass:

  1. a REAL Postgres-connectivity probe against ``database_url`` (connect + ``SELECT 1``,
     short connect timeout, **fail-closed** — any exception is treated as "not reachable",
     never raised out of the probe); and
  2. the pluggable ``schema_check`` — "migrations/schema current" (M2 supplies the real
     Alembic current-head == expected-head comparison; until then a fail-closed placeholder).

``/health`` stays liveness-only (``200 alive`` regardless) — it never consults either half.

Security note: the DB probe must NEVER log or return the DSN / connection details /
credentials. On failure it logs only a sanitized reason (``db_unreachable``) — never the
URL and never the raw exception (which can embed the DSN). The core config layer stays
framework- and driver-neutral (D10): ``psycopg`` is imported lazily inside the probe, never
at module top level, and never in ``agentforge.config``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable

from fastapi import FastAPI

from agentforge.health import create_app

_logger = logging.getLogger(__name__)

# Short connect timeout so an unreachable DB fails fast instead of hanging the probe.
_CONNECT_TIMEOUT_SECONDS = 2


def _db_ok(database_url: str | None) -> bool:
    """Real Postgres-connectivity probe — connect + ``SELECT 1``. Fail-closed.

    Returns ``True`` only if a fresh connection to ``database_url`` opens and a trivial
    query returns. ANY failure — missing URL, unreachable host, auth error, driver
    absent — returns ``False`` and is NEVER raised out of this function, so ``/ready``
    degrades to 503 rather than 500.

    Security: the DSN / credentials are never logged or returned. On failure only the
    sanitized reason ``db_unreachable`` is logged — never ``database_url`` and never the
    raw exception (which can embed the DSN).
    """
    if not database_url:
        _logger.warning("readiness: db_unreachable")
        return False
    try:
        # Lazy import: confine the driver to the readiness path so the framework-neutral
        # core (agentforge.config) never imports psycopg (D10).
        import psycopg

        with (
            psycopg.connect(database_url, connect_timeout=_CONNECT_TIMEOUT_SECONDS) as conn,
            conn.cursor() as cur,
        ):
            cur.execute("SELECT 1")
            row = cur.fetchone()
        return row is not None and row[0] == 1
    except Exception:
        # Sanitized reason only: never log the URL or the exception (which can carry the DSN).
        _logger.warning("readiness: db_unreachable")
        return False


def _placeholder_schema_check() -> bool:
    """Fail-closed placeholder schema check: schema not yet verified.

    Returns ``False`` — a non-production box that has not verified its schema must not
    report ready. This is the default handed to :func:`build_app` for the ASGI entrypoint.

    # M2 (AC): replace with the Alembic current-head == expected-head comparison.
    """
    return False


def build_app(database_url: str | None, schema_check: Callable[[], bool]) -> FastAPI:
    """Compose the two independent readiness signals and wrap the frozen app factory.

    ``/ready`` is 200 only when BOTH the real DB-connectivity probe (:func:`_db_ok`
    against ``database_url``) AND ``schema_check`` are truthy; otherwise 503. ``create_app``
    (in :mod:`agentforge.health`) is left UNCHANGED — this only supplies its
    ``readiness_check``.
    """
    return create_app(readiness_check=lambda: _db_ok(database_url) and bool(schema_check()))


# The ASGI entrypoint the container runs (``agentforge.app:app``). DATABASE_URL is read from
# the environment; the schema half is fail-closed until M2 wires the real Alembic check.
app = build_app(os.environ.get("DATABASE_URL"), _placeholder_schema_check)
