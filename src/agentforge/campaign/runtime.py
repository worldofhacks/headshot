"""Production composition root for the authorized bounded-run CLI (M11-coordinator).

``python -m agentforge.campaign run …`` (:mod:`agentforge.campaign.__main__`) must construct the
REAL production collaborators the injection-driven :func:`agentforge.campaign.cli.main` needs — a
real DB engine, a real :class:`~agentforge.target.openemr_adapter.OpenEmrAdapter`, a real clock, and
real run accounting — rather than failing closed for want of an injection. This module is that
composition root: the ONE place the live dependencies are built.

Two properties matter for safety:

* **Preflight is network-free and stays separate from run.** Building these dependencies opens NO
  socket: :func:`production_engine` uses ``pool_pre_ping`` but SQLAlchemy connects lazily (first
  use only), and :func:`live_adapter_factory` returns an adapter whose ``httpx`` client is built
  lazily inside ``send()``. So the composition root constructs inert objects; the target connection
  is made ONLY at the first post-gate dispatch inside ``run_case`` — after authorization + binding +
  scope validation pass. The presence-only preflight (``scripts/preflight_status.py``) never touches
  this module.
* **A misconfiguration fails closed, legibly.** A missing ``DATABASE_URL`` for a ``run`` is a typed
  :class:`RuntimeConfigError` (an operational error), NOT a silent default — the bounded run never
  launches against an unspecified store.

Framework-neutral at construction: ``httpx`` is never imported here (the adapter imports it lazily);
only SQLAlchemy's engine factory and stdlib are used.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

from sqlalchemy import Engine, create_engine

from agentforge.target.openemr_adapter import OpenEmrAdapter

# The per-target-request cost estimate the budget cap projects against. A live campaign's dispatch
# cost is dominated by the target call (hosted Red Team generation is skipped in seed replay); a
# small positive default keeps the budget cap MEANINGFUL (a zero estimate would neuter it). Override
# via HEADSHOT_PER_CALL_USD for a target with a known per-request price.
_DEFAULT_PER_CALL_USD = 0.01
_PER_CALL_USD_ENV = "HEADSHOT_PER_CALL_USD"


class RuntimeConfigError(Exception):
    """Raised when the runtime cannot be composed from the environment (e.g. no ``DATABASE_URL``).

    A dedicated, catchable type so an operational misconfiguration is distinguishable from a
    fail-closed authorization refusal — the composition root maps it to an operational exit code.
    """


def _to_psycopg_dialect(url: str) -> str:
    """Normalize a DSN to the ``postgresql+psycopg://`` dialect the stack installs (psycopg3).

    A bare ``postgresql://`` / ``postgres://`` scheme would let SQLAlchemy 2.x pick the default
    (psycopg2) driver, which is not installed; rewriting binds psycopg3. An explicit ``+psycopg``
    dialect is left untouched.
    """
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    return url


def production_engine(database_url: str | None) -> Engine:
    """Build the real SQLAlchemy engine from ``database_url``; fail closed if it is unset.

    The engine is created with ``pool_pre_ping`` (fail fast on a dead connection) but does NOT
    connect here — SQLAlchemy connects lazily on first use, so constructing it opens no socket. A
    missing/empty ``database_url`` raises :class:`RuntimeConfigError` (an operational error) rather
    than defaulting to some store — a bounded live run never launches against an unspecified DB.
    """
    if not database_url:
        raise RuntimeConfigError(
            "DATABASE_URL is not set — the authorized bounded run needs a real evidence store; "
            "refusing to launch against an unspecified database (fail closed)"
        )
    return create_engine(_to_psycopg_dialect(database_url), pool_pre_ping=True, future=True)


class SystemClock:
    """The real wall clock the gateway's rate/timeout caps read (``now()`` -> epoch seconds)."""

    def now(self) -> float:
        return time.time()


class RunAccounting:
    """The real run accounting the gateway's budget cap reads and charges.

    Exposes ``spent_usd`` (accumulated across the whole run — the coordinator reuses ONE accounting
    for every case) and the REQUIRED ``per_call_usd`` estimate the budget cap projects against
    BEFORE each dispatch; ``charge()`` commits the estimate after a physical send. A positive
    ``per_call_usd`` keeps the budget cap meaningful.
    """

    def __init__(self, per_call_usd: float | None = None) -> None:
        self.per_call_usd = _DEFAULT_PER_CALL_USD if per_call_usd is None else float(per_call_usd)
        self.spent_usd = 0.0
        self.request_count = 0

    def charge(self) -> None:
        self.spent_usd += self.per_call_usd
        self.request_count += 1


def accounting_from_environment() -> RunAccounting:
    """Build :class:`RunAccounting` with the per-call estimate from ``HEADSHOT_PER_CALL_USD``.

    An unset/blank/unparseable value falls back to the positive default — the estimate is never
    silently zero (which would neuter the budget cap).
    """
    raw = os.environ.get(_PER_CALL_USD_ENV, "").strip()
    if not raw:
        return RunAccounting()
    try:
        return RunAccounting(per_call_usd=float(raw))
    except ValueError:
        return RunAccounting()


def live_adapter_factory(*, timeout_seconds: float | None = None) -> Callable[..., OpenEmrAdapter]:
    """Return the factory the CLI calls as ``factory(base_url=...) -> OpenEmrAdapter``.

    The returned adapter carries NO injected client, so its real ``httpx`` client is built LAZILY
    inside ``send()`` on the first post-gate dispatch — constructing the adapter opens no socket.
    There is no fallback to the P9 fake: this is the sole live transport the composition root wires.
    """

    def _factory(*, base_url: str) -> OpenEmrAdapter:
        if timeout_seconds is None:
            return OpenEmrAdapter(base_url=base_url)
        return OpenEmrAdapter(base_url=base_url, timeout_seconds=timeout_seconds)

    return _factory
