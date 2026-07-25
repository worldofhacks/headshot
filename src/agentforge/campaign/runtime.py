"""Shared runtime primitives for the private durable Runner and Scheduler.

The Railway Runner is the only supported live campaign executor. It consumes a durable
``agent_work`` job, revalidates the exact persisted authorization before dispatch, records target
and agent execution rows, and exports the corresponding Langfuse observations.

The former one-shot ``python -m agentforge.campaign run`` composition root is retired because its
local-file workflow could bypass that durable ledger. The generic engine, clock, and accounting
helpers remain here because the authoritative private Runner and Scheduler use them. The legacy
live-adapter factory now refuses instead of constructing a target transport.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from typing import TextIO

from sqlalchemy import Engine, create_engine

from agentforge.target.openemr_adapter import OpenEmrAdapter

# The per-target-request cost estimate the budget cap projects against. A live campaign's dispatch
# cost is dominated by the target call (hosted Red Team generation is skipped in seed replay); a
# small positive default keeps the budget cap MEANINGFUL (a zero estimate would neuter it). Override
# via HEADSHOT_PER_CALL_USD for a target with a known per-request price.
_DEFAULT_PER_CALL_USD = 0.01
_PER_CALL_USD_ENV = "HEADSHOT_PER_CALL_USD"
LEGACY_LIVE_EXECUTION_EXIT_CODE = 2
LEGACY_LIVE_EXECUTION_MESSAGE = (
    "operational-error: direct legacy live execution is disabled because it bypasses the durable "
    "campaign, agent, target-request, cost, and Langfuse telemetry ledger. Use the authenticated "
    "Railway Web control plane: create an exact-scope /api/v1/campaign-authorization-requests "
    "record, obtain a decision from a distinct approver, then launch through /api/v1/campaigns. "
    "Only the private DurableCampaignRunner may contact a live target."
)


def refuse_legacy_live_execution(*, stream: TextIO | None = None) -> int:
    """Fail closed before credentials, storage, adapters, or target sockets are touched."""

    print(LEGACY_LIVE_EXECUTION_MESSAGE, file=stream or sys.stderr)
    return LEGACY_LIVE_EXECUTION_EXIT_CODE


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
            "DATABASE_URL is not set — the private durable service needs its authoritative store; "
            "refusing to start against an unspecified database (fail closed)"
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
    """Refuse the retired direct-live adapter composition path.

    ``timeout_seconds`` remains in the signature only to make stale callers fail with the explicit
    safety error instead of silently changing call semantics. The durable Runner constructs its
    adapter only after loading and revalidating persisted control-plane authority.
    """

    del timeout_seconds
    raise RuntimeConfigError(LEGACY_LIVE_EXECUTION_MESSAGE)
