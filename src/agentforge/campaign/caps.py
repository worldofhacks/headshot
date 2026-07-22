"""RunCaps — FAIL-CLOSED parsing of budget/rate/attempt/timeout into a bounded RunPolicy.

M11-coordinator (ARCHITECTURE.md §5 live-campaign gate F5; DECISIONS.md D16). The caps are the
enforcement-point ceilings the trusted :class:`~agentforge.policy.gateway.PolicyGateway` reads —
a run is only reachable AFTER every cap parses. So parsing is fail-closed: EVERY cap must be a
FINITE POSITIVE number and ``<=`` a hard platform maximum. A missing, zero, negative, non-numeric,
infinite, NaN, or over-maximum value is a typed :class:`CapError` — never a silent default, never
an unbounded run. There is no "unset means unlimited" path: an unbounded dimension can never slip
through.

The hard platform maxima are a *ceiling on the ceilings*: even an authorized operator cannot
request an unbounded-in-practice budget/rate/attempt/timeout. They are deliberately generous (so
a real bounded run is never obstructed) but finite (so ``10**12`` is refused).

Framework-neutral core: stdlib + gateway RunPolicy only; no web framework, no network.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from agentforge.policy.gateway import RunPolicy

# The four caps every run MUST declare — there is no default for any of them.
_BUDGET = "budget_usd"
_ATTEMPTS = "max_attempts_per_run"
_RATE = "target_requests_per_second"
_TIMEOUT = "run_timeout_seconds"
_REQUIRED_CAPS: tuple[str, ...] = (_BUDGET, _ATTEMPTS, _RATE, _TIMEOUT)

# Hard platform maxima — a ceiling on the ceilings, finite so an unbounded-in-practice request is
# refused. Generous enough that a genuine bounded run is never obstructed.
_HARD_MAXIMA: dict[str, float] = {
    _BUDGET: 1_000_000.0,  # USD per run
    _ATTEMPTS: 1_000_000.0,  # attempts per run
    _RATE: 1_000_000.0,  # target requests per second
    _TIMEOUT: 86_400.0,  # seconds (24h) per run
}


class CapError(Exception):
    """Raised when a run cap is missing, non-positive, non-finite, non-numeric, or over-maximum.

    A dedicated, catchable type so a fail-closed cap refusal (an unbounded/nonsensical ceiling
    refused) is distinguishable from an incidental bug. The message names the offending cap so
    the refusal is legible in a log or a traceback.
    """


class RunCaps:
    """Fail-closed parser: a caps mapping -> an immutable RunPolicy, or a typed CapError."""

    @staticmethod
    def parse(config: Mapping[str, Any]) -> RunPolicy:
        """Parse ``config`` into a :class:`RunPolicy`, failing closed on any invalid cap.

        Each of the four caps must be PRESENT and a FINITE POSITIVE number ``<=`` its hard
        platform maximum. ``budget``/``rate``/``timeout`` are floats; ``max_attempts_per_run`` is
        an integer. Any violation raises :class:`CapError` — no silent default, no unbounded run.
        """
        if not isinstance(config, Mapping):
            raise CapError(
                f"run caps must be a mapping of the four ceilings, got {type(config).__name__} "
                "— an unbounded run can never launch from an absent caps config (fail closed)"
            )
        budget = RunCaps._finite_positive(config, _BUDGET)
        attempts = RunCaps._finite_positive_int(config, _ATTEMPTS)
        rate = RunCaps._finite_positive(config, _RATE)
        timeout = RunCaps._finite_positive(config, _TIMEOUT)
        return RunPolicy(
            budget_usd=budget,
            max_attempts_per_run=attempts,
            target_requests_per_second=rate,
            run_timeout_seconds=timeout,
        )

    @staticmethod
    def _coerce_number(config: Mapping[str, Any], field: str) -> float:
        """Return ``config[field]`` as a finite positive float, or raise :class:`CapError`.

        A missing key, a ``None``, a bool (rejected explicitly — ``True`` is not a budget), a
        non-numeric value, a zero/negative value, or an infinite/NaN value each fails closed.
        """
        if field not in config:
            raise CapError(
                f"run cap {field!r} is MISSING — every ceiling must be explicit; a missing cap "
                "is never a silent default (fail closed, no unbounded run)"
            )
        value = config[field]
        # A bool is an int subclass in Python — refuse it so True/False can never be a cap.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CapError(
                f"run cap {field!r}={value!r} is not a numeric ceiling — a non-numeric cap can "
                "never bound a run (fail closed)"
            )
        numeric = float(value)
        if not math.isfinite(numeric):
            raise CapError(
                f"run cap {field!r}={value!r} is not finite (inf/NaN) — an unbounded or "
                "nonsensical ceiling never parses (fail closed)"
            )
        if numeric <= 0.0:
            raise CapError(
                f"run cap {field!r}={value!r} must be a POSITIVE number — a zero/negative cap "
                "can never bound a run (fail closed)"
            )
        maximum = _HARD_MAXIMA[field]
        if numeric > maximum:
            raise CapError(
                f"run cap {field!r}={value!r} exceeds the hard platform maximum {maximum!r} — "
                "a run can never request an unbounded-in-practice ceiling (fail closed)"
            )
        return numeric

    @staticmethod
    def _finite_positive(config: Mapping[str, Any], field: str) -> float:
        return RunCaps._coerce_number(config, field)

    @staticmethod
    def _finite_positive_int(config: Mapping[str, Any], field: str) -> int:
        """Like :meth:`_finite_positive` but for an attempt count — coerced to ``int``.

        The value must be a whole number (a fractional attempt count is nonsensical); it is
        validated as a finite positive within-maximum number first, then coerced to ``int``.
        """
        numeric = RunCaps._coerce_number(config, field)
        if numeric != int(numeric):
            raise CapError(
                f"run cap {field!r}={numeric!r} must be a whole number of attempts (fail closed)"
            )
        return int(numeric)
