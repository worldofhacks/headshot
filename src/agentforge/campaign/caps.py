"""RunCaps — FAIL-CLOSED parsing of every execution ceiling into a bounded RunPolicy.

M11-coordinator (ARCHITECTURE.md §5 live-campaign gate F5; DECISIONS.md D16). The caps are the
enforcement-point ceilings the trusted :class:`~agentforge.policy.gateway.PolicyGateway` reads —
a run is only reachable AFTER every applicable cap parses. Budget/rate/count/timeout caps must be
finite and positive; retries must be a non-negative integer. Missing, invalid, or over-maximum
values raise :class:`CapError` rather than becoming unbounded defaults. An optional field may be
absent only when an explicitly supplied trusted target maximum also omits that legacy dimension.

The hard platform maxima are a *ceiling on the ceilings*: even an authorized operator cannot
request an unbounded-in-practice budget/rate/count/attempt/timeout. They are deliberately generous
(so a real bounded run is never obstructed) but finite (so ``10**12`` is refused).

Framework-neutral core: stdlib + target-domain caps + gateway RunPolicy; no web framework/network.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from agentforge.policy.gateway import RunPolicy
from agentforge.target.spec import SafetyCaps

# The legacy four caps are always required. The three physical-execution caps are also required
# unless a trusted legacy target maximum explicitly omits the corresponding dimension.
_BUDGET = "budget_usd"
_ATTEMPTS = "max_attempts_per_run"
_RATE = "target_requests_per_second"
_TIMEOUT = "run_timeout_seconds"
_LOGICAL_CASES = "logical_case_limit"
_PHYSICAL_REQUESTS = "physical_request_limit"
_RETRIES_PER_TURN = "target_retries_per_turn"

# Hard platform maxima — a ceiling on the ceilings, finite so an unbounded-in-practice request is
# refused. Generous enough that a genuine bounded run is never obstructed.
_HARD_MAXIMA: dict[str, float] = {
    _BUDGET: 1_000_000.0,  # USD per run
    _ATTEMPTS: 1_000_000.0,  # attempts per run
    _RATE: 1_000_000.0,  # target requests per second
    _TIMEOUT: 86_400.0,  # seconds (24h) per run
    _LOGICAL_CASES: 1_000_000.0,
    _PHYSICAL_REQUESTS: 1_000_000.0,
    _RETRIES_PER_TURN: 100.0,
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
    def parse(
        config: Mapping[str, Any],
        *,
        trusted_maximum: SafetyCaps | None = None,
    ) -> RunPolicy:
        """Parse ``config`` into a :class:`RunPolicy`, failing closed on any invalid cap.

        The four legacy caps are always required. The logical-case, physical-request, and retry
        caps are also required unless a supplied trusted target maximum explicitly omits that
        dimension. This makes legacy compatibility an explicit target property rather than a
        missing-input default. Any requested cap must also narrow the trusted maximum.
        """
        if not isinstance(config, Mapping):
            raise CapError(
                f"run caps must be a mapping of the four ceilings, got {type(config).__name__} "
                "— an unbounded run can never launch from an absent caps config (fail closed)"
            )
        if trusted_maximum is not None and not isinstance(trusted_maximum, SafetyCaps):
            raise CapError("trusted maximum must be a validated SafetyCaps value")
        budget = RunCaps._finite_positive(config, _BUDGET)
        attempts = RunCaps._finite_positive_int(config, _ATTEMPTS)
        rate = RunCaps._finite_positive(config, _RATE)
        timeout = RunCaps._finite_positive(config, _TIMEOUT)
        logical_cases = (
            RunCaps._finite_positive_int(config, _LOGICAL_CASES)
            if _LOGICAL_CASES in config
            else RunCaps._omitted_optional_cap(
                _LOGICAL_CASES,
                trusted_maximum=trusted_maximum,
            )
        )
        physical_requests = (
            RunCaps._finite_positive_int(config, _PHYSICAL_REQUESTS)
            if _PHYSICAL_REQUESTS in config
            else RunCaps._omitted_optional_cap(
                _PHYSICAL_REQUESTS,
                trusted_maximum=trusted_maximum,
            )
        )
        retries_per_turn = (
            RunCaps._nonnegative_int(config, _RETRIES_PER_TURN)
            if _RETRIES_PER_TURN in config
            else RunCaps._omitted_optional_cap(
                _RETRIES_PER_TURN,
                trusted_maximum=trusted_maximum,
            )
        )
        requested = SafetyCaps(
            budget_usd=budget,
            max_attempts_per_run=attempts,
            target_requests_per_second=rate,
            run_timeout_seconds=timeout,
            logical_case_limit=logical_cases,
            physical_request_limit=physical_requests,
            target_retries_per_turn=retries_per_turn,
        )
        if trusted_maximum is not None and not requested.is_within(trusted_maximum):
            raise CapError("requested run caps do not narrow the trusted target maximum")
        return RunPolicy(**requested.canonical_payload())

    @staticmethod
    def _omitted_optional_cap(
        field: str,
        *,
        trusted_maximum: SafetyCaps | None,
    ) -> None:
        if trusted_maximum is None or getattr(trusted_maximum, field) is not None:
            raise CapError(
                f"run cap {field!r} is MISSING — this execution ceiling must be explicit "
                "(fail closed, no unbounded or legacy-retry fallback)"
            )
        return None

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

    @staticmethod
    def _nonnegative_int(config: Mapping[str, Any], field: str) -> int:
        value = config[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > _HARD_MAXIMA[field]
        ):
            raise CapError(f"run cap {field!r} must be a non-negative integer (fail closed)")
        return value
