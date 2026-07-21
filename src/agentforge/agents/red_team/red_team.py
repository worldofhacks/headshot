"""The Red Team agent — the untrusted generator that dispatches ONLY through the gateway (M8).

ARCHITECTURE.md §3/§8/§16 (trust split F2, live-campaign gate F7, S1/S3), DECISIONS.md D14;
PRD-14/17.

:class:`RedTeam` selects cases (coverage-aware), sequences multi-turn attempts, and dispatches
EACH one ONLY through the trusted M4 ``PolicyGateway.execute`` — the gateway it is handed is the
SOLE object that can reach a target. The Red Team holds NO adapter, NO credential, and NO
outbound path of its own; the only reference it keeps is that gateway (plus an offline provider
for mutation). It returns the gateway's authoritative ``AttemptResult``s and mints NO evidence
itself.

The gateway (M4) owns budget/rate/timeout/attempt caps and the HARD ABORT. The Red Team RESPECTS
them and never enforces, owns, or bypasses them: it does not catch the gateway's
:class:`AbortError` / :class:`OffAllowlistDenied`, so a cap breach or an off-allowlist denial
propagates as a STOP the Red Team obeys — it never overruns a cap by dispatching more.

Framework-neutral (D10): imports policy(gateway) / the offline provider — never a web framework,
never a target adapter.
"""

from __future__ import annotations

from typing import Any

from agentforge.agents.red_team.providers import RedTeamProvider
from agentforge.agents.red_team.selection import select_cases
from agentforge.policy.gateway import AttemptResult, PolicyGateway, RunPolicy

# A nominal wall-clock advance charged between attempts so a run's elapsed time progresses
# deterministically against the gateway's INJECTED clock (the gateway owns the timeout cap; this
# only models time passing so that cap can trip without real sleeping). Applied only when the
# clock is advanceable (a test double); a production monotonic clock has no ``advance`` and moves
# on its own.
_ATTEMPT_TICK_SECONDS = 1.0


class RedTeam:
    """The independent, untrusted adversarial generator.

    Constructed with the trusted gateway (its SOLE exit to any target) and an OFFLINE provider
    (for mutation). It deliberately keeps NO adapter/credential/secret attribute — the only way
    it can reach a target is by calling ``gateway.execute``.
    """

    def __init__(self, *, gateway: PolicyGateway, provider: RedTeamProvider) -> None:
        # Stored under names that carry no "adapter"/"credential"/"secret" in them — the RT holds
        # neither. The gateway is the ONLY object here that can reach a target.
        self.gateway = gateway
        self.provider = provider

    def run(
        self,
        cases: list[dict[str, Any]],
        policy: RunPolicy,
        *,
        target_id: str = "fake",
        coverage: dict[str, int] | None = None,
    ) -> list[AttemptResult]:
        """Dispatch each selected attempt through the gateway, in order, and return the results.

        When a ``coverage`` snapshot is supplied the cases are selected coverage-aware (least-
        covered category first); otherwise they are dispatched in the given order. EACH attempt is
        handed to ``PolicyGateway.execute`` — the gateway is the SOLE path to the target, enforces
        every cap, and returns the authoritative :class:`AttemptResult`.

        The Red Team does NOT catch the gateway's :class:`AbortError` or ``OffAllowlistDenied``: a
        cap breach or an off-allowlist denial propagates as a STOP, so the Red Team can never
        overrun a cap or bypass the gate. There is no fallback dispatch path — if the gateway is
        absent, the call fails loudly rather than opening the Red Team's own route to a target.
        """
        if self.gateway is None:
            raise ValueError(
                "the Red Team has no gateway; it cannot reach a target by any other path "
                "(the gateway is its SOLE exit) — refusing to dispatch"
            )

        ordered = select_cases(cases, coverage) if coverage is not None else list(cases)

        results: list[AttemptResult] = []
        for attempt in ordered:
            # The ONLY outbound call the Red Team makes. A raised AbortError / OffAllowlistDenied
            # propagates unchanged — the Red Team stops, it does not overrun or bypass the gate.
            result = self.gateway.execute(attempt, policy, target_id=target_id)
            results.append(result)
            # Model wall-clock progress between attempts so the gateway's timeout cap can trip
            # deterministically against its injected clock. This does NOT enforce the cap — the
            # gateway does; it only lets time advance without real sleeping.
            self._advance_clock()
        return results

    def _advance_clock(self) -> None:
        """Advance the gateway's injected clock by one nominal tick, if it is advanceable.

        A test double exposes ``advance``; advancing it lets the gateway's OWN timeout cap trip
        deterministically without real sleeping. A production monotonic clock has no ``advance``
        and is left untouched (time moves on its own). The Red Team never reads or enforces the
        cap — that is the gateway's; it only models the passage of time.
        """
        clock = getattr(self.gateway, "clock", None)
        advance = getattr(clock, "advance", None)
        if callable(advance):
            advance(_ATTEMPT_TICK_SECONDS)
