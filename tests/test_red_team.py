"""M8 — Red Team AGENT RED tests (written first, NO src/ code).

Anchors: ARCHITECTURE.md §3/§8/§16 (trust split F2, live-campaign gate F7, S1/S3),
DECISIONS.md D14; PRD-14/17; IMPLEMENTATION_PLAN.md M8; wf-m8-redteam DESIGN + ACCEPTANCE.

The **Red Team** is the INDEPENDENT, UNTRUSTED generator. It selects cases (coverage-aware),
sequences multi-turn attempts, and dispatches EACH one ONLY through the trusted M4
``PolicyGateway.execute`` — the gateway is the SOLE path to any target. The RT holds NO adapter,
NO credential, NO outbound path; it produces NO Judge evidence. The gateway (M4) owns the
budget/rate/timeout caps and the HARD ABORT; the RT NEVER enforces, owns, or bypasses them, and
a gateway :class:`AbortError` propagates as a STOP the RT respects (it does not overrun).

These tests dispatch through the **REAL M4 gateway** wired to the deterministic P9
FakeTargetAdapter + an injected clock/accounting, so caps trip WITHOUT real sleeping or real
cost, and NO network is ever touched. Every test pins an ACCEPTANCE edge — never a happy path
alone. Until ``agentforge.agents.red_team.*`` exists, every import below fails and this module
RED-collects for the right reason (import error, not logic bug).
"""

from __future__ import annotations

import contextlib
import socket

import pytest

# The RT surface under test (does not exist yet -> RED by import error).
from agentforge.agents.red_team.mutation import mutate
from agentforge.agents.red_team.providers import FakeProvider
from agentforge.agents.red_team.red_team import RedTeam
from agentforge.agents.red_team.selection import least_covered_category, select_cases
from agentforge.config import Settings
from agentforge.contracts import validate
from agentforge.policy.allowlist import Allowlist, AllowlistEntry
from agentforge.policy.gateway import AbortError, PolicyGateway, RunPolicy
from agentforge.target.base import RateLimitedError, TargetRequest
from agentforge.target.fake_adapter import FakeTargetAdapter, canonical_key

# The only locally-allowlisted target is the deterministic P9 fake (no live URL is resolvable).
FAKE_TARGET_ID = "fake"


# ---------------------------------------------------------------------------
# Deterministic doubles — the SAME shape the M4 gateway suite injects: a hand-advanced clock
# and a manual spend meter, so budget/rate/timeout caps trip WITHOUT real time or real cost.
# ---------------------------------------------------------------------------
class FakeClock:
    """A monotonic clock the test advances by hand. ``now()`` returns seconds as a float."""

    def __init__(self, start: float = 0.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


class FakeAccounting:
    """A manual spend meter: each dispatch is charged ``per_call_usd``; total is queryable."""

    def __init__(self, per_call_usd: float = 1.0) -> None:
        self.per_call_usd = per_call_usd
        self.spent_usd = 0.0

    def charge(self) -> None:
        self.spent_usd += self.per_call_usd


def _allowlist() -> Allowlist:
    """An allowlist admitting ONLY the P9 fake target (no live URL locally)."""
    return Allowlist([AllowlistEntry(target_id=FAKE_TARGET_ID, adapter_name="fake")])


def _gateway(
    *,
    adapter: FakeTargetAdapter | None = None,
    clock: FakeClock | None = None,
    accounting: FakeAccounting | None = None,
) -> PolicyGateway:
    """The REAL M4 gateway wired to deterministic doubles (all injectable, no network)."""
    return PolicyGateway(
        allowlist=_allowlist(),
        adapter=adapter or FakeTargetAdapter(),
        settings=Settings(environment="local"),
        clock=clock or FakeClock(),
        accounting=accounting or FakeAccounting(),
    )


def _policy(
    *,
    budget_usd: float = 1000.0,
    max_attempts_per_run: int = 1000,
    target_requests_per_second: float = 1000.0,
    run_timeout_seconds: float = 3600.0,
) -> RunPolicy:
    return RunPolicy(
        budget_usd=budget_usd,
        max_attempts_per_run=max_attempts_per_run,
        target_requests_per_second=target_requests_per_second,
        run_timeout_seconds=run_timeout_seconds,
    )


def _attempt(case_ref: str, seq: list[str], category: str = "prompt_injection") -> dict:
    """A minimal, credential-free AttackAttempt (the RT's proposed input only)."""
    return {
        "schema_version": "1",
        "case_ref": case_ref,
        "input_sequence": list(seq),
        "category": category,
    }


# A tiny in-repo case set spanning the three corpus categories, so selection has a gap to steer
# toward. Each is a schema-shaped AttackAttempt (single- and multi-turn).
_CASES = [
    _attempt("AF-M11-PI-001", ["pi turn"], "prompt_injection"),
    _attempt("AF-M11-PI-002", ["mt one", "mt two"], "prompt_injection"),
    _attempt("AF-M11-DX-001", ["dx turn"], "data_exfiltration"),
    _attempt("AF-M11-TM-001", ["tm turn"], "tool_misuse"),
]


# ===========================================================================
# (b) the RT dispatches ONLY via the gateway — it holds no adapter/credential/outbound path
# ===========================================================================
def test_red_team_dispatches_every_attempt_through_the_gateway() -> None:
    """A run dispatches each selected case through ``PolicyGateway.execute`` and returns the
    gateway's authoritative AttemptResult(s). The RT never reaches a target by any other path.
    """
    adapter = FakeTargetAdapter()
    gateway = _gateway(adapter=adapter)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    results = rt.run(_CASES, _policy(), target_id=FAKE_TARGET_ID)

    # Every dispatch physically reached the P9 fake THROUGH the gateway (adapter.calls records
    # each send); the count matches the attempts run.
    assert len(adapter.calls) == len(results) >= 1
    # The results are the gateway's own AttemptResult objects (they carry the minted evidence).
    for result in results:
        assert result.campaign_run_id
        assert result.content_hash


def test_red_team_holds_no_adapter_or_credential() -> None:
    """The RT is untrusted: it must NOT hold an adapter, a credential, or an outbound path of
    its own. The only object that can reach a target is the gateway it was handed."""
    rt = RedTeam(gateway=_gateway(), provider=FakeProvider())

    state = {**getattr(rt, "__dict__", {})}
    # No TargetAdapter anywhere on the RT.
    assert not any(isinstance(v, FakeTargetAdapter) for v in state.values()), (
        "the Red Team holds a TargetAdapter — it must reach a target ONLY via the gateway"
    )
    # No attribute that smells like a credential/secret/adapter on the RT.
    for name in dir(rt):
        lowered = name.lower()
        assert "credential" not in lowered, f"RT exposes a credential-shaped attr {name!r}"
        assert "adapter" not in lowered, f"RT exposes an adapter-shaped attr {name!r}"
        assert "secret" not in lowered, f"RT exposes a secret-shaped attr {name!r}"


def test_red_team_cannot_dispatch_without_a_gateway() -> None:
    """There is no bypass: constructing an RT with no gateway (or running with none) cannot
    reach a target — it must fail loudly rather than open its own path."""
    with pytest.raises((TypeError, ValueError, AttributeError)):
        RedTeam(gateway=None, provider=FakeProvider()).run(  # type: ignore[arg-type]
            _CASES, _policy(), target_id=FAKE_TARGET_ID
        )


# ===========================================================================
# (d) multi-turn sequences are dispatched IN ORDER (not a single-prompt collapse)
# ===========================================================================
def test_multi_turn_attempt_dispatched_in_order() -> None:
    """A multi-turn case is delivered to the gateway as an ordered ``input_sequence`` — the
    gateway builds a TargetRequest whose turns match the case turns, in order. We assert the
    fake saw the exact ordered turn key."""
    adapter = FakeTargetAdapter()
    gateway = _gateway(adapter=adapter)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    multi = _attempt("AF-M11-PI-002", ["turn one", "turn two"], "prompt_injection")
    rt.run([multi], _policy(), target_id=FAKE_TARGET_ID)

    # The fake keys a request by the ORDERED turn sequence; the reversed order is a different
    # key, so an out-of-order dispatch would not match.
    ordered_key = canonical_key(TargetRequest(turns=("turn one", "turn two")))
    reversed_key = canonical_key(TargetRequest(turns=("turn two", "turn one")))
    assert ordered_key in adapter.calls
    assert reversed_key not in adapter.calls


# ===========================================================================
# (c) coverage-aware selection — least-covered category first
# ===========================================================================
def test_least_covered_category_is_identified_from_a_snapshot() -> None:
    """Given a coverage snapshot (category -> covered count), the least-covered category is
    picked. tool_misuse here has the fewest covered attempts."""
    coverage = {"prompt_injection": 9, "data_exfiltration": 4, "tool_misuse": 1}

    assert least_covered_category(coverage) == "tool_misuse"


def test_selection_orders_least_covered_category_first() -> None:
    """``select_cases`` orders the least-covered category's cases FIRST, so the campaign steers
    toward the coverage gap. Deterministic given a fixed snapshot (no order-breaking
    randomness)."""
    coverage = {"prompt_injection": 9, "data_exfiltration": 4, "tool_misuse": 1}

    ordered = select_cases(_CASES, coverage)

    # The first selected case belongs to the least-covered category.
    assert ordered[0]["category"] == "tool_misuse"
    # Same snapshot -> same order (determinism).
    assert select_cases(_CASES, coverage) == ordered
    # Every input case is still present (selection reorders, never silently drops).
    assert {c["case_ref"] for c in ordered} == {c["case_ref"] for c in _CASES}


def test_selection_is_deterministic_and_total() -> None:
    """A different snapshot flips the priority deterministically; selection remains total
    (all cases represented, no duplicates)."""
    coverage = {"prompt_injection": 1, "data_exfiltration": 8, "tool_misuse": 8}

    ordered = select_cases(_CASES, coverage)

    assert ordered[0]["category"] == "prompt_injection"
    refs = [c["case_ref"] for c in ordered]
    assert len(refs) == len(set(refs)) == len(_CASES)


# ===========================================================================
# (c) a PARTIAL success spawns N variants toward the least-covered category, lineage preserved
# ===========================================================================
def test_partial_success_spawns_n_variants_toward_least_covered_category() -> None:
    """A partial-success attempt mutates into N variants aimed at the least-covered category —
    each variant a schema-valid AttackAttempt, each preserving lineage back to its seed."""
    coverage = {"prompt_injection": 9, "data_exfiltration": 4, "tool_misuse": 1}
    partial = _attempt("AF-M11-PI-001", ["partial seed"], "prompt_injection")

    variants = mutate(partial, coverage=coverage, count=3, provider=FakeProvider())

    assert len(variants) == 3
    for variant in variants:
        validate("attack_attempt", variant)  # each is contract-valid
        # Lineage: the variant records the seed it descends from.
        assert partial["case_ref"] in variant.get("mutation_lineage", [])
        # No trusted signal rides along on a mutated attempt either.
        assert "credential" not in variant
        assert "content_hash" not in variant
        assert "verdict" not in variant


def test_variant_lineage_chains_across_generations() -> None:
    """Mutating a variant again EXTENDS the lineage (a grandchild records its whole ancestry),
    so a confirmed exploit remains traceable to the original seed."""
    coverage = {"prompt_injection": 1, "data_exfiltration": 8, "tool_misuse": 8}
    seed = _attempt("AF-M11-PI-001", ["gen0"], "prompt_injection")

    gen1 = mutate(seed, coverage=coverage, count=1, provider=FakeProvider())[0]
    gen2 = mutate(gen1, coverage=coverage, count=1, provider=FakeProvider())[0]

    assert seed["case_ref"] in gen2["mutation_lineage"]
    assert gen1["case_ref"] in gen2["mutation_lineage"]
    # Lineage only grows.
    assert len(gen2["mutation_lineage"]) >= len(gen1.get("mutation_lineage", [])) + 0


# ===========================================================================
# (f) the gateway's BUDGET cap trips an ABORT that the RT RESPECTS (does not overrun)
# ===========================================================================
def test_red_team_respects_gateway_budget_abort() -> None:
    """A tight budget makes the gateway HARD-ABORT after the affordable dispatches. The RT must
    surface/stop on the AbortError — it must NOT overrun the cap by dispatching more."""
    adapter = FakeTargetAdapter()
    # Budget affords exactly 2 dispatches at $1/call (projected spend must stay <= budget).
    accounting = FakeAccounting(per_call_usd=1.0)
    gateway = _gateway(adapter=adapter, accounting=accounting)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    policy = _policy(budget_usd=2.0)

    # Either the RT stops cleanly at the cap (<=2 dispatches) or it lets the AbortError
    # propagate — both are "respect". What it must NEVER do is overrun the budget.
    with contextlib.suppress(AbortError):
        rt.run(_CASES, policy, target_id=FAKE_TARGET_ID)

    assert accounting.spent_usd <= policy.budget_usd, (
        f"the Red Team overran the gateway budget cap: spent ${accounting.spent_usd} > "
        f"${policy.budget_usd} — it must respect the gateway's HARD ABORT"
    )
    assert len(adapter.calls) <= 2, "the RT dispatched past the budget-affordable count"


def test_red_team_respects_gateway_attempt_cap_abort() -> None:
    """A per-run attempt cap of 1 lets exactly one attempt through; the RT does not overrun it —
    the gateway aborts the second, and the RT stops (never dispatches a third)."""
    adapter = FakeTargetAdapter()
    gateway = _gateway(adapter=adapter)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    policy = _policy(max_attempts_per_run=1)

    with contextlib.suppress(AbortError):
        rt.run(_CASES, policy, target_id=FAKE_TARGET_ID)

    # The attempt cap is 1, so at most one logical attempt physically dispatched.
    assert len(adapter.calls) <= 1, "the RT overran the gateway's attempt cap"


def test_red_team_respects_gateway_timeout_abort() -> None:
    """When the run window has elapsed the gateway HARD-ABORTS the next dispatch; the RT stops
    rather than overrunning the timeout. The clock is advanced by hand (deterministic)."""
    adapter = FakeTargetAdapter()
    clock = FakeClock()
    gateway = _gateway(adapter=adapter, clock=clock)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    # A zero-length window: the first admission anchors t0, any later dispatch is over-window.
    policy = _policy(run_timeout_seconds=0.0)

    # Advancing the clock between attempts is the deterministic timeout trigger; the RT must
    # not swallow the resulting AbortError into a silent overrun.
    clock.advance(1.0)
    with contextlib.suppress(AbortError):
        rt.run(_CASES, policy, target_id=FAKE_TARGET_ID)

    # A breached timeout aborts BEFORE dispatch, so at most a single call can have landed.
    assert len(adapter.calls) <= 1, "the RT overran the gateway's timeout cap"


def test_red_team_does_not_swallow_adapter_rate_limit_into_a_synthetic_success() -> None:
    """When the target's adapter rate-limits every retry, the gateway QUEUES the attempt and
    HARD-ABORTS (never a synthetic 200). The RT must not launder that into a 'success' — the
    abort surfaces and no fabricated result is returned for the failed attempt."""
    case = _attempt("AF-M11-DX-001", ["dx turn"], "data_exfiltration")
    failing_adapter = FakeTargetAdapter()
    failing_adapter.fail(
        TargetRequest(turns=("dx turn",)),
        RateLimitedError("synthetic rate limit", retry_after=0.01),
    )
    gateway = _gateway(adapter=failing_adapter)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    with pytest.raises(AbortError):
        rt.run([case], _policy(), target_id=FAKE_TARGET_ID)

    # The failed attempt was durably queued by the gateway — nothing was silently dropped.
    assert gateway.queued_attempts, "a rate-limited attempt was neither delivered nor queued"


# ===========================================================================
# (b) off-allowlist / bypass — the RT cannot reach a target the gateway denies
# ===========================================================================
def test_off_allowlist_target_is_denied_through_the_gateway() -> None:
    """The RT dispatches through the gateway, so an off-allowlist target_id is DENIED at the
    gate (the RT has no way around it). The denial surfaces; no dispatch occurs."""
    adapter = FakeTargetAdapter()
    gateway = _gateway(adapter=adapter)
    rt = RedTeam(gateway=gateway, provider=FakeProvider())

    from agentforge.policy.allowlist import OffAllowlistDenied

    with pytest.raises((OffAllowlistDenied, AbortError)):
        rt.run(_CASES, _policy(), target_id="not-on-the-allowlist")

    assert adapter.calls == [], "a denied target still reached the adapter — bypass!"


# ===========================================================================
# (h) NO network / socket in ANY RT run — patch socket to RAISE
# ===========================================================================
def test_red_team_run_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Break socket construction; a full RT run over the offline P9 fake then proves it opened
    ZERO sockets. The whole offline slice is genuinely network-free."""

    def boom(*_args, **_kwargs):
        raise AssertionError("the Red Team attempted network I/O (opened a socket)")

    monkeypatch.setattr(socket, "socket", boom)

    adapter = FakeTargetAdapter()
    rt = RedTeam(gateway=_gateway(adapter=adapter), provider=FakeProvider())

    results = rt.run(_CASES, _policy(), target_id=FAKE_TARGET_ID)  # must not touch the network

    assert results
    assert adapter.calls  # work really happened, offline
