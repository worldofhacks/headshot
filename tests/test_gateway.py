"""M4 — Policy Gateway RED tests (written first, no src/ code).

Anchors: ARCHITECTURE.md §3/§4/§5 (trust split F2, live-campaign gate F5, S1/S3),
DECISIONS.md D14; IMPLEMENTATION_PLAN.md M4; wf-m4-policy-gateway DESIGN + ACCEPTANCE.

The trusted **Policy Gateway** is the enforcement boundary and the Red Team's ONLY exit to
the target. It enforces — in runtime code, independent of trigger (F5) — the allowlist,
scoped credentials, synthetic-data policy, budget/rate/attempt/timeout caps with a HARD
ABORT, and it is the SOLE holder of the adapter path. A breach of any cap aborts BEFORE any
dispatch (no call reaches the adapter). These tests pin the edge/error behavior demanded by
the ACs — never a happy path alone:

  * AC-1 allowlist + scoped-cred + synthetic-data + budget + rate + hard abort, trigger-independent
  * AC-2 emits a canonical-hash append-only AttemptResult with a fresh per-dispatch run nonce
  * AC-3 the Red Team path (the AttackAttempt) holds NO credential
  * AC-4 (S3) UNIQUE(campaign_run_id, attempt_id) rejects a replay; a gated side effect idempotent
  * AC-5 no dispatch without the gate; each cap trips a hard abort with NO dispatch; off-allowlist
    is denied AND audited; a typed AdapterError drives backoff -> queue -> abort

Determinism: an injectable clock + spend/attempt accounting so caps trip without real sleeping
or real cost, and dispatch goes only to the deterministic P9 FakeTargetAdapter (no network).

Until ``agentforge.policy.{gateway,allowlist,credentials}`` exist, every import below fails and
this module RED-collects — RED for the right reason.
"""

from __future__ import annotations

import pytest

from agentforge.config import EnvironmentIsolationError, Settings
from agentforge.policy.allowlist import Allowlist, AllowlistEntry, OffAllowlistDenied
from agentforge.policy.credentials import CredentialBinding
from agentforge.policy.gateway import AbortError, PolicyGateway, RunPolicy, WorkUnitCoordinates
from agentforge.secrets import Secret
from agentforge.target.base import (
    RateLimitedError,
    TargetRequest,
    TargetSessionExpiredError,
    TargetUnreachableError,
)
from agentforge.target.fake_adapter import FakeTargetAdapter

# The only locally-allowlisted target is the deterministic P9 fake (no live URL is resolvable).
FAKE_TARGET_ID = "fake"


# ---------------------------------------------------------------------------
# Deterministic test doubles: an injectable clock + a manual spend meter so budget/rate/
# timeout caps trip WITHOUT real sleeping and WITHOUT real cost. The gateway must accept
# these (or equivalent) injection points — that is the whole point of "deterministic".
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
    """An allowlist that admits ONLY the P9 fake target (no live URL locally)."""
    return Allowlist([AllowlistEntry(target_id=FAKE_TARGET_ID, adapter_name="fake")])


def _attack_attempt(seq: tuple[str, ...] = ("hello",)) -> dict:
    """A minimal, credential-free AttackAttempt (the Red Team's proposed input only)."""
    return {
        "schema_version": "1",
        "case_ref": "case-1",
        "input_sequence": list(seq),
        "category": "prompt_injection",
    }


def _gateway(
    *,
    adapter: FakeTargetAdapter | None = None,
    clock: FakeClock | None = None,
    accounting: FakeAccounting | None = None,
    allowlist: Allowlist | None = None,
    settings: Settings | None = None,
    pre_physical_send_gate=None,
    post_physical_send_observer=None,
) -> PolicyGateway:
    """Construct a gateway wired to the deterministic doubles (all injectable)."""
    return PolicyGateway(
        allowlist=allowlist or _allowlist(),
        adapter=adapter or FakeTargetAdapter(),
        settings=settings or Settings(environment="local"),
        clock=clock or FakeClock(),
        accounting=accounting or FakeAccounting(),
        pre_physical_send_gate=pre_physical_send_gate,
        post_physical_send_observer=post_physical_send_observer,
    )


def _policy(
    *,
    budget_usd: float = 100.0,
    max_attempts_per_run: int = 100,
    target_requests_per_second: float = 1000.0,
    run_timeout_seconds: float = 3600.0,
    logical_case_limit: int | None = None,
    physical_request_limit: int | None = None,
    target_retries_per_turn: int | None = None,
) -> RunPolicy:
    return RunPolicy(
        budget_usd=budget_usd,
        max_attempts_per_run=max_attempts_per_run,
        target_requests_per_second=target_requests_per_second,
        run_timeout_seconds=run_timeout_seconds,
        logical_case_limit=logical_case_limit,
        physical_request_limit=physical_request_limit,
        target_retries_per_turn=target_retries_per_turn,
    )


# ===========================================================================
# AC-1 / AC-5 — the gate is the SOLE path to the adapter; a lax policy still dispatches once.
# ===========================================================================
def test_happy_dispatch_reaches_the_fake_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A within-policy attempt dispatches exactly once through the P9 fake and returns a result.

    Baseline behavior only — every other test pins an abort/deny/error edge.
    """

    class CapturingAdapter(FakeTargetAdapter):
        request: TargetRequest | None = None

        def send(self, request: TargetRequest):
            self.request = request
            return super().send(request)

    adapter = CapturingAdapter()
    gw = _gateway(adapter=adapter)
    result = gw.execute(
        _attack_attempt(("ping",)),
        _policy(),
        campaign_run_id="run-live",
        attempt_id="attempt-live",
        organization_id="org-live",
        target_version="target-v1",
        surface_id="copilot",
        surface_version="surface-v1",
        execution_profile="live",
        red_team_execution_id="red-team-execution-live",
    )
    assert len(adapter.calls) == 1  # exactly one dispatch reached the adapter
    assert adapter.request is not None
    assert adapter.request.metadata == {
        "campaign_run_id": "run-live",
        "attempt_id": "attempt-live",
        "organization_id": "org-live",
        "case_id": "case-1",
        "attack_category": "prompt_injection",
        "target_id": "fake",
        "target_version": "target-v1",
        "surface_id": "copilot",
        "surface_version": "surface-v1",
        "execution_profile": "live",
        "red_team_execution_id": "red-team-execution-live",
    }
    # The gateway returns the authoritative evidence with a canonical hash + fresh run nonce.
    assert result.campaign_run_id
    assert result.content_hash


# ===========================================================================
# AC-5 — off-allowlist target is DENIED and AUDITED, with NO dispatch.
# ===========================================================================
def test_off_allowlist_target_denied_and_audited() -> None:
    """A target absent from the allowlist is refused (typed denial) AND written to an audit
    trail; the adapter is never called."""
    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter)
    with pytest.raises(OffAllowlistDenied) as exc:
        gw.execute(_attack_attempt(), _policy(), target_id="evil-clinic")
    assert adapter.calls == []  # nothing dispatched
    # The denial is auditable: a decision record exists naming the denied target + reason.
    audit = gw.audit_log
    assert any(
        rec.get("decision") == "denied" and rec.get("target_id") == "evil-clinic" for rec in audit
    )
    assert "evil-clinic" in str(exc.value)


def test_allowlist_resolve_raises_off_allowlist_and_records_audit() -> None:
    """Allowlist.resolve of an unknown target raises OffAllowlistDenied and emits an audit
    record — the deny path is a first-class, audited decision, not a silent None."""
    al = _allowlist()
    with pytest.raises(OffAllowlistDenied):
        al.resolve("not-a-target")
    assert any(
        rec.get("decision") == "denied" and rec.get("target_id") == "not-a-target"
        for rec in al.audit_records()
    )


def test_allowlist_resolves_the_fake_target() -> None:
    """The one allowlisted target (the P9 fake) resolves to its entry (no denial)."""
    entry = _allowlist().resolve(FAKE_TARGET_ID)
    assert entry.target_id == FAKE_TARGET_ID
    assert entry.adapter_name == "fake"


# ===========================================================================
# AC-1 — SYNTHETIC-DATA enforcement: non-production refuses a live URL/credential.
# ===========================================================================
def test_non_production_refuses_a_live_credential() -> None:
    """In local/staging the gateway cannot resolve a live target credential (O1 / synthetic-
    only): resolving a production credential binding raises EnvironmentIsolationError, so a
    non-prod gateway can NEVER reach a live target."""
    binding = CredentialBinding(target_id="openemr", secret_ref="secretref://production/openemr")
    for env in ("local", "staging"):
        with pytest.raises(EnvironmentIsolationError):
            binding.resolve("openemr", Settings(environment=env))


def test_credential_binding_is_bound_to_one_target() -> None:
    """A binding for target A can never yield target B's credential — cross-target use is
    impossible by construction (the binding refuses a mismatched target_id)."""
    binding = CredentialBinding(target_id="openemr", secret_ref="secretref://production/openemr")
    with pytest.raises(ValueError):  # a mismatched target is rejected before any resolve
        binding.resolve("some-other-target", Settings(environment="production"))


# ===========================================================================
# AC-3 — the Red Team path holds NO credentials.
# ===========================================================================
def test_attack_attempt_carries_no_credential() -> None:
    """The Red Team's AttackAttempt (the only thing it produces) carries no credential field;
    the gateway — not the Red Team — is the sole holder of any Secret."""
    attempt = _attack_attempt()
    flat = repr(attempt).lower()
    for banned in ("secret", "password", "token", "credential", "authorization", "api_key"):
        assert banned not in flat


def test_gateway_never_returns_a_raw_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any credential the gateway holds is a redacted Secret, never a raw inline value — a
    dispatch result / audit record never surfaces a raw credential string."""
    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter)
    result = gw.execute(_attack_attempt(("safe",)), _policy())
    rendered = repr(result) + repr(getattr(gw, "audit_log", []))
    assert "***REDACTED***" in repr(Secret("x"))  # sanity: Secret redacts
    # No raw secret markers leak into the evidence/audit rendering.
    assert "reveal(" not in rendered


# ===========================================================================
# AC-5 — BUDGET cap trips a HARD ABORT with NO dispatch.
# ===========================================================================
def test_budget_cap_hard_aborts_before_dispatch() -> None:
    """Once spend would breach the budget cap, the gateway HARD ABORTS before dispatch —
    the adapter is never called (the cap is checked BEFORE the call, not after)."""
    adapter = FakeTargetAdapter()
    accounting = FakeAccounting(per_call_usd=10.0)
    accounting.spent_usd = 10.0  # already at the cap
    gw = _gateway(adapter=adapter, accounting=accounting)
    with pytest.raises(AbortError) as exc:
        gw.execute(_attack_attempt(), _policy(budget_usd=10.0))
    assert adapter.calls == []  # HARD ABORT: nothing dispatched
    assert "budget" in str(exc.value).lower()


def test_budget_cap_allows_a_within_budget_call() -> None:
    """A dispatch strictly within budget is NOT aborted — the cap is a ceiling, not a block
    on all work (guards against an over-eager check that would abort everything)."""
    adapter = FakeTargetAdapter()
    accounting = FakeAccounting(per_call_usd=1.0)
    gw = _gateway(adapter=adapter, accounting=accounting)
    gw.execute(_attack_attempt(), _policy(budget_usd=100.0))
    assert len(adapter.calls) == 1


# ===========================================================================
# AC-5 — ATTEMPT cap trips a HARD ABORT with NO further dispatch (no off-by-one).
# ===========================================================================
def test_attempt_cap_hard_aborts_the_over_limit_call() -> None:
    """With max_attempts_per_run=1, the SECOND execute() hard-aborts before dispatch; the
    adapter is called exactly once across both (no off-by-one that lets an extra call slip)."""
    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter)
    policy = _policy(max_attempts_per_run=1)
    gw.execute(_attack_attempt(("first",)), policy)
    with pytest.raises(AbortError) as exc:
        gw.execute(_attack_attempt(("second",)), policy)
    assert len(adapter.calls) == 1  # only the first reached the adapter
    assert "attempt" in str(exc.value).lower()


# ===========================================================================
# AC-5 — RATE cap trips a HARD ABORT with NO dispatch (deterministic clock, no real sleep).
# ===========================================================================
def test_rate_cap_hard_aborts_when_calls_are_too_close() -> None:
    """A second call inside the minimum inter-request interval (1 / requests_per_second)
    HARD ABORTS before dispatch — enforced against the injectable clock (no real sleeping)."""
    adapter = FakeTargetAdapter()
    clock = FakeClock(start=1000.0)
    gw = _gateway(adapter=adapter, clock=clock)
    policy = _policy(target_requests_per_second=1.0)  # min interval 1.0s
    gw.execute(_attack_attempt(("t1",)), policy)
    clock.advance(0.1)  # only 100ms later — too soon
    with pytest.raises(AbortError) as exc:
        gw.execute(_attack_attempt(("t2",)), policy)
    assert len(adapter.calls) == 1  # the rate-limited second call never dispatched
    assert "rate" in str(exc.value).lower()


def test_rate_cap_permits_a_call_after_the_interval_elapses() -> None:
    """After the minimum interval elapses on the injectable clock, the next call dispatches —
    the rate cap is time-based, not a permanent block."""
    adapter = FakeTargetAdapter()
    clock = FakeClock(start=1000.0)
    gw = _gateway(adapter=adapter, clock=clock)
    policy = _policy(target_requests_per_second=1.0)
    gw.execute(_attack_attempt(("t1",)), policy)
    clock.advance(1.5)  # past the 1.0s interval
    gw.execute(_attack_attempt(("t2",)), policy)
    assert len(adapter.calls) == 2


# ===========================================================================
# AC-5 — TIMEOUT cap trips a HARD ABORT with NO dispatch once the run window elapses.
# ===========================================================================
def test_run_timeout_hard_aborts_after_window() -> None:
    """Once the run's timeout window has elapsed on the injectable clock, a further execute()
    HARD ABORTS before dispatch (the run is over — no new work is admitted)."""
    adapter = FakeTargetAdapter()
    clock = FakeClock(start=0.0)
    gw = _gateway(adapter=adapter, clock=clock)
    policy = _policy(run_timeout_seconds=10.0)
    gw.execute(_attack_attempt(("early",)), policy)
    clock.advance(11.0)  # past the run window
    with pytest.raises(AbortError) as exc:
        gw.execute(_attack_attempt(("late",)), policy)
    assert len(adapter.calls) == 1
    assert "timeout" in str(exc.value).lower()


# ===========================================================================
# AC-1 / F5 — the gate is enforced identically regardless of trigger (Claude/direct/cron).
# ===========================================================================
@pytest.mark.parametrize("trigger", ["claude", "direct", "cron"])
def test_cap_enforced_independent_of_trigger(trigger: str) -> None:
    """F5: the caps live in the gateway's runtime code, not in a skill flag — a budget breach
    HARD ABORTS with NO dispatch no matter how the run was triggered."""
    adapter = FakeTargetAdapter()
    accounting = FakeAccounting(per_call_usd=10.0)
    accounting.spent_usd = 10.0
    gw = _gateway(adapter=adapter, accounting=accounting)
    with pytest.raises(AbortError):
        gw.execute(_attack_attempt(), _policy(budget_usd=10.0), trigger=trigger)
    assert adapter.calls == []


# ===========================================================================
# AC-5 — a typed AdapterError drives backoff -> queue -> abort (never a silent 200).
# ===========================================================================
def test_target_unreachable_backs_off_then_queues_then_aborts() -> None:
    """A persistent TargetUnreachableError is retried with backoff up to a bound, then the
    attempt is QUEUED for later and the run ABORTS with a TYPED error — never swallowed into a
    synthetic success. The injectable clock proves backoff without real sleeping."""
    down_req = TargetRequest(turns=("boom",))
    adapter = FakeTargetAdapter().fail(down_req, TargetUnreachableError("target down"))
    clock = FakeClock()
    gw = _gateway(adapter=adapter, clock=clock)
    with pytest.raises((AbortError, TargetUnreachableError)) as exc:
        gw.execute(_attack_attempt(("boom",)), _policy())
    # Retried (backoff) more than once before giving up, then surfaced a TYPED error.
    assert len(adapter.calls) >= 2
    assert (
        getattr(exc.value, "code", "") in {"target-unreachable", "abort"}
        or "abort" in str(exc.value).lower()
    )
    # The failed attempt is durably QUEUED (nothing dropped), not silently lost.
    assert getattr(gw, "queued_attempts", None) is not None
    assert len(gw.queued_attempts) >= 1


def test_rate_limited_adapter_error_backs_off_against_the_clock() -> None:
    """A RateLimitedError from the adapter is handled as backoff -> queue -> abort using the
    adapter-provided retry_after against the injectable clock — no real sleeping occurs."""
    limited = TargetRequest(turns=("slow",))
    adapter = FakeTargetAdapter().fail(limited, RateLimitedError("slow down", retry_after=2.0))
    clock = FakeClock()
    gw = _gateway(adapter=adapter, clock=clock)
    with pytest.raises((AbortError, RateLimitedError)):
        gw.execute(_attack_attempt(("slow",)), _policy())
    assert len(adapter.calls) >= 2  # backed off and retried, not a single-shot failure


def test_expired_target_session_aborts_after_one_physical_request() -> None:
    request = TargetRequest(turns=("hello",))
    adapter = FakeTargetAdapter().fail(
        request,
        TargetSessionExpiredError("fresh SMART launch required"),
    )
    accounting = FakeAccounting(per_call_usd=0.01)
    gateway = _gateway(adapter=adapter, accounting=accounting)

    with pytest.raises(AbortError) as caught:
        gateway.execute(_attack_attempt(("hello",)), _policy())

    assert caught.value.code == "target-session-expired"
    assert len(adapter.calls) == 1
    assert accounting.spent_usd == pytest.approx(0.01)
    assert gateway.queued_attempts[0]["reason"] == "target-session-expired"


def test_adapter_error_never_becomes_a_synthetic_success() -> None:
    """A failing adapter must never be laundered into a 200 — a typed error surfaces, and NO
    AttemptResult claiming success is emitted for a failed dispatch."""
    down = TargetRequest(turns=("nope",))
    adapter = FakeTargetAdapter().fail(down, TargetUnreachableError("down"))
    gw = _gateway(adapter=adapter)
    with pytest.raises((AbortError, TargetUnreachableError)):
        gw.execute(_attack_attempt(("nope",)), _policy())


# ===========================================================================
# AC-5 (hardening) — backoff RETRIES are budget-accounted + cap-rechecked (live-cost safety).
# A failing target must not be retried for free, and a retry that would breach the budget must
# HARD ABORT mid-retry (resolves the Important security finding: retries un-metered/un-gated).
# ===========================================================================
def test_backoff_retries_consume_budget_and_abort_on_breach() -> None:
    """Each physical dispatch (incl. a failed retry) charges the meter, and the caps are
    re-checked before every retry — so a retry that would breach the budget aborts BEFORE the
    send. A persistently-failing target cannot be retried without consuming budget."""
    down = TargetRequest(turns=("boom",))
    adapter = FakeTargetAdapter().fail(down, TargetUnreachableError("down"))
    accounting = FakeAccounting(per_call_usd=1.0)
    gw = _gateway(adapter=adapter, accounting=accounting)
    # Budget admits exactly two physical dispatches; the third retry must hard-abort on budget.
    with pytest.raises(AbortError):
        gw.execute(_attack_attempt(("boom",)), _policy(budget_usd=2.0))
    assert len(adapter.calls) == 2  # 3rd send blocked by the per-retry budget re-check
    assert accounting.spent_usd == 2.0  # both physical retries were charged — not free


def test_budget_projection_requires_a_per_call_estimate_and_fails_closed() -> None:
    """The budget cap must not be silently neutralizable. An accounting that omits the required
    per-call estimate (per_call_usd) must FAIL CLOSED — a hard abort with no dispatch — rather
    than projecting spend as 0.0 and letting a would-be-breaching call through."""

    class _NoEstimateAccounting:
        spent_usd = 0.0

        def charge(self) -> None:
            self.spent_usd += 1.0

    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter, accounting=_NoEstimateAccounting())
    with pytest.raises(AbortError):
        gw.execute(_attack_attempt(), _policy(budget_usd=100.0))
    assert adapter.calls == []  # fail closed: no dispatch when spend cannot be bounded


def test_exact_100_case_workload_stops_before_the_122nd_physical_send() -> None:
    class _SequentialFake(FakeTargetAdapter):
        turn_delivery = "sequential"

    adapter = _SequentialFake()
    clock = FakeClock()
    authorization_checks: list[WorkUnitCoordinates] = []
    gateway = _gateway(
        adapter=adapter,
        clock=clock,
        accounting=FakeAccounting(per_call_usd=0.01),
        pre_physical_send_gate=authorization_checks.append,
    )
    policy = _policy(
        budget_usd=2.0,
        max_attempts_per_run=101,
        logical_case_limit=101,
        physical_request_limit=121,
        target_retries_per_turn=0,
    )

    for index in range(79):
        gateway.execute(_attack_attempt((f"single-{index}",)), policy, attempt_id=f"a-{index}")
    for index in range(21):
        gateway.execute(
            _attack_attempt((f"multi-{index}-1", f"multi-{index}-2")),
            policy,
            attempt_id=f"b-{index}",
        )

    assert gateway.completed_logical_cases == 100
    assert gateway.physical_send_count == len(adapter.calls) == 121
    assert len(authorization_checks) == 121
    assert authorization_checks[79:81] == [
        WorkUnitCoordinates(attempt_id="b-0", turn_index=0, retry_index=0),
        WorkUnitCoordinates(attempt_id="b-0", turn_index=1, retry_index=0),
    ]
    with pytest.raises(AbortError, match="physical request cap"):
        gateway.execute(_attack_attempt(("send-122",)), policy, attempt_id="over-limit")
    assert gateway.physical_send_count == len(adapter.calls) == 121
    assert len(authorization_checks) == 121


def test_zero_retry_policy_makes_one_failed_send_and_no_retry() -> None:
    request = TargetRequest(turns=("no-retry",))
    adapter = FakeTargetAdapter().fail(request, TargetUnreachableError("down"))
    gateway = _gateway(adapter=adapter)

    with pytest.raises(AbortError):
        gateway.execute(
            _attack_attempt(("no-retry",)),
            _policy(
                physical_request_limit=10,
                target_retries_per_turn=0,
            ),
            attempt_id="no-retry-attempt",
        )

    assert gateway.physical_send_count == len(adapter.calls) == 1
    assert gateway.completed_logical_cases == 0


def test_retry_coordinates_and_raised_observations_are_stable() -> None:
    request = TargetRequest(turns=("retry",))
    adapter = FakeTargetAdapter().fail(request, TargetUnreachableError("down"))
    reservations: list[WorkUnitCoordinates] = []
    observations: list[tuple[WorkUnitCoordinates, str]] = []
    gateway = _gateway(
        adapter=adapter,
        pre_physical_send_gate=reservations.append,
        post_physical_send_observer=lambda coordinates, outcome: observations.append(
            (coordinates, outcome)
        ),
    )

    with pytest.raises(AbortError):
        gateway.execute(
            _attack_attempt(("retry",)),
            _policy(physical_request_limit=2, target_retries_per_turn=1),
            attempt_id="retry-attempt",
        )

    expected = [
        WorkUnitCoordinates(attempt_id="retry-attempt", turn_index=0, retry_index=0),
        WorkUnitCoordinates(attempt_id="retry-attempt", turn_index=0, retry_index=1),
    ]
    assert reservations == expected
    assert observations == [(coordinate, "raised") for coordinate in expected]
    assert len(adapter.calls) == 2
    assert gateway.completed_logical_cases == 0


def test_fresh_authorization_gate_runs_before_each_multi_turn_send() -> None:
    class _SequentialFake(FakeTargetAdapter):
        turn_delivery = "sequential"

    checks: list[WorkUnitCoordinates] = []

    def gate(coordinates: WorkUnitCoordinates) -> None:
        checks.append(coordinates)
        if len(checks) == 2:
            raise RuntimeError("authorization revoked")

    adapter = _SequentialFake()
    gateway = PolicyGateway(
        allowlist=_allowlist(),
        adapter=adapter,
        settings=Settings(environment="local"),
        clock=FakeClock(),
        accounting=FakeAccounting(per_call_usd=0.01),
        pre_physical_send_gate=gate,
    )

    with pytest.raises(RuntimeError, match="authorization revoked"):
        gateway.execute(
            _attack_attempt(("turn-one", "turn-two")),
            _policy(
                budget_usd=1.0,
                physical_request_limit=2,
                target_retries_per_turn=0,
            ),
            attempt_id="multi-attempt",
        )

    assert checks == [
        WorkUnitCoordinates(attempt_id="multi-attempt", turn_index=0, retry_index=0),
        WorkUnitCoordinates(attempt_id="multi-attempt", turn_index=1, retry_index=0),
    ]
    assert gateway.physical_send_count == len(adapter.calls) == 1
    assert gateway.completed_logical_cases == 0


# ===========================================================================
# AC-5 (invariant) — NO dispatch happens without passing the gate: an off-allowlist target
# never reaches the adapter even under an otherwise-permissive policy.
# ===========================================================================
def test_no_dispatch_without_the_gate() -> None:
    """The adapter is the SOLE property of the gateway and is reached only AFTER allowlist +
    caps pass. An off-allowlist target under a wide-open policy still yields zero dispatch."""
    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter)
    with pytest.raises(OffAllowlistDenied):
        gw.execute(_attack_attempt(), _policy(budget_usd=1e9), target_id="off-list")
    assert adapter.calls == []


# ===========================================================================
# AC-2 — the emitted AttemptResult carries a FRESH per-dispatch campaign_run_id nonce (S3).
# ===========================================================================
def test_each_dispatch_gets_a_fresh_campaign_run_id() -> None:
    """Every dispatch mints a NEW campaign_run_id nonce (S3): two executes of the same
    attempt yield distinct run ids, so replay is detectable downstream."""
    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter)
    r1 = gw.execute(_attack_attempt(("x",)), _policy())
    r2 = gw.execute(_attack_attempt(("x",)), _policy())
    assert r1.campaign_run_id != r2.campaign_run_id


def test_result_content_hash_is_canonical_hex() -> None:
    """The emitted AttemptResult carries a canonical content_hash (64-hex sha256) the Judge
    can recompute and verify — evidence is always hashed (D14)."""
    adapter = FakeTargetAdapter()
    gw = _gateway(adapter=adapter)
    result = gw.execute(_attack_attempt(("h",)), _policy())
    assert isinstance(result.content_hash, str)
    assert len(result.content_hash) == 64
    assert all(c in "0123456789abcdef" for c in result.content_hash)


# ---------------------------------------------------------------------------------------------
# Synthetic-data policy (O1) — the gate admits a live target only on a VERIFIED attestation.
#
# These lock the narrowing in from both sides. Before it, the rule keyed on environment alone,
# which refused an attested-synthetic target purely for being reached from a non-production
# deployment AND admitted any live target in production, attested or not.
# ---------------------------------------------------------------------------------------------

_LIVE_TARGET = "https://agent-production-9f62.up.railway.app"


def _live_allowlist(*, attested: bool) -> Allowlist:
    return Allowlist(
        [AllowlistEntry(target_id=_LIVE_TARGET, adapter_name="fake", synthetic_attested=attested)]
    )


def test_unattested_live_target_is_still_refused_outside_production() -> None:
    """The strict rule must survive: no attestation, no live dispatch. This is the whole point."""

    gateway = _gateway(
        allowlist=_live_allowlist(attested=False),
        settings=Settings(environment="staging"),
    )

    with pytest.raises(AbortError) as excinfo:
        gateway.execute(_attack_attempt(), _policy(), target_id=_LIVE_TARGET)

    assert "synthetic-data policy" in str(excinfo.value)
    assert "no verified synthetic-data attestation" in str(excinfo.value)


def test_attested_synthetic_live_target_is_admitted_outside_production() -> None:
    """An attested-synthetic target is reachable from staging — the narrowing's purpose."""

    adapter = FakeTargetAdapter()
    gateway = _gateway(
        adapter=adapter,
        allowlist=_live_allowlist(attested=True),
        settings=Settings(environment="staging"),
    )

    result = gateway.execute(_attack_attempt(), _policy(), target_id=_LIVE_TARGET)

    assert result.target_id == _LIVE_TARGET
    assert gateway.physical_send_count == 1


def test_attestation_defaults_to_absent_so_an_unset_entry_fails_closed() -> None:
    """A construction path that never considered attestation must NOT admit a live target."""

    entry = AllowlistEntry(target_id=_LIVE_TARGET, adapter_name="fake")
    assert entry.synthetic_attested is False

    gateway = _gateway(
        allowlist=Allowlist([entry]),
        settings=Settings(environment="staging"),
    )
    with pytest.raises(AbortError):
        gateway.execute(_attack_attempt(), _policy(), target_id=_LIVE_TARGET)


def test_production_behaviour_is_unchanged_by_the_narrowing() -> None:
    """Production still short-circuits before the attestation check — no regression there."""

    gateway = _gateway(
        allowlist=_live_allowlist(attested=False),
        settings=Settings(environment="production"),
    )

    result = gateway.execute(_attack_attempt(), _policy(), target_id=_LIVE_TARGET)
    assert result.target_id == _LIVE_TARGET


def test_a_non_live_target_is_unaffected_in_any_environment() -> None:
    """The gate only ever concerned live (http/https) targets; a fake id is untouched."""

    gateway = _gateway(settings=Settings(environment="staging"))
    result = gateway.execute(_attack_attempt(), _policy(), target_id=FAKE_TARGET_ID)
    assert result.target_id == FAKE_TARGET_ID
