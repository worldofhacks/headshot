"""Trusted Policy Gateway — the Red Team's SOLE, cap-enforced exit to a target.

ARCHITECTURE.md §3/§4/§5 (trust split F2, live-campaign gate F5, S1/S3), DECISIONS.md D14/D16.

The gateway is the enforcement boundary. The Red Team produces only a credential-free
``AttackAttempt`` and hands it here; it holds NO adapter, NO credential, and NO outbound path
of its own. Every dispatch flows through :meth:`PolicyGateway.execute`, which — in runtime
code, INDEPENDENT OF the trigger (F5), BEFORE any dispatch reaches the adapter — enforces, in
order:

1. **Allowlist** (D16) — an off-allowlist target is DENIED and AUDITED, with zero dispatch.
2. **Synthetic-data / O1** — a non-production gateway can never resolve a live credential; a
   live target/credential is refused outside production.
3. **Budget / rate / attempt / timeout caps** — a breach of ANY cap is a HARD ABORT
   (:class:`AbortError`) with ZERO dispatch. The caps read an injectable clock + accounting so
   they trip deterministically without real sleeping or real cost. This is the enforcement
   point the platform's live-safety depends on: a live call is only reachable AFTER every cap
   passes (against the P9 fake, no real inference occurs regardless).
4. **Scoped credential** — resolved by reference into a :class:`Secret`; never inlined/logged.
5. **Dispatch** — via the single injected :class:`TargetAdapter` (the P9 fake here). A typed
   :class:`AdapterError` drives backoff -> queue -> abort; a failure NEVER becomes a synthetic
   200.
6. **Evidence** — a fresh per-dispatch ``campaign_run_id`` nonce (S3) + ``policy_decision_id``
   are minted and an :class:`AttemptResult` is built with a canonical ``content_hash`` (D14).

Framework-neutral (D10): imports config/secrets/target/policy — never a web framework.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from agentforge.config import Settings
from agentforge.policy.allowlist import Allowlist, AllowlistEntry, OffAllowlistDenied
from agentforge.policy.recorder import ExecutionRecorder
from agentforge.secrets import Secret
from agentforge.target.base import (
    AdapterError,
    RateLimitedError,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
)

# Bound on how many times a single logical attempt is retried against a typed AdapterError
# before it is queued and the run aborts. >1 so backoff is genuinely exercised, finite so a
# persistent failure can never loop forever.
_MAX_DISPATCH_ATTEMPTS = 3

# A live-target marker: a target reached over a URL is a LIVE target, forbidden in non-prod.
_LIVE_SCHEMES = ("http://", "https://")


class AbortError(Exception):
    """A HARD ABORT of a run — a cap breach (budget/rate/attempt/timeout) or an exhausted,
    queued adapter failure. Raised BEFORE any dispatch on a cap breach, so a breached run
    reaches the adapter zero times. Carries ``code`` for the typed error taxonomy."""

    code: str = "abort"

    def __init__(self, message: str, *, code: str = "abort") -> None:
        super().__init__(message)
        self.code = code


class _Clock(Protocol):
    def now(self) -> float: ...


class _Accounting(Protocol):
    spent_usd: float
    # REQUIRED (not a soft default): the projected cost of the next dispatch. The budget cap
    # projects spent_usd + per_call_usd BEFORE dispatch; if an accounting cannot supply this,
    # the gateway fails closed rather than silently treating the next call as free.
    per_call_usd: float

    def charge(self) -> None: ...


@dataclass(frozen=True)
class RunPolicy:
    """The per-run caps the gateway enforces. Immutable so a run's ceilings cannot be widened
    mid-flight."""

    budget_usd: float
    max_attempts_per_run: int
    target_requests_per_second: float
    run_timeout_seconds: float
    logical_case_limit: int | None = None
    physical_request_limit: int | None = None
    target_retries_per_turn: int | None = None


@dataclass(frozen=True)
class AttemptResult:
    """The authoritative evidence the gateway emits per dispatch (D14 subset).

    Carries a FRESH per-dispatch ``campaign_run_id`` nonce (S3) and a canonical
    ``content_hash`` the Judge can recompute-and-verify. ``credential`` is only ever a
    :class:`Secret` (or ``None``) — a raw credential never appears here. ``__repr__`` renders
    the Secret redacted, so no raw credential leaks into an evidence/log rendering."""

    campaign_run_id: str
    attempt_id: str
    policy_decision_id: str
    target_id: str
    content_hash: str
    fields: dict[str, Any]
    credential: Secret | None = None
    # The MEASURED consumption dimensions a black-box POST /chat exposes, collected by the gateway
    # during THIS dispatch: ``elapsed_ms`` (the gateway's OWN wall-clock duration of the physical
    # send(s), from the injected clock), ``request_count`` (the physical sends performed for this
    # attempt, incl. retries), and ``response_size`` (the response body's byte length). Target-
    # internal input/output TOKENS, tool_calls, and target LLM COST are NOT observable from /chat
    # and are deliberately absent here — they are never fabricated onto the measurement.
    resource_measurements: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class WorkUnitCoordinates:
    """Stable identity for one physical send within a logical campaign attempt."""

    attempt_id: str
    turn_index: int
    retry_index: int


@dataclass
class PolicyGateway:
    """The trusted enforcement boundary; the SOLE holder of the target adapter.

    All injection points (allowlist, adapter, settings, clock, accounting) are constructor
    arguments so the caps are deterministic in tests — the clock and accounting are advanced
    by hand rather than by real time or real spend.
    """

    allowlist: Allowlist
    adapter: TargetAdapter
    settings: Settings
    clock: _Clock
    accounting: _Accounting
    recorder: ExecutionRecorder = field(default_factory=ExecutionRecorder)
    credentials: dict[str, Any] = field(default_factory=dict)
    sleeper: Callable[[float], None] = field(default=time.sleep, repr=False)
    pre_physical_send_gate: Callable[[WorkUnitCoordinates], None] | None = field(
        default=None, repr=False
    )
    post_physical_send_observer: Callable[[WorkUnitCoordinates, str], None] | None = field(
        default=None, repr=False
    )

    # Per-gateway run accounting (deterministic, clock/accounting-driven).
    audit_log: list[dict] = field(default_factory=list)
    queued_attempts: list[dict] = field(default_factory=list)
    _attempts_used: int = field(default=0, init=False)
    _physical_sends_used: int = field(default=0, init=False)
    _last_dispatch_at: float | None = field(default=None, init=False)
    _run_started_at: float | None = field(default=None, init=False)

    def execute(
        self,
        attack_attempt: dict,
        policy: RunPolicy,
        *,
        target_id: str = "fake",
        trigger: str = "direct",
        campaign_run_id: str | None = None,
        attempt_id: str | None = None,
        organization_id: str = "",
        target_version: str = "",
        surface_id: str = "",
        surface_version: str = "",
        execution_profile: str = "",
        red_team_execution_id: str | None = None,
    ) -> AttemptResult:
        """Enforce the gate, then dispatch exactly one logical attempt through the adapter.

        The ``trigger`` (claude/direct/cron) is recorded but NEVER changes enforcement — the
        caps live here in runtime code, not in a caller flag (F5). Returns an
        :class:`AttemptResult`; raises :class:`OffAllowlistDenied` (off-allowlist) or
        :class:`AbortError` (cap breach / exhausted adapter failure) BEFORE any dispatch on a
        gate failure.
        """
        # (0) Anchor the run window on first admission (deterministic clock).
        now = self.clock.now()
        if self._run_started_at is None:
            self._run_started_at = now

        # (1) Allowlist gate — deny + audit off-allowlist, with ZERO dispatch. The gateway's
        # own audit_log mirrors the allowlist's decision so a denial is attributable here too.
        try:
            entry = self.allowlist.resolve(target_id)
        except OffAllowlistDenied:
            self.audit_log.append(
                {"decision": "denied", "target_id": target_id, "trigger": trigger}
            )
            raise
        self.audit_log.append({"decision": "allowed", "target_id": target_id, "trigger": trigger})

        # (2) Synthetic-data / O1 — a live target (URL) is admitted only in production or when the
        # allowlist entry carries a verified synthetic-data attestation. The entry resolved above is
        # reused so the decision reads off the same admitted binding (and is not re-audited).
        self._enforce_synthetic_data(target_id, entry)

        # (3) Caps — a breach of ANY is a HARD ABORT before dispatch, trigger-independent.
        self._enforce_caps(policy, now)

        # (4) Scoped credential — resolved by reference into a Secret, only if bound.
        credential = self._resolve_credential(target_id)

        # (5) Dispatch through the SOLE adapter. Caps are RE-CHECKED and the meter CHARGED on
        # each physical send inside the loop, so a failing target's retries consume budget/rate
        # and abort the moment a cap is breached — a failed dispatch is never free.
        request_metadata = {
            "campaign_run_id": campaign_run_id or "",
            "attempt_id": attempt_id or "",
            # Tenant context is trusted Runner metadata, not part of the untrusted, strictly
            # versioned AttackAttempt contract.
            "organization_id": organization_id,
            "case_id": str(attack_attempt.get("case_ref", "")),
            "attack_category": str(attack_attempt.get("category", "")),
            "target_id": target_id,
            "target_version": target_version,
            "surface_id": surface_id,
            "surface_version": surface_version,
            "execution_profile": execution_profile,
        }
        if red_team_execution_id:
            request_metadata["red_team_execution_id"] = red_team_execution_id
        request = TargetRequest(
            turns=tuple(attack_attempt.get("input_sequence", [])),
            metadata=request_metadata,
        )
        self._enforce_sequence_capacity(request, policy)

        # MEASURE the black-box-observable dimensions ACROSS the physical dispatch. The gateway's
        # OWN wall-clock (the injected clock) is sampled immediately before and after the send(s),
        # so ``elapsed_ms`` is a real measurement of how long THIS attempt took — the only timing a
        # black-box /chat exposes. The physical-send counter is sampled the same way so
        # ``request_count`` is exactly the sends (incl. retries) performed for THIS attempt.
        dispatch_started_at = self.clock.now()
        sends_before = self._physical_sends_used
        response = self._dispatch_with_backoff(
            request,
            attack_attempt,
            policy,
            attempt_id=attempt_id or "",
        )
        elapsed_ms = int(round(max(0.0, self.clock.now() - dispatch_started_at) * 1000.0))
        request_count = self._physical_sends_used - sends_before
        response_size = len(response.output.encode("utf-8"))

        # (6) Count the logical attempt after a real dispatch, then build hashed evidence.
        # (charge + _last_dispatch_at are committed per physical send in _dispatch_with_backoff.)
        self._attempts_used += 1
        return self._build_result(
            attack_attempt,
            target_id,
            request,
            response,
            credential,
            campaign_run_id=campaign_run_id,
            attempt_id=attempt_id,
            resource_measurements={
                "elapsed_ms": elapsed_ms,
                "request_count": request_count,
                "response_size": response_size,
            },
        )

    @property
    def completed_logical_cases(self) -> int:
        return self._attempts_used

    @property
    def physical_send_count(self) -> int:
        return self._physical_sends_used

    # ------------------------------------------------------------------ gate steps

    def _enforce_synthetic_data(self, target_id: str, entry: AllowlistEntry) -> None:
        """Refuse a live target/credential unless its data is attested synthetic.

        The rule this enforces is a SYNTHETIC-DATA policy, not an environment policy: never point
        the platform at a target holding real data. Environment was only ever a proxy for that —
        the assumption being that production is where the attested-synthetic target lives.

        That proxy was too coarse. It refused an attested-synthetic target purely for being reached
        from a non-production deployment, while permitting ANY live target in production, attested
        or not. Both halves were wrong.

        So the gate is narrowed to the fact it actually cares about: outside production a live
        target is admitted only when its catalog spec carries a verified synthetic-data attestation
        (``synthetic_data_only is True`` AND a non-empty ``synthetic_data_attestation_ref``, both
        validated by ``TargetSpec`` and re-checked by the runner's ``synthetic_data_attestation_
        missing`` preflight blocker). Anything not attested is refused exactly as before.

        ``AllowlistEntry.synthetic_attested`` defaults to ``False``, so every construction path that
        has not established the attestation keeps the strict behaviour. Admitting a live target is
        opt-in and evidence-backed, never assumed.
        """
        if self.settings.environment == "production":
            return
        if not target_id.startswith(_LIVE_SCHEMES):
            return
        if entry.synthetic_attested:
            return
        raise AbortError(
            f"synthetic-data policy: a live target {target_id!r} is refused in "
            f"environment {self.settings.environment!r} — it carries no verified synthetic-data "
            "attestation (only production, or an attested-synthetic target, may be reached)",
            code="abort",
        )

    def _enforce_caps(self, policy: RunPolicy, now: float) -> None:
        """Enforce budget/attempt/rate/timeout caps. A breach HARD ABORTS before any dispatch.

        Every check runs off the injected clock/accounting so it is deterministic — no real
        sleeping, no real cost. The projected spend (current + this call's charge) is compared
        against the ceiling, so the cap is checked BEFORE the call, never after it.
        """
        # TIMEOUT — the run window has elapsed; no new work is admitted.
        elapsed_run = None if self._run_started_at is None else now - self._run_started_at
        if elapsed_run is not None and elapsed_run > policy.run_timeout_seconds:
            raise AbortError(
                f"run timeout: {elapsed_run:.3f}s elapsed exceeds the "
                f"{policy.run_timeout_seconds}s window — HARD ABORT before dispatch",
                code="abort",
            )

        # ATTEMPT — the per-run attempt ceiling is reached; a further call is refused.
        logical_limit = policy.max_attempts_per_run
        if policy.logical_case_limit is not None:
            logical_limit = min(logical_limit, policy.logical_case_limit)
        if self._attempts_used >= logical_limit:
            raise AbortError(
                f"attempt cap: {self._attempts_used} attempt(s) used reaches the limit of "
                f"{logical_limit} — HARD ABORT before dispatch",
                code="abort",
            )

        if (
            policy.physical_request_limit is not None
            and self._physical_sends_used >= policy.physical_request_limit
        ):
            raise AbortError(
                f"physical request cap: {self._physical_sends_used} send(s) reaches the limit of "
                f"{policy.physical_request_limit} — HARD ABORT before dispatch",
                code="physical-request-cap-exceeded",
            )

        # BUDGET — the projected spend (current + the next call's cost) would breach the
        # ceiling. per_call_usd is a REQUIRED part of the accounting contract; if it is absent
        # we FAIL CLOSED (hard abort, no dispatch) rather than defaulting the estimate to 0.0
        # and letting a breaching call through — the cap must not be silently neutralizable.
        try:
            per_call = float(self.accounting.per_call_usd)
        except AttributeError as exc:
            raise AbortError(
                "budget cap: accounting exposes no per-call cost estimate (per_call_usd) — "
                "spend cannot be bounded; HARD ABORT before dispatch (fail closed)",
                code="abort",
            ) from exc
        projected = self.accounting.spent_usd + per_call
        if projected > policy.budget_usd:
            raise AbortError(
                f"budget cap: projected spend ${projected:.2f} would breach the "
                f"${policy.budget_usd:.2f} budget — HARD ABORT before dispatch",
                code="abort",
            )

        # RATE — the min inter-request interval has not elapsed since the last dispatch. A
        # positive-but-too-small gap (a call fired inside the interval) HARD ABORTS; a
        # zero-elapsed pair on a frozen clock is the same instant/batch, not a rate breach.
        if policy.target_requests_per_second > 0 and self._last_dispatch_at is not None:
            min_interval = 1.0 / policy.target_requests_per_second
            elapsed = now - self._last_dispatch_at
            if 0.0 < elapsed < min_interval:
                raise AbortError(
                    f"rate cap: {elapsed:.3f}s since last dispatch is under the "
                    f"{min_interval:.3f}s min interval — HARD ABORT before dispatch",
                    code="abort",
                )

    def _resolve_credential(self, target_id: str) -> Secret | None:
        """Resolve a scoped credential binding into a :class:`Secret`, if one is bound.

        The P9 fake is not a live target and has no binding, so it dispatches credential-free.
        Any credential the gateway does hold is a redacted :class:`Secret` — never a raw value.
        """
        binding = self.credentials.get(target_id)
        if binding is None:
            return None
        return binding.resolve(target_id, self.settings)

    def _enforce_sequence_capacity(self, request: TargetRequest, policy: RunPolicy) -> None:
        """Preflight the known minimum cost/time of a gateway-owned turn sequence.

        This prevents a three-turn attempt from sending two turns and only then discovering that
        the third cannot fit under the authorization-bound budget or minimum rate window.
        """

        if getattr(self.adapter, "turn_delivery", "atomic") != "sequential":
            return
        turn_count = len(request.turns)
        if turn_count < 1:
            raise AbortError(
                "multi-turn sequence contains no request turns — HARD ABORT before dispatch",
                code="abort",
            )
        if (
            policy.physical_request_limit is not None
            and self._physical_sends_used + turn_count > policy.physical_request_limit
        ):
            raise AbortError(
                "physical request cap: the complete turn sequence cannot fit inside the "
                "remaining authorized sends — HARD ABORT before dispatch",
                code="physical-request-cap-exceeded",
            )
        try:
            per_call = float(self.accounting.per_call_usd)
        except AttributeError as exc:
            raise AbortError(
                "budget cap: accounting exposes no per-call cost estimate (per_call_usd) — "
                "sequence cost cannot be bounded; HARD ABORT before dispatch",
                code="abort",
            ) from exc
        projected = self.accounting.spent_usd + (per_call * turn_count)
        if projected > policy.budget_usd:
            raise AbortError(
                f"budget cap: {turn_count}-turn sequence projects ${projected:.2f}, breaching "
                f"the ${policy.budget_usd:.2f} budget — HARD ABORT before dispatch",
                code="abort",
            )
        if self._run_started_at is not None and policy.target_requests_per_second > 0:
            minimum_sequence_seconds = (turn_count - 1) / policy.target_requests_per_second
            projected_elapsed = self.clock.now() - self._run_started_at + minimum_sequence_seconds
            if projected_elapsed > policy.run_timeout_seconds:
                raise AbortError(
                    "run timeout: the minimum paced multi-turn sequence cannot fit inside the "
                    "remaining run window — HARD ABORT before dispatch",
                    code="abort",
                )

    def _dispatch_with_backoff(
        self,
        request: TargetRequest,
        attack_attempt: dict,
        policy: RunPolicy,
        *,
        attempt_id: str,
    ) -> TargetResponse:
        """Dispatch one logical attempt as one atomic request or a paced turn sequence.

        Conversational adapters opt in through ``turn_delivery == "sequential"``. The gateway
        then performs one physical send per turn through the same adapter/client, re-enforcing
        every cap and charging the meter for every request. Other adapters retain the atomic
        ordered-sequence contract.
        """

        if getattr(self.adapter, "turn_delivery", "atomic") != "sequential":
            return self._dispatch_one_with_backoff(
                request,
                attack_attempt,
                policy,
                attempt_id=attempt_id,
                turn_index=0,
            )

        responses: list[TargetResponse] = []
        total = len(request.turns)
        for index, turn in enumerate(request.turns):
            if index:
                self._pace_sequence_turn(policy)
            turn_request = TargetRequest(
                turns=(turn,),
                metadata={
                    **dict(request.metadata),
                    "turn_index": str(index),
                    "turn_count": str(total),
                },
            )
            response = self._dispatch_one_with_backoff(
                turn_request,
                attack_attempt,
                policy,
                attempt_id=attempt_id,
                turn_index=index,
            )
            responses.append(response)
            if not 200 <= response.status < 300:
                break

        if len(responses) != total:
            raise AbortError(
                "multi-turn sequence ended before every authorized turn was sent — "
                "HARD ABORT without logical completion",
                code="incomplete-multi-turn-attempt",
            )
        final = responses[-1]
        transcript = {
            "delivery": "sequential",
            "turns": [
                {
                    "index": index,
                    "status": response.status,
                    "output": response.output,
                }
                for index, response in enumerate(responses)
            ],
        }
        trace_ids = [
            str(response.metadata["trace_id"])
            for response in responses
            if response.metadata.get("trace_id")
        ]
        return TargetResponse(
            output=json.dumps(
                transcript,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            status=final.status,
            metadata={
                "adapter": final.metadata.get("adapter", self.adapter.name),
                **({"trace_id": trace_ids[-1]} if trace_ids else {}),
                **({"turn_trace_ids": json.dumps(trace_ids)} if trace_ids else {}),
            },
        )

    def _pace_sequence_turn(self, policy: RunPolicy) -> None:
        if policy.target_requests_per_second <= 0 or self._last_dispatch_at is None:
            return
        minimum = 1.0 / policy.target_requests_per_second
        remaining = minimum - (self.clock.now() - self._last_dispatch_at)
        if remaining > 0:
            self._wait(remaining)

    def _wait(self, seconds: float) -> None:
        advance = getattr(self.clock, "advance", None)
        if callable(advance):
            advance(seconds)
        else:
            self.sleeper(seconds)

    def _dispatch_one_with_backoff(
        self,
        request: TargetRequest,
        attack_attempt: dict,
        policy: RunPolicy,
        *,
        attempt_id: str,
        turn_index: int,
    ) -> TargetResponse:
        """Dispatch one physical request, retrying typed AdapterError with backoff.

        A typed :class:`AdapterError` is retried up to :data:`_MAX_DISPATCH_ATTEMPTS` with a
        backoff driven by the injectable wait seam. Every physical send —
        including a failed retry — is preceded by a full cap re-check (:meth:`_enforce_caps`)
        and followed by an :meth:`charge` + rate-window advance, so retries against a failing
        target consume budget/rate and hard-abort the instant a cap is breached (they are not
        free, and cannot outrun the caps). If it never succeeds the attempt is durably QUEUED
        (nothing dropped) and a typed error is re-raised — a failure is NEVER laundered into a
        synthetic 200.
        """
        last_error: AdapterError | None = None
        retry_limit = (
            _MAX_DISPATCH_ATTEMPTS - 1
            if policy.target_retries_per_turn is None
            else policy.target_retries_per_turn
        )
        for dispatch_no in range(1, retry_limit + 2):
            coordinates = WorkUnitCoordinates(
                attempt_id=attempt_id,
                turn_index=turn_index,
                retry_index=dispatch_no - 1,
            )
            # Re-check local caps immediately before durable reservation.  Reservation is the last
            # admission action: once it commits, no later local check may strand an unobserved row
            # without an adapter invocation.
            self._enforce_caps(policy, self.clock.now())
            if self.pre_physical_send_gate is not None:
                self.pre_physical_send_gate(coordinates)
            # Reserve the physical-send slot before handing control to the adapter.  The counter
            # therefore includes failed sends and makes the first over-limit call unreachable.
            self._physical_sends_used += 1
            try:
                response = self.adapter.send(request)
            except AdapterError as exc:
                if self.post_physical_send_observer is not None:
                    self.post_physical_send_observer(coordinates, "raised")
                # A failed physical dispatch still consumes budget and advances the rate window.
                self.accounting.charge()
                self._last_dispatch_at = self.clock.now()
                last_error = exc
                if not exc.retryable:
                    self.queued_attempts.append(
                        {
                            "attack_attempt": attack_attempt,
                            "reason": exc.code,
                            "queued": True,
                        }
                    )
                    raise AbortError(
                        "target credential requires human renewal after one dispatch; "
                        "attempt queued — HARD ABORT",
                        code=exc.code,
                    ) from exc
                # Backoff uses the adapter-provided retry_after when given, else exponential.
                # Tests advance an injectable clock; production sleeps through the injected seam.
                retry_after = getattr(exc, "retry_after", None)
                backoff = float(retry_after) if retry_after else float(2**dispatch_no)
                self._wait(backoff)
                continue
            except BaseException:
                if self.post_physical_send_observer is not None:
                    self.post_physical_send_observer(coordinates, "raised")
                raise
            # Success: charge this physical dispatch and advance the rate window, then return.
            if self.post_physical_send_observer is not None:
                self.post_physical_send_observer(coordinates, "returned")
            self.accounting.charge()
            self._last_dispatch_at = self.clock.now()
            return response
        # Exhausted retries: QUEUE the attempt (nothing lost), then surface a TYPED error.
        self.queued_attempts.append(
            {
                "attack_attempt": attack_attempt,
                "reason": last_error.code if last_error else "adapter-error",
                "queued": True,
            }
        )
        if isinstance(last_error, RateLimitedError):
            raise AbortError(
                f"adapter rate-limited after {retry_limit + 1} dispatch attempt(s); "
                "attempt queued — HARD ABORT (never a synthetic 200)",
                code="abort",
            ) from last_error
        raise AbortError(
            f"target unreachable after {retry_limit + 1} dispatch attempt(s); attempt "
            "queued — HARD ABORT (never a synthetic 200)",
            code="abort",
        ) from last_error

    def _build_result(
        self,
        attack_attempt: dict,
        target_id: str,
        request: TargetRequest,
        response,
        credential: Secret | None,
        *,
        campaign_run_id: str | None = None,
        attempt_id: str | None = None,
        resource_measurements: dict[str, Any] | None = None,
    ) -> AttemptResult:
        """Mint a fresh run-nonce (S3) + policy_decision_id and build hashed D14 evidence.

        The MEASURED consumption trio (``elapsed_ms`` / ``request_count`` / ``response_size``) is
        carried BOTH on the returned :class:`AttemptResult` (``resource_measurements``) and folded
        into the hashed ``fields`` under ``resource_measurements`` — so the recorder persists it
        append-only and the coordinator can RE-READ the measured dimensions before adjudicating,
        never trusting the in-memory value alone.
        """
        campaign_run_id = campaign_run_id or uuid.uuid4().hex
        attempt_id = attempt_id or uuid.uuid4().hex
        policy_decision_id = f"pd-{uuid.uuid4().hex}"
        fields: dict[str, Any] = {
            "schema_version": "1",
            "campaign_run_id": campaign_run_id,
            "attempt_id": attempt_id,
            "campaign_id": attack_attempt.get("case_ref"),
            "target_id": target_id,
            "target_version": response.metadata.get("adapter", self.adapter.name),
            "attack_attempt": attack_attempt,
            "request_transcript": {"request": list(request.turns)},
            "response_transcript": response.output,
            "trace_id": response.metadata.get("trace_id"),
            "policy_decision_id": policy_decision_id,
            "recorder_identity": "policy-gateway@1",
        }
        if resource_measurements is not None:
            # A hashed evidence field: the measured trio is part of the tamper-evident record.
            fields["resource_measurements"] = dict(resource_measurements)
        content_hash = self.recorder.canonical_hash(fields)
        return AttemptResult(
            campaign_run_id=campaign_run_id,
            attempt_id=attempt_id,
            policy_decision_id=policy_decision_id,
            target_id=target_id,
            content_hash=content_hash,
            fields=fields,
            credential=credential,
            resource_measurements=(
                dict(resource_measurements) if resource_measurements is not None else None
            ),
        )
