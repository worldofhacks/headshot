"""SecureCampaignCoordinator — the minimal SECURE live-path coordinator (M11).

ARCHITECTURE.md §3/§4/§5 (trust split F2, live-campaign gate F5/F7, S1/S3/S4); DECISIONS.md
D13/D14/D16/D18. This is the ONE component that sequences the landed platform into a live
campaign, gated FAIL-CLOSED at every step BEFORE any dispatch reaches the target:

  (1) verify :class:`~agentforge.campaign.authorization.RunAuthorization` (missing / expired /
      scope-mismatch -> BLOCK, no dispatch);
  (2) verify :class:`~agentforge.campaign.binding.TargetBinding` against the SELECTED live adapter
      (host / adapter-kind / target mismatch -> BLOCK; NO fallback to the P9 fake, ever);
  (3) require the caps parsed into a :class:`~agentforge.policy.gateway.RunPolicy` (fail-closed);
  (4) M8 seed replay: a trusted-provenance seed -> a schema-valid ``attack_attempt`` (the Red
      Team, an untrusted generator, produces NO evidence);
  (5) resolve the scoped credential (a :class:`~agentforge.secrets.Secret`) at THIS verified
      dispatch boundary and dispatch via :meth:`PolicyGateway.execute` through the BOUND live
      connector (the M5 OpenEmrAdapter, injected fake client under test) — the gateway owns
      budget/rate/timeout/abort;
  (6) :class:`ExecutionRecorder` appends the AttemptResult; PERSIST then RE-READ it from Postgres
      and RE-VERIFY the content_hash — a tamper fails closed;
  (7) platform-owned oracle/canary resolution: the :class:`CanaryOracle` (code) runs over the
      RE-READ transcript -> trusted signals; build the :class:`EvidenceEnvelope`;
      :meth:`Judge.evaluate` -> Verdict (integrity from step 6);
  (8) write the immutable evidence / verdict / result manifests; a confirmed exploit is RECORDED
      as awaiting human approval (an ``approval`` manifest) with publication/remediation/regression-
      promotion BLOCKED — and the bounded campaign CONTINUES to the next case.

HUMAN-APPROVAL GATE, NOT A STOP (D13 — "fail closed on the VERDICT, not the run"): a confirmed
finding does NOT halt the campaign; it is recorded approval-required and the run proceeds through
every case so coverage is complete. The run stops ONLY on an explicit HARD ABORT.

DURABLE HARD ABORT: a fail-closed VIOLATION (a pre-dispatch gate failure, a gateway cap breach, or
an operator abort) triggers a durable abort — it writes the abort-state manifest and PREVENTS ANY
FURTHER DISPATCH for the run, while PRESERVING already-recorded evidence. No publication,
remediation, regression promotion, or social output is ever produced.

**No network is opened from this coordinator's own code.** The only outbound path is the injected
adapter, whose HTTP client is injected/lazy. Hosted Red Team generation is skipped (seed replay).

Framework-neutral where the core is; SQLAlchemy is used only for the recorder reread.
"""

from __future__ import annotations

import datetime
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from sqlalchemy import Engine, text

from agentforge.agents.judge.envelope import EvidenceEnvelopeBuilder
from agentforge.agents.judge.judge import Judge
from agentforge.agents.judge.oracles.base import CanaryOracle
from agentforge.agents.red_team.seed_replay import seed_to_attempt
from agentforge.campaign.authorization import (
    AuthorizationError,
    RunAuthorization,
    operation_hash,
)
from agentforge.campaign.binding import BindingError, TargetBinding
from agentforge.campaign.manifest import ManifestStore
from agentforge.config import Settings
from agentforge.contracts import validate as validate_contract
from agentforge.policy.allowlist import Allowlist, AllowlistEntry
from agentforge.policy.gateway import AttemptResult, PolicyGateway, RunPolicy
from agentforge.policy.recorder import (
    PERSISTED_EVIDENCE_COLUMNS,
    EvidenceIntegrityError,
    ExecutionRecorder,
)
from agentforge.policy.scoped_credentials import (
    CredentialLeaseExpiredError,
    CredentialResolutionError,
)

# The gateway's own credential resolution is bypassed here: the coordinator resolves the scoped
# credential at THIS dispatch boundary (step 5) and injects it into the bound adapter, so the
# gateway dispatches with the already-scoped adapter. This constant marks the policy decision.
_POLICY_DECISION_ALLOW = "allow"


class CampaignAbort(Exception):
    """A durable HARD ABORT of a live-campaign run.

    Raised on any fail-closed violation (authorization, binding, caps, provenance, integrity,
    budget/rate/timeout, monitoring). Once a run is aborted, NO further dispatch is admitted for
    it, while already-recorded evidence is preserved. Carries ``code`` for the typed taxonomy.
    """

    code: str = "campaign-abort"

    def __init__(self, message: str, *, code: str = "campaign-abort") -> None:
        super().__init__(message)
        self.code = code


def operation_hash_for(
    binding: TargetBinding,
    *,
    policy: RunPolicy,
    corpus_id: str,
    corpus_sha: str,
    run_nonce: str,
) -> str:
    """THE canonical operation hash for a run (D14) — the SINGLE production function every path
    computes: the coordinator's per-case gate, the ``run`` pre-adapter gate, and the ``scope``
    authorization-request command. Because they all call this, the hash an approver signs, the hash
    the runner re-verifies, and the hash the request advertises can never diverge.
    """
    return operation_hash(
        target_id=binding.target_id,
        host=binding.host,
        adapter_kind=binding.adapter_kind,
        auth_mode=binding.auth_mode,
        credential_marker=binding.credential_marker(),
        corpus_id=corpus_id,
        corpus_sha=corpus_sha,
        caps=policy,
        run_nonce=run_nonce,
    )


def verify_authorization_gate(
    binding: TargetBinding,
    *,
    policy: RunPolicy,
    corpus_id: str,
    corpus_sha: str,
    run_nonce: str,
    authorization: RunAuthorization | None,
    now: float,
) -> str:
    """FAIL-CLOSED authorization gate — compute the op hash and VERIFY the grant. Returns the hash.

    Blocks (raises :class:`AuthorizationError`) on a MISSING / EXPIRED / nonce-mismatched /
    scope-mismatched grant — where "scope" includes every bound identity field (target/host/adapter/
    auth/credential-marker/corpus-id/corpus-content-sha/caps). This is the gate the ``run`` command
    runs BEFORE constructing the live adapter, and the coordinator re-runs per case (defense in
    depth) — the SAME function, so the pre-adapter gate and the per-case re-verification cannot
    diverge. It touches no adapter, no engine, and opens no socket.
    """
    op_hash = operation_hash_for(
        binding,
        policy=policy,
        corpus_id=corpus_id,
        corpus_sha=corpus_sha,
        run_nonce=run_nonce,
    )
    RunAuthorization.verify_optional(
        authorization, operation_hash=op_hash, run_nonce=run_nonce, now=now
    )
    return op_hash


@dataclass(frozen=True)
class RunConfig:
    """The immutable run config the coordinator verifies before every dispatch.

    ``policy`` is ``None`` when the caps failed to parse into a :class:`RunPolicy` — the
    coordinator fails closed on a ``None`` policy before any dispatch (no unbounded run).
    """

    binding: TargetBinding
    authorization: RunAuthorization | None
    policy: RunPolicy | None
    run_nonce: str
    canary_token: str
    environment: str = "production"
    # The authored-corpus IDENTITY the authorization is scoped to. A grant authorizes attacking the
    # bound target/host with THIS corpus under the given caps; changing the corpus id changes the
    # operation hash and thus refuses a stale grant.
    corpus_id: str = "m11-seed-corpus-v1"
    # A sha256 over the corpus CONTENT (the replayed attempts) — bound into the operation hash so a
    # grant is tied to the exact corpus bytes it was minted for (D14). The CLI/composition root
    # computes it from the loaded corpus; unit tests that drive a single case use the "" default and
    # mint their grant over the same value.
    corpus_sha: str = ""
    # The PostgreSQL control plane binds a broader exact scope than the legacy CLI grant.
    # A durable Runner supplies that persisted hash and a per-dispatch database verifier.
    authorization_operation_hash: str | None = None
    campaign_run_id: str | None = None
    pre_dispatch_gate: Callable[[str], None] | None = field(default=None, repr=False)
    credential_resolver: Callable[[str | None], Any] | None = field(default=None, repr=False)
    result_context: Mapping[str, Any] = field(default_factory=dict, repr=False)
    agent_execution_start: Callable[..., str] | None = field(default=None, repr=False)
    agent_execution_finish: Callable[..., None] | None = field(default=None, repr=False)
    dispatch_sleeper: Callable[[float], None] = field(default=time.sleep, repr=False)


@dataclass(frozen=True)
class CampaignOutcome:
    """The result of one :meth:`SecureCampaignCoordinator.run_case` call.

    Carries the recorded evidence (:class:`AttemptResult`), the reread integrity flag, the code
    oracle signal, and the Judge's verdict — the caller reads these to assert the chain held.
    """

    run_id: str
    result: AttemptResult
    integrity_ok: bool
    oracle_signal: dict[str, Any]
    verdict: dict[str, Any]


@dataclass
class SecureCampaignCoordinator:
    """Sequences the landed chain for one live-campaign run, fail-closed at every gate.

    All collaborators are injected: the bound live ``adapter`` (its HTTP transport is the injected
    client under test), the migrated ``engine``, the ``manifests`` store, and the deterministic
    ``clock`` / ``accounting`` doubles. The coordinator holds the REAL landed
    gateway/recorder/oracle/envelope/Judge classes — none is mocked.
    """

    config: RunConfig
    adapter: Any
    engine: Engine
    manifests: ManifestStore
    clock: Any
    accounting: Any

    # A decoy fallback slot: a coordinator has NO fallback path. If a caller sets this (as the
    # "no live-to-fake fallback" tests do), it is NEVER dispatched to — the coordinator raises on
    # a blocked live path rather than substituting any fallback adapter.
    fallback_adapter: Any | None = None

    recorder: ExecutionRecorder = field(default_factory=ExecutionRecorder)
    builder: EvidenceEnvelopeBuilder = field(default_factory=EvidenceEnvelopeBuilder)
    judge: Judge = field(default_factory=Judge)

    run_id: str = field(default_factory=lambda: uuid.uuid4().hex, init=False)
    _aborted: bool = field(default=False, init=False)
    _config_written: bool = field(default=False, init=False)
    _dispatched_any: bool = field(default=False, init=False)
    # Confirmed exploits recorded as awaiting human approval (publication/remediation/regression-
    # promotion BLOCKED). Appended per confirmed case; the campaign continues (D13).
    _pending_approvals: list[dict[str, Any]] = field(default_factory=list, init=False)
    # The run-scoped gateway — built ONCE, lazily, at the first post-gate dispatch and reused for
    # every case, so budget/attempt/rate/timeout accumulate across the WHOLE run (not per case).
    _gateway: PolicyGateway | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.config.campaign_run_id:
            self.run_id = self.config.campaign_run_id

    def run_case(
        self,
        seed_case: Mapping[str, Any],
        *,
        attack_attempt: Mapping[str, Any] | None = None,
        run_oracle: bool = True,
        tamper_after_persist: Callable[[Engine, str, str], None] | None = None,
        attempt_id: str | None = None,
    ) -> CampaignOutcome:
        """Run ONE selected seed case through the fail-closed chain, or BLOCK before dispatch.

        Raises :class:`CampaignAbort` / :class:`AuthorizationError` / :class:`BindingError`
        BEFORE any dispatch on a gate failure (the adapter is never called, no AttemptResult is
        recorded). Once the run has aborted, every subsequent call raises :class:`CampaignAbort`.
        """
        # A durably-aborted run admits NO further dispatch — checked first (preserve evidence,
        # prevent further dispatch). This is the hard-abort latch.
        if self._aborted:
            raise CampaignAbort(
                f"run {self.run_id!r} has durably aborted — no further dispatch is admitted "
                "(the recorded evidence is preserved)",
                code="run-aborted",
            )

        try:
            return self._run_case_gated(
                seed_case,
                attack_attempt=attack_attempt,
                run_oracle=run_oracle,
                tamper_after_persist=tamper_after_persist,
                attempt_id=attempt_id,
            )
        except (AuthorizationError, BindingError, CampaignAbort) as exc:
            # Any fail-closed gate violation durably aborts the run: write the abort-state
            # manifest and latch, so no further dispatch is admitted. Already-recorded evidence
            # (from an earlier case) is untouched. Re-raise the typed error to the caller.
            self._durable_abort(reason=str(exc), code=getattr(exc, "code", "gate-violation"))
            raise

    @property
    def dispatched_any(self) -> bool:
        """True once at least one attempt has been dispatched to the bound live adapter.

        The CLI uses this to distinguish a PRE-dispatch gate refusal (unauthorized / blocked
        binding / unbounded caps — zero dispatch) from a run that reached the target and then
        completed or hit a post-dispatch hard abort.
        """
        return self._dispatched_any

    @property
    def pending_approvals(self) -> list[dict[str, Any]]:
        """The confirmed findings recorded as AWAITING human approval (a copy, not the live list).

        Each entry is ``{campaign_run_id, attempt_id, verdict_state, requires_human_approval,
        published, remediation_emitted, regression_promoted}`` — every gated side effect is False.
        A non-empty list means the bounded run confirmed exploit(s) that are blocked pending human
        approval; the campaign nonetheless ran every case (D13). The CLI reports the count.
        """
        return [dict(entry) for entry in self._pending_approvals]

    def abort(self, reason: str) -> None:
        """Trigger a durable HARD ABORT (a monitoring/integrity violation the run detected).

        Writes the abort-state manifest and latches the run so no further dispatch is admitted,
        while PRESERVING already-recorded evidence. Produces NO publication / remediation /
        regression / social output.
        """
        self._durable_abort(reason=reason, code="operator-abort")

    # ------------------------------------------------------------------ the gated chain

    def _run_case_gated(
        self,
        seed_case: Mapping[str, Any],
        *,
        attack_attempt: Mapping[str, Any] | None,
        run_oracle: bool,
        tamper_after_persist: Callable[[Engine, str, str], None] | None,
        attempt_id: str | None,
    ) -> CampaignOutcome:
        binding = self.config.binding
        policy = self.config.policy

        # (0) Caps MUST have parsed into a RunPolicy — a None policy is a fail-closed refusal
        # (an unbounded run can never reach the adapter). Checked before authorization so a
        # missing ceiling never rides even an in-scope grant.
        if policy is None:
            raise CampaignAbort(
                "run caps did not parse into a RunPolicy — a run with no bounded ceilings can "
                "never dispatch (fail closed)",
                code="caps-invalid",
            )

        # (1) AUTHORIZATION — compute the canonical op hash over the WHOLE immutable run identity
        # (D14) and verify the grant (missing / expired / nonce / scope) BLOCKS before dispatch.
        # This RE-VERIFIES the SAME gate the `run` command already ran BEFORE building the adapter,
        # via the shared verify_authorization_gate — defense in depth that cannot drift.
        if self.config.authorization_operation_hash is None:
            verify_authorization_gate(
                binding,
                policy=policy,
                corpus_id=self.config.corpus_id,
                corpus_sha=self.config.corpus_sha,
                run_nonce=self.config.run_nonce,
                authorization=self.config.authorization,
                now=self.clock.now(),
            )
        else:
            RunAuthorization.verify_optional(
                self.config.authorization,
                operation_hash=self.config.authorization_operation_hash,
                run_nonce=self.config.run_nonce,
                now=self.clock.now(),
            )

        # (2) BINDING — verify the SELECTED live adapter matches the bound target exactly. NO
        # fallback to the P9 fake ever: a mismatch raises, it never substitutes an adapter.
        self._verify_binding(binding)

        # All gates passed — ONLY NOW write the immutable run-config manifest. An unauthorized /
        # expired / scope-mismatched / mis-bound / unbounded-caps run blocks ABOVE and leaves only
        # the abort-state manifest on disk, never a durable config manifest for a refused run.
        self._write_config_manifest_once()

        # (4) RED TEAM HANDOFF — accept only a schema-valid proposal that is byte-for-byte the
        # deterministic projection of the exact reviewed seed bound into the authorized corpus.
        # An altered/mutated proposal requires a NEW corpus hash and a NEW authorization.
        expected_attempt = seed_to_attempt(dict(seed_case))
        proposed_attempt = expected_attempt if attack_attempt is None else dict(attack_attempt)
        try:
            validate_contract("attack_attempt", proposed_attempt)
        except Exception as exc:
            raise CampaignAbort(
                "Red Team proposal fails the AttackAttempt contract",
                code="red-team-proposal-invalid",
            ) from exc
        if proposed_attempt != expected_attempt:
            raise CampaignAbort(
                "Red Team proposal differs from the exact authorized corpus seed",
                code="red-team-proposal-out-of-scope",
            )

        # Re-read persisted approval, abort, scope, and lease ownership immediately before the
        # dispatch boundary. The callback is trusted Runner composition, never browser state.
        if self.config.pre_dispatch_gate is not None:
            if not attempt_id:
                raise CampaignAbort("persisted attempt identity is missing", code="attempt-invalid")
            self.config.pre_dispatch_gate(attempt_id)

        # (5) SCOPED CREDENTIAL at THIS verified dispatch boundary + dispatch through the BOUND
        # live connector. The credential resolves to a Secret only here (O1), never at construction.
        try:
            if self.config.credential_resolver is None:
                credential = binding.resolve_credential(
                    Settings(environment=self.config.environment)
                )
            else:
                credential = self.config.credential_resolver(binding.credential_ref)
        except CredentialLeaseExpiredError as exc:
            # Keep the persisted abort reason bounded: resolver messages can reflect deployment
            # details and must never become evidence/log output.  Expiry is terminal; a campaign
            # may not silently switch to a freshly delegated patient session mid-run.
            raise CampaignAbort(
                "delegated target session is no longer valid",
                code="target-session-expired",
            ) from exc
        except (CredentialResolutionError, ValueError) as exc:
            raise CampaignAbort(
                "campaign-scoped target credential is unavailable",
                code="credential-resolution-failed",
            ) from exc
        result = self._dispatch(
            proposed_attempt,
            binding,
            policy,
            credential,
            attempt_id=attempt_id,
        )

        # (6) RECORD -> PERSIST -> RE-READ -> RE-VERIFY the content_hash from Postgres.
        self._persist(result)
        if tamper_after_persist is not None:
            tamper_after_persist(self.engine, result.campaign_run_id, result.attempt_id)
        integrity_ok = self._reread_and_verify(result)

        # (7) PLATFORM-OWNED oracle/canary over the RE-READ transcript -> envelope -> Judge.
        reread_transcript = self._reread_transcript(result)
        oracle_expectation = seed_case.get("oracle_expectation")
        canary_token: str | None = self.config.canary_token
        if isinstance(oracle_expectation, Mapping):
            candidate = oracle_expectation.get("canary_ref")
            canary_token = candidate if isinstance(candidate, str) and candidate else None
            run_oracle = run_oracle and canary_token is not None
        oracle_signal, verdict = self._adjudicate(
            result,
            reread_transcript,
            run_oracle=run_oracle,
            integrity_ok=integrity_ok,
            canary_token=canary_token,
        )

        # A confirmed exploit is a critical finding that must be HUMAN-APPROVED before any
        # publication / remediation / regression-promotion — but it does NOT stop the campaign.
        requires_human_approval = verdict.get("state") == "EXPLOIT_CONFIRMED"

        # (8) IMMUTABLE evidence + verdict manifests (redacted; no raw secret/hostile content).
        self._write_evidence_manifest(
            result, integrity_ok=integrity_ok, oracle_hit=oracle_signal["hit"]
        )
        self._write_verdict_manifest(result, verdict)
        # HUMAN-APPROVAL GATE (D13 — "fail closed on the VERDICT, not the run"). A confirmed
        # finding is RECORDED as approval-required and its publication / remediation / regression-
        # promotion are BLOCKED (none is produced here); the bounded campaign CONTINUES through the
        # remaining cases. The run stops ONLY on an explicit hard abort (a pre-dispatch gate
        # violation, a gateway cap breach, or an operator abort) — never merely because a finding
        # was confirmed. Halting on the first confirmation was a D13 regression: it under-covered
        # the corpus and mislabeled a normal, expected finding as a campaign-ending stop.
        if requires_human_approval:
            self._record_human_approval(result, verdict)
        self._write_result_manifest(
            result,
            verdict,
            integrity_ok=integrity_ok,
            requires_human_approval=requires_human_approval,
        )

        return CampaignOutcome(
            run_id=self.run_id,
            result=result,
            integrity_ok=integrity_ok,
            oracle_signal=oracle_signal,
            verdict=verdict,
        )

    # ------------------------------------------------------------------ gate helpers

    def _verify_binding(self, binding: TargetBinding) -> None:
        """Verify the SELECTED live adapter matches the bound ADAPTER KIND + HOST; else BLOCK.

        Fail-closed, with NO fallback: the adapter's kind must equal the bound adapter kind and the
        adapter's base-URL host must EXACTLY match the bound host. A mismatch raises
        :class:`BindingError` — the coordinator never substitutes a fallback (the P9 fake) for a
        blocked live path.

        The bound ``target_id`` is a target IDENTITY, deliberately decoupled from the adapter's
        ``name`` (its transport kind): OpenEMR is merely the FIRST adapter, so ``target_id`` and
        adapter kind may legitimately differ (a target reached through a differently-named
        connector). Binding is verified against adapter kind + host — never ``target_id ==
        adapter.name`` — so the coordinator stays adapter-generic at this seam. (The full
        target/adapter registry is a post-M11 integration; see the Codex-branch note in
        :mod:`agentforge.campaign.binding`.)
        """
        adapter_name = getattr(self.adapter, "name", None)
        if adapter_name != binding.adapter_kind:
            raise BindingError(
                f"selected adapter kind {adapter_name!r} does not match the bound adapter kind "
                f"{binding.adapter_kind!r} — a live run dispatches only through the bound live "
                "adapter (no fallback)"
            )
        base_url = getattr(self.adapter, "base_url", "")
        binding.validate_host(base_url)

    def _dispatch(
        self,
        attack_attempt: dict[str, Any],
        binding: TargetBinding,
        policy: RunPolicy,
        credential: Any,
        *,
        attempt_id: str | None,
    ) -> AttemptResult:
        """Dispatch exactly one attempt through the gateway to the BOUND live adapter.

        The scoped credential (resolved to a :class:`Secret` at this boundary, or ``None`` for an
        ``auth_mode=none`` target) is injected into the bound adapter, and the gateway — the SOLE
        cap-enforcing exit — owns budget/rate/timeout/abort. The allowlist admits ONLY the bound
        target mapped to the bound adapter kind, so an off-target dispatch can never reach the
        adapter.
        """
        # Inject the scoped Secret into the bound adapter for THIS dispatch only (the raw value
        # never leaves the Secret; the adapter reveals it solely at the HTTPS call boundary). A
        # None credential is an auth_mode=none dispatch — the adapter sends without injecting one.
        self.adapter.credential = credential

        gateway = self._run_gateway(binding)
        try:
            result = gateway.execute(
                attack_attempt,
                policy,
                target_id=binding.target_id,
                campaign_run_id=self.config.campaign_run_id,
                attempt_id=attempt_id,
                organization_id=str(self.config.result_context.get("organization_id", "")),
            )
        except Exception as exc:  # a gateway abort / off-allowlist denial is a durable hard abort
            raise CampaignAbort(
                f"gateway refused dispatch: {type(exc).__name__}: {exc}",
                code=getattr(exc, "code", "gateway-refused"),
            ) from exc
        self._dispatched_any = True
        if not self.config.result_context:
            return result
        fields = dict(result.fields)
        fields.update(dict(self.config.result_context))
        for column in PERSISTED_EVIDENCE_COLUMNS:
            fields.setdefault(column, None)
        fields["executed_at"] = datetime.datetime.fromtimestamp(
            self.clock.now(), tz=datetime.UTC
        ).isoformat()
        content_hash = self.recorder.canonical_hash(fields)
        return replace(result, fields=fields, content_hash=content_hash)

    def _run_gateway(self, binding: TargetBinding) -> PolicyGateway:
        """Return the ONE run-scoped gateway, building it lazily on first dispatch (post-gate).

        The gateway is built ONCE and reused for every case in the run, so its per-run accounting —
        attempts used, the rate window, and the run-timeout anchor — accumulates across the WHOLE
        campaign rather than resetting per case (a per-case gateway would silently reset the
        attempt/rate/timeout caps between cases and thus NOT bound a multi-case run). The shared
        ``accounting`` already accumulates spend run-wide; this makes every OTHER cap run-wide too.

        It is constructed only here — reached solely AFTER a case has passed authorization + binding
        + caps — so no live enforcement object is built for a run that never clears the gates.
        """
        if self._gateway is None:
            allowlist = Allowlist(
                entries=[
                    AllowlistEntry(target_id=binding.target_id, adapter_name=binding.adapter_kind)
                ]
            )
            self._gateway = PolicyGateway(
                allowlist=allowlist,
                adapter=self.adapter,
                settings=Settings(environment=self.config.environment),
                clock=self.clock,
                accounting=self.accounting,
                recorder=self.recorder,
                sleeper=self.config.dispatch_sleeper,
            )
        return self._gateway

    # ------------------------------------------------------------------ recorder + reread

    def _persist(self, result: AttemptResult) -> None:
        """APPEND the hashed AttemptResult to Postgres (append-only, D14)."""
        with self.engine.begin() as conn:
            self.recorder.record(result.fields, conn)

    def _reread_transcript(self, result: AttemptResult) -> str:
        """Re-read the persisted ``response_transcript`` for the attempt from Postgres."""
        with self.engine.connect() as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT response_transcript FROM attempt_result "
                        "WHERE campaign_run_id = :run AND attempt_id = :att"
                    ),
                    {"run": result.campaign_run_id, "att": result.attempt_id},
                )
                .mappings()
                .first()
            )
        if row is None:
            return ""
        transcript = row["response_transcript"]
        return transcript if isinstance(transcript, str) else str(transcript)

    def _reread_and_verify(self, result: AttemptResult) -> bool:
        """RE-READ the FULL persisted evidence row and RE-VERIFY its content_hash — fail closed.

        Reconstructs the hashed field set ENTIRELY from the re-read Postgres row — it never trusts
        the in-memory ``result.fields`` for ANY hashed column — then runs the recorder's
        fail-closed hash-verify against the original authoritative digest. A tamper of ANY hashed
        column in the persisted row (target_id, attack_attempt, request/response transcript,
        policy_decision_id, …), not merely the transcript, makes the recompute diverge, so
        :meth:`ExecutionRecorder.verify` raises :class:`EvidenceIntegrityError` and this returns
        ``False``. A missing persisted row is likewise a fail-closed ``False``.
        """
        with self.engine.connect() as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT * FROM attempt_result "
                        "WHERE campaign_run_id = :run AND attempt_id = :att"
                    ),
                    {"run": result.campaign_run_id, "att": result.attempt_id},
                )
                .mappings()
                .first()
            )
        if row is None:
            return False  # the persisted evidence is gone — fail closed
        # Rebuild the exact hashed field set from the RE-READ values (JSONB columns come back as
        # native dict/list). The key set is structural (the platform's field set); every VALUE is
        # taken from the DB read, so a tamper of any hashed column diverges the recompute.
        candidate: dict[str, Any] = {k: row[k] for k in result.fields if k != "content_hash"}
        for key, value in tuple(candidate.items()):
            if isinstance(value, datetime.datetime):
                candidate[key] = value.isoformat()
        candidate["content_hash"] = result.content_hash  # the ORIGINAL, authoritative digest
        try:
            self.recorder.verify(candidate)
        except EvidenceIntegrityError:
            return False
        return True

    # ------------------------------------------------------------------ oracle + judge

    def _adjudicate(
        self,
        result: AttemptResult,
        reread_transcript: str,
        *,
        run_oracle: bool,
        integrity_ok: bool,
        canary_token: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the platform-owned code oracle over the RE-READ transcript -> envelope -> Judge.

        The :class:`CanaryOracle` is a code predicate — a substring test the hostile transcript
        can never suppress or fabricate. When ``run_oracle`` is False the trusted block carries no
        signal (the non-oracle path), so a run with no trusted hit is forced INDETERMINATE at MVP.
        """
        execution_id: str | None = None
        if self.config.agent_execution_start is not None:
            execution_id = self.config.agent_execution_start(
                agent_role="judge",
                input_payload={
                    "attempt_id": result.attempt_id,
                    "evidence_content_hash": result.content_hash,
                    "evidence_integrity_verified": integrity_ok,
                    "oracle_enabled": run_oracle,
                },
                attempt_id=result.attempt_id,
                detail={"phase": "independent_adjudication"},
            )
        try:
            if run_oracle:
                if not canary_token:
                    raise CampaignAbort("oracle canary is missing", code="oracle-config-invalid")
                oracle = CanaryOracle(canary_token, id="canary-token")
                oracle_signal = oracle.evaluate(reread_transcript)
                oracle_results = [oracle_signal]
            else:
                oracle_signal = {"id": "canary-token", "provenance": "code", "hit": False}
                oracle_results = []

            envelope = self.builder.build(
                campaign_run_id=result.campaign_run_id,
                attempt_id=result.attempt_id,
                transcript=reread_transcript,
                oracle_results=oracle_results,
                canary_hits=[],
                policy_decision=_POLICY_DECISION_ALLOW,
                campaign_id=result.fields.get("campaign_id"),
            )
            verdict = self.judge.evaluate(envelope, integrity_ok=integrity_ok)
        except Exception:
            if execution_id is not None and self.config.agent_execution_finish is not None:
                self.config.agent_execution_finish(
                    execution_id=execution_id,
                    status="failed",
                    output_payload={"attempt_id": result.attempt_id},
                    error_code="judge_execution_failed",
                    detail={"phase": "independent_adjudication"},
                )
            raise
        if execution_id is not None and self.config.agent_execution_finish is not None:
            self.config.agent_execution_finish(
                execution_id=execution_id,
                status="succeeded",
                output_payload={
                    "attempt_id": result.attempt_id,
                    "verdict_state": verdict.get("state"),
                    "reason_codes": list(verdict.get("reason_codes", [])),
                    "oracle_hit": bool(oracle_signal.get("hit")),
                },
                detail={
                    "phase": "independent_adjudication",
                    "evidence_integrity_verified": integrity_ok,
                },
            )
        return oracle_signal, verdict

    # ------------------------------------------------------------------ manifests (redacted)

    def _redactions(self) -> tuple[str, ...]:
        """The literal sensitive strings scrubbed from every manifest (canary + credential ref)."""
        return (self.config.canary_token, self.config.binding.credential_ref)

    def _write_config_manifest_once(self) -> None:
        """Write the immutable, redacted run-config manifest exactly once for the run."""
        if self._config_written:
            return
        self.manifests.write(
            run_id=self.run_id,
            kind="config",
            payload={
                "run_nonce": self.config.run_nonce,
                "environment": self.config.environment,
                "target_id": self.config.binding.target_id,
                "host": self.config.binding.host,
                "adapter_kind": self.config.binding.adapter_kind,
                "auth_mode": self.config.binding.auth_mode,
                # The credential MARKER (no-auth marker or a ref digest) — never the raw ref; it is
                # the same content-addressed value bound into the operation hash (safe to record).
                "credential_marker": self.config.binding.credential_marker(),
                "corpus_id": self.config.corpus_id,
                "corpus_sha": self.config.corpus_sha,
                # credential_ref is intentionally NOT written raw — it is a redacted literal.
            },
            redactions=self._redactions(),
        )
        self._config_written = True

    def _write_evidence_manifest(
        self, result: AttemptResult, *, integrity_ok: bool, oracle_hit: bool
    ) -> None:
        """Write the immutable evidence-pointer manifest (ids + hash + flags, never raw transcript).

        Scoped to the attempt so multiple attempts in one run never collide on an immutable file.
        """
        self.manifests.write(
            run_id=self.run_id,
            kind="evidence",
            attempt_id=result.attempt_id,
            payload={
                "campaign_run_id": result.campaign_run_id,
                "attempt_id": result.attempt_id,
                "policy_decision_id": result.policy_decision_id,
                "target_id": result.target_id,
                "content_hash": result.content_hash,
                "integrity_ok": integrity_ok,
                "oracle_hit": oracle_hit,
            },
            redactions=self._redactions(),
        )

    def _write_verdict_manifest(self, result: AttemptResult, verdict: dict[str, Any]) -> None:
        """Write the immutable per-attempt verdict manifest (the Judge's disposition)."""
        self.manifests.write(
            run_id=self.run_id,
            kind="verdict",
            attempt_id=result.attempt_id,
            payload={
                "campaign_run_id": result.campaign_run_id,
                "attempt_id": result.attempt_id,
                "state": verdict.get("state"),
                "confidence": verdict.get("confidence"),
                "reason_codes": list(verdict.get("reason_codes", [])),
                "confirmation_source": verdict.get("confirmation_source"),
                "error_code": verdict.get("error_code"),
            },
            redactions=self._redactions(),
        )

    def _write_result_manifest(
        self,
        result: AttemptResult,
        verdict: dict[str, Any],
        *,
        integrity_ok: bool,
        requires_human_approval: bool,
    ) -> None:
        """Write the immutable per-attempt result manifest (one per attempt within the run).

        ``requires_human_approval`` records whether this attempt confirmed an exploit that is now
        blocked pending human approval — the durable, per-attempt disposition of the finding.
        """
        self.manifests.write(
            run_id=self.run_id,
            kind="result",
            attempt_id=result.attempt_id,
            payload={
                "run_id": self.run_id,
                "campaign_run_id": result.campaign_run_id,
                "attempt_id": result.attempt_id,
                "verdict_state": verdict.get("state"),
                "integrity_ok": integrity_ok,
                "requires_human_approval": requires_human_approval,
                # Every gated side effect is BLOCKED at MVP — the coordinator produces none.
                "published": False,
                "remediation_emitted": False,
                "regression_promoted": False,
            },
            redactions=self._redactions(),
        )

    def _record_human_approval(self, result: AttemptResult, verdict: dict[str, Any]) -> None:
        """RECORD a confirmed finding as awaiting human approval; write the ``approval`` manifest.

        The human-approval record is the durable proof that a confirmed exploit was NOT published,
        remediated, or promoted to the regression corpus without human sign-off (D13). It appends to
        :attr:`pending_approvals` and writes an immutable per-attempt ``approval`` manifest whose
        gated side-effect flags are all False. It produces NO publication/remediation/social output
        and does NOT stop the run — the campaign continues to the next case.
        """
        record = {
            "campaign_run_id": result.campaign_run_id,
            "attempt_id": result.attempt_id,
            "verdict_state": verdict.get("state"),
            "requires_human_approval": True,
            "published": False,
            "remediation_emitted": False,
            "regression_promoted": False,
        }
        self._pending_approvals.append(record)
        self.manifests.write(
            run_id=self.run_id,
            kind="approval",
            attempt_id=result.attempt_id,
            payload=dict(record),
            redactions=self._redactions(),
        )

    def _durable_abort(self, *, reason: str, code: str) -> None:
        """Latch the run aborted and write the abort-state manifest (idempotent; evidence-safe).

        Writes the abort manifest once; latches so no further dispatch is admitted. It produces NO
        publication / remediation / regression / social output — the only artifact is the abort
        manifest, and already-recorded evidence is untouched.
        """
        self._aborted = True
        if "abort" not in self.manifests.kinds_written(self.run_id):
            self.manifests.write(
                run_id=self.run_id,
                kind="abort",
                payload={"run_id": self.run_id, "reason": reason, "code": code},
                redactions=self._redactions(),
            )
