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
  (8) write the immutable evidence / verdict manifests.

DURABLE HARD ABORT: any violation triggers a durable abort — it writes the abort-state manifest
and PREVENTS ANY FURTHER DISPATCH for the run, while PRESERVING already-recorded evidence. No
publication, remediation, regression promotion, or social output is ever produced.

**No network is opened from this coordinator's own code.** The only outbound path is the injected
adapter, whose HTTP client is injected/lazy. Hosted Red Team generation is skipped (seed replay).

Framework-neutral where the core is; SQLAlchemy is used only for the recorder reread.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
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
from agentforge.policy.allowlist import Allowlist, AllowlistEntry
from agentforge.policy.gateway import AttemptResult, PolicyGateway, RunPolicy
from agentforge.policy.recorder import EvidenceIntegrityError, ExecutionRecorder

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
    # The authored-corpus identity the authorization is scoped to (target / surface / corpus).
    # A grant authorizes attacking a target's surface with THIS corpus under the given caps —
    # changing the corpus id changes the operation hash and thus refuses a stale grant.
    corpus_id: str = "m11-seed-corpus-v1"


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

    def run_case(
        self,
        seed_case: Mapping[str, Any],
        *,
        run_oracle: bool = True,
        tamper_after_persist: Callable[[Engine, str, str], None] | None = None,
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
                seed_case, run_oracle=run_oracle, tamper_after_persist=tamper_after_persist
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
        binding / unbounded caps — zero dispatch) from a POST-dispatch human-gate stop (a
        confirmed finding halts the run for approval — a successful bounded run).
        """
        return self._dispatched_any

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
        run_oracle: bool,
        tamper_after_persist: Callable[[Engine, str, str], None] | None,
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

        # The operation hash the authorization must be in scope for — over the target IDENTITY the
        # run attacks (target / surface / corpus) plus the caps + nonce, NOT the adapter transport.
        # The bound host is the attacked SURFACE; adapter kind + credential ref are HOW the wire is
        # made, deliberately excluded so a grant stays adapter-generic (OpenEMR is the 1st adapter).
        op_hash = operation_hash(
            target_id=binding.target_id,
            surface=binding.host,
            corpus_id=self.config.corpus_id,
            caps=policy,
            run_nonce=self.config.run_nonce,
        )

        # (1) AUTHORIZATION — missing / expired / scope-mismatch BLOCKS before dispatch.
        RunAuthorization.verify_optional(
            self.config.authorization,
            operation_hash=op_hash,
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

        # (4) SEED REPLAY — a trusted-provenance seed -> a schema-valid attack_attempt (the Red
        # Team produces no evidence). Hosted generation is skipped (deterministic replay).
        attack_attempt = seed_to_attempt(dict(seed_case))

        # (5) SCOPED CREDENTIAL at THIS verified dispatch boundary + dispatch through the BOUND
        # live connector. The credential resolves to a Secret only here (O1), never at construction.
        credential = binding.resolve_credential(Settings(environment=self.config.environment))
        result = self._dispatch(attack_attempt, binding, policy, credential)

        # (6) RECORD -> PERSIST -> RE-READ -> RE-VERIFY the content_hash from Postgres.
        self._persist(result)
        if tamper_after_persist is not None:
            tamper_after_persist(self.engine, result.campaign_run_id, result.attempt_id)
        integrity_ok = self._reread_and_verify(result)

        # (7) PLATFORM-OWNED oracle/canary over the RE-READ transcript -> envelope -> Judge.
        reread_transcript = self._reread_transcript(result)
        oracle_signal, verdict = self._adjudicate(
            result, reread_transcript, run_oracle=run_oracle, integrity_ok=integrity_ok
        )

        # (8) IMMUTABLE evidence + verdict manifests (redacted; no raw secret/hostile content).
        self._write_evidence_manifest(
            result, integrity_ok=integrity_ok, oracle_hit=oracle_signal["hit"]
        )
        self._write_verdict_manifest(result, verdict)
        self._write_result_manifest(result, verdict, integrity_ok=integrity_ok)

        outcome = CampaignOutcome(
            run_id=self.run_id,
            result=result,
            integrity_ok=integrity_ok,
            oracle_signal=oracle_signal,
            verdict=verdict,
        )

        # HUMAN-GATE: a confirmed exploit is a critical finding — the run durably STOPS here
        # (no further dispatch) pending human approval before any publication/remediation. The
        # already-recorded evidence + manifests are preserved. This latches AFTER the outcome is
        # built, so the confirming case's result is fully returned. (A live campaign never keeps
        # attacking a target once a confirmed exploit is in hand — findings are human-gated.)
        if verdict.get("state") == "EXPLOIT_CONFIRMED":
            self._durable_abort(
                reason="confirmed exploit — run halted for human approval (finding gate)",
                code="human-gate-confirmed",
            )
        return outcome

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

        allowlist = Allowlist(
            entries=[AllowlistEntry(target_id=binding.target_id, adapter_name=binding.adapter_kind)]
        )
        gateway = PolicyGateway(
            allowlist=allowlist,
            adapter=self.adapter,
            settings=Settings(environment=self.config.environment),
            clock=self.clock,
            accounting=self.accounting,
            recorder=self.recorder,
        )
        try:
            result = gateway.execute(attack_attempt, policy, target_id=binding.target_id)
        except Exception as exc:  # a gateway abort / off-allowlist denial is a durable hard abort
            raise CampaignAbort(
                f"gateway refused dispatch: {type(exc).__name__}: {exc}",
                code=getattr(exc, "code", "gateway-refused"),
            ) from exc
        self._dispatched_any = True
        return result

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
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the platform-owned code oracle over the RE-READ transcript -> envelope -> Judge.

        The :class:`CanaryOracle` is a code predicate — a substring test the hostile transcript
        can never suppress or fabricate. When ``run_oracle`` is False the trusted block carries no
        signal (the non-oracle path), so a run with no trusted hit is forced INDETERMINATE at MVP.
        """
        if run_oracle:
            oracle = CanaryOracle(self.config.canary_token, id="canary-token")
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
        self, result: AttemptResult, verdict: dict[str, Any], *, integrity_ok: bool
    ) -> None:
        """Write the immutable per-attempt result manifest (one per attempt within the run)."""
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
            },
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
