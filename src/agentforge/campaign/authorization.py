"""RunAuthorization — a PERSISTED, EXPIRING, SCOPED grant that gates every live campaign run.

M11-coordinator (ARCHITECTURE.md §5 live-campaign gate F5/F7, S1/S3; DECISIONS.md D16).

An authorization is NOT a config flag and NOT an environment: a configured, credentialed box is
never on its own authorized to attack a live target. A run is authorized only by a minted
:class:`RunAuthorization` that:

* binds a canonical **operation hash** of the immutable run config (target id + exact host +
  adapter kind + credential reference + caps + run nonce) — so a grant minted for one run config
  can never authorize a *different* config (scope is content-addressed);
* carries an absolute **expiry** on the injectable clock — a grant is a bounded window, never a
  standing permission; and
* pins the **run nonce** — the grant rides exactly one run instance, so a stale/replayed auth
  cannot ride a new run.

:meth:`RunAuthorization.verify` BLOCKS (raises the typed :class:`AuthorizationError`) when the
auth is EXPIRED (``now >= deadline``) or SCOPE-MISMATCHED (operation hash or run nonce differs).
:meth:`RunAuthorization.verify_optional` additionally blocks a MISSING (``None``) auth — the
absence of a minted grant refuses the run. This gate runs BEFORE any dispatch.

The authorization is frozen (immutable once minted): its bound scope cannot be widened after the
fact. It is persisted as a file/DB record by the coordinator — never a transient in-memory flag.

Framework-neutral core: stdlib only; no web framework, no network, no secret manager.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from agentforge.policy.gateway import RunPolicy


class AuthorizationError(Exception):
    """Raised when a live-campaign run is NOT authorized — missing, expired, or out of scope.

    A dedicated, catchable type so a fail-closed authorization refusal (the gate doing its job)
    is distinguishable from an incidental bug. The message always names the reason so the
    refusal is legible in a log or a traceback.
    """


def operation_hash(
    *,
    target_id: str,
    host: str,
    adapter_kind: str,
    credential_ref: str,
    caps: RunPolicy,
    run_nonce: str,
) -> str:
    """Return the canonical 64-hex operation hash of the immutable run config.

    A pure function of the bound run config — the same config always hashes to the same digest,
    so an auth minted for it can be re-verified independently. Serialized with sorted keys and
    explicit separators (order-independent, byte-reproducible), then sha256-hexed. Changing ANY
    bound field (host, adapter, credential reference, any cap, the nonce) changes the hash, so a
    grant can never silently authorize a different target/host/credential/budget.
    """
    payload = {
        "target_id": target_id,
        "host": host,
        "adapter_kind": adapter_kind,
        "credential_ref": credential_ref,
        "caps": {
            "budget_usd": caps.budget_usd,
            "max_attempts_per_run": caps.max_attempts_per_run,
            "target_requests_per_second": caps.target_requests_per_second,
            "run_timeout_seconds": caps.run_timeout_seconds,
        },
        "run_nonce": run_nonce,
    }
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class RunAuthorization:
    """A minted, immutable authorization for exactly one live-campaign run.

    Frozen so its bound scope (``operation_hash`` / ``run_nonce`` / ``deadline``) cannot be
    widened after the fact — immutability is a structural property, not a convention.
    """

    operation_hash: str
    run_nonce: str
    deadline: float

    def verify(self, *, operation_hash: str, run_nonce: str, now: float) -> None:
        """BLOCK unless this grant is unexpired AND in-scope for the current run.

        Fail-closed, in order:

        1. **Expiry** — ``now >= deadline`` is EXPIRED (the window is closed the instant the
           deadline is reached; there is no off-by-one that extends the grant).
        2. **Scope: operation hash** — the bound operation hash must equal the current run's
           operation hash; an auth minted for a different run config can never authorize this one.
        3. **Scope: run nonce** — the bound nonce must equal the current run's nonce; a
           stale/replayed grant cannot ride a new run instance.

        Raises :class:`AuthorizationError` on any of these; returns ``None`` when the grant is
        present, live, and in scope (the only non-blocking path).
        """
        if now >= self.deadline:
            raise AuthorizationError(
                f"authorization has EXPIRED: now={now} has reached deadline={self.deadline} — "
                "an authorization is a bounded grant, never a standing permission (fail closed)"
            )
        if self.operation_hash != operation_hash:
            raise AuthorizationError(
                "authorization SCOPE mismatch: the bound operation_hash does not match this "
                "run's operation_hash — a grant minted for one run config can never authorize a "
                "different config (fail closed)"
            )
        if self.run_nonce != run_nonce:
            raise AuthorizationError(
                "authorization SCOPE mismatch: the bound run_nonce does not match this run's "
                "nonce — the grant is tied to exactly one run instance, a stale/replayed auth "
                "cannot ride a new run (fail closed)"
            )

    @classmethod
    def verify_optional(
        cls,
        authorization: RunAuthorization | None,
        *,
        operation_hash: str,
        run_nonce: str,
        now: float,
    ) -> None:
        """BLOCK a MISSING authorization, else delegate to :meth:`verify`.

        A ``None`` authorization is a fail-closed refusal: a configured environment is NOT
        authorization; the absence of a minted grant refuses the run BEFORE any dispatch.
        """
        if authorization is None:
            raise AuthorizationError(
                "no authorization was minted for this run — a configured environment is NOT "
                "authorization; a run-scoped authorization is required (fail closed)"
            )
        authorization.verify(operation_hash=operation_hash, run_nonce=run_nonce, now=now)
