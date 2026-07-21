"""Env-scoped target allowlist + audited off-allowlist denial (ARCHITECTURE.md §5, D16).

The allowlist is the FIRST gate the Policy Gateway consults: a target absent from it can
never be dispatched to, no matter how permissive the run policy is. Locally the ONLY
allowlisted target is the deterministic P9 fake — NO live URL is resolvable from a
non-production box (this is the structural half of the synthetic-data / O1 guarantee).

A denial is never a silent ``None``: it is a first-class, AUDITED decision. ``resolve`` of an
unknown target raises :class:`OffAllowlistDenied` AND appends a denial record to an in-memory
audit trail (``audit_records()``), so every refusal is attributable after the fact.

Framework-neutral core (D10): stdlib only; imports no web/orchestration framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class OffAllowlistDenied(Exception):
    """Raised when a target is not on the env-scoped allowlist.

    A dedicated, catchable type so a policy refusal (the allowlist doing its job) is
    distinguishable from an incidental bug. The message always names the denied target so the
    denial is legible in a log or a traceback.
    """

    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        super().__init__(
            f"target {target_id!r} is not on the allowlist and may not be dispatched to "
            "(off-allowlist denial, D16)"
        )


@dataclass(frozen=True)
class AllowlistEntry:
    """One admitted (target_id -> adapter_name) binding on the allowlist."""

    target_id: str
    adapter_name: str


@dataclass
class Allowlist:
    """An env-scoped allowlist that admits ONLY its explicit entries.

    ``resolve`` returns the matching :class:`AllowlistEntry` or raises
    :class:`OffAllowlistDenied` — and, crucially, records the denial to an append-only audit
    trail either way (an ``allowed`` record on success, a ``denied`` record on refusal), so a
    denial is a durable, attributable decision rather than a silent drop.
    """

    entries: list[AllowlistEntry] = field(default_factory=list)
    audit_log: list[dict] = field(default_factory=list)

    def _index(self) -> dict[str, AllowlistEntry]:
        return {entry.target_id: entry for entry in self.entries}

    def resolve(self, target_id: str) -> AllowlistEntry:
        """Return the entry for ``target_id`` or raise :class:`OffAllowlistDenied`.

        Both outcomes are audited: a matched target appends an ``allowed`` record; an unknown
        target appends a ``denied`` record (naming the target and the reason) and then raises.
        """
        entry = self._index().get(target_id)
        if entry is None:
            self.audit_log.append(
                {
                    "decision": "denied",
                    "target_id": target_id,
                    "reason": "off-allowlist",
                }
            )
            raise OffAllowlistDenied(target_id)
        self.audit_log.append(
            {
                "decision": "allowed",
                "target_id": target_id,
                "adapter_name": entry.adapter_name,
            }
        )
        return entry

    def audit_records(self) -> list[dict]:
        """The append-only audit trail of every allowlist decision made so far."""
        return self.audit_log
