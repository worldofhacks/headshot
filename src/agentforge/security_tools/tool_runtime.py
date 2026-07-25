"""Per-tool execution evidence + runtime state (Task 4).

A scan exercises many integrated tools; each one that dispatches emits ONE execution-evidence
record so the tool-run counters stop reading zero and the Tools page can show a live per-tool
runtime state:

* ``idle``      — the tool has no recorded run for this surface;
* ``running``   — a dispatch is in flight (reserved, not yet recorded);
* ``evidenced`` — the tool executed and produced a durable evidence artifact;
* ``error``     — the last dispatch failed with a named error code.

"No fabricated evidence" is a structural invariant, not a convention: an ``evidenced`` record must
reference a real evidence artifact URI, a ``running`` record cannot already be finished, and an
``error`` record must name an error code. The record projects onto the additive ToolScopeReadModel
fields (``runtime_state`` / ``last_error_code`` + existing counters) so the render surface (Codex's
lane) shows exactly what was emitted. Stdlib only; framework-neutral.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ToolRuntimeState = Literal["idle", "running", "evidenced", "error"]


def derive_tool_runtime_state(
    *,
    running: bool,
    error_code: str | None,
    evidenced_count: int,
) -> ToolRuntimeState:
    """Pure per-tool runtime-state machine (error > running > evidenced > idle).

    Codex's read-model population calls this to project the four counters into a single state.
    """
    if error_code:
        return "error"
    if running:
        return "running"
    if evidenced_count > 0:
        return "evidenced"
    return "idle"


@dataclass(frozen=True, slots=True)
class ToolExecutionEvidence:
    """One per-tool execution-evidence record a scan emits, structurally unable to fabricate."""

    tool_id: str
    run_id: str
    runtime_state: ToolRuntimeState
    executed_attempt_count: int
    evidenced_finding_count: int
    error_code: str | None
    started_at: str | None
    last_executed_at: str | None
    evidence_uri: str | None

    @classmethod
    def running(cls, *, tool_id: str, run_id: str, started_at: str) -> ToolExecutionEvidence:
        if not started_at:
            raise ValueError("a running tool record must carry a start time")
        return cls(
            tool_id=tool_id,
            run_id=run_id,
            runtime_state="running",
            executed_attempt_count=0,
            evidenced_finding_count=0,
            error_code=None,
            started_at=started_at,
            last_executed_at=None,  # a running record is not yet finished
            evidence_uri=None,
        )

    @classmethod
    def evidenced(
        cls,
        *,
        tool_id: str,
        run_id: str,
        executed_attempt_count: int,
        evidenced_finding_count: int,
        last_executed_at: str,
        evidence_uri: str,
    ) -> ToolExecutionEvidence:
        if not evidence_uri:
            raise ValueError(
                "an evidenced tool record must reference a real evidence artifact "
                "(no fabricated evidence)"
            )
        if not last_executed_at:
            raise ValueError("an evidenced tool record must carry a finished time")
        if executed_attempt_count < 0 or evidenced_finding_count < 0:
            raise ValueError("tool evidence counts must be non-negative")
        return cls(
            tool_id=tool_id,
            run_id=run_id,
            runtime_state="evidenced",
            executed_attempt_count=executed_attempt_count,
            evidenced_finding_count=evidenced_finding_count,
            error_code=None,
            started_at=None,
            last_executed_at=last_executed_at,
            evidence_uri=evidence_uri,
        )

    @classmethod
    def error(cls, *, tool_id: str, run_id: str, error_code: str) -> ToolExecutionEvidence:
        if not error_code:
            raise ValueError("an error tool record must name an error code")
        return cls(
            tool_id=tool_id,
            run_id=run_id,
            runtime_state="error",
            executed_attempt_count=0,
            evidenced_finding_count=0,
            error_code=error_code,
            started_at=None,
            last_executed_at=None,
            evidence_uri=None,
        )

    def to_tool_scope_fields(self) -> dict[str, object]:
        """Project onto the additive ToolScopeReadModel fields the render surface consumes."""
        return {
            "runtime_state": self.runtime_state,
            "executed_attempt_count": self.executed_attempt_count,
            "evidenced_finding_count": self.evidenced_finding_count,
            "last_error_code": self.error_code,
            "last_executed_at": self.last_executed_at,
        }


__all__ = ["ToolExecutionEvidence", "ToolRuntimeState", "derive_tool_runtime_state"]
