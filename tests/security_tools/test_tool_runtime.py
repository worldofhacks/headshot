"""RED tests for per-tool execution evidence + runtime state (Task 4).

Today a scan dispatches nothing per-tool, so the Tools page shows no execution evidence and the
counters stay zero. This module lets a scan EMIT one execution-evidence record per tool it exercises
and derives a per-tool runtime state (idle / running / evidenced / error). "No fabricated evidence"
is enforced structurally: an ``evidenced`` record must reference a real evidence artifact, a
``running`` record cannot already be finished, and an ``error`` record must name an error code.

The record projects exactly onto the additive ToolScopeReadModel fields so the render surface can
show live per-tool state. Offline; stdlib only.
"""

from __future__ import annotations

import pytest

from agentforge.security_tools.tool_runtime import (
    ToolExecutionEvidence,
    derive_tool_runtime_state,
)


def test_derive_state_is_idle_when_nothing_ran() -> None:
    assert derive_tool_runtime_state(running=False, error_code=None, evidenced_count=0) == "idle"


def test_derive_state_is_running_while_a_dispatch_is_in_flight() -> None:
    assert derive_tool_runtime_state(running=True, error_code=None, evidenced_count=0) == "running"


def test_derive_state_is_evidenced_after_a_recorded_run() -> None:
    assert (
        derive_tool_runtime_state(running=False, error_code=None, evidenced_count=3) == "evidenced"
    )


def test_derive_state_error_takes_precedence() -> None:
    assert (
        derive_tool_runtime_state(running=True, error_code="dispatch-failed", evidenced_count=5)
        == "error"
    )


def test_evidence_record_projects_onto_the_read_model_fields() -> None:
    ev = ToolExecutionEvidence.evidenced(
        tool_id="zap",
        run_id="run-1",
        executed_attempt_count=4,
        evidenced_finding_count=2,
        last_executed_at="2026-07-24T12:00:00Z",
        evidence_uri="postgres://tool_findings?tool=zap&run=run-1",
    )
    fields = ev.to_tool_scope_fields()
    assert fields["runtime_state"] == "evidenced"
    assert fields["executed_attempt_count"] == 4
    assert fields["evidenced_finding_count"] == 2
    assert fields["last_error_code"] is None
    assert fields["last_executed_at"] == "2026-07-24T12:00:00Z"


def test_evidenced_record_requires_a_real_evidence_artifact() -> None:
    with pytest.raises(ValueError, match="evidence"):
        ToolExecutionEvidence.evidenced(
            tool_id="zap",
            run_id="run-1",
            executed_attempt_count=1,
            evidenced_finding_count=0,
            last_executed_at="2026-07-24T12:00:00Z",
            evidence_uri="",  # no artifact -> cannot claim evidenced
        )


def test_running_record_cannot_be_already_finished() -> None:
    running = ToolExecutionEvidence.running(tool_id="garak", run_id="run-2", started_at="t0")
    assert running.runtime_state == "running"
    assert running.to_tool_scope_fields()["last_executed_at"] is None


def test_error_record_must_name_an_error_code() -> None:
    with pytest.raises(ValueError, match="error"):
        ToolExecutionEvidence.error(tool_id="pyrit", run_id="run-3", error_code="")
    err = ToolExecutionEvidence.error(tool_id="pyrit", run_id="run-3", error_code="dispatch-failed")
    assert err.to_tool_scope_fields()["runtime_state"] == "error"
    assert err.to_tool_scope_fields()["last_error_code"] == "dispatch-failed"
