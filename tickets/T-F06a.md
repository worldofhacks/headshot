---
id: T-F06a
title: Implement fresh regression replay executor
status: backlog
wave: 17
depends_on: [T-F05a, T-F05d, T-F05e, T-F05f, T-F05g, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05n, T-F05o, T-F05p, T-F14b]
branch: ticket/T-F06a-replay-code
file_scopes:
  - src/agentforge/regression/replay.py
  - src/agentforge/regression/executor.py
  - src/agentforge/scheduler.py
  - src/agentforge/runner.py
test_scopes: [tests/test_regression_execution.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Regression Harness
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-23, PRD-24, PRD-36, OPT-16
---

## Context
Wave 17 deterministic code consumes T-F05a lineage, T-F05d's one target-session fixture identity,
T-F05h/T-F05i authenticated fresh-state artifacts, T-F05e's context/fresh validators, T-F05j's
configuration/job binding, T-F05k loader, T-F05l source, T-F05m provider, T-F05n/T-F05o ordered
rotation evidence, T-F05f's Runner enforcement, T-F05g's rotation contract, and
T-F14b failure contracts. It produces fresh replay and duration metrics. Its Runner edits preserve
the landed context import, one-resolution, per-attempt, terminal-cleanup, and no-overlap hooks; it
cannot add a parallel parser or substitute a replay-specific fixture manifest.

## Acceptance Criteria
- **AC-1**: Given admitted case/trigger, executor creates a new campaign ID and target call plan; prior verdict reuse causes exit 3.
- **AC-2**: Right-reason comparator keys expected-safe oracle, case hash and target version; wording-only change cannot pass.
- **AC-3**: Cross-category comparator uses accepted baseline artifact hash and emits regression when state worsens `NO_EXPLOIT_OBSERVED→{EXPLOIT_LIKELY,EXPLOIT_CONFIRMED,INDETERMINATE,ERROR}` or confirmed/likely count increases; linked category evidence required.
- **AC-4**: Missing authorization/calibration/version/integrity parks with zero adapter calls.
- **AC-5**: Fixture critical-subset/full-suite durations are emitted for downstream SLO measurement.
- **AC-6**: Every replay path uses the identical T-F05d identity tuple/canonical manifest hash and immutable T-F05e context reference/hash bound by its authorization; preserves T-F05j persistence, T-F05k pinning, and fresh T-F05l→T-F05h plus T-F05i validation through T-F05m immediately post-claim and before every physical dispatch; and preserves T-F05n/T-F05o/T-F05f/T-F05g ordered no-overlap behavior. Replay cannot use another manifest, accept combined/caller state, reuse a stale observation, reload/reparse context, resolve twice, infer history from one snapshot, or rotate in place.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F06a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No fixture/context/SMART lease/rotation reimplementation, live replay, benchmark, promotion, or remediation.
