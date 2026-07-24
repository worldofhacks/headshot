---
id: T-F14a
title: Complete security-tool runtime correlation
status: backlog
wave: 3
depends_on: [T-F00]
branch: ticket/T-F14a-security-tools
file_scopes:
  - src/agentforge/security_tools/repository.py
  - src/agentforge/security_tools/normalization.py
  - src/agentforge/security_tools/workbench.py
  - src/agentforge/agents/orchestrator/security_signals.py
test_scopes: [tests/security_tools/test_runtime_correlation.py]
model_hint: capable
attempts: 0
traces_to:
  - docs/requirements/REQUIREMENTS_MATRIX.csv LEAD-03
  - Week_3_AgentForge.pdf traditional tooling and Orchestrator signals
---

## Context
Wave 3 deterministic code consumes T-F00's local-gate/report interface and existing versioned scanner artifacts, then exposes normalized immutable security signals to the Orchestrator. `Week_3_AgentForge.pdf`, LEAD-03, and the scanner tool/version/run/artifact plus normalized-signal hashes are authoritative.

## Acceptance Criteria
- **AC-1**: Given versioned scanner artifacts, normalization retains tool/version/run/artifact hashes and deduplicated finding lineage.
- **AC-2**: Given verified findings, Orchestrator security snapshot consumes only hash-valid normalized signals; malformed/version-mismatch yields typed failure/degraded state.
- **AC-3**: Given historical runs, repository query returns immutable evidence refs and never overwrites prior scan.
- **AC-4**: Given untrusted scanner text, it cannot set authorization, severity override, target scope, or execution command.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F14a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No live scanner target, new scanner install, or remediation.
