---
id: T-F01a
title: Export sanitized authoritative eval evidence
status: backlog
wave: 1
depends_on: [T-F00]
branch: ticket/T-F01a-eval-export
file_scopes: [src/agentforge/evals/export.py, src/agentforge/evals/__main__.py, scripts/export_live_eval.py]
test_scopes: [tests/evals/test_live_export.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Stage 3 and Eval Dataset
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-07, PRD-09, PRD-37
---

## Context
Wave 1 deterministic code begins only after T-F00's `.tdd-swarm/run-local-gates.sh` contract lands; it consumes immutable recorder/Judge/cost rows and emits `evals/results/live/<campaign-id>/manifest.json`. `Week_3_AgentForge.pdf` Stage 3, PRD-07/09/37, the release SHA, and SHA-256 values computed from source artifacts are authoritative.

## Acceptance Criteria
- **AC-1**: Given immutable campaign rows and release SHA, when export runs, then `evals/results/live/<campaign-id>/manifest.json` contains case/result/evidence/verdict/agent/cost artifact paths and SHA-256 values; exit 0.
- **AC-2**: Given secrets, headers, sessions, canaries, or PHI-like fields, when sanitation runs, then raw values are absent and a redaction ledger hash is present; unclassifiable sensitive data exits 2 without final manifest.
- **AC-3**: Given all `INDETERMINATE`, missing/orphan/hash-invalid data, when aggregating, then no pass/finding is inferred; integrity gaps exit 3 and write `gap-report.json`.
- **AC-4**: Given run `aceddc495808427992efbd2b73b3598d`, fixture verification expects exactly 9 HTTP 200, 9 evidence, 9 `INDETERMINATE`, $0.09 outbound and no confirmed finding.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F01a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No documentation reconciliation, live execution, or finding publication.
