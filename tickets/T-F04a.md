---
id: T-F04a
title: Implement bounded Red Team novelty controls
status: backlog
wave: 2
depends_on: [T-F00, T-F02]
branch: ticket/T-F04a-redteam-code
file_scopes:
  - src/agentforge/agents/red_team/providers.py
  - src/agentforge/agents/red_team/provider_runtime.py
  - src/agentforge/agents/red_team/novelty.py
  - src/agentforge/agents/red_team/minimization.py
  - src/agentforge/agents/red_team/mutation.py
  - src/agentforge/agents/red_team/selection.py
  - .env.example
  - .tdd-swarm/red-team-eval-policy.json
test_scopes: [tests/test_red_team_final.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Red Team role and model constraints
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-14, PRD-16, PRD-17, LEAD-02
---

## Context
Wave 2 deterministic code consumes T-F00's local-gate interface and T-F02's package-to-root contract parity manifest, and produces the provider runtime plus `.tdd-swarm/red-team-eval-policy.json`. `Week_3_AgentForge.pdf`, PRD-14/16/17 and LEAD-02, package contract hashes, and the landed evaluation-policy hash are authoritative.

## Acceptance Criteria
- **AC-1**: Given provider config, zero-call preflight requires provider/model/scoped reference/timeout/retries/gateway budget; missing field exits 4 before transport construction.
- **AC-2**: Given candidates, canonical hash equality yields one admitted candidate with all parent/transformation hashes.
- **AC-3**: Given versioned `RedTeamEvalPolicy`, candidate/depth/wall-clock/token/USD counters stop exactly at policy limits and emit `search_budget_exhausted`.
- **AC-4**: Given deterministic reproduction oracle and policy order, delta minimization returns a 1-minimal sequence (removing any remaining unit fails reproduction) with expected-safe hash unchanged.
- **AC-5**: Provider refusal/timeout/malformed output yields typed failure; no silent seed fallback or secret leakage.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F04a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No paid/provider execution, target traffic, or semantic-quality claim.
