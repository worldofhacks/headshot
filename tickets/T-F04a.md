---
id: T-F04a
title: Implement bounded Red Team novelty controls
status: backlog
wave: 4
depends_on: [T-F00, T-F02, T-F04c, T-F04f, T-F04g]
branch: ticket/T-F04a-redteam-code
file_scopes:
  - src/agentforge/agents/red_team/providers.py
  - src/agentforge/agents/red_team/provider_runtime.py
  - src/agentforge/agents/red_team/novelty.py
  - src/agentforge/agents/red_team/minimization.py
  - src/agentforge/agents/red_team/mutation.py
  - src/agentforge/agents/red_team/selection.py
  - .tdd-swarm/red-team-eval-policy.json
test_scopes: [tests/test_red_team_final.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Red Team role and model constraints
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-14, PRD-16, PRD-17, LEAD-02
---

## Context
Wave 4 deterministic code consumes T-F04g-approved persisted Red Team configuration, T-F04f's injected role client, T-F00's local-gate interface, and T-F02's package parity manifest, then produces Red Team search/runtime plus `.tdd-swarm/red-team-eval-policy.json`. T-F04c/T-F04g/T-F04f own staging/authority/credentials/transport/accounting; this ticket remains sole owner of mutation, novelty, minimization, and provider-evaluation semantics.

## Acceptance Criteria
- **AC-1**: Given the T-F04g-approved persisted T-F04c Red Team record plus T-F04f role client, zero-call preflight requires the exact authorized configuration-set/model/upstream/schema/prompt/policy identity and search policy; missing/mismatched field exits 4 before credential resolution or transport construction.
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
