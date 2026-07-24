---
id: T-F03a
title: Implement independent fail-closed Judge calibration
status: backlog
wave: 1
depends_on: [T-F00]
branch: ticket/T-F03a-judge-code
file_scopes:
  - src/agentforge/agents/judge/calibration.py
  - src/agentforge/agents/judge/provider.py
  - src/agentforge/agents/judge/judge.py
  - src/agentforge/agents/judge/__init__.py
  - scripts/run_judge_calibration.py
  - .tdd-swarm/judge-calibration-policy.json
test_scopes: [tests/test_judge_final.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Judge role and drift governance
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-15, PRD-16, PRD-18, OPT-08
---

## Context
Wave 1 deterministic code starts after T-F00's gate-wrapper interface and consumes the packaged Judge verdict/evidence contracts while producing `.tdd-swarm/judge-calibration-policy.json` and the calibration CLI contract. `Week_3_AgentForge.pdf`, PRD-15/16/18 and OPT-08, packaged-contract hashes, and the calibration-policy hash are authoritative.

## Acceptance Criteria
- **AC-1**: Given labeled category samples, calibration emits agreement, false-negative, abstention, disagreement, and calibration error and validates against thresholds serialized in the calibration-policy artifact; threshold breach exits 1.
- **AC-2**: Given provider/model/rubric/criteria/ground-truth hash drift, runtime enablement is false until distinct-human approval plus passing recalibration.
- **AC-3**: Given timeout/refusal/malformed/schema error/provider identity collision, result is `INDETERMINATE|ERROR`, never safe/likely.
- **AC-4**: Given deterministic confirmation plus contradictory model text, `EXPLOIT_CONFIRMED` wins; uncalibrated non-oracle evidence cannot become safe/likely.
- **AC-5**: Given the measured 60%/33.3%/60% baseline, the gate exits 1; no test changes thresholds to force pass.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F03a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No paid calls, credentials, or calibration evidence execution.
