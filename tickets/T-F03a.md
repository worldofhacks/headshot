---
id: T-F03a
title: Implement independent fail-closed Judge calibration
status: backlog
wave: 4
depends_on: [T-F00, T-F04c, T-F04f, T-F04g]
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
Wave 4 deterministic code consumes T-F04g-approved persisted Judge/Red-Team configurations and the T-F04f injected Judge-only client plus packaged Verdict/Evidence contracts. T-F04c/T-F04g/T-F04f own staging, read-only authority, credential resolution, routing identity, transport, and accounting; this ticket is sole owner of strict model-output-to-`Verdict` adaptation, Judge independence, calibration, and deterministic oracle/canary precedence. No paid call is permitted.

## Acceptance Criteria
- **AC-1**: Given labeled category samples, when calibration runs, then it emits agreement, false-positive, false-negative, abstention, disagreement, and calibration error by category and globally against the versioned calibration-policy artifact; any threshold breach exits 1.
- **AC-2**: Given provider/requested-returned model/upstream endpoint/prompt/rubric/criteria/ground-truth/policy/configuration hash drift, when runtime enablement is checked, then it remains false until distinct-human approval plus passing recalibration.
- **AC-3**: Given a schema-valid EvidenceEnvelope and the injected T-F04f Judge-only client, when hosted judging runs, then only the persisted Judge configuration/credential reference is used, strict JSON output is parsed into the repository `Verdict` contract, and exact requested/returned/upstream/trace/token/cost/configuration/prompt/rubric/criteria metadata is handed off.
- **AC-4**: Given persisted Judge and Red Team configurations plus an actual Judge response, when independence is checked before and after dispatch, then any shared/colliding credential reference, requested model, returned model, prompt/rubric-or-criteria hash, model family, expected upstream provider/endpoint, or actual upstream provider/endpoint rejects the Judge result as typed `ERROR|INDETERMINATE`; comparison never resolves either role's secret.
- **AC-5**: Given timeout/refusal/malformed/schema error/missing accounting/identity drift or collision, when the adapter handles it, then it produces `INDETERMINATE|ERROR`, never safe/likely, and never substitutes another model, endpoint, provider, credential, or deterministic success identity.
- **AC-6**: Given deterministic oracle/canary confirmation plus contradictory schema-valid model text, when final precedence runs after parsing, then `EXPLOIT_CONFIRMED` wins; without confirmation and valid enabled calibration, hosted output cannot become `NO_EXPLOIT_OBSERVED|EXPLOIT_LIKELY`.
- **AC-7**: Given the measured 60%/33.3%/60% baseline, when the calibration gate runs, then it exits 1; no test or implementation changes thresholds to force pass.

## Test Plan
- Unit (deterministic): strict Verdict parsing, hostile/extra/missing fields, Judge-only client use, every Judge/Red-Team collision dimension, metadata handoff, calibration/drift, failure mapping, oracle precedence.
- Integration (deterministic): injected T-F04f transport with persisted T-F04c records; socket/provider SDK/secret resolver cross-role access patched to fail.
- Eval: graded calibration belongs to T-F03b; no mock is called quality evidence.
- E2E: none; no paid provider call.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F03a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No paid calls, credentials, or calibration evidence execution.
