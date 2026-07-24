---
id: T-F07b
title: Execute separately authorized 100-case staging stress
status: backlog
wave: 10
depends_on: [T-F05b, T-F07a]
branch: ticket/T-F07b-live-stress
file_scopes: [docs/performance/live/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf load/stress tests
  - docs/requirements/REQUIREMENTS_MATRIX.csv OPT-18
---

## Context
Wave 10 authorized operational evidence consumes T-F05b's reviewed current-SHA campaign manifest and T-F07a's metric definitions/baseline hash, producing `docs/performance/live/<run>/`. `Week_3_AgentForge.pdf`, OPT-18, and the bound release, target, case, rate, cost, and result hashes are authoritative. The owner-supplied `docs/evidence/authorizations/live-stress.json` is read-only; if absent or invalid, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: `docs/evidence/authorizations/live-stress.json` must bind exactly 100 cases, staging target, rate/concurrency/timeout/USD caps, monitor, abort owner, lease, launcher/distinct approver; invalid exits 4/zero calls.
- **AC-2**: Run/abort writes raw orchestration/provider latency, CPU/RSS, storage throughput, errors/retries/cost/target counts and artifact hashes under `docs/performance/live/<run>/`.
- **AC-3**: Cap/lease/health/abort breach stops new dispatch and preserves partial manifest.
- **AC-4**: Performance/Security reviewers verify exactly authorized request count, bottleneck and evidence-based architecture response.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No production load, reused authorization, or guessed target limit.
