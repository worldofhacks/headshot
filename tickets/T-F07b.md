---
id: T-F07b
title: Execute separately authorized 100-case staging stress
status: backlog
wave: 19
depends_on: [T-F05b, T-F05d, T-F05e, T-F05f, T-F05g, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05n, T-F05o, T-F05p, T-F07a]
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
Wave 19 authorized operational evidence consumes T-F05b, the complete T-F05d through T-F05p chain,
and T-F07a metrics. The distinct stress authorization must bind the identical T-F05d target-session
fixture identity and T-F05e context hash used by the campaign; it cannot reuse `campaign.json`.

## Acceptance Criteria
- **AC-1**: `docs/evidence/authorizations/live-stress.json` must bind exactly 100 cases, staging target/version/surface, the complete identical T-F05d identity/manifest hash, rate/concurrency/timeout/USD caps, monitor, abort owner, launcher/distinct Approver, immutable T-F05e context hash/reference/times/value digest/policy/release/source-trust binding, and required fresh T-F05h/T-F05i state; invalid exits 4/zero calls before resolution or adapter construction.
- **AC-2**: Run/abort writes raw orchestration/provider latency, CPU/RSS, storage throughput, errors/retries/cost/target counts and artifact hashes under `docs/performance/live/<run>/`.
- **AC-3**: Before each physical attempt, cap/health/abort plus the pinned T-F05e context and newly acquired/projected authenticated T-F05l→T-F05h and T-F05i observations are revalidated through T-F05m/T-F05f; breach stops dispatch, never reloads context, re-resolves, infers rotation history from one snapshot, or rotates in place, and preserves the partial manifest.
- **AC-4**: Performance/Security reviewers verify exactly authorized request count, bottleneck and evidence-based architecture response.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No production load, reused authorization, or guessed target limit.
