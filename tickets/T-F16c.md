---
id: T-F16c
title: Replace partial evidence and UI surface profiles
status: backlog
wave: 19
depends_on: [T-F16a, T-F16b]
branch: ticket/T-F16c-evidence-ui-adapters
file_scopes:
  - src/agentforge/target/openemr_adapter.py
  - src/agentforge/target/clinical_copilot_probe_adapters.py
test_scopes:
  - tests/test_openemr_adapter_surfaces.py
  - tests/test_clinical_copilot_probe_adapters.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live target and full attack-surface mapping
  - sanitized owner contracts in docs/planning/final-target-adapters.md
  - integration baseline 1ac3ee0 / partial commit 54b3a4d
---

## Context
[locked-decision] `54b3a4d` added path-derived evidence/document profiles inside `OpenEmrAdapter`; they are the partial implementation to harden or remove, not a second adapter to leave beside new code. This ticket extracts reviewed single-operation evidence/UI flows, removes superseded path heuristics/profile fallbacks, and preserves only the existing reviewed chat/legacy transport behavior in `OpenEmrAdapter`.

## Acceptance Criteria
- **AC-1**: Evidence produces exactly one anonymous `POST /evidence/search` with bounded `query`, integer `k` in `1..10`, JSON headers, and zero credential lookup/header/cookie/body/query placement.
- **AC-2**: Evidence accepts only HTTP 200 typed JSON with exact top-level/item fields, <=10 items, content-addressed source/corpus IDs, scores `[0,1]`, and matching body/header correlation; malformed/oversized/wrong media responses fail typed.
- **AC-3**: UI produces exactly one `GET /app` or `GET /week2`, revealing the session only as query key `sid` at final transport serialization. Literal-canary tests prove `session_id` and every header/cookie/body/alternate query placement are absent.
- **AC-4**: UI records only redacted route, status, `text/html`, bounded byte count, optional correlation, and body hash. Raw session/credential URL is absent from client recording after send, telemetry, metadata, exception, repr, and report.
- **AC-5**: UI has no browser/DOM/script/subresource/screenshot/navigation capability; redirect, non-HTML, oversized, off-host, or expired-session responses fail closed.
- **AC-6**: Construction uses the T-F16a profile/policy hash, never relative-path inference. The partial `copilot_evidence_search`, public-GET/document surface branches are removed or made unreachable under new policy; chat regression remains green.

## Test Plan
- Unit: exact operation bodies/keys, response schemas, canary redaction, profile/hash mismatch, removal of heuristic fallthrough.
- Integration: injected one-operation sender against the `1ac3ee0` partial adapter baseline; zero sockets/screenshots.
- Eval/E2E: none.

## Definition of Done
- [ ] Reviewed criterion-tagged RED is frozen against the landed partial code.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16c.md <DIFF_BASE>` exits 0.
- [ ] No duplicate reachable evidence/UI/document implementation remains in `OpenEmrAdapter`.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No document workflow implementation, Runner/catalog, scan fanout, live call, or deploy.
