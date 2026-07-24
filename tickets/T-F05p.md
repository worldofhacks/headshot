---
id: T-F05p
title: Freeze the authorized Clinical Co-Pilot target catalog
status: backlog
wave: 7
depends_on: [T-F04h]
branch: ticket/T-F05p-clinical-copilot-target-catalog
file_scopes:
  - config/targets/clinical-copilot-20260724.json
  - src/agentforge/config.py
  - railway/web.json
  - railway/runner.json
  - .env.example
test_scopes: [tests/test_clinical_copilot_target_catalog.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf deployed target URL, exact allowlist, scoped credentials, synthetic-only data
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07
  - .tdd-swarm/reports/session-binding-readiness.md SB-001, SB-003
---

## Context
[locked-decision] This half-day ticket is the sole owner of the tracked non-secret staging target
catalog and its identical Web/Runner loading contract. It freezes two authorized target identities,
surface enablement, and opaque credential bindings. It never contains, discovers, resolves, copies,
or reports a credential/session value or locally extracted browser/bundle artifact.

## Acceptance Criteria
- **AC-1**: `config/targets/clinical-copilot-20260724.json` is tracked, strict JSON accepted by `TrustedTargetCatalog`, contains exactly one unambiguous entry each for `clinical-copilot-week1` and `clinical-copilot-week2`, and contains no other target. Each entry is staging, synthetic-only, exact-host allowlisted, session-authenticated, versioned, and carries only a canonical opaque `secretref://` credential binding; no environment-variable name/value, cookie/header/session value, local path, or extracted artifact content appears.
- **AC-2**: Staging Web and Runner load the identical tracked file from the release image and independently recompute the same required SHA-256. `railway/web.json`, `railway/runner.json`, and configuration reject inline catalog JSON, alternate path, environment-specific duplicate, caller-supplied entry, or hash mismatch. Web may read/authorize the non-secret catalog but cannot receive or resolve target credential variables.
- **AC-3**: Only the two versioned chat surfaces are enabled. Every UI, evidence/search, and upload/write surface is present as applicable and explicitly `enabled:false` or denied by transport policy until its own adapter test, code review, and security-review hashes are landed and a later authorized catalog ticket changes it. An absent enablement flag, unknown surface, or generic catch-all route fails closed.
- **AC-4**: Runner alone may receive sealed secret environment variables through a reviewed fixed resolver mapping from opaque catalog bindings; variable names and values are absent from the catalog, Web configuration, job payload, prompt, test fixture, report, log, and artifact. A binding must resolve to exactly its selected target/session generation, and missing/ambiguous/cross-target/cross-generation resolution fails before adapter/client/network.
- **AC-5**: Live campaign authorization and jobs select exactly one of the two target IDs, exactly one enabled session-auth chat surface, exactly one credential reference/generation, and exactly one T-F05d patient/context identity. The T-F05e context and T-F05f Runner pin that target/session/patient tuple for the campaign; target, surface, session, or patient switching/reuse is terminal.
- **AC-6**: Deterministic tests parse the tracked file through production catalog code, verify exact IDs/surface states/opaque bindings/Web–Runner hash parity/Runner-only resolution boundary and one-target-one-session selection, and scan planning/output fixtures for secret or extracted-artifact material. Socket/DNS/HTTP/resolver/provider/target/Railway hooks are patched to fail.

## Test Plan
- Unit (deterministic): exact catalog membership, strict target/surface/binding shape, enabled/disabled policy, secret-free content, and one-target-one-session selection.
- Integration (deterministic): Web/Runner load identical file/hash; Web cannot resolve; Runner-only fake resolver binds the exact selected generation; all egress hooks fail if reached.
- Eval/E2E: none; no live target, Railway action, session material, or network.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05p.md <DIFF_BASE>` exits 0.
- [ ] Exact target/surface/credential/patient selection and Web–Runner catalog parity are frozen.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No adapter enablement beyond chat, credential/session discovery or provisioning, live target call,
source-state acquisition, campaign execution, Railway mutation, deployment, network, or spend.
