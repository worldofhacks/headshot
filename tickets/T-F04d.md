---
id: T-F04d
title: Implement hosted advisory adapters and composed smoke CLI
status: backlog
wave: 6
depends_on: [T-F03a, T-F04a, T-F04f, T-F04g, T-F04h]
branch: ticket/T-F04d-four-role-smoke-command
file_scopes:
  - src/agentforge/agents/composition.py
  - src/agentforge/agents/orchestrator/advisory.py
  - src/agentforge/agents/orchestrator/__init__.py
  - src/agentforge/agents/documentation/advisory.py
  - src/agentforge/agents/documentation/__init__.py
  - scripts/run_openrouter_four_role_smoke.py
test_scopes: [tests/test_openrouter_four_role_composition.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf four-agent execution, Orchestrator, Documentation, Judge independence, and cost
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-15, PRD-16, PRD-20, PRD-21, PRD-22, PRD-25, PRD-26, PRD-33, OPT-08
  - .tdd-swarm/reports/openrouter-scope-review.md I1
  - .tdd-swarm/reports/openrouter-scope-review-final.md I1
---

## Context
[locked-decision] Wave 6 owns only hosted Orchestrator/Documentation advisory adapters, the one composed target-free runtime, and the public `execute` CLI. It consumes the exact T-F04c staged set through T-F04g read-only preflight, T-F04f reserved clients, T-F03a/T-F04a role semantics, and T-F04h fixture/contracts/verifier. It constructs no target adapter.

## Acceptance Criteria
- **AC-1**: Given a set staged through the public T-F04c command, when the exact CLI invokes T-F04g preflight, then the identical configuration-set SHA-256 reaches composition; no environment reinterpretation, record write, activation shortcut, or secret resolution occurs before preflight success.
- **AC-2**: Given a hosted Orchestrator proposal, when reconciled, then only deterministic-authorized categories/actions are selectable and scope/caps/abort cannot expand; given Documentation, only confirmed sanitized content-addressed input can produce draft-only output.
- **AC-3**: Given `python scripts/run_openrouter_four_role_smoke.py execute --authorization <AUTHORIZATION> --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture <FIXTURE> --result-output <RESULT_MANIFEST> --evidence-output <EVIDENCE_MANIFEST>`, when injected transports run, then exactly four logical dispatches occur Orchestrator→Red Team→Judge→Documentation through one shared T-F04f reservation/abort ledger, outputs validate against T-F04h contracts, and target-adapter construction/calls remain zero.
- **AC-4**: Before execution, both outputs must resolve beneath fixed result/evidence roots to absent regular-file leaf paths for the same new run ID. Parent traversal, path escape, symlink/reparse point at any component, pre-existing leaf, non-regular leaf, reused run ID, or equal result/evidence path exits non-zero before provider dispatch and never follows or overwrites anything.
- **AC-5**: The CLI canonicalizes manifest bytes once, stages each copy in its destination directory with create-exclusive/no-follow descriptors, writes and fsyncs bytes, fsyncs directories, and publishes with no-replace semantics under one recoverable transaction/commit marker. Only after both identical files and their one canonical SHA-256 are durably committed may the command report success or reviews begin. Any injected write/fsync/publish failure rolls back only transaction-owned paths; a simulated process crash leaves no partial manifest bytes, and recovery refuses or removes a matching uncommitted half-set before reuse. Existing files/symlinks are never removed.
- **AC-6**: Given a reservation/provider/schema/identity/cap/abort failure at role N, when execution stops, then no later role dispatches; the same create-only atomic protocol publishes a typed terminal/omitted manifest with reservation/reconciliation evidence and no fallback identity.
- **AC-7**: Given an integration reachability test, when it invokes public stage CLI → public check-only preflight → public composed execute CLI → T-F04h offline verifier, then the same configuration-set hash persists end to end, exactly four dispatches occur, both immutable manifest bytes/hashes match, and no external network/target adapter is touched.

## Test Plan
- Unit (deterministic): Orchestrator/Documentation adapter gates, terminal composition states, fixed-root path validation, no-follow/exclusive publication, transaction recovery.
- Integration (deterministic): public stage→preflight→execute→offline-verify chain with injected store/resolver/transports/filesystem faults; exactly four dispatches, shared reservation/abort, identical durable dual outputs, pre-existing-file/symlink/path-escape/reused-run/crash/no-partial negative cases, target constructor patched to fail.
- Eval: sampled provider execution belongs to T-F04e.
- E2E: target-free CLI with no socket.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F04d.md <DIFF_BASE>` exits 0.
- [ ] Public reachability chain proves staged configuration is consumable outside store internals.
- [ ] Result/evidence manifests are identical create-only durable commits; unsafe paths, overwrite, and partial publication are impossible by frozen tests.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No schema/fixture/registry authoring, configuration persistence/preflight implementation, transport implementation, paid evidence run, live target, publication, or remediation.
