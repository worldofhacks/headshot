---
id: T-F17d
title: Compose HostedFourRoleRuntime in the private production Runner
status: backlog
wave: 28
depends_on: [T-F17c]
branch: ticket/T-F17d-runner-hosted-composition
file_scopes:
  - src/agentforge/runner.py
  - src/agentforge/agents/hosted_composition.py
  - docs/integration/migrations/hosted-target-evaluator-v1.md
test_scopes:
  - tests/test_runner_hosted_runtime.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf multi-agent adversarial system and live target hard gate
  - AGENTS.md Policy Gateway, Railway, Clerk, and human-approval invariants
  - docs/deployment/FOUR_MODEL_RECOVERY.md Runtime and evidence acceptance
  - docs/planning/agent-runtime-provenance.md Hosted Runner path
---

## Context
Wave 28 consumes the prompt-bound hosted runtime and physical provider-event contract from T-F17c.
The persisted `HostedRunBinding`, exact staged configuration, current queue lease, Policy Gateway,
and existing deterministic evidence/oracle path are authoritative. Only the private Runner may
resolve provider/target credentials.

## Acceptance Criteria
- **AC-1**: Given an authorized campaign with `scope.hosted_run`, when a claimed job passes
  preflight, then the Runner loads the exact organization-scoped staged configuration, verifies all
  prompt/model/policy/cap/session hashes, resolves four distinct Runner-only credential references,
  and constructs one shared-ledger `HostedFourRoleRuntime`.
- **AC-2**: Given a hosted campaign with any missing/mismatched binding, prompt, credential,
  configuration, queue lease, target/session generation, cap, or two-person authorization, when
  preflight runs, then it records a bounded blocker and performs zero provider and target calls.
- **AC-3**: Given one authorized case, when the hosted runtime executes, then role order is
  Orchestrator -> Red Team -> one trusted target evaluator -> Judge -> conditional Documentation,
  with parent-linked logical executions and no role sharing attack-generation/Judge context.
- **AC-4**: Given the hosted Red Team output, when target evaluation occurs, then exactly one typed
  trusted evaluator delegates through the existing Policy Gateway, persists/re-reads evidence, runs
  deterministic oracles, and returns evidence plus deterministic verdict from the same dispatch;
  there is no second target exit or divergent callback.
- **AC-5**: Given deterministic exploit/error evidence and a contradictory hosted Judge response,
  when verdict precedence is applied, then deterministic evidence wins and a confirmed exploit can
  never become safe.
- **AC-6**: Given no finding, when the attempt completes, then Documentation is explicitly skipped
  without a provider call; given a confirmed/likely finding, Documentation emits only an unpublished
  draft behind the existing human approval gate.
- **AC-7**: Given a campaign without `scope.hosted_run`, when executed, then the existing
  deterministic path remains byte/behavior compatible; a hosted-path failure never falls back to it.
- **AC-8**: Given provider/target/persistence failure after work begins, when the Runner terminates
  the campaign, then typed agent/provider events and preserved target evidence reconcile to a
  terminal state without retrying outside authorization.

## Test Plan
- Unit: hosted/deterministic branch selection and zero-I/O preflight blockers.
- Integration: real Runner/queue/store/Policy Gateway against fake provider and fake target; exact
  role order, one target exit, parent lineage, oracle precedence, draft gate, failure reconciliation.
- Eval: separately authorized live model quality/evidence after deployment.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged RED and Test Reviewer froze it.
- [ ] No new target/model client bypasses Policy Gateway or the hosted transport.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F17d.md <DIFF_BASE>` exits 0 with live Postgres.
- [ ] Deterministic Runner, authorization, abort, budget/rate, and Judge invariant suites stay green.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No Web credential access, production deployment, live provider/target call, authorization creation,
critical publication, remediation, or per-role browser activation.
