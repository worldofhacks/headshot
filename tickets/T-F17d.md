---
id: T-F17d
title: Compose HostedFourRoleRuntime in the private production Runner
status: backlog
wave: 28
depends_on: [T-F17c, T-F16f]
branch: ticket/T-F17d-runner-hosted-composition
file_scopes:
  - src/agentforge/runner.py
  - src/agentforge/agents/hosted_composition.py
  - src/agentforge/campaign/coordinator.py
  - src/agentforge/campaign/hosted_mutation.py
  - src/agentforge/policy/gateway.py
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/orchestration_snapshot.json
  - contracts/v1/orchestration_snapshot.json
  - src/agentforge/contracts/v1/hosted_orchestration_decision.json
  - contracts/v1/hosted_orchestration_decision.json
  - src/agentforge/contracts/v1/hosted_mutation_envelope.json
  - contracts/v1/hosted_mutation_envelope.json
  - docs/integration/migrations/hosted-orchestration-contracts-v1.md
  - docs/integration/migrations/hosted-target-evaluator-v1.md
test_scopes:
  - tests/test_runner_hosted_runtime.py
  - tests/test_hosted_mutation_gateway.py
  - tests/test_hosted_final_target_scan_integration.py
  - tests/contract/test_conformance.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf multi-agent adversarial system and live target hard gate
  - AGENTS.md Policy Gateway, Railway, Clerk, and human-approval invariants
  - docs/deployment/FOUR_MODEL_RECOVERY.md Runtime and evidence acceptance
  - docs/planning/agent-runtime-provenance.md Hosted Runner path
---

## Context
Wave 28 is cut from the accepted T-F16f final two-target composition commit plus T-F17c. It is the
sole post-T-F16 owner of `runner.py` and the gateway mutation seam; T-F16e/f cannot run or merge in
parallel. The persisted `HostedRunBinding`, final ScanPlan and parent/eight-child decisions, staged
configuration, current queue lease, per-surface Policy Gateway, and deterministic evidence/oracle
path are authoritative.

## Acceptance Criteria
- **AC-1**: Given an authorized campaign with `scope.hosted_run`, when a claimed job passes
  preflight, then the Runner loads the exact organization-scoped staged configuration, verifies all
  prompt/model/policy/profile/call/token/spend/time/session hashes, resolves four distinct
  Runner-only credential references, and constructs one shared-ledger `HostedFourRoleRuntime`.
- **AC-2**: Given a hosted campaign with any missing/mismatched binding, prompt, credential,
  configuration, queue lease, target/session generation, cap, or two-person authorization, when
  preflight runs, then it records a bounded blocker and performs zero provider and target calls.
- **AC-3**: Given one authorized case, when the hosted runtime executes, then role order is
  Orchestrator selection -> Red Team mutation envelope -> one final T-F16 per-surface trusted target
  evaluator -> Judge -> conditional Documentation, with pre-created parent-linked logical
  contexts, a Runner-owned per-attempt physical-context factory for each logical call, and no role
  sharing attack-generation/Judge context.
- **AC-4**: Given a fresh secret-free coverage/cost/regression snapshot and authorized candidate
  set, when Orchestrator responds, then package/root mirrors of upgraded
  `OrchestrationSnapshotV1` bind organization/campaign, scan-plan id/revision/hash, candidate
  ids/parent seed hashes, coverage/OWASP/findings/regression/signal/unknown-cost state, remaining
  provider/target/input/output/reasoning/time caps, and issued/expiry timestamps. Package/root
  mirrors of `HostedOrchestrationDecisionV1` accept only a strict tagged union of current in-set
  `select(candidate_id, reason_codes)` or bounded `halt(reason_code)`; it drives the next action and
  persists snapshot/candidate/decision/signal hashes.
- **AC-5**: Given hosted Red Team output, when target evaluation occurs, then a content-addressed
  `HostedMutationEnvelopeV1` binds parent seed, selected candidate, policy, exact mutable pointers
  and allowed replace/prefix/suffix/closed-token transforms, byte/turn/string/physical bounds, and
  all target/surface/method/path/credential/category/OWASP hashes. The final T-F16 gateway validates
  derivation from the exact seed before exactly one dispatch; seed substitution, metadata drift,
  unbounded content, undeclared transforms, and host/method/path/query/header/credential/session
  changes send zero target calls.
- **AC-6**: Given deterministic exploit/error evidence and a contradictory hosted Judge response,
  when verdict precedence is applied, then deterministic evidence wins and a confirmed exploit can
  never become safe.
- **AC-7**: Given no finding, when the attempt completes, then Documentation is explicitly skipped
  without a provider call; given a confirmed/likely finding, Documentation emits only an unpublished
  draft behind the existing human approval gate.
- **AC-8**: Given a campaign without `scope.hosted_run`, when executed, then the existing
  deterministic path remains byte/behavior compatible; a hosted-path failure never falls back to it.
- **AC-9**: Given provider/target/persistence failure after work begins, when the Runner terminates
  the campaign, then typed agent/provider events and preserved target evidence reconcile to a
  terminal state without retrying outside authorization.

- **AC-10**: Given the 100-case hosted profile, when it completes, then the ledger proves exactly
  100 Orchestrator, 100 Red Team, 100 Judge, and `F` eligible Documentation calls, no retries or
  unmatched invocations, `physical_count=300+F`, and 100 terminal target/verdict records; any halt,
  unknown outcome, missing case, or mismatch is partial and cannot be labeled hosted-100 complete.
- **AC-11**: Given contract packaging and conformance, when the wheel/root mirrors and registry are
  checked, then the orchestration snapshot and hosted decision schemas are versioned, byte-equal,
  strict, and migration-documented; legacy `campaign_directive.json` remains compatible and is not
  overloaded with hosted select/halt semantics.

## Test Plan
- Unit: hosted/deterministic branch selection, zero-I/O preflight blockers, strict snapshot and
  select/halt contract conformance, mirror equality, and legacy directive compatibility.
- Integration: real final T-F16f API/queue/store/Runner and two-target per-surface Policy Gateway
  against fake provider/target; selection/halt, mutation negatives, exact role order, one target
  exit, parent lineage, oracle precedence, 100-case reconciliation, and failure recovery.
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
