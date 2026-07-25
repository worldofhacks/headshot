---
id: T-F05f
title: Enforce the canonical SMART lease in Runner dispatch
status: backlog
wave: 14
depends_on: [T-F05a, T-F05d, T-F05e, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05p]
branch: ticket/T-F05f-smart-session-runner
file_scopes:
  - src/agentforge/policy/scoped_credentials.py
  - src/agentforge/runner.py
test_scopes: [tests/test_smart_session_lease_runner.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07, LEAD-09
  - .tdd-swarm/reports/session-binding-readiness.md SB-001, SB-002, SB-003
  - .tdd-swarm/reports/session-lease-scope-review.md I1, I3, I4
---

## Context
[locked-decision] This ticket only integrates the landed T-F05e validators, T-F05j reference/job
contract, T-F05k loader, and T-F05m provider into private Runner: atomic claim, immediate
non-secret validation, one secret resolution/raw-shape/digest check, one pinned session/client,
fresh authoritative state per physical attempt, and terminal cleanup. The durable queue's atomic
claim/lease acquisition is the sole pre-validation mutation exemption.

## Acceptance Criteria
- **AC-1**: For a SMART live job, Runner may atomically claim/acquire its durable queue lease and perform no other mutation. Immediately post-claim it constructs T-F05e's trusted non-serializable `current_claim`, uses T-F05j to require setting/job/store reference equality, uses T-F05k to load/pin the context, invokes the immutable validator, then calls T-F05m `AuthenticatedRunnerStateProvider.observe(context, now, current_claim)`. The authenticated control artifact identifies exactly this live claim and no other lease/campaign. All checks complete before campaign-running state, attempt/work-unit/evidence mutation, secret resolution, adapter/client construction, network, or spend; Runner copies no parser/policy/source logic.
- **AC-2**: If immediate validation fails, Runner invokes only the landed T-F05j lease-owned queue contract once with `failure_code='smart_session_lease_rejected'`, a nonempty internal detail, and `retryable=False`. The only public/persisted message is exactly `worker-supplied failure detail omitted`; machine state is independently and exactly `last_failure_code='smart_session_lease_rejected'`, durable status `dead_letter`, and `FailureOutcome.DEAD_LETTERED`. Runner returns a typed non-secret rejection outcome with no free-form detail. No test or interface requires, exposes, logs, or persists any worker-supplied internal detail.
- **AC-3**: The terminal transition clears the lease and creates no campaign-running/attempt/work-unit/evidence row, resolves no secret, initializes no adapter/client, retries nothing, and emits no input/path/artifact content. Tests distinguish the permitted claim plus sanitized terminal rejection from every forbidden mutation and prove arbitrary internal detail cannot bypass queue sanitation.
- **AC-4**: Only after immediate validation succeeds, Runner resolves the exact canonical credential reference once. T-F05e's raw validator and constant-time lowercase `value_sha256` comparison execute before adapter/client/call; shape/digest failure exposes no value through return, exception, repr, log, telemetry, artifact, or test.
- **AC-5**: One immutable T-F05k context object/ref, one T-F05p target plus enabled chat surface, one redacting `Secret` and credential generation, one T-F05d patient/context identity, one adapter, and one owned HTTP client are pinned for the campaign. Target/surface/session/context/reference/value/patient replacement, cross-target resolution, a second resolution, silent normalization, refresh, filesystem reload, or in-place rotation is refused. Only Runner may resolve the binding; Web/catalog/job/prompt/report surfaces never receive the value.
- **AC-6**: Immediately before every physical attempt and before its work-unit/evidence mutation, Runner injects a fresh clock and calls T-F05m again with the same current claim after reasserting lease ownership. T-F05m must acquire a new signed controller observation through T-F05l, project it with T-F05h, project T-F05i in a new read-only transaction, and validate through T-F05e. No cached success survives source unavailability/replay/staleness, another claim, abort, expiry, overlap, or lease loss.
- **AC-7**: Success, local failure, target-confirmed session expiry, lost authorization/job lease, hard abort, and fresh-state failure release the reference, pinned `Secret`, adapter, and owned HTTP client exactly once. Completed evidence stays immutable, any begun interrupted attempt is terminal, later attempts are omitted, and cleanup failure cannot resume dispatch.
- **AC-8**: Non-session and synthetic execution remain compatible and never require SMART settings, job fields, context files, or source providers. Focused tests patch mutation/resolver/adapter/client/AF_INET/controller/database/provider/target/spend hooks to raise and prove exact ordering at post-claim and every attempt.

## Test Plan
- Unit (deterministic): claim exemption; exact sanitized public message plus separate machine code/status; one resolution; raw shape/digest/redaction; pinning; release-on-all-paths; non-session compatibility.
- Integration (deterministic): fake queue/store/loader/provider/adapter with injected clocks and synthetic authorities; source acquisition/validation failure before post-claim or an attempt leaves every later hook untouched.
- Eval/E2E: none; no network, live database/controller, or real credential material.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05f.md <DIFF_BASE>` exits 0.
- [ ] Tests prove claim-only exemption, sanitized rejection, immediate validation, one resolution, fresh per-attempt state, and cleanup.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No schema/projection/delivery/store/config/queue change, Railway edit, credential provisioning,
real session, deployment, provider/target call, or authorization creation.
