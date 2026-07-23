# Role and four-agent release audit - 2026-07-23

- Audited at: `2026-07-23T18:47:42Z`
- Branch: `codex/final-integration-audit`
- Base commit: `bd7d940652d33741df11604e788537fdc8f9b65b`
- Data policy: synthetic/offline fixtures only; no live target request, Clerk administration,
  credential read, publication, remediation, merge, or deployment was performed.

## Decision

**Release gate: blocked.** The two-role authorization correction and the four-agent offline
integration pass their local automated gates, but the branch does not satisfy all canonical Final
requirements in `Week_3_AgentForge.pdf` and the requirements matrix. It must not be merged to
`main` or deployed under the requested "only if both pass and meet the requirements" condition.

## Two-role Clerk authorization

The only accepted human Organization roles are:

- `org:operator`: read/audit, campaign launch/abort, target management, and configuration.
- `org:approver`: read/audit, campaign authorization, and finding approval/resolution.

No role or permission can waive `approver_user_id != launcher_user_id`. Revision `0012` rejects new
`self_approval_override` rows, and Runner preflight rejects both same-user decisions and any legacy
override. The historical column remains readable for expand-only compatibility.

## Four-agent runtime finding

The authoritative offline Runner now records all four distinct roles:

1. Orchestrator reads a contract-valid, hash-verified PostgreSQL snapshot and selects bounded work.
2. Red Team converts only the exact authorization-bound corpus into AttackAttempt proposals.
3. Independent Judge consumes re-read, hash-verified evidence with deterministic oracle precedence.
4. Documentation consumes confirmed, sanitized evidence references and emits draft-only reports and
   blocked regression dispositions.

Every invocation is written to `agent_executions` with role, parent linkage, input/output hashes,
status, latency, trace, optional token observations, and measured cost. The protected Agent
Operations and Birdseye screens project those durable rows; they do not invent activity.

## Fresh local gates

| Gate | Result |
|---|---|
| Ruff lint | pass |
| Ruff format | pass; 202 files |
| Eval corpus and duplicate validation | pass; 9 cases, 15 labels, 3 categories, 1 fixture |
| Python suite with PostgreSQL | pass; 997 passed, 3 skipped |
| Four-agent/Runner/regression/calibration subset | pass |
| Alembic graph | pass; one head at `0012` |
| Wheel outside repository | pass; 15 packaged schemas |
| Frontend dependency audit | pass; 0 vulnerabilities |
| Frontend unit/component suite | pass; 75 tests |
| Frontend typecheck/build | pass |
| Production bundle policy | pass; 207 files |
| Browser suite | pass; 4 tests |
| Forbidden-language policy | pass |
| Secret scan | pass; 429 files |

The Python suite emitted one non-failing Starlette/httpx compatibility deprecation warning. The
Vite build emitted the existing Clerk vendor-chunk size warning; its bundle policy still passed.

## Canonical release blockers

- **PRD-14/PRD-17:** the active Red Team is exact-corpus replay. It does not yet perform bounded
  novelty search, mutation of partial successes, semantic duplicate clustering, or confirmed-case
  minimization.
- **PRD-14/PRD-17:** the live `copilot_chat` adapter still joins a multi-turn sequence into one
  `message`; it does not execute the reviewed sequence turn by turn.
- **PRD-18:** the implemented calibration gate works and fails closed, but the current Judge identity
  fails its ground-truth thresholds: 60% agreement, 33.33% false-negative rate, and 60% abstention.
  Runtime enable remains false.
- **PRD-23/PRD-24:** replay planning/evaluation primitives and storage exist, but no automatic
  target-version queue worker executes the full regression suite or performs cross-category
  reappearance analysis.
- **PRD-03/PRD-09 and user gates:** no distinct real Approver has authorized the bounded staging
  campaign, and the two Clerk role assignments have not been verified in the admin console.
- Performance/load evidence, genuine independently reproduced reports, current dual-CI evidence,
  and the remaining human-owned Final artifacts are still missing or blocked in the requirements
  matrix.

## Required next release sequence

1. Close the Red Team turn-by-turn novelty/mutation/minimization gap.
2. Pass Judge calibration without weakening thresholds and retain the exact identity artifact.
3. Wire automatic authorization-bound regression execution and cross-category detection.
4. Add deterministic performance gates and refresh all evidence/matrix rows.
5. Commit the integration branch and require green GitHub and GitLab pipelines for the same commit.
6. Have a different Clerk Approver authorize the exact staging corpus/target/caps.
7. Run and retain the bounded deployed trace, then re-audit before merging and deploying production.
