# T-F17 hosted runtime/provenance planner report

Status: DONE

## Scope

[locked-decision] Planned the independent P0 slice that makes the private production Runner execute
the real four-role hosted runtime, binds versioned system prompts to provider messages, persists
provider-confirmed physical-call lineage, derives Web capability from a fresh Runner heartbeat, and
renders configured-versus-observed truth in the Agents screen.

## Evidence inspected

- Canonical `Week_3_AgentForge.pdf` (17 pages; text extraction plus rendered visual inspection).
- `AGENTS.md`, `CLAUDE.md`, and `.claude/skills/tdd-swarm/SKILL.md`.
- Hosted configuration/runtime/transport, Runner, Policy Gateway/evidence path, control-plane
  execution storage, migrations, Web/PostgreSQL read models, Clerk permission boundary, Agents
  TypeScript decoder/screen, Docker/Railway configuration, recovery runbook, and relevant tests.

## Artifacts

- `docs/planning/agent-runtime-provenance.md`
- `tickets/T-F17a.md` through `tickets/T-F17f.md`
- T-F17 addendum in `TICKETS.md`
- thirty RED/review/GREEN/code-review/security dispatch prompts under `.tdd-swarm/prompts/`
- this report

Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan`
Branch: `codex/agent-runtime-provenance-plan`

## Key decisions

- Runner constructs the executable runtime; Web consumes only a secret-free fresh capability
  heartbeat.
- Raw package-resource bytes are the prompt hash authority.
- Prompt content requires `org:config:manage`; prompt version/hash remains visible with
  `org:console:read` pending owner confirmation.
- `provider_call_events` stores one terminal append-only event per physical attempt; missing
  provider measurements stay unavailable.
- Hosted target dispatch and deterministic verdict are returned from one typed trusted evaluator,
  preventing two evidence paths.
- Deterministic campaigns remain compatible; hosted failures never fall back.

## Safety boundary

No application or test code was written. No provider/target call, credential read/rotation,
deployment, external mutation, main merge, or publication was performed. T-F16 files were not
touched.

## Validation

- Structural check: six tickets, thirty role prompts, required ticket sections, exact worktree /
  branch / report references, no T-F16 change, and `git diff --check` all passed.
- `gitleaks dir . --redact --no-banner --no-color --max-target-megabytes 2`: no leaks found.

[open-question] An independent Plan Reviewer must still issue `REVIEW_PASS` before any T-F17 RED
dispatch. This Planner does not approve its own plan.
