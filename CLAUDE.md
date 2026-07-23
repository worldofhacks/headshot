# CLAUDE.md — AgentForge / Adversarial Machine

Repo orientation for Claude Code. Durable rules only. Full requirements live in
`Week_3_AgentForge.pdf` (source of truth); the roadmap is in `PLAN.md`.

## What this is
A **multi-agent adversarial evaluation platform** — a reusable system that continuously
red-teams AI applications. It discovers, evaluates, validates, and documents
vulnerabilities autonomously, without a human in the loop for every step.
Gauntlet AI — Week 3.

**The platform is target-agnostic. The OpenEMR Clinical Co-Pilot is its first target,
not its subject.** That Co-Pilot already exists and is deployed; it is attacked over its
**live URL** and no target code lives in this repo. Every target is reached through a
**pluggable adapter behind an allowlist** — never hardcode a target.

**Generalize the mechanism, specialize the content.** The PRD grades against the
Co-Pilot case study, so `THREAT_MODEL.md`, the eval suite, and the vuln reports are
Co-Pilot-specific — while the engine, contracts, regression harness, and observability
stay target-neutral. Over-generalizing fails the case study ("traceable back to the
problem"); under-generalizing misses the PRD's own "reusable platform" requirement.

## Build posture — `production-grade` (locked)
The bar is "defend it in front of a hospital CISO," not "it demos." Testing,
deploy/rollback, failure-mode coverage, and observability are **required**, not
nice-to-have. `arch-draft` and `arch-finalize` judge their audits against this posture.

## Hard gates (non-negotiable)
- A **deployed target URL** is submitted with *every* checkpoint; the platform tests a
  **live system**, never only a mock.
- **Multi-agent, not a pipeline.** Distinct agents, distinct trust levels.
- The **Judge is independent** of attack generation — an agent that both attacks and
  judges is compromised by design.
- **Human approval gates** before publishing critical findings or any remediation.
- Every eval case exercises a **boundary, invariant, or regression** — never happy-path
  only. The Judge must **never** approve a confirmed exploit (an invariant).
- Every attack case maps to **OWASP Top 10 (web)** and **OWASP LLM Top 10**.
- Cost is **never** modeled as tokens × N.
- **"Optional Engineering Deliverables" are mandatory** — the PRD grades them.
- **No real PHI** — synthetic fixtures only.
- **Railway hosts the full platform**: the console/API Web service is the only public
  service; runner, scheduler, and Postgres services are private. Staging and production
  have separate service bindings, databases, secrets, target authorization, and Clerk
  configuration.
- **Clerk authentication is mandatory for every meaningful human-facing route.** Access
  is invitation-only/restricted, requires the exact Headshot Organization, and requires
  MFA for every user. Personal accounts and user-created organizations are disabled.
- Authentication is not campaign authorization. No authenticated user, role, or custom
  permission may bypass the Policy Gateway's exact live-target authorization controls.

## Human identity, authorization, and public routes (locked)

**Provider and enrollment.** Clerk is the managed human identity provider. Signup is
restricted/invitation-only; every user must belong to the one required **Headshot** Clerk
Organization. Personal accounts and user-created organizations are disabled. MFA is required for
all users, preferring TOTP plus backup codes; SMS must never be the only available factor. Clerk
integration and authenticated Railway deployment remain **selected/planned until integration is
verified** — do not describe them as deployed.

**Backend authority only.** The backend accepts only a verified Clerk `session_token` for human
requests, verifies it networklessly with `CLERK_JWT_KEY`, checks an explicit non-wildcard
`CLERK_AUTHORIZED_PARTIES`, and requires the exact `CLERK_REQUIRED_ORG_ID`. Authorization uses the
immutable set of **custom organization permissions from verified Clerk claims**. A frontend role
label, request field, cookie value, client-supplied permission, or Clerk system permission has no
authority. Frontend controls improve UX; they never enforce access.

| Clerk Organization role | Backend-authoritative custom permissions |
|---|---|
| `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` |
| `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` |

**Two-person invariant.** A launcher cannot approve or authorize their own operation. Approval
requires a different authenticated `org:approver` principal carrying the required custom permission;
role or permission alone never overrides `approver.user_id != launcher_user_id`. There is no solo-user
or emergency self-approval bypass. Both immutable identities are audit fields.

**Public-route allowlist.** Only `GET /health`, `GET /ready`, and the minimal static/sign-in/callback
shell required to complete Clerk authentication may be public. Before integration, that shell's
concrete paths must be enumerated rather than matched by a broad wildcard. No console data, API,
finding/evidence response, SSE/event stream, WebSocket, campaign action, or approval endpoint is
public. Everything not explicitly allowlisted defaults to authenticated and authorized.

**Identity separation.** Clerk principals represent human users. Agent/workload identity continues to
use service boundaries, per-agent database roles, and target-scoped credential bindings; a Clerk token
is never an agent credential. Human authentication alone never constitutes authorization to attack a
target, publish a critical finding, or perform remediation.

## Runtime agents (application code — defined in ARCHITECTURE.md, not yet written)
- **Orchestrator** — reads observability (coverage gaps, open findings, regressions),
  prioritizes the next campaign, triggers regression runs, governs cost.
- **Red Team** — generates and mutates adversarial inputs; multi-turn sequences.
- **Judge** — independent verdicts (success / fail / partial); drift-guarded, calibrated.
- **Documentation** — confirmed exploit → structured vuln report; data-quality gated.
- Plus the **regression & validation harness** and the **observability layer**.

These are built in `src/` via tdd-swarm. **They are NOT skills.**

## Skills = our dev workflows (in `.claude/skills/`)
Core pipeline: **arch-draft → arch-finalize → tasks-gen → tdd-swarm**. Support skills:
`devlog` (run at every phase boundary), `grilling` (stress-test a plan before building),
`eval-triage` + `bug-hunt` (during build), `interview-prep` (before each video interview).
Week-3 skills being added (see `PLAN.md`): `threat-model`, `adversarial-eval-lifecycle`,
`judge-calibration`, `authorized-live-campaign`, `contract-steward`.

**Four skills are intentionally forked** from their installed-plugin versions and patched
for this project: `arch-draft` (repo-only, no upstream), plus `arch-finalize`, `devlog`,
and `interview-prep`. Patches applied: `AUDIT.md` → `THREAT_MODEL.md`, cost scale →
**test runs**, `arch-draft`'s uninstalled Excalidraw helpers flagged inline, and
**`arch-draft` Phase H rewritten to the DECISIONS-style defense-script format**
(index table + per-beat **Say / Why it holds / If pushed / Concede** + status tags).
**If you re-sync any skill from the plugin, re-apply these patches.**

Notes that override the stock skill text:
- **Diagrams: Excalidraw** (`locked`). `arch-draft`'s two Excalidraw helper skills are
  **not installed** — apply its layout, color-zone, and contrast rules manually. Always
  commit the `.excalidraw` source **plus an exported SVG/PNG**, since `.excalidraw` does
  not render on GitHub.
- **`AUDIT.md` → `THREAT_MODEL.md`.** Four skills (`arch-draft`, `arch-finalize`,
  `devlog`, `interview-prep`) expect a root `AUDIT.md` — an assumption inherited from the
  skills' earlier-project lineage. **This project is greenfield: there is no audit and
  none is coming.** `THREAT_MODEL.md` occupies that slot, and unlike an audit it is an
  artifact we *produce*, not one we inherit. Never create `AUDIT.md`; never wait for one.
- The arch skills also assume "users"-scale cost and an "Early" stage. For Week 3:
  scale is **test runs** (100 / 1K / 10K / 100K); stages are **Defense / MVP / Final**.
- **Threat model precedes architecture.** `arch-draft` wants the AUDIT-slot artifact as
  an *input*, and the PRD orders Stage 2 (threat model) before Stage 4 (architecture).
  A first-pass `THREAT_MODEL.md` comes out of `arch-draft` Phase A/B; the `threat-model`
  skill deepens it for MVP. Note the threat model describes the **target**, so it needs
  the target's shape (endpoints, tools, auth) — observed from the running system if one
  exists, otherwise derived from the OpenEMR Clinical Co-Pilot reference design.
- **`tasks-gen`'s "deliverables checklist"** = `Week_3_AgentForge.pdf` + `PLAN.md` §6–§7.
  Hand it those paths so it doesn't stall asking.
- **`tdd-swarm` cannot run yet.** It assumes a GitHub remote, protected `main`, CI status
  checks, and an existing test runner. Chain: build-vs-configure ADR (stack) → push to
  GitHub → CI + test runner → `tdd-swarm`.
- **Trigger boundaries** — these overlap on the word "eval":
  `adversarial-eval-lifecycle` authors/mutates/promotes cases · `eval-triage` diagnoses a
  *failing* eval · `judge-calibration` is systematic ground-truth and drift work, never
  per-incident · `bug-hunt` is deterministic code bugs.
- `authorized-live-campaign` must gate **every** live attack run (allowlist, synthetic
  data, budget + rate caps, abort). Live attacks are always intentional.

## Deliverable names are law (repo root)
`ARCHITECTURE.md` · `THREAT_MODEL.md` · `USERS.md` · `README.md` (with the deployed URL) ·
`IMPLEMENTATION_PLAN.md`. Planning artifacts live in `docs/planning/`.

## Dual-remote law (GitHub + GitLab)
Every checkpoint and release must be pushed to both `origin` (GitHub) and `gitlab` (Gauntlet Labs).
The two `main` refs must resolve to the same commit, and both CI systems must be green.
(`main` tracks `origin`; push the same `main` commit to `gitlab` with `git push gitlab main` — never
`-u`, never `--mirror`, never force-push.)

## Deadlines
- **Architecture Defense** — ~2.5h after kickoff (needs `docs/defense/DEFENSE_SCRIPT.md`,
  diagrams, and the build-vs-configure ADR).
- **MVP** — Tue Jul 21, 11:59 PM.
- **Final** — Fri Jul 24, 12:00 PM.

## Guardrails for any Claude session here
- Planning skills never write application code.
- Never fabricate a value; unknowns stay visible as `open question`.
- Keep the domain model and JSON contracts **framework-neutral** until the
  build-vs-configure ADR locks the stack.
