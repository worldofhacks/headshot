# CLAUDE.md — AgentForge / Adversarial Machine

Repo orientation for Claude Code. Durable rules only. Full requirements live in
`Week_3_AgentForge.pdf` (source of truth); the roadmap is in `PLAN.md`.

## What this is
A **multi-agent adversarial evaluation platform** that continuously red-teams the
**OpenEMR Clinical Co-Pilot** (an AI-assisted clinical workflow). It discovers,
evaluates, validates, and documents vulnerabilities — autonomously and continuously,
without a human in the loop for every step. Gauntlet AI — Week 3.

**This repo is the platform only.** The Clinical Co-Pilot target lives separately and
is attacked over its **live deployed URL** (see hard gates). No target code lives here.

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
Week-3 skills being added (see `PLAN.md`): `threat-model`, `adversarial-eval-authoring`,
`judge-calibration`, `authorized-live-campaign`.

Notes that override the stock skill text:
- **Diagrams: use Mermaid** (renders on GitHub). `arch-draft` references Excalidraw
  skills that are **not installed** — substitute Mermaid.
- The arch skills were written for an earlier project (they mention `AUDIT.md`,
  "users"-scale cost, an "Early" stage). For Week 3: scale is **test runs**
  (100 / 1K / 10K / 100K) and stages are **Defense / MVP / Final**.
- `authorized-live-campaign` must gate **every** live attack run (allowlist, synthetic
  data, budget + rate caps, abort). Live attacks are always intentional.

## Deliverable names are law (repo root)
`ARCHITECTURE.md` · `THREAT_MODEL.md` · `USERS.md` · `README.md` (with the deployed URL) ·
`IMPLEMENTATION_PLAN.md`. Planning artifacts live in `docs/planning/`.

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
