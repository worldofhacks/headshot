# CLAUDE_CODE_HANDOFF.md — for `/arch-finalize` (Brain 2)

> The instruction set the next stage consumes. Produced by `/arch-draft`. **Run `/arch-finalize` in a
> fresh session or subagent** — the value of the pass is cold eyes on this draft.

## Build posture
**Production-grade** (locked, CLAUDE.md + PLAN.md §1). Finalize *and* gap-audit against this bar:
testing, deploy/rollback, failure-mode coverage, observability, auth, and error paths are in-scope
requirements, not deferrable. The standard is "defend it to a hospital CISO."

## What you (arch-finalize) must do
1. **Read everything first — do not start implementation.** Read all of `docs/planning/*`
   (`PRESEARCH.md`, `RESEARCH.md`, `DECISIONS.md`, `ARCHITECTURE_DRAFT.md`, `DIAGRAM_PLAN.md`, this
   file), plus repo-root `THREAT_MODEL.md` + `USERS.md`, `docs/adrs/0001-build-vs-configure.md`,
   `docs/defense/DEFENSE_SCRIPT.md`, and the PRD (`Week_3_AgentForge.pdf`) + `PLAN.md` + `CLAUDE.md`.
2. **Run a second-pass gap audit** across ~13 dimensions: missing flows · lifecycle states · failure
   modes · interfaces/schemas · unclear source-of-truth · unresearched deps · inconsistent decisions ·
   overbuilt scope · missing tests · deploy path · trust boundaries · diagrams · task-planning anchors.
3. **Propose precise edits; confirm load-bearing changes with the human**, then produce the finalized
   **repo-root `ARCHITECTURE.md`** from `templates/ARCHITECTURE.md` (if absent, follow the PRD's
   Architecture-doc requirement: open with a **~500-word summary**, name each agent + role + inputs/
   outputs + trust level + coordination, and include the **agent-interaction diagram**). Preserve the
   draft's `§N` anchors — downstream `tasks-gen` binds to them.
4. **Only then** hand off to `/tasks-gen` for `IMPLEMENTATION_PLAN.md`. Do **not** generate it here.

## Files this stage wrote
- `docs/planning/PRESEARCH.md` · `RESEARCH.md` · `DECISIONS.md` · `ARCHITECTURE_DRAFT.md` (§1–§17,
  stack sections filled) · `DIAGRAM_PLAN.md` · `CLAUDE_CODE_HANDOFF.md` (this file)
- `THREAT_MODEL.md` (first pass) · `USERS.md` (both repo root)
- `docs/adrs/0001-build-vs-configure.md` · `docs/defense/DEFENSE_SCRIPT.md`

## Locked decisions (do not silently reopen; challenge only with cause)
Standard mode · production-grade · Python · Railway (Docker/GitHub, managed Postgres, cron,
deployment-history rollback, no GPU) · LangGraph OSS engine + PostgresSaver · self-hosted Langfuse
(exploit DB = system-of-record for finding status) · one Postgres for DB+checkpoints+`SKIP LOCKED`
queue · per-role models (RedTeam local 24–33B uncensored · Judge Sonnet 4.6 · Orchestrator Opus 4.8 ·
Docs GPT-5.4) · configure/wrap OSS + build the four capabilities (ADR-0001) · versioned framework-
neutral JSON-Schema contracts + typed error taxonomy · compliance = synthetic-data simulation.

## Still-open questions the finalize pass should track (never invent values)
- **OQ1** target auth mode · **OQ2** target API shape + rate limits + **whether it exposes a web
  surface for ZAP** (freezes the OWASP-Web slot) · **OQ3** seeded-demo-data provenance (confirm no real
  PHI).
- **Measure at MVP, don't guess:** per-agent token profiles, Mac tok/s (local-vs-hosted Red Team
  crossover), `exploit_rate` (Documentation call volume) — no cost number is CISO-defensible until
  these are measured from real traces.
- **Pin the LangGraph 1.x version** before the ADR is frozen; settle the Langfuse-vs-exploit-DB
  ownership split for observability Q3/Q4.
- **D12 (proposed):** MVP ships a hand-authored seed corpus + custom mutation loop; wrap PyRIT/Garak/
  Giskard post-MVP. Ratify in `tasks-gen`.

## Audit hotspots (where this draft is most likely thin — look here hardest)
- **§4 contracts:** the draft names the message boundaries but not full field-level schemas — the PRD
  grades versioned schemas + typed error schemas + both-sided contract tests. Deepen or explicitly
  defer to `contract-steward`.
- **§6 data model:** entities + invariants are listed; full column/index/migration detail is a
  `tdd-swarm` concern but the finalize pass should confirm the data-quality validators are pinned.
- **§9 observability:** the six questions are covered; confirm the Q3/Q4 system-of-record split is
  unambiguous so Langfuse and the exploit DB can't drift.
- **§11 cost:** the *method* is locked; the *numbers* are deliberately absent (unmeasured) — make sure
  finalize doesn't let a placeholder number slip in.
