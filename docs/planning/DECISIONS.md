# DECISIONS.md — AgentForge / Adversarial Machine

> ADR-style decision log. Each entry: the decision, status, why, the fallback, and what would
> invalidate it. Grounded in `RESEARCH.md` (July 2026 sources) and the `/arch-draft` interview.
> The build-vs-configure decision has its own standalone record: `docs/adrs/0001-build-vs-configure.md`
> (a required Architecture Defense deliverable). Status: `locked` unless noted.

| # | Decision | Status |
|---|---|---|
| D1 | Planning mode = Standard; posture = production-grade | locked |
| D2 | Language = Python 3.12+ | locked |
| D3 | Platform host = Railway (Docker/GitHub, managed Postgres, cron, deployment-history rollback; no GPU) | locked |
| D4 | Orchestration = LangGraph (OSS engine only, self-hosted) + PostgresSaver | locked |
| D5 | Observability = self-hosted Langfuse (OTEL SDK v4); exploit DB = system-of-record for finding status | locked |
| D6 | State + queue = one Postgres; `SKIP LOCKED` jobs table; cron enqueues; no Redis | locked |
| D7 | Exploit DB = Railway Postgres (Alembic migrations; partition/BRIN at scale) | locked |
| D8 | Models: RedTeam=local 24–33B uncensored (+hosted burst) · Judge=Claude Sonnet 4.6 · Orchestrator=Opus 4.8 · Docs=GPT-5.4 | locked |
| D9 | Security tooling = configure/wrap OSS; build the 4 graded capabilities; buy nothing | locked (→ ADR-0001) |
| D10 | Contracts = versioned JSON Schema, framework-neutral, typed error taxonomy | locked |
| D11 | Compliance = synthetic-data simulation, ATO-*style*; OSS self-host sufficient, no BAA tier | locked |
| D12 | MVP seed strategy = hand-authored corpus + custom mutation loop; wrap PyRIT/Garak/Giskard post-MVP | proposed |

---

### D4 — Orchestration: LangGraph (engine only) + PostgresSaver `locked`
**Why.** First-class human-in-the-loop (`interrupt()`/`Command(resume=…)`) is the human-approval
gate; PostgresSaver reuses the Railway Postgres we already run; per-node LLM clients make Judge
independence *structural*, not conventional. Rejected AutoGen (maintenance mode) and CrewAI (no
first-class Postgres checkpointer, weaker at-any-node interrupt). We use the **MIT OSS engine only** —
never LangGraph Platform/LangSmith — so there is no lock-in and contracts stay ours.
**Fallback.** Thin custom asyncio orchestrator on the *same* JSON-Schema contracts (a swap, not a
rewrite). Layer DBOS-on-Postgres *under* LangGraph if unattended multi-hour campaigns need exactly-once.
**Invalidate if.** LangGraph 1.x breaks `interrupt()`/PostgresSaver before MVP; a hard exactly-once
requirement lands. **Action:** pin the LangGraph 1.x version before the ADR is frozen.

### D5 — Observability: self-hosted Langfuse; exploit DB is system-of-record `locked`
**Why.** OTEL-native SDK keeps emission framework-neutral; one-request=one-trace with per-agent span
tags gives native per-agent cost + inter-agent order. LangSmith/Braintrust self-host is Enterprise-
only (fails Railway/budget). **Split pinned:** Langfuse observes the *campaign*; the Postgres exploit
DB is system-of-record for finding status (Q4) and resilience trend (Q3) — surfaced via a Postgres
view so the two never drift.
**Fallback.** Langfuse Cloud Hobby (free) for the ~2.5h Defense demo → Railway self-host for MVP with
zero re-instrumentation.
**Invalidate if.** Real BAA/HIPAA/SOC2 grading appears (it does not — D11) → paid tier + masking.

### D6 — State + queue: one Postgres, `SKIP LOCKED`, cron enqueues `locked`
**Why.** Postgres already exists (exploit DB + checkpoints); a hand-rolled `jobs` table with
`SELECT … FOR UPDATE SKIP LOCKED` and a `queue`/priority column carries both agent work and regression
runs durably; cron *enqueues* (never runs inline) to sidestep its 5-min/overlap-skip limits. Adding
Redis/Celery would split state and duplicate durability. Scale (≤100K total) is far below contention
limits.
**Fallback.** pgmq on the same Postgres (SQS-style metrics) via schema-only install or the
Supabase-Postgres template. **Watch:** keep claim transactions short + archive completed jobs to avoid
hot-table bloat.

### D8 — Per-role models `locked`
**Why.** RedTeam must not refuse authorized offensive generation → local uncensored open-weights;
**on the confirmed 32–48GB Mac, default 24–33B (Dolphin-Mixtral / WhiteRabbitNeo-33B)**, hosted-OSS
burst for the hardest cases and 10K+ scale (a 70B is throughput-tight here). Judge = Claude Sonnet 4.6
(refusal-integrity is the "never approve an exploit" property; structurally independent of the local
Red Team). Orchestrator = Opus 4.8 (planning reasoning, low call volume). Documentation = GPT-5.4
(*different vendor from the Judge* → breaks correlated failure; schema-gated output).
**Fallback.** RedTeam→hosted-OSS uncensored if the Mac saturates/offline; Judge→GPT-5.4.
**Invalidate if.** Real per-agent token/throughput traces move the local-vs-hosted crossover; a
provider ships a reliable authorized-offensive mode. **Action:** measure token profiles + Mac tok/s at
MVP before presenting a cost number.

### D9 — Security tooling: configure/wrap, build the four `locked` → ADR-0001
**Why.** Garak/PyRIT/Giskard/Promptfoo/ZAP/Semgrep cover breadth, multi-turn scaffolding, RAG seeds,
OWASP mapping, web DAST, and our-code SAST — all free/OSS. The four things none of them do (coverage-
driven orchestration, autonomous mutation, an independent drift-guarded Judge, regression admission)
are exactly the graded custom work. Buying a commercial red-team platform is out of budget, closed,
un-governable, and *is* the product we're asked to build. Full record + verdict: ADR-0001.

### D11 — Compliance posture `locked`
**Why.** PRD mandates synthetic fixtures only and an ATO-*style* packet (the artifact a reviewer would
want), not a real authorization. Self-hosted OSS observability is sufficient; the design stays
BAA-upgradeable (masking, data-residency notes) as a documented hardening path, unpaid.

### D12 — MVP seed strategy `proposed`
**Why.** Wrapping PyRIT/Garak/Giskard is real Python engineering that CSA notes needs scoping; it
risks the Tue MVP. Ship MVP with a hand-authored seed corpus + our custom mutation loop (the hard
gates: Orchestrator, Judge, regression admission cannot be cut), then wrap the OSS seed sources
post-MVP. The contract JSON makes seed sources hot-swappable. *A tasks-gen sequencing call — arch-
finalize/tasks-gen to ratify.*
