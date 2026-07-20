# DIAGRAM_PLAN.md — AgentForge / Adversarial Machine

> Plans the diagram set **after** architecture, per playbook Phase 17. Tool: **Excalidraw** (locked).
> The two Excalidraw helper skills are **not installed** — layout / color-zone / contrast rules are
> applied manually below. Each diagram is committed as `.excalidraw` **source + exported SVG/PNG**
> (raw `.excalidraw` does not render on GitHub). Target dir: `docs/diagrams/`.
>
> **Each diagram has a build spec** at `docs/diagrams/<ID>-<slug>.spec.md`. **The spec is the source
> of truth; the `.excalidraw` is a render of it** — any change starts in the spec. **D2 and D4 are
> merged** into one canvas: `D2-D4-agent-interaction-trust.spec.md`. Every colour word used in
> `docs/defense/DEFENSE_SCRIPT.md` must match the legend below exactly.

## Shared visual language (apply to every diagram)
- **Trust zones by fill color** — the **as-built legend** (the load-bearing idea: distinct trust levels):
  - **Blue** = trusted control plane (Orchestrator, LangGraph, regression harness).
  - **Green** = data & observability plane (Postgres, Langfuse + OTEL, Coverage + Findings view).
  - **Purple / teal** = governed evaluators (Judge, Documentation).
  - **Red / orange** = **untrusted / quarantined** (Red Team + all adversarial content, Target adapter).
  - **Gray** = external, out-of-repo (live target, model providers, Railway).
  - **Yellow** = human gate (critical publish + remediation approval).
- **Contrast:** dark text on light fills; ≥ 4.5:1. No color-only meaning — every zone is also labeled.
- **Edge semantics:** solid = data/message flow; dashed = control/trigger; red-outlined = adversarial
  payload path (must visibly *not* cross into the control plane).
- **Legend** on every diagram. Left-to-right or top-down flow; no crossing edges where avoidable.

---

## D1 — System Context (the one-glance overview)
- **Purpose:** show the platform as one box against its external world; orient any reviewer in 10s.
- **Nodes:** `AgentForge platform` (blue boundary) · `OpenEMR Clinical Co-Pilot` (gray, live URL) ·
  `Model providers` (gray: Anthropic/OpenAI/OpenRouter/local Mac) · `Railway` (gray: Postgres, cron,
  deploy) · `Human operator` (yellow) · `GitHub` (gray).
- **Edges:** platform → target (dashed "authorized live campaign, allowlist + synthetic data") ·
  platform ↔ providers (per-role inference) · platform ↔ Railway · operator → platform (approval
  gates).
- **Must convey:** target is external and reached only through the allowlist; no target code inside.

## D2 — Agent Interaction (REQUIRED by the PRD; the Defense centerpiece)
- **Purpose:** name each agent, its trust level, and how work + verdicts flow — the ARCHITECTURE.md
  mandatory diagram.
- **Nodes, edges, badges, layout rules:** see the build spec —
  `docs/diagrams/D2-D4-agent-interaction-trust.spec.md`. **Merged with D4** onto one canvas. Do not
  re-enumerate nodes here; the spec is the single source of truth and this avoids drift.
- **Must convey:** (a) Red Team and Judge are *different, differently-trusted* agents; (b) the
  Judge is independent of attack generation; (c) the Observability→Orchestrator loop is what makes it
  "learning, not random"; (d) adversarial (red) edges never enter the blue control plane — the Red
  Team has **exactly one exit**, the Target adapter.

## D3 — Attack / Request Lifecycle (one case, end to end)
- **Purpose:** trace a single attack case through every state — the e2e trace evidence.
- **Swimlanes:** Orchestrator | Red Team | Target | Judge | Documentation | Regression | Human.
- **Flow:** select campaign → generate attempt → run vs target → judge → {partial → mutate → loop} →
  {success → document → human gate (if critical) → publish} → admit to regression → future regression
  run. Show the typed-error branch (target-unreachable / budget-exceeded / judge-timeout).
- **Must convey:** mutation loop on partials; the human gate; regression admission "only if
  reproduces deterministically + passes for the right reason."

## D4 — Trust Boundaries & Data Flow (the CISO diagram)
- **Purpose:** where trust changes hands; where secrets, PHI-surrogate data, and adversarial content
  live and are contained.
- **Merged into D2** — one canvas carries both. See `docs/diagrams/D2-D4-agent-interaction-trust.spec.md`.
  Trust content it must retain: adversarial input in red with **exactly one exit** (the Target adapter);
  control plane in blue; data stores in green; per-target **credential binding** as a locked edge that
  cannot fan out to other targets.
- **Must convey:** adversarial content is quarantined and never reaches the control plane; credentials
  are bound to their target; synthetic-data-only assertion at the target boundary.

## D5 — Deployment & Rollback (Railway)
- **Purpose:** the production-grade deploy/rollback + scheduled-run story.
- **Nodes:** GitHub → Railway build (Dockerfile) → platform service · Railway **managed Postgres**
  (exploit DB) · Railway **cron** (Orchestrator regression trigger) · **deployment history** (rollback
  arrow) · local Mac (optional local Red Team inference — a *separate* line from hosting).
- **Must convey:** deploy-from-first-commit, managed Postgres for durable exploit storage, cron as the
  regression trigger, deployment-history as rollback, and hosting-vs-inference as separate cost lines.

---

## Build order (against the ~2.5h Defense window)
**D2 (agent interaction) first** — it is PRD-mandatory and the Defense centerpiece — then **D4 (trust
boundaries)**, then **D1 (context)**. D3 and D5 can follow for MVP if time is tight (`simplification`:
D3/D5 may be sketched for Defense, finalized for MVP). Every committed diagram ships `.excalidraw` +
SVG/PNG.
