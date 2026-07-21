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

> **Identity/hosting export status (2026-07-21):** this planning specification now requires the
> Browser → Clerk → Railway Web authentication boundary and the public/private Railway topology.
> `D2-D4-agent-interaction-trust.spec.md` now carries that overlay. The existing D2/D4
> `.excalidraw`, SVG, and PNG predate it and are intentionally untouched in the Clerk-foundation
> change because their source and both exports cannot be regenerated here as one verified set.
> **Mandatory integration follow-up:** update the `.excalidraw` source from the build spec, then
> regenerate and visually verify both SVG and PNG in the same commit before presenting those exports
> as current. Until then, the exports are historical architecture-defense evidence, not proof that
> Clerk/Railway auth is deployed.

## Shared visual language (apply to every diagram)
- **Trust zones by fill color** — the **as-built legend** (the load-bearing idea: distinct trust levels):
  - **Blue** = trusted control plane (Railway Web authorization boundary, Policy Gateway,
    Orchestrator, LangGraph, regression harness).
  - **Green** = data & observability plane (Postgres, Langfuse + OTEL, Coverage + Findings view).
  - **Purple / teal** = governed evaluators (Judge, Documentation).
  - **Red / orange** = **untrusted / quarantined** (Red Team + all adversarial content). The TargetAdapter
    remains inside the trusted blue Policy Gateway + Execution Recorder boundary.
  - **Gray** = external / managed boundary (Clerk, live target, model providers, Railway platform
    boundary). Railway services inside that boundary retain their own blue/green trust fill.
  - **Yellow** = human-controlled boundary (Browser, critical publish + remediation approval).
- **Contrast:** dark text on light fills; ≥ 4.5:1. No color-only meaning — every zone is also labeled.
- **Edge semantics:** solid = data/message flow; dashed = control/trigger; red-outlined = adversarial
  payload path (must visibly *not* cross into the control plane).
- **Legend** on every diagram. Left-to-right or top-down flow; no crossing edges where avoidable.

---

## D1 — System Context (the one-glance overview)
- **Purpose:** show the platform as one box against its external world; orient any reviewer in 10s.
- **Nodes:** `Human operator + Browser` (yellow) · `Clerk managed IdP` (gray) · `Railway` outer
  boundary containing `public Web: console + FastAPI` (blue), `private Runner` (blue), `private
  Scheduler` (blue), and `private PostgreSQL` (green) · `Policy Gateway + Execution Recorder` (blue,
  inside runner trust boundary) · `OpenEMR Clinical Co-Pilot` (gray, external live URL) · `Model
  providers` (gray: Anthropic/OpenAI/OpenRouter/local Mac) · `GitHub` (gray).
- **Edges:** Browser ↔ Clerk (solid "restricted sign-in + MFA") · Browser → public Railway Web
  (solid "Clerk session_token") · Web verifies token locally using Clerk PEM public key (annotated
  "networkless; exact authorizedParties + Headshot org + custom permissions") · Web → Policy Gateway
  (dashed "authenticated request; campaign authorization still required") · Policy Gateway → target
  (red-outlined "authorized live campaign, allowlist + synthetic data + caps + abort") · private
  services ↔ PostgreSQL over Railway private networking · runner ↔ providers (per-role inference) ·
  operator → human approval gate.
- **Must convey:** only Railway Web is public; Clerk is human identity, not agent/workload identity;
  authentication does not authorize a target; the external target is reached only through the Policy
  Gateway; no target code lives inside the platform.

## D2 — Agent Interaction (REQUIRED by the PRD; the Defense centerpiece)
- **Purpose:** name each agent, its trust level, and how work + verdicts flow — the ARCHITECTURE.md
  mandatory diagram.
- **Nodes, edges, badges, layout rules:** see the build spec —
  `docs/diagrams/D2-D4-agent-interaction-trust.spec.md`. **Merged with D4** onto one canvas. Do not
  re-enumerate nodes here; the spec is the single source of truth and this avoids drift.
- **Must convey:** (a) Red Team and Judge are *different, differently-trusted* agents; (b) the
  Judge is independent of attack generation; (c) the Observability→Orchestrator loop is what makes it
  "learning, not random"; (d) adversarial (red) edges never enter the blue control plane — the Red
  Team has **exactly one exit**, the trusted Policy Gateway. **Identity/hosting overlay required on
  the same canvas:** Browser → Clerk → public Railway Web; exact Headshot Principal/custom-permission
  check at Web; Web → Policy Gateway only after the human gate; private runner/scheduler/Postgres
  inside the Railway boundary; external target beyond the Policy Gateway. Human Clerk identity and
  workload/agent identity must be visibly separate.

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
  Trust content it must retain: adversarial input in red with **exactly one exit** (the trusted Policy
  Gateway); control plane in blue; data stores in green; per-target **credential binding** as a locked
  edge that cannot fan out to other targets. Add the Browser/Clerk boundary, public Railway Web,
  private runner/scheduler/Postgres, and external target as explicit nested/adjacent zones.
- **Must convey:** adversarial content is quarantined and never reaches the control plane; credentials
  are bound to their target; synthetic-data-only assertion at the target boundary; only Web is public;
  the Web's networkless Clerk check establishes a human Principal but does not release target
  credentials or constitute campaign authorization; tokens/headers are not persisted or forwarded.

## D5 — Deployment & Rollback (Railway)
- **Purpose:** the production-grade deploy/rollback + scheduled-run story.
- **Nodes:** GitHub → Railway build (Dockerfile) → environment boundary containing **public Web**,
  **private Runner**, **private Scheduler**, and **private managed Postgres** · Browser (yellow) · Clerk
  (gray) · trusted Policy Gateway (blue, runner path) · external target (gray) · Railway deployment
  history (code rollback arrow) · Postgres backup/PITR (data-recovery arrow) · local Mac (optional local
  Red Team inference — a separate line from hosting). Draw staging and production as separate repeated
  boundaries with different Clerk origins/Organization IDs and databases.
- **Edges:** Browser ↔ Clerk → Web; Web ↔ private Postgres; Web → private runner job; scheduler →
  Postgres enqueue; runner → Policy Gateway → external target; GitHub → staged build/promotion;
  deployment history → services; PITR → replacement/restored database.
- **Must convey:** only Web has public ingress; restricted Clerk identity terminates at Web;
  runner/scheduler/Postgres are private; staging cannot accept production Clerk or target
  configuration; pre-deploy migrations and readiness gate promotion; deployment-history rolls back
  code while expand/contract + PITR govern data; hosting and inference remain separate cost lines.

---

## Build order (against the ~2.5h Defense window)
**D2 (agent interaction) first** — it is PRD-mandatory and the Defense centerpiece — then **D4 (trust
boundaries)**, then **D1 (context)**. D3 and D5 can follow for MVP if time is tight (`simplification`:
D3/D5 may be sketched for Defense, finalized for MVP). Every committed diagram ships `.excalidraw` +
SVG/PNG.

**Current integration order:** review the updated merged D2/D4 build spec against this plan, update its
Excalidraw source, export SVG and PNG, inspect both at readable scale, and update the defense script's
diagram status. Do not edit only one export and do not present the old render beside the new
Clerk/Railway text without the historical-status warning above.
