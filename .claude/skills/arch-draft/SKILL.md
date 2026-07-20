---
name: arch-draft
version: 1.0.0
description: >-
  Interview-gated architecture planning: turn a PRD into research-backed planning
  artifacts under docs/planning/ — intake, users & flows, constraints mapping,
  sourced research, an ADR decision log, a §-anchored architecture draft, rendered
  architecture diagrams, and a defense presentation script. Planning only; never
  writes application code. Hands off to /arch-finalize for the adversarial pass
  that produces the binding repo-root ARCHITECTURE.md. Invoke when the user says
  "draft the architecture", "plan the architecture", "arch draft", or starts a new
  project from a PRD.
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, AskUserQuestion, WebSearch
---

# arch-draft

You run the planning arc from PRD to a defensible architecture draft:

```
PRD → intake → users & flows → constraints → research → decisions (ADRs)
    → ARCHITECTURE_DRAFT.md → diagrams → defense script → handoff → /arch-finalize
```

---

## Operating rules (apply to every phase)

- **Interview-gated.** Stop and ask at every decision the user must own. Use
  AskUserQuestion. One topic per question. Give a recommendation + why, then options.
- **Facts vs decisions.** If a fact is discoverable from the PRD, the repo, or the
  web — look it up; never ask the user for it. Decisions belong to the user.
- **Never fabricate.** Unanswered → tag `open question`. A wrong value propagates
  through every downstream artifact.
- **Tag everything:** `locked` / `proposed` / `open question` / `scope simplification`
  / `production-hardening` / `deferred` / `research required`.
- **Never write application code.** Planning only.
- **Deliverable names are law:** `./ARCHITECTURE.md`, `./THREAT_MODEL.md`, `./USERS.md`
  at repo root. Planning artifacts live in `docs/planning/`. This project is greenfield —
  there is no `AUDIT.md` and none is coming; `THREAT_MODEL.md` fills that slot and is an
  artifact you *produce*, not one you inherit. Never create `AUDIT.md`.

---

## Inputs

Ask one at a time if missing:

1. Path to the PRD (or pasted text). Read fully before anything else.
2. Base repo root (for integration-surface recon).
3. `THREAT_MODEL.md` and `USERS.md` if they exist yet — the architecture must trace to
   both. Neither is inherited here: produce a first-pass `THREAT_MODEL.md` of the
   **target** (endpoints, tools, auth) in Phase A/B — from the live target if reachable,
   otherwise from its reference design.

---

## Phase A — Intake & setup

1. Extract from the PRD: product-in-one-sentence, is / is-not, primary problem,
   candidate users, core workflow, explicit requirements, implied requirements,
   external dependencies, hard gates & deadlines, ambiguities, initial risks.
2. Recon the base repo just enough to know the integration surfaces (APIs, auth
   model, extension points, deployment tooling). Concrete paths > guesses.
3. Confirm with the user: **planning depth** (`default` = full artifact set;
   `compact` = PRESEARCH + DRAFT only, for small scopes) and **build posture**
   (`production-grade` is the default — the bar is "defend it in front of a
   hospital CTO"; `prototype` only if the user insists, flagged).
4. Write the intake to `docs/planning/PRESEARCH.md` as you go.

Stop condition: user confirms the product summary and posture before any drafting.

## Phase B — Users, flows, traceability

1. Force ONE narrow user (vague personas get punished). Put the load-bearing persona
   decision to the user with a data-backed recommendation: which persona can be
   served end-to-end with the data and platform that actually exist?
2. For each use case: actor, trigger, steps, success, failure states, data touched —
   and an explicit **"why is an agent the right shape"** answer (rule: every
   capability must trace to a use case or it doesn't get built).
3. Cover non-happy flows: degraded modes, ops flows (deploy/rollback/alert response).
4. Output feeds `USERS.md` (root deliverable) + flows section of PRESEARCH.md.

## Phase C — Constraints & engineering-requirements mapping

Map every engineering requirement to a design element or an open question — none may
dangle: correlation IDs across boundaries · strict schemas on every tool I/O ·
real-time dashboard (requests, error rate, p50/p95, tool calls, retries,
verification pass/fail) · ≥3 documented alerts · separate /health and /ready with
real dependency checks · runnable API collection · load tests @ 10/50 concurrent ·
baseline CPU/mem/latency/throughput profiles · AI cost analysis at 100/1K/10K/100K
**test runs** (never cost-per-token × n) · eval suite where every case is boundary /
invariant / regression (happy-path-only fails).

## Phase D — Research

For every fact a decision will rest on (pricing, platform capabilities, regulatory
requirements, library claims): WebSearch, record in `docs/planning/RESEARCH.md` as
**R# entries — finding → sources → architecture impact**. Actively try to falsify
the design's premises; a research finding that kills a feature is a win, not a
setback. State the fallback when a fact can't be verified.

## Phase E — Decisions (ADR log)

Write `docs/planning/DECISIONS.md` as numbered ADRs (D1, D2, …):

- Options considered (table for the load-bearing ones)
- Why the winner wins — argued from THIS use case, citing R# research
- Tradeoffs owned out loud (say them before an interviewer does)
- Invalidation conditions (what evidence would reverse this)
- Tag: locked / proposed / open

Load-bearing decisions (target user, integration pattern, stack, LLM, observability,
deployment) go to the user via AskUserQuestion with a recommendation. Everything
else may be `proposed` with rationale.

## Phase F — Architecture draft

Write `docs/planning/ARCHITECTURE_DRAFT.md` with stable `§N` anchors:

§1 overview + explicit non-goals · §2 components · §3 request lifecycle ·
§4 trust boundaries & authz · §5 verification/safety pipeline · §6 failure modes
(table: failure → designed behavior) · §7 observability & ops (engineering
requirements mapped) · §8 evaluation strategy · §9 cost model skeleton ·
§10 build order against the checkpoint deadlines.

Every § cites its ADRs. Every capability cites a USERS.md use case.

## Phase G — Diagrams (spec-first, then rendered)

1. Write `docs/planning/DIAGRAM_PLAN.md`: which diagrams, what interview question each
   must answer, presentation order, and the shared color-zone legend.
2. For **each** diagram write a build spec to `docs/diagrams/<ID>-<slug>.spec.md` using
   the fixed template below — verbatim section order, verbatim headings. **The spec is
   the source of truth; the `.excalidraw` is a render of it.** Any later change starts
   in the spec.

```
DIAGRAM <ID> — <Title>
Style: Excalidraw, hand-drawn, color-zoned. Export SVG + PNG.

TITLE:    <canvas title>
SUBTITLE: <one line>

=== COLOR LEGEND ===     one line per plane: <color> = <meaning>
=== ZONES ===            Z#  NAME  border-color, position
=== NODES ===            grouped into horizontal BANDs; NAME  color  "sublabel"
=== EDGES ===            numbered; FROM -> TO  "label"  [DASHED if not solid]
=== POLICY BADGES ===    small dashed callouts + what each points at
=== LAYOUT RULES ===     R1..Rn — banding, grouped connectors, forbidden routes
```

3. Render each spec to `docs/diagrams/<ID>-<slug>.excalidraw` (hand-drawn, color-zoned),
   then export `.svg` + `.png` alongside it — `.excalidraw` does not render on GitHub.
   NOTE: the `excalidraw-diagram` and `architecture-excalidraw-comparison` helper skills
   are **not installed** — apply layout, color-zone, and contrast rules manually.
   Excalidraw is the locked diagram format; do not substitute another.
4. The standard set:
   - **System context** — components + trust zones; "where does it live, where are the
     boundaries."
   - **Primary interaction loop** — the numbered end-to-end walkthrough diagram.
   - **Trust boundaries & authz map** — what each zone can and cannot do, where
     enforcement lives; answers the hardest security question directly. May be **merged**
     with the interaction loop when one canvas carries both without crowding.
   - **Deployment & CI topology** — services, data stores, deploy-on-green, rollback.
5. Hard rules:
   - Every box label must trace to the draft — no diagram-only architecture.
   - **LAYOUT RULES are mandatory, not decorative.** At minimum: band the canvas and
     forbid any edge crossing a band boundary twice; represent shared infrastructure as a
     substrate band reached by **one grouped connector**, never one line per consumer;
     give any quarantined zone **exactly one exit** and say so — that single edge is the
     visual proof of containment.
   - The legend must name **every** colour actually used on the canvas.
   - Any colour word used in `docs/defense/DEFENSE_SCRIPT.md` must match the legend
     exactly. A script that narrates a colour the diagram does not use is a live error.

## Phase H — Defense script

Write `docs/defense/DEFENSE_SCRIPT.md` — the presentation walkthrough for the
architecture defense. **The format mirrors `DECISIONS.md`**: dense, declarative,
every claim carrying its own counterfactual. Never loose prose sections.

Structure, in this order:
1. **Framing blockquote** — what this is, the four bold labels used per beat, the
   goal, the evidence pack, and the default tag.
2. **Index table** — `| # | Beat | What it lands | Time |`, one row per beat, IDs
   `S0…Sn`. It must be scannable standing alone.
3. `---`, then **one section per beat**, headed ``### S# — Title `tag` ``.

Every beat uses the same four bold-label paragraphs — this rhythm is the format:
- **Say.** The line to deliver, in quotes where spoken verbatim.
- **Why it holds.** The substantiation — named mechanisms, real numbers from
  RESEARCH.md, exact tradeoffs from the ADR.
- **If pushed.** The follow-up answer, with the likely question named inline
  (e.g. *If pushed — "isn't this just microservices with prompts?"*).
- **Concede.** The honest limit. Omit only where a beat genuinely has none.

Tags mirror the DECISIONS status convention: `must-land` (default) · `spine` ·
`reactive` · `pre-flight` · `volunteer these` · `scope`.

- Use a **table** wherever content is already Q→A (anticipated hard questions),
  tagged `reactive`.
- Include a **run-of-show** beat tagged `pre-flight` — ordered, with any item other
  beats depend on marked as blocking.
- Include a **still-open** beat tagged `volunteer these` — unresolved items stated
  proactively, each with where it is tracked.
- Include a **what-I-cut** beat tagged `scope` when there are researched removals;
  scope discipline is presentation material, not a footnote.
- Optional appendix: a compressed ~5-minute version for time-boxed formats (the
  index table's Time column is the budget).
- Hard constraint: the script may only assert what DECISIONS.md / RESEARCH.md /
  the draft already contain — a claim invented for the podium is a claim that
  dies under one follow-up question. Tradeoffs are stated before an interviewer
  can raise them.

## Handoff

Write `docs/planning/CLAUDE_CODE_HANDOFF.md`: confirmed posture, artifact list,
open questions, known tensions. Tell the user:

> Draft complete. Next: run **/arch-finalize** — ideally in a fresh session or
> subagent so the gap audit gets adversarial eyes — to produce the binding
> repo-root ARCHITECTURE.md.

Then stop. Do not finalize in the same breath you drafted.

---

## Outputs

```
docs/planning/PRESEARCH.md            intake, users, flows, constraints, risks
docs/planning/RESEARCH.md             R# findings with sources + impact
docs/planning/DECISIONS.md            D# ADRs, tagged, research-cited
docs/planning/ARCHITECTURE_DRAFT.md   §-anchored draft
docs/planning/DIAGRAM_PLAN.md         diagram intents, order, color legend
docs/diagrams/*.excalidraw            the standard four, rendered + editable
docs/defense/DEFENSE_SCRIPT.md        chose/considered/why walkthrough + 5-min appendix
docs/planning/CLAUDE_CODE_HANDOFF.md  open questions + tensions for /arch-finalize
```

---

## Hard rules

- Never skip the interview or the posture question.
- Never fabricate values; unknowns stay visible as open questions.
- Never write application code from this skill.
- Never let a capability into the draft without a USERS.md use-case trace.
- Never produce a happy-path-only eval plan.
- Owned tradeoffs may not be softened — honesty is the defense strategy.
