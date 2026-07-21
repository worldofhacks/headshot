# Headshot Operator Console

A **faithful frontend foundation** (React + Vite + TypeScript) for the Headshot Operator Console —
the monitoring-and-intervention instrument for **Headshot**, the target-agnostic autonomous
adversarial-evaluation platform in this repo (`src/agentforge/`).

It is a pixel-faithful recreation of the frozen **titanium & ceramic** design prototype
(`Headshot Console.dc.html`) from the *Headshot Adversarial Testing Console* handoff bundle
(Claude Design). The design is **frozen** — see `DESIGN_SYSTEM.md` in the handoff bundle. Do not
restyle or add features without an explicit new request.

> **Status: faithful frontend foundation — not production-operational.** The UI, routing,
> state machines, accessibility, and honest Demo/Integration presentation are complete and build
> clean, but this is a *foundation*, not a running product. It is **not production-operational**
> until **authentication (Clerk)**, the **read-model + command APIs**, the **FlowEvent stream**,
> and **server-enforced authorization** are integrated. Until then it renders the built-in Demo
> scenario and honest "no live projection" Integration empty-states — never real campaign data.

## Run it

```bash
cd console
npm ci                    # clean install from package-lock.json
npm run dev               # http://localhost:5173
npm run typecheck         # tsc --noEmit
npm run check:forbidden   # fail if clinical/OpenEMR/platform language regresses into the UI
npm run build             # tsc --noEmit + vite build → dist/
npm run preview           # serve the built output
```

Requires Node `^20.19 || >=22.12` (developed on Node 22; Vite 7). No backend is required — the
console runs entirely on its built-in **Demo scenario** (synthetic, animated) plus an honest
**Integration state** (see below). Fonts (Geist / Geist Mono) are **self-hosted** (`src/fonts/`),
so no external font requests are made and a strict `font-src 'self'` CSP holds.

### URL contract (frozen)

The `screen` (+ primary entity) is the route, synced to the address bar and browser history:

```
/live                 /coverage   /resilience   /traces   /costs   /targets   /config
/live/A-0185          (attempt-focused stream)
/findings/F-1042      /approvals/AP-01
```

Navigation updates the URL; direct deep-loads select the right screen/entity; Back/Forward restore
state exactly; and on mobile, Back closes an open drill-in (each drill-in is its own history entry).

## What's here

Nine desktop screens + full mobile parity, faithfully translated from the prototype:

- **Live** — the operational home. Two modes over one authoritative campaign/selection state:
  **Birdseye** (7-band trust-zone war room: untrusted Red Team → trusted Policy Gateway + Recorder →
  trusted Target Connector → separate external target → Recorder `AttemptResult` → independent Judge)
  and **Attempt Stream** (`Queued → Policy check → Executing → Recording → Judging → Resolved`).
- **Findings / Approvals** — verdict + provenance + severity + trust semantics; rationale-required,
  two-person-blocked, non-optimistic decision sheet; guarded campaign **Abort**.
- **Coverage / Resilience / Traces / Costs** — read-only analytics surfaces.
- **Targets** — registry list + six-tab detail, lifecycle (`DRAFT→VALIDATING→READY→DISABLED`+`ARCHIVED`),
  attack-surface versioning, and two-person **probe authorization** (approver ≠ launcher).
- **Configuration** — agent config with model catalog, three-scope effective config, the publish
  lifecycle (`DRAFT→VALIDATING→REVIEW→PUBLISHED→ACTIVE`), and the **Judge-calibration invariant**
  (changing the Judge model/rubric/threshold invalidates calibration → non-oracle cases fail closed
  to `INDETERMINATE` until recalibrated).
- **Mobile** — full-viewport (`env(safe-area-inset-*)`, no device frame), 5-tab bottom nav, Birdseye
  phase accordion + node bottom sheet, and intentional Targets/Configuration drill-in flows that bind
  the **same commands as desktop**.

Two independently-designed themes (dark graphite-ink, light cool-ceramic), compact/comfortable density,
command palette (`⌘K`), and the accessibility contract (focus-trap + scroll-lock overlays, `Esc` to
close, `aria-current`/`role="tab"`, `aria-live` announcements, non-color status channels, 44px mobile
targets, reduced-motion/transparency/contrast handling).

## Architecture

The prototype's single streaming Design Component (`class Component extends DCLogic`) is essentially a
React component with `setState`, so it is ported as a real root class rather than re-architected:

```
src/
  styles/tokens.css   # the frozen :root / [data-theme=light] tokens, verbatim (the "real token layer")
  styles/base.css     # reset, keyframes, reduced-motion/transparency/contrast
  types.ts            # AppState (mirrors the prototype this.state 1:1) + the ConsoleApp contract
  data.ts             # all synthetic fixtures + meta maps, ported verbatim (VMETA, CAT, TARGETX, …)
  App.tsx             # root React.Component — the state authority: every ported method + VM builder,
                      #   the demo tick-loop, and all state machines. render() → <Shell app={this}/>
  components/         # Shell (routing), Sidebar, TopBar, Icon, primitives (VerdictChip, TrustRail, …)
  screens/            # Live, Findings, Approvals, Coverage, Resilience, Traces, Costs, Targets,
                      #   Configuration, Mobile — pure presentational, consume `app`
  overlays/Overlays.tsx  # command palette, abort dialog, decision sheet, model catalog, drawers,
                         #   probe-auth, role menu, toast + aria-live region
```

Colors are always CSS variables from `tokens.css` (assign by **role**, never per-component); depth is
borders-first (shadows reserved for floating layers). See the handoff's `DESIGN_SYSTEM.md` for the full
frozen system.

## Data honesty (important)

There is **no console API today** — every console query/command/stream is **PROPOSED / UNAVAILABLE**
(see `FINAL_IMPLEMENTATION_HANDOFF.md` and `PRODUCTION_INTEGRATION_MAP.md` in the handoff bundle). The
console therefore ships two explicit, structurally-separate data sources, toggled in the top bar:

- **Demo scenario** — synthetic, animated, clearly labelled. All sample data is synthetic; the default
  target is *Atlas Support Agent · v1.4.2 · Staging*. No real PHI, no clinical/vendor/platform branding.
- **Integration state** — renders true per-component availability and shows honest **"no live projection"**
  empty-states wherever a source is absent. Production must **never** silently fall back to demo data.

Frontend authority guardrails are preserved: the browser never computes/upgrades a verdict, never
determines evidence integrity, never holds a provider secret, and no control exceeds a server cap.

## Prototype-only, remove before wiring to production

Per the handoff, these are demonstration affordances, not production controls: the **principal/role
switcher**, the entire **Demo scenario** animation loop (tick/budget-burn/spawn), and any "Simulate …"
control. When a real read-model API + FlowEvent stream lands, flip each surface from Demo scenario to a
live binding (integration order in `FINAL_IMPLEMENTATION_HANDOFF.md` §5: auth → read-model API →
registry/heartbeat → stream → projections → target/surface commands → agent config → approvals → …) and
keep Integration state honest for whatever is not yet wired.

## Provenance

Recreated from `Headshot Console.dc.html` (472 KB streaming Design Component). Tokens and base styles are
transcribed verbatim from the prototype `<head>`; fixtures are ported verbatim from its constructor.
The DC runtime (`support.js`) is intentionally **not** shipped.
