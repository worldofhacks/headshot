# D2/D4 — Agent Interaction + Trust Boundaries (merged)

> Build spec. **This file is the source of truth**; `D2-D4-agent-interaction-trust.excalidraw`
> is a render of it. Any change to the diagram starts here. Export `.svg` + `.png` alongside
> the `.excalidraw` — it does not render on GitHub.
> Serves `DEFENSE_SCRIPT.md` **S3** (walkthrough) and **S4c** (trust boundaries).
>
> ⚠️ **RENDER STALE — INTEGRATION FOLLOW-UP REQUIRED (2026-07-21).** This spec includes both the F2
> trust-split correction and the selected Clerk/Railway identity boundary. The Red Team's one exit is a
> **trusted Policy Gateway + Execution Recorder** (blue), and the Judge reads the recorder's hashed
> `AttemptResult` rather than the raw target response. The existing `.excalidraw`, SVG, and PNG do not
> yet show that complete topology. Regenerate all three together from this spec; do not present the
> current exports as the authenticated deployment. (`ARCHITECTURE.md` §5, `DECISIONS.md` D14.)

```
DIAGRAM D2/D4 — AgentForge Agent Interaction + Trust Boundaries (merged)
Style: Excalidraw, hand-drawn, color-zoned. Export SVG + PNG.

TITLE:    AgentForge — Adversarial Machine
SUBTITLE: Continuous multi-agent red-teaming of the live OpenEMR Clinical Co-Pilot

=== COLOR LEGEND (bottom-left, 6 entries) ===
blue        = trusted control plane
green       = data & observability plane
purple/teal = governed evaluators
red/orange  = quarantined (untrusted)
gray        = external
yellow      = human gate

=== ZONES ===
Z0  HUMAN + MANAGED IDP  gray border, top strip
Z1  RAILWAY PLATFORM     blue border, large, left 3/4
    label: RAILWAY — public Web edge · private services/network · rollback
Z2  EXTERNAL EXECUTION   gray border, right column

=== ENTRY + IDENTITY NODES ===
Z0      HUMAN BROWSER         gray    "invited Headshot member · MFA"
Z0      CLERK                 gray    "managed IdP · required Headshot Organization · custom permissions"
Z1 EDGE PUBLIC WEB            blue    "ONLY public service · health/auth shell allowlist · protected API/console"

=== NODES (5 horizontal bands inside the private portion of Z1) ===
BAND A  ORCHESTRATOR          blue    "trusted control plane"
BAND B  RED TEAM              red     "untrusted / quarantined"   (dashed border)
        POLICY GATEWAY +      blue    "TRUSTED enforcement boundary: allowlist · scoped creds ·
        EXECUTION RECORDER            synthetic data · budget/rate · hard abort · hashed AttemptResult"
                                      (shield icon, on Z1 edge — the Red Team's ONE exit; holds the
                                       TargetAdapter + the only target credentials)
BAND C  JUDGE                 purple  "independent evaluator"
        DOCUMENTATION         teal    "gated reporting"
BAND D  REGRESSION HARNESS    blue    "deterministic admission · target-change + schedule"
        PRIVATE SCHEDULER     blue    "Railway private service · trigger only"
BAND E  PRIVATE POSTGRES      green   "Railway managed DB · exploit DB · checkpoints · SKIP LOCKED queues"
                                     (cylinder; no public endpoint)
        PRIVATE RUNNER        blue    "Railway private service · agents and campaign workers"
        LANGFUSE + OTEL       green   "traces · per-agent cost"
        LANGGRAPH             blue    "orchestration + interrupt()"
LEFT RAIL
        COVERAGE + FINDINGS   green   "SQL view — system of record"
Z2      LIVE OPENEMR CO-PILOT gray    "external deployed API + UI"
        MODEL PROVIDERS       gray    (cloud icon)
        LOCAL OSS MODEL       gray    (server icon)
BELOW-RIGHT
        HUMAN APPROVAL        yellow  "critical publish + remediation" (diamond)
        VULN REPORT           gray    (document icon)

=== EDGES ===
solid unless noted
 0a HUMAN BROWSER     -> CLERK           "invitation-only sign-in · MFA · Organization membership"
 0b CLERK             -> HUMAN BROWSER   "short-lived session token"
 0c HUMAN BROWSER     -> PUBLIC WEB      "HTTPS · Bearer session_token"
 0d PUBLIC WEB        -> PRIVATE RUNNER  "verified identity + authorized intent; token never forwarded"
 0e PRIVATE SCHEDULER -> ORCHESTRATOR    "scheduled regression trigger"
 1  COVERAGE+FINDINGS -> ORCHESTRATOR    "coverage gaps · open findings · resilience trend"
 2  ORCHESTRATOR      -> RED TEAM        "campaign brief"
 3  ORCHESTRATOR      -> REGRESSION      "trigger regression run"
 4  RED TEAM          -> POLICY GATEWAY  "AttackAttempt (proposed input — no creds, no evidence)"
 5  POLICY GATEWAY    -> LIVE OPENEMR    "execute: allowlisted · scoped creds · synthetic data only"
 5b LIVE OPENEMR      -> EXECUTION RECORDER "target response (recorded)"
 6  EXECUTION RECORDER-> JUDGE           "AttemptResult (hashed · append-only)"
 7  JUDGE             -> RED TEAM        "partial -> mutate"        [DASHED]
 8  JUDGE             -> DOCUMENTATION   "confirmed exploit"
 9  JUDGE             -> REGRESSION      "admission candidate"
10  REGRESSION        -> POLICY GATEWAY  "replay (new run-nonce, re-executes live) on target change + schedule"
11  DOCUMENTATION     -> HUMAN APPROVAL  "draft report"
12  HUMAN APPROVAL    -> VULN REPORT     "publish"
13  BAND B/C/D (grouped) -> PRIVATE POSTGRES "state · findings · queue" [ONE private edge]
14  BAND B/C/D (grouped) -> LANGFUSE     "traces · cost"              [ONE edge]
15  PRIVATE POSTGRES  -> COVERAGE+FINDINGS "SQL view"
16  MODEL PROVIDERS   -> ORCHESTRATOR    "Opus 4.8"        [DASHED]
17  MODEL PROVIDERS   -> JUDGE           "Sonnet 4.6"      [DASHED]
18  MODEL PROVIDERS   -> DOCUMENTATION   "GPT-5.4"         [DASHED]
19  LOCAL OSS MODEL   -> RED TEAM        "local 24-33B"    [DASHED]

=== POLICY BADGES (small dashed callouts, top-right inside Z1) ===
blue dashed    "Versioned JSON Schemas"            -> points at inter-agent edges 2,7,8,11
purple dashed  "OWASP Web + LLM Top 10"            -> points at RED TEAM
red dashed     "Budget · rate limits · hard abort" -> points at ORCHESTRATOR + POLICY GATEWAY
yellow dashed  "Clerk: RS256 local verification · exact azp + org · custom permissions"
                                                     -> points at PUBLIC WEB
yellow dashed  "Authentication != campaign authorization · distinct approver"
                                                     -> points at edge 0d + HUMAN APPROVAL

=== LAYOUT RULES ===
R1  Five bands, top to bottom: A, B, C, D, E. No edge crosses a band boundary twice.
R2  Band E is a SUBSTRATE the agents sit on. Draw ONE grouped connector from the
    agent stack to Postgres and ONE to Langfuse. Never one line per agent.
R3  RED TEAM's only exit is the trusted POLICY GATEWAY. The attacker holds no credentials
    and never produces the evidence the Judge reads — no edge carries a raw target response
    or a Red-Team-authored transcript to the Judge. That visual is the proof of quarantine.
R4  Edge 6 (EXECUTION RECORDER -> JUDGE) enters JUDGE carrying the hashed AttemptResult;
    edge 7 leaves JUDGE toward the RED TEAM. The mutate loop must read as a loop, not a tangle.
R5  Route model-provider dashed edges (16-19) outside the platform border. They are
    supply, not flow.
R6  HUMAN APPROVAL sits outside Z1 — autonomy visibly stops at the platform boundary.
R7  PUBLIC WEB is the only Internet-reachable Railway service. Runner, scheduler, and Postgres
    stay behind Railway's private boundary; no browser edge reaches them directly.
R8  Do not draw a request-time PUBLIC WEB -> CLERK verification edge. The Web verifies Clerk
    session tokens networklessly with the configured PEM public key, exact authorized party,
    exact Headshot Organization ID, and custom permission claims. Clerk remains on the sign-in flow.
R9  The session token terminates at PUBLIC WEB. Downstream edges carry a minimal immutable human
    principal, never the Authorization header or token. Human identity is distinct from workload/
    agent identity, and neither identity alone proves live-campaign authorization.
```

## Why these choices

- **`COVERAGE + FINDINGS` replaces a generic "Observability" box.** Per `DECISIONS.md` D5,
  Langfuse observes the *campaign* while the Postgres exploit DB is system-of-record for
  finding status and resilience trend, surfaced through a SQL view. Naming the view makes
  edge 1 — the "why this learns instead of attacking randomly" edge — self-explanatory.
- **Green is in the legend.** It carries three nodes; an unlegended color is a question
  waiting to be asked.
- **R2 kills the crossing-line cluster.** Shared infrastructure reached by one grouped
  connector instead of one line per consumer.
- **R3 turns quarantine into evidence.** A single exit from the red zone is the picture
  that answers S4c before it is asked.
- **The exit is trusted, not red (F2).** The enforcement boundary — allowlist, scoped
  credentials, budget/rate, hard abort — cannot be an untrusted component; it is the blue
  **Policy Gateway + Execution Recorder**. The Judge reads that recorder's hashed
  `AttemptResult`, so the attacker never controls the evidence the Judge evaluates. This is
  the diagram's load-bearing correction (`ARCHITECTURE.md` §5, `DECISIONS.md` D14).
- **Identity terminates at the public edge.** Clerk performs invitation-only sign-in and MFA;
  Railway Web verifies the session token without a request-time IdP call and passes only a reduced
  principal into the private plane. The identity gate and two-person campaign policy are shown as
  separate controls so the diagram cannot imply that a valid login authorizes a live attack.
