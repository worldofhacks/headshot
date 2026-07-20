# D2/D4 — Agent Interaction + Trust Boundaries (merged)

> Build spec. **This file is the source of truth**; `D2-D4-agent-interaction-trust.excalidraw`
> is a render of it. Any change to the diagram starts here. Export `.svg` + `.png` alongside
> the `.excalidraw` — it does not render on GitHub.
> Serves `DEFENSE_SCRIPT.md` **S3** (walkthrough) and **S4c** (trust boundaries).

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
Z1  AGENTFORGE PLATFORM   blue border, large, left 3/4
Z2  EXTERNAL              gray border, right column
Z3  RAILWAY               gray rounded bar, full width, bottom
    label: RAILWAY — Docker from GitHub · managed Postgres · cron · rollback

=== NODES (5 horizontal bands inside Z1) ===
BAND A  ORCHESTRATOR          blue    "trusted control plane"
BAND B  RED TEAM              red     "untrusted / quarantined"   (dashed border)
        TARGET ADAPTER        red     "allowlist + synthetic data" (shield icon, on Z1 edge)
BAND C  JUDGE                 purple  "independent evaluator"
        DOCUMENTATION         teal    "gated reporting"
BAND D  REGRESSION HARNESS    blue    "deterministic admission · target-change + cron"
BAND E  POSTGRES              green   "exploit DB · checkpoints · SKIP LOCKED queues" (cylinder)
        LANGFUSE + OTEL       green   "traces · per-agent cost"
        LANGGRAPH             blue    "orchestration + interrupt()"
LEFT RAIL
        COVERAGE + FINDINGS   green   "SQL view — system of record"
Z2      LIVE OPENEMR CO-PILOT gray    "API + UI"
        MODEL PROVIDERS       gray    (cloud icon)
        LOCAL OSS MODEL       gray    (server icon)
BELOW-RIGHT
        HUMAN APPROVAL        yellow  "critical publish + remediation" (diamond)
        VULN REPORT           gray    (document icon)

=== EDGES ===
solid unless noted
 1  COVERAGE+FINDINGS -> ORCHESTRATOR   "coverage gaps · open findings · resilience trend"
 2  ORCHESTRATOR      -> RED TEAM       "campaign brief"
 3  ORCHESTRATOR      -> REGRESSION     "trigger regression run"
 4  RED TEAM          -> TARGET ADAPTER "attack sequence"
 5  TARGET ADAPTER    -> LIVE OPENEMR   "allowlisted · synthetic data only"
 6  LIVE OPENEMR      -> JUDGE          "target response"
 7  JUDGE             -> RED TEAM       "partial -> mutate"        [DASHED]
 8  JUDGE             -> DOCUMENTATION  "confirmed exploit"
 9  JUDGE             -> REGRESSION     "admission candidate"
10  REGRESSION        -> TARGET ADAPTER "replay on target change + cron"
11  DOCUMENTATION     -> HUMAN APPROVAL "draft report"
12  HUMAN APPROVAL    -> VULN REPORT    "publish"
13  BAND B/C/D (grouped) -> POSTGRES    "state · findings · queue"   [ONE edge]
14  BAND B/C/D (grouped) -> LANGFUSE    "traces · cost"              [ONE edge]
15  POSTGRES          -> COVERAGE+FINDINGS  "SQL view"
16  MODEL PROVIDERS   -> ORCHESTRATOR   "Opus 4.8"        [DASHED]
17  MODEL PROVIDERS   -> JUDGE          "Sonnet 4.6"      [DASHED]
18  MODEL PROVIDERS   -> DOCUMENTATION  "GPT-5.4"         [DASHED]
19  LOCAL OSS MODEL   -> RED TEAM       "local 24-33B"    [DASHED]

=== POLICY BADGES (small dashed callouts, top-right inside Z1) ===
blue dashed    "Versioned JSON Schemas"            -> points at inter-agent edges 2,7,8,11
purple dashed  "OWASP Web + LLM Top 10"            -> points at RED TEAM
red dashed     "Budget · rate limits · hard abort" -> points at ORCHESTRATOR + TARGET ADAPTER

=== LAYOUT RULES ===
R1  Five bands, top to bottom: A, B, C, D, E. No edge crosses a band boundary twice.
R2  Band E is a SUBSTRATE the agents sit on. Draw ONE grouped connector from the
    agent stack to Postgres and ONE to Langfuse. Never one line per agent.
R3  RED TEAM's only rightward exit is TARGET ADAPTER. No other edge leaves the red
    zone toward Z2 — that visual is the proof of quarantine.
R4  Edge 6 enters JUDGE from the right; edge 7 leaves JUDGE from the left. The mutate
    loop must read as a loop, not a tangle.
R5  Route model-provider dashed edges (16-19) outside the platform border. They are
    supply, not flow.
R6  HUMAN APPROVAL sits outside Z1 — autonomy visibly stops at the platform boundary.
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
