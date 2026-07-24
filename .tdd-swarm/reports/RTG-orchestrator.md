# RTG orchestrator report — red-team gap-closure swarm

**Role:** root orchestrator (PROMPT-ORCHESTRATOR.md + README.md controlling).
**Worktree:** `<repo>` (verified via `pwd`).
**Status:** `BLOCKED(base-precondition)` — held at Wave 0 entry. Live **target** authorization
now received & tracked (see §8); live **platform-deployment** surface still incomplete.
**Last updated:** session start + owner target-authorization received.

---

## 1. Orientation completed

Read in full: `AGENTS.md`, `CLAUDE.md`, `PLAN.md` (via CLAUDE.md summary), the coverage
review `docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md`, the swarm `README.md`,
`PROMPT-ORCHESTRATOR.md`, and the full WP index (WP-01 … WP-22 incl. lettered subpackages)
plus role overlays. Requirements source of truth `Week_3_AgentForge.pdf` acknowledged as
canonical.

Swarm shape understood: 18 waves (Wave 0 → Wave 18), Test → independent Test Review/freeze →
Implementer → independent Code + Security Review per code package, ≤3 concurrent workers,
serialized migrations (WP-02 → WP-10 → WP-04 → WP-11 → WP-16A → WP-18A → WP-15 → WP-19),
contract stewardship (WP-19B), then the live phase WP-21A (zero-call preflight) → WP-21B–E
(live, authorization-gated) → WP-21 reconciliation → WP-22 independent audit.

## 2. Repository state inventory (preserve, do not touch)

| Fact | Value |
|---|---|
| Branch | `swarm/final-submission-gap-closure` |
| HEAD | `66e670fee8c6c66a5236c7d932a0c4a2e9f74b87` (`plan: authorize reviewed OpenRouter execution swarm`) |
| local/origin/gitlab `main` | `23490ea9846bffcf36168b58f2c36edeceabb8df` (all three identical — dual-remote main in sync) |
| Commits ahead of main | 2, both planning-only (`define final submission TDD swarm`, `authorize OpenRouter execution swarm`) |
| Modified tracked files | 92 (unstaged) |
| Untracked files | 123 |
| Dirty in `.tdd-swarm/prompts/` (PROTECTED, count-sensitive) | 52 |
| Dirty under `src/` | 24 |
| Dirty under `console/` | 8 |
| Dirty under `docs/` | 3 |
| Dirty elsewhere (reports, manifest, TICKETS.md, …) | 44 |

The active final-submission swarm (`T-F00 … T-F15`, many lettered subpackages) is
**mid-execution**: `.tdd-swarm/final-submission-manifest.md` is itself dirty and being edited
("session-lease scope repair"); its evidence boundary is anchored on base `23490ea`; it owns
its own live-authorization packages (T-F04b/T-F05b/T-F06b/T-F07b). It is **neither complete
nor deliberately paused.**

## 3. Base-SHA precondition — NOT satisfiable without a human decision

README Precondition #2 (verbatim intent): choose/record a **clean** `<RED_TEAM_GAP_BASE_SHA>`
**after** the active final-submission work "has been integrated or explicitly set aside."
README ¶7–9: this bundle is deliberately outside `.tdd-swarm/prompts/`; do not copy prompts
into that namespace "until the active swarm is complete or deliberately paused."

Neither condition holds. Every path to a clean base requires an action I am explicitly
forbidden to take unilaterally:

1. **Commit / integrate the active work** → that is "integrating" it on the user's behalf and
   risks corrupting the count-sensitive 82-prompt contract in `.tdd-swarm/prompts/`. Forbidden
   ("preserve all user changes; never edit the count-sensitive namespace").
2. **Stash / set aside the active work** → that is "explicitly setting it aside" — the user's
   decision, not mine; also risks the 123 untracked files and the count-sensitive namespace.
3. **Run the swarm on the dirty tree (base = HEAD 66e670f, dirty)** → breaks the swarm's core
   discipline: per-package disjoint file ownership, frozen test-file hashes, immutable
   `<REVIEW_SHA>`, reviews scoped to `<DIFF_BASE>..<REVIEW_SHA>`, and `git diff --check` are
   all contaminated when ~215 uncommitted changes ride every branch checkout. A "clean base"
   in the README's sense does not exist while the tree is dirty.
4. **Run in a separate `git worktree` at 66e670f (excludes the uncommitted work)** → builds the
   gap-swarm on a base that omits the in-flight final-submission changes to the *same* files
   (`policy/gateway.py`, `runner.py`, `coordinator.py`, `target/openemr_adapter.py`,
   `campaign/*`, `api/*`, console). Guarantees a massive future merge conflict — exactly what
   Precondition #2 exists to prevent. Contradicts the explicit *sequencing* requirement.

**Conclusion:** no safe default exists. Resolving the active swarm (integrate **or** pause) is
a decision only the user can make. Candidate base once resolved is recorded below.

- **Candidate `<RED_TEAM_GAP_BASE_SHA>` (pending user decision):** to be the sole current head
  after the active swarm is integrated or paused. If paused-in-place with a clean tree at
  today's HEAD, that is `66e670f`; if the final-submission work is merged to `main` first, the
  base becomes that new integrated head. **Not yet recorded as final — awaiting decision.**

## 4. Second, predetermined blocker — live validation is unauthorized

The kickoff states verbatim: **"This kickoff message is not campaign autho."** The Live-only
evidence law (README §"Live-only evidence law") and WP-21 require named, hash-bound
authorization artifacts that must **never** be synthesized:

- exact deployed Railway release SHA + dual-remote/CI-green attestations;
- owner-authorized deployed OpenEMR **live test-environment URL** with seeded synthetic
  **non-PHI** live records and provisioned test principals;
- Headshot/Clerk controls, separate campaign authorizations, genuine pinned tools/providers,
  budgets, rate caps, aborts, and observation points.

None are present in this kickoff. Therefore, independent of the base-SHA blocker:

- WP-21B–E are **predetermined `BLOCKED`** (missing live authorization ≠ permission to
  substitute a mock/fixture/cassette/fake-target — that stays non-evidentiary).
- WP-22 **cannot** certify the platform as "fully live-validated"; every behavioral criterion
  requiring live proof (RT-01/02/03/04/05/06/07/08 live legs, and the RT-09–14 live legs)
  remains open/blocked.

Even a fully successful WP-01 → WP-20 build yields only `LIVE_EVIDENCE_REQUIRED` implementation
prechecks — never operational/demonstrated/regression-protected/closed status.

## 5. Decision required from the user (single unblock)

To let Wave 0 begin safely, choose how the active final-submission swarm is resolved so a clean
base exists (README Precondition #2):

- **(A) Pause the active swarm in place** — you commit or stash the ~215 uncommitted changes
  yourself (so the count-sensitive namespace stays under your control), tell me the resulting
  clean head SHA, and I take that as `<RED_TEAM_GAP_BASE_SHA>`.
- **(B) Integrate the active swarm first** — land the final-submission work onto `main`
  (dual-remote, CI green), then I base the gap-swarm on that new integrated head.
- **(C) Explicitly authorize a separate isolated worktree at a base you name**, accepting the
  future-merge-conflict risk in §3 item 4, and explicitly waiving Precondition #2's sequencing
  for that isolated run.

Separately, live validation (WP-21B–E, and any WP-22 "closed" claim) needs the §4 authorization
artifacts. Absent those, the swarm can at most reach WP-20 + WP-21A (zero-call preflight), and
the honest end-state is **not fully live-validated**.

## 6. Predetermined answers to the final required report (as of now)

1. **Integrated commits / completed waves:** none. Held at Wave 0 entry pending §5 decision.
2. **Test/review status:** no packages dispatched; no tests authored/frozen; no reviews run.
3. **Live evidence / independent review status:** none produced; WP-21 phase not reachable
   without §4 authorization.
4. **RT-01…RT-14:** 0 closed. All 14 are `BLOCKED` on the base-SHA decision (§3) and, for their
   live legs, on live authorization (§4). None can be closed by local/deterministic evidence.
5. **Exact remaining blockers:** (a) base-SHA precondition — active swarm not integrated/paused
   (§3); (b) live-campaign authorization + deployed-target/Railway/Clerk artifacts absent (§4).
6. **Fully live-validated?** **No** — and cannot be, in this session, without the §4 live
   authorizations. Local tests never establish coverage or closure (README closure standard).

## 7. Orchestrator actions taken (safe, non-destructive)

- Verified worktree via `pwd`; inventoried and preserved all dirty files (no writes to tracked
  files, no writes anywhere under `.tdd-swarm/prompts/`, no branch/reset/checkout/stash/push).
- Created this report only (new file under `.tdd-swarm/reports/`, the location the kickoff
  designates).
- **No** provider/target/ZAP/OAST/browser/deployment/publication/remediation/spend/push/merge
  action was taken (compliant with WP-01…WP-20 external-action freeze and the unauthorized live
  phase).

---

## 8. Session update — owner target authorization received (tracked, SID-free)

The owner supplied a **live target authorization** in answer to §5. It is recorded SID-free at
`.tdd-swarm/reports/RTG-target-authorization.md` and summarized here.

- **Target:** `https://agent-production-9f62.up.railway.app`; surfaces Week1 `/app`, Week2
  `/week2`, plus `POST /chat {session_id,message}`. Synthetic-only, bounded, ≤3 workers, no
  DoS/infra-change/rotation/deletion. Two per-week **SIDs = bearer credentials**, stored ONLY in
  the out-of-repo bundle; never committed here.
- Target is **already partially wired** in-repo (`README.md`, `docs/evidence/zap/*`,
  `evals/results/live-campaign-20260724/*`, three `AF-VULN-2026-0724-*` reports,
  `scripts/live_probe.py`, `console/vite.config.ts`); a prior live run (`aceddc4…`) already hit
  it (9×200 / 9 INDETERMINATE / $0.09).

**What this changes:** the *owner-authorized deployed live target URL + surfaces + provisioned
synthetic principals* requirement is now satisfied — a real advance for RT-07 (Week2 exposes the
missing ingestion/upload/extraction/RAG surfaces) and for the live legs generally.

**What it does NOT change — the swarm is still blocked from starting:**

1. **[Still blocks Wave 0]** Base-SHA precondition (§3). The owner's answer did not integrate or
   pause the active final-submission swarm; the tree still carries ~215 uncommitted changes incl.
   52 files in the protected `.tdd-swarm/prompts/` namespace. I cannot safely begin the TDD code
   waves. **This is the single gating item.**
2. **[Blocks live phase]** The rest of the WP-21A surface is absent: exact deployed **AgentForge
   platform** Railway SHA, dual-remote/CI-green for it, Headshot/Clerk controls, a **separate**
   two-person approver identity (launcher ≠ approver), platform budgets/rate caps/abort wiring,
   observation points. Target-auth ≠ platform-auth.
3. **[Blocks live phase]** The capabilities a live campaign would exercise (mutation loop,
   semantic/oracle Judge, OAST, browser, active ZAP, expanded corpus, wired regression) mostly do
   not exist yet — they are what WP-01→20 build. Live execution "through production code paths"
   is impossible for code not yet written.
4. **[Architecture caveat]** The bundle is a **Bruno CLI** harness = an *independent* target
   exerciser, not the AgentForge production path. It can corroborate + seed regression, but does
   not by itself satisfy WP-21 "operational/demonstrated" (which requires the deployed platform's
   own gateway/adapter/Recorder/Judge).

**Remaining single decision to start the build waves:** resolve the active swarm so a clean base
exists — options A (you pause & give me the clean head SHA), B (integrate final-submission to
main first), or C (explicitly authorize an isolated worktree at a named base, waiving
Precondition #2's sequencing and accepting future-merge-conflict risk). Until then, held at Wave
0. The tracked target authorization will be consumed by WP-21A once the build reaches the live
phase and the §2 platform-deployment surface is present.

---

## 9. Session update — base largely cleared; one temporary blocker (active live run)

Re-inventoried live state. **Major progress:**

- HEAD advanced `66e670f → 54b3a4d3` (branch `swarm/final-submission-gap-closure`, now **5 ahead
  of `main`**). New commits: `efd5ce3` register authorized targets · `23fbdfe` authorized
  synthetic live campaign (target config/scan/draft reports) · `54b3a4d3` final live findings +
  target config + 4 vuln reports.
- **Protected `.tdd-swarm/prompts/` namespace is now 0 dirty** (committed). Dirty count fell
  ~215 → **9**.
- **Secret hygiene verified solid:** `54b3a4d3` gitignores `**/Runtime.bru`,
  `**/adversarial-smart-bruno-*/`, `**/claude-adversarial-run/`, `tmp/`; SIDs stay in gitignored
  `.env.campaign`/`.env.local`. Working-tree SID sweep = clean (no SID string anywhere in-repo).

**One remaining, temporary blocker — an active live campaign is mutating the tree:**

- Process **PID 61972** `python scripts/platform_live_run.py`, `LC_CAMPAIGN_RUN_ID=
  platform-live-20260724b-week1` (paced), is **running now**. The 9 dirty entries are its output
  (old `…20260724-week1` manifests deleted, new `…20260724b-week1/` attempts DX-001/DX-002 being
  written, `approval.json` + `scripts/platform_live_run.py` modified).
- Therefore **no clean base exists yet** and starting the gap-swarm now is unsafe: worker
  branches, `scripts/check.sh`, `git diff --check`, and frozen-hash freezes cannot run against a
  tree a live process is actively rewriting, and the swarm must not interfere with a live run.

**Base-SHA decision (resolved in principle):** the owner effectively chose path A/B-hybrid by
committing the active work to the branch. Intended `<RED_TEAM_GAP_BASE_SHA> = 54b3a4d3` (or its
clean successor once the in-flight live-run output is committed/stashed). **Awaiting a clean
tree** (live run finishes or is paused → its 9 entries committed/stashed).

**Live-phase closure caveats (unchanged; block WP-21 closure, NOT the WP-01→20 build):** platform
Railway SHA + dual-remote/CI-green for it + Clerk/Headshot + separate two-person approver +
platform budgets/rate/abort + observation points still required; and the capabilities WP-01→20
build do not exist yet, so live "through production code paths" comes only after the build.

**Ready-to-start trigger:** clean working tree at `54b3a4d3` (or successor) → I lock the base,
reserve no migration until WP-02's wave, and dispatch Wave 0 (WP-01 physical dispatch gate;
WP-07 public shell; WP-08 ownership authorization) under the Test → Test-Review/freeze →
Implement → Code+Security review sequence, ≤3 workers.

---

## 10. Gap analysis outcome — DE-SCOPED execution plan (do the biggest/best only)

Ran a 7-agent grounded gap analysis (workflow `wf_3207c24e-216`) against current code, through two
lenses: expand security-SCAN capability + use ALL tools fully on every user-engaged run.

**Core finding:** a user-engaged run today **VALIDATES a fixed ~14-case corpus; it does not
red-team generatively and invokes ZERO security tools live.** Garak/PyRIT/Giskard/Promptfoo
contribute only 5 pre-baked single-turn prompt-injection candidates frozen offline by sha256;
ZAP/fuzzer/OAST/browser never run; only 1 oracle fires (substring canary) so 7/9 seeds →
permanent `INDETERMINATE`. The web findings (AF-VULN-004/005/006) came from an **external Bruno
client, not the platform scanner.**

**Hard ordering rule:** decisiveness gates breadth. More tools/corpus before oracles = more
INDETERMINATE, not more findings. **WP-11 oracles/instrumentation MUST precede all breadth work.**

**Ranked focus (execute these):**
1. WP-11 — deterministic recorder/tool-call + state-diff oracles & trusted observation. *Value
   gate for everything.* (L)
2. WP-13 + WP-13E — tool broker + wire the 4 adapters into the run behind `target_scope:none`,
   dispatch via existing PolicyGateway. *Seed-replay → generative scan; per-run tool use 0→N.* (L)
3. WP-14 — full-spectrum corpus (all 6 PRD categories + OWASP Agentic ASI) as default workload. (L)
4. WP-13A/13B/13C — Garak multi-family · PyRIT multi-turn (Crescendo/TAP) · Giskard RAG/agent. (M/L)
5. WP-12(config-unpin, S) + WP-16B fuzzer + WP-17 BOLA/BFLA matrix over the **already-built** Week2
   upload/read/RAG surfaces (currently `enabled:false`). *Highest find-power vs the real target.*
6. WP-03 + WP-16D — pin validated destination (DNS-rebind TOCTOU) + governed process-egress.
   *Prerequisite that gates all live active-process/web scanning.*
7. WP-15 — authorized feedback mutation loop (new hash + 2nd authorization). *After 1,2,4.*
8. WP-05 — expired-lease reaper loop (crash self-heal for long autonomous scans). (M)

**Deliberately DEFER/SKIP (not the biggest levers now):**
- **Already done:** WP-01 (RT-09 abort/lease/scope re-check); the live-coordinator run + AF-VULN-004/5/6.
- **Hardening, not capability:** WP-02 DB roles, WP-04 idempotency (fold into 13B), WP-06/07/08
  readiness/public-shell/ownership-auth. WP-09 = 1-line ZAP evidence-drift truthfulness fix (do
  inline, not as a lever).
- **Low-ROI this window:** WP-13D Promptfoo (overlaps Garak), WP-16A/16C workbench/checks,
  WP-18A OAST, WP-18B WebSocket/DOM, WP-19A report export. WP-19 regression loop → re-open only
  AFTER rank-1 oracles make replays decisive.

**Sequence (honoring ≤3 workers + serialized contract/migration):** W0 parallel {WP-09 fix ·
WP-12 config-unpin · WP-03 pin} → W1 lead {WP-11 via contract-steward} → W2 {WP-13/13E broker ‖
WP-14 corpus; serialize the two schema migrations} → W3 {13A‖13B(+WP-04)‖13C behind broker} →
W4 {WP-16D egress first, then WP-16B‖WP-17‖passive-ZAP live} → W5 {WP-15 → WP-05 → reopen WP-19}.

**Caveats:** live-web scan needs a separate persisted ZAP/target authorization (campaign approval
is insufficient); the "Week2 surfaces already addressed" analyst flag was WRONG — surfaces built
but still `enabled:false`, so config-unpin is genuinely not-done; two-person + gateway-owned
dispatch invariants must hold through every lever; WP-13/WP-15 each add a new inter-agent contract
(serialization tax not in the L estimate).

**Base/live status:** live run finished (0 processes); HEAD `1ac3ee0`, 6 ahead of main, tree DIRTY
(25 entries = completed run output). Ready to lock base + start W0 the moment the tree is clean.
