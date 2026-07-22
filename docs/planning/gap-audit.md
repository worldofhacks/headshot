# gap-audit.md — /arch-finalize coverage audit (AgentForge / Adversarial Machine)

> Workpaper for the adversarial finalize pass (2026-07-20). Audits `ARCHITECTURE_DRAFT.md` +
> all planning artifacts against the PRD (`Week_3_AgentForge.pdf`) across the 12 arch-finalize
> dimensions, judged at **production-grade** posture. Inputs: `REVIEW_FINDINGS.md` (F1–F12,
> mandatory), a primary-source verification pass (F3/F8/F12), a cold-eyes re-audit (17 new
> findings), and the user's resolution at the finalize gate. The binding record of each
> resolution lives in **`ARCHITECTURE.md` §20** and **`DECISIONS.md`**; this file is the audit
> trail. Section references (`§N`) are to the finalized repo-root `ARCHITECTURE.md`.

## 0. Gate decisions (user, 2026-07-20)

| Topic | Decision |
|---|---|
| **F3 observability** | **Langfuse Cloud (Hobby, free) for MVP**, synthetic data only; self-host documented as post-MVP with its full 6-container footprint. Keeps D6's one-Postgres/no-Redis true. |
| **F7 Red Team inference** | **Config-switch; deployed default = hosted OSS uncensored**; local Mac reserved for dev + cost-baseline. Mac tok/s stays an `open question`. Makes "continuous/unattended" true on Railway. |
| **F1 Judge invariant** | Adopt as prescribed (deterministic, fail-closed **verdict state machine**); **async dual-judging** in calibration, **not** per-case second-Judge concurrence. Full spec → `DECISIONS.md` D13. |
| **F2 trust split** | Adopt as prescribed (untrusted generator → **trusted policy gateway + execution recorder** → external target; Judge sees recorder `AttemptResult` only). **Canonical-hash + append-only** evidence integrity, **not** signatures, within the shared trust domain; signing/KMS = documented hardening path. Full spec → `DECISIONS.md` D14. |
| **Fix scope** | **Full content propagation**: ARCHITECTURE.md + DECISIONS.md + content-only corrections to THREAT_MODEL (F8), ADR-0001 (F12), diagram spec (F2, render flagged for regen), DEFENSE_SCRIPT (F11 + F1/F2 content). No format changes to the hand-revised beat/legend files. |

## 1. Primary-source verification (claims that overturn locked decisions)

| Claim | Verdict | Source | Consequence |
|---|---|---|---|
| **F3** — Langfuse self-host needs Web+Worker+Postgres+**ClickHouse**+**Redis/Valkey**+**S3** (all required); documented min "≥2 CPU/4 GB across all containers" (the "~4 vCPU/8 GB" is a realistic *total* estimate, **not** a Langfuse-quoted figure). Cloud Hobby = $0, 50k units/mo, 2 users, 30-day retention, no card. | **supported** | langfuse.com/self-hosting (+ /infrastructure/{clickhouse,cache,blobstorage,containers}, /pricing) | D5 amended → Langfuse Cloud for MVP; self-host footprint documented honestly. |
| **F8** — OWASP Top 10:**2025** has shipped; SSRF (was A10:2021) folded into **A01**; Injection **A03:2021→A05:2025**; new **A03:2025** Software Supply Chain Failures, **A10:2025** Mishandling of Exceptional Conditions. 2021 has SSRF standalone (A10) + Injection (A03); the PRD enumerates SSRF standalone → **PRD is anchored to 2021**. | **supported** | owasp.org/Top10/2025 (+ /0x00_2025-Introduction), owasp.org/Top10/2021 | Map to **2021 explicitly**; add 2021↔2025 crosswalk; store `{framework,version,id,name}` tags (D15). |
| **F12** — Promptfoo maps OWASP **Web** Top 10 "with no custom code" (a turnkey `owasp:web` preset). | **refuted** | promptfoo.dev/docs/red-team/{configuration,plugins,owasp-api-top-10}, /blog/owasp-red-teaming | **No `owasp:web` preset exists.** Promptfoo ships `owasp:llm`, `owasp:api`, `mitre:atlas`, `nist:ai:measure` (+ `owasp:agentic`, `eu:ai-act`, `iso:42001`, `gdpr`). Soften ADR-0001; assign OWASP-Web mapping to **our deterministic validator over ZAP output**; note `owasp:api` partially covers the API/write-back surface. |

## 2. PRD coverage table (must-haves — zero blank cells)

> Optional Engineering Deliverables are **graded/mandatory** per the PRD's own text and CLAUDE.md — treated as must-haves below.

| PRD | Requirement (abridged) | Covered by | Status |
|---|---|---|---|
| PRD-01 | Deployed target URL every checkpoint; tests a live system | §2, §19 (README seam), hard gate | covered |
| PRD-02 | Target running locally + deployed, testable | §2, §17 (OQ1/OQ2 resolve at Stage 1) | covered (external; seam named) |
| PRD-03 | Document changes to make target testable → README/threat-model | §2, §19 (README/THREAT_MODEL seam) | covered (seam) |
| PRD-04 | Threat model: 6 attack categories, full surface | `THREAT_MODEL.md`; §5 (taxonomy) | covered |
| PRD-05 | Per-category surface/impact/difficulty/existing-defenses | `THREAT_MODEL.md` (per-category blocks) | covered |
| PRD-06 | `THREAT_MODEL.md` + ~500-word summary + priority | `THREAT_MODEL.md` | covered |
| PRD-07 | Seed adversarial cases, highest-priority categories (not static) | §6 (AttackCase), §10, §16 (mutation loop) | covered |
| PRD-08 | Attack-case field list (cat/subcat, input seq, expected-safe, observed, severity+exploitability, regression flag) | §6 (**AttackCase field table**) | covered (added) |
| PRD-09 | `./evals/` ≥3 categories + ≥1 live agent vs deployed target | §3, §10, §18, §19 | covered (plan) |
| PRD-10 | Forward architecture plan: roles, I/O, coordination | §3, §4 | covered |
| PRD-11 | Address: who does what · comms/format · Orchestrator targeting · Judge→regression · human gates · AI-vs-deterministic · cost/rate/scale · state framework | §3–§16 (each bullet mapped) | covered |
| PRD-12 | `ARCHITECTURE.md` + ~500-word summary + agents + trust + diagram | §1, §3, D2/D4 diagram | covered |
| PRD-13 | Multi-agent, distinct authority (not single-agent/pipeline) | §3 (6 agents, distinct trust) | covered |
| PRD-14 | Collective capabilities: generate·mutate·multi-turn·evaluate·prioritize·halt-on-no-signal·trigger-regression | §3, §10, §11 (circuit-breaker), §13 | covered |
| PRD-15 | Separate attack generation from evaluation; Judge independent | §3, §5, D14 (recorder mediation) | covered (strengthened) |
| PRD-16 | Justify model per role (refusal + cost) | §8, D8 (amended) | covered |
| PRD-17 | Red Team probes/mutates/escalates autonomously | §3, §16 (build: mutation loop) | covered |
| PRD-18 | Judge: sole evaluator; criteria; anti-drift; validate the judge | §3, D13, §15, `judge-calibration` | covered |
| PRD-19 | Orchestrator reads state → directs Red Team | §3, §9, §13 (fallback policy) | covered |
| PRD-20 | Documentation Agent: confirmed exploit → report, no human writing | §3, §6 (VulnReport), §19 | covered |
| PRD-21 | Vuln-report field list (ID+severity, desc+clinical impact, min repro, observed/expected, remediation, status+fix-validation) | §6 (**VulnReport field table**) | covered (added) |
| PRD-22 | Senior engineer reproduces from report alone | §6 (Documentation acceptance criterion) | covered (added) |
| PRD-23 | Regression harness: versioned store, auto-run, detect reappearance + cross-category regressions | §10 | covered |
| PRD-24 | Regression passes because *fixed*, not because behavior changed | §10 (admission invariant), D13, §18 (test) | covered |
| PRD-25 | Observability answers the six questions | §9 | covered |
| PRD-26 | Observability = data substrate the Orchestrator reads | §9, §13 (Langfuse-down fallback) | covered |
| PRD-27 | Trust boundaries + human approval gates before autonomous publish/remediation | §5, §14 (two-person rule) | covered (strengthened) |
| PRD-28 | OWASP **Web** Top 10 + OWASP **LLM** Top 10 mapping per case | §5 (taxonomy, D15), §16 (ZAP+validator; Promptfoo `owasp:llm`) | covered (F12/F8 corrected) |
| PRD-29 | GitHub repo: setup, arch overview, deployed link, run instructions | §19, README seam | covered (seam) |
| PRD-30 | `USERS.md` users/workflows/why-automation | `USERS.md`; every §capability traces to it | covered |
| PRD-31 | Demo video 3–5 min, live attacks | §19 (submission artifacts) | covered (seam) |
| PRD-32 | ≥3 vulnerability reports | §6, §19 | covered (seam) |
| PRD-33 | Cost analysis @ 100/1K/10K/100K runs; not tokens×N | §11 (F4 corrected), D17 | covered (method; numbers `open question`) |
| PRD-34 | Deployed application; live tests | §2, §12, §19 | covered |
| PRD-35 | Social post (Final), tag @GauntletAI | §19 | covered (seam) |
| PRD-36 | Schedule: Defense (~2.5h) · MVP (Tue) · Final (Fri) | §17, `PLAN.md` | covered |
| PRD-37 | Eight core objectives (discover/generate/measure/convert/validate/prevent-regression/document/visibility) | §3, §9, §10, §16 | covered |
| PRD-OPT-01 | Every case = boundary\|invariant\|regression (not static) | §6, §10, §18 | covered |
| PRD-OPT-02 | Build-vs-configure ADR (Burp/ZAP/Semgrep/Garak/COTS) | §16 → ADR-0001 (F12 corrected) | covered |
| PRD-OPT-03 | Triage 10+ findings (crit/high/med/false-positive) | §19 (**Triage exercise seam**) | covered (added) |
| PRD-OPT-04 | Typed contracts every boundary + contract tests + migration notes + evidence packet | §4, §19, `contract-steward` | covered |
| PRD-OPT-05 | Integration: build one / inherit one / integration lead | §4, §19 (**Integration packet seam**) | covered (added) |
| PRD-OPT-06 | Versioned schema in `/contracts`; both-sided conformance; breaking→version bump | §4, D10 | covered |
| PRD-OPT-07 | ATO-style evidence packet (arch+data-flow diagram, **auth model**, dep list w/ versions, self-scan, test evidence, incident/postmortem) | §19 (**ATO packet seam** + auth-model matrix) | covered (added) |
| PRD-OPT-08 | AI-use disclosure; Judge criteria independently verifiable; detect/correct drift | §15, D13, `judge-calibration` | covered |
| PRD-OPT-09 | Integration packet (diffs, ADRs, contract-test results, dep map, e2e trace) | §19 | covered (added) |
| PRD-OPT-10 | Version API contracts (min v1); breaking→bump+migration note+tests | §4, D10 | covered |
| PRD-OPT-11 | Explicit typed error schemas per failure mode, in `/contracts` | §4 (error taxonomy) | covered |
| PRD-OPT-12 | Document rate limits + auth for every external API; backoff/queue/abort in ARCHITECTURE | §5, §11, §17 (OQ for exact caps) | covered (method; exact caps `open question`) |
| PRD-OPT-13 | Data-quality checks (unique ID, required fields, no dup sequence) in Documentation Agent | §6 (validators, shared with CI) | covered |
| PRD-OPT-14 | Migration without data loss; queue depth monitoring + backpressure | §6, §7, §11, §12 (expand/contract) | covered |
| PRD-OPT-15 | Data model + access control (who writes/reads exploits; human approval) | §6 (per-agent DB roles), §5, §14 | covered (strengthened) |
| PRD-OPT-16 | SQL indexes on common query patterns; regression SLO verified in CI | §6, §10 (tiered SLO), §18 | covered |
| PRD-OPT-17 | Baseline CPU/mem/latency/throughput under representative run | §19 (**baseline-profiling seam**) | covered (added) |
| PRD-OPT-18 | Load test 100 consecutive cases; bottleneck + remediation | §19 (**load-test seam**), §11 | covered (added) |

**No blank cells.** Out-of-scope items: none (the target itself is external — PRD-02/03 handled via the README/threat-model seam and TargetAdapter config, not as platform code).

## 3. F1–F12 resolution summary (binding record: `ARCHITECTURE.md` §20)

| # | Resolution | Recorded in |
|---|---|---|
| F1 | Judge invariant is **deterministic, fail-closed** — a verdict state machine (EXPLOIT_CONFIRMED / EXPLOIT_LIKELY / NO_EXPLOIT_OBSERVED / INDETERMINATE / ERROR) with oracle/canary precedence over the LLM Judge; fail-closed **on the verdict, not the run**; cross-provider separation demoted to defense-in-depth. Calibration = async dual-judging, not per-case concurrence. | §3, §5, §15; D13; D8 amended |
| F2 | Target Adapter **split**: untrusted generator → **trusted policy gateway + execution recorder** (allowlist, scoped creds, budget/rate, hard abort, canonical-hash + append-only `AttemptResult`) → external target. Judge evaluates recorder transcript **only**. Contract direction corrected (`ExecutionRecorder → Judge`), recorded as an interface migration. | §4, §5; D14; diagram spec |
| F3 | Langfuse **Cloud** for MVP (synthetic-only); self-host full footprint documented as post-MVP. | §9, §12; D5 amended |
| F4 | Cost = **two independent line families** (measured tokens × current rates w/ cache+batch adjustment for hosted inference; amortized capex+power+operator ÷ measured capacity for local; hosting/storage/egress separate). The `list_price / throughput` division is **removed** as dimensionally invalid. | §11; D17 |
| F5 | Allowlist, scoped creds, authorization, budget, rate caps, egress restriction enforced in **runtime code** (the policy gateway), independent of trigger; skill flag is convenience only; gated side effects **idempotent** (run-nonce). | §5, §14; D14 |
| F6 | Postgres queue given full delivery semantics: at-least-once, lease expiry, heartbeat, reaper, dead-letter, idempotency keys, dedup, cancellation, poison-job handling; no long work in the claim txn; depth monitoring + backpressure. | §6, §7, §11; D6 amended |
| F7 | **Config-switch**; deployed default = hosted OSS; Mac = dev/cost-baseline; Mac tok/s stays `open question`. | §8, §12; D8 amended |
| F8 | OWASP mapped to **2021 explicitly** (the set the PRD enumerates) + 2021↔2025 crosswalk + structured `{framework,version,id,name}` tags. | §5, `THREAT_MODEL.md`; D15 |
| F9 | Stale `PLAN.md` content fixed (status line, §7, §9, tree, two matrix rows). | `PLAN.md` (done) |
| F10 | `disable-model-invocation: true` on `tdd-swarm/SKILL.md`. | skill file (done) |
| F11 | DEFENSE_SCRIPT claims labeled **implemented/selected/measured/planned**; "contract schemas" removed from evidence pack; S2/S4b/S4c corrected for F1/F2/F5. | `DEFENSE_SCRIPT.md` |
| F12 | ADR-0001 softened: Promptfoo has **no `owasp:web` preset**; OWASP-Web mapping = our deterministic validator over ZAP; `owasp:api` partial. | ADR-0001 §16 |

## 4. Re-audit findings beyond F1–F12 (cold-eyes pass)

> All are consistent with (not reversals of) the locked posture; folded into `ARCHITECTURE.md`. Severity per production-grade bar.

**Security / trust (S#):**
- **S1 (critical)** — Signing-key custody: within one shared process a compromised Red Team node could read a signing key. *Resolved by the user's F2 choice*: canonical-hash + append-only + **per-agent DB roles** (S2) within the trust domain; separate-recorder-principal + signing/KMS is the documented hardening path when a boundary is crossed. → §5, D14.
- **S2 (critical)** — Judge reads a Postgres the Red Team also writes. Fix: **per-agent DB roles** — Red Team INSERT-only into a staging table it can't read back; recorder writes the canonical transcript into an append-only table (no UPDATE/DELETE to any agent role); Judge SELECT-only, joins on hash-verified payload, never on a Red-Team-supplied id; contract test that a Red Team role write to the Recorder-owned append-only AttemptResult table is DB-rejected. → §5, §6, §18.
- **S3 (important)** — Replay: no run-scoped nonce. Fix: bind every `AttemptResult`/`Verdict` to `{campaign_run_id, attempt_id}` inside the hashed payload; UNIQUE constraint; coverage counts distinct pairs; regression runs generate a **new** `campaign_run_id` and re-execute live (never reuse verdicts). → §4, §6, §10.
- **S4 (critical)** — Prompt injection against the **Judge and Documentation agents themselves** (attacker payload echoed in the transcript is a live injection aimed at the next LLM). Fix: treat transcript as untrusted **data** — fenced delimiters, rubric-as-system + transcript-as-user-data, structured extraction; add platform-injection cases to the Judge calibration set; Documentation renders from structured fields + escaped evidence. → §5, §15, §18.
- **S5 (important)** — Judge fallback to GPT-5.4 collapses cross-vendor chain (Documentation is GPT-5.4). Fix: Judge fallback **vendor-disjoint** from Documentation; runtime invariant `Judge.vendor != Documentation.vendor` fail-closes the run. → §8, D8.
- **S6 (important)** — Coverage-map poisoning: Orchestrator steers on metrics the untrusted agents write. Fix: compute coverage/resilience only from hash-verified, nonce-deduped verdicts (never raw spans); sanity invariants (no "covered" without N distinct verified attempts + ≥1 oracle/human-checked case; unexplained resilience jump flagged). → §9, §13.
- **S7 (important)** — Separation of duties: launcher must never equal approver. Fix: Clerk-verified
  immutable identities + exact custom permission + runtime two-person rule on campaign authorization,
  critical publish, and remediation (`approver_user_id != launcher_user_id`, both in the audit log).
  There is no single-operator exception; without a distinct authorized Approver, the action stays blocked.
  → §5, §14, §15, D24.
- **S8 (important)** — Canary determinism assumes canaries in the **external** target's data. Fix: make canary provisioning an explicit owned step in `authorized-live-campaign` where the platform has write access; **where it does not, state PHI-exfil detection is Judge-judgment + human-escalation, not deterministic** — honestly. → §5, §10, §15.
- **S9 (nice-to-have)** — Two evidence records (hashed transcript vs Langfuse span) with no reconciliation. Fix: the hashed `AttemptResult` is the **authoritative** evidence object; the span carries the same `transcript_hash`; a reconciliation check marks a divergent run degraded. → §6, §9.

**Ops / observability / testing (O#):**
- **O1 (critical)** — §12 defines **zero environments** (one Railway env conflates CI/dev/live-attacking prod). Fix: ≥2 environments; staging points TargetAdapter at a mock/non-prod allowlist + separate Postgres; **prod alone holds live-target creds**; environment-scoped allowlist; promotion gated on green regression SLO + contract tests. → §12.
- **O2 (critical)** — Code rollback ≠ DB rollback; in-flight leases/checkpoints share one Postgres. Fix: **expand/contract** migrations; version checkpoint + jobs payload; dead-letter unknown rows; **drain-before-deploy**; document Postgres **PITR** as the true rollback of record. → §7, §12.
- **O3 (important)** — No alerting layer for unattended operation. Fix: alert channel + conditions (human-approval-pending w/ SLA, regression/reopen, budget breaker, target-unreachable, queue-depth, emission failure) tied to the durable source (exploit DB / queue), not Langfuse alone. → §9, §13.
- **O4 (important)** — No platform-code testing strategy beyond contract tests. Fix: §18 test pyramid incl. adversarial/boundary tests for the four BUILD capabilities + invariant tests for the 10 invariants + CI matrix. → §18.
- **O5 (important)** — 100K "sample regression runs" breaks the completeness guarantee. Fix: **stratified** — always run critical + recently-reopened on every target change; sample lower-severity/older; full suite on cadence; verdict caching bounded by `target_version` + case-content hash; SLO = two numbers. → §10, §11.
- **O6 (important)** — No durable campaign/finding correlation IDs across multi-day lineage + interrupt/resume + the Langfuse↔exploit-DB split. Fix: `campaign_id`/`attempt_id`/`finding_id` generated at campaign start, propagated as span attributes **and** row columns; `finding_id` joins across the split; lineage completeness as a data-quality invariant. → §6, §9.
- **O7 (important)** — No failure mode for **Langfuse unavailable** (the Orchestrator's decision substrate). Fix: §13 row — degrade to the exploit-DB system-of-record + queue table for coverage/priority signals (documented fallback policy), emit alert; the coverage signal must be derivable from Postgres. → §9, §13.
- **O8 (nice-to-have)** — Regression SLO / load test have no defined CI substrate. Fix: ephemeral Postgres + mock TargetAdapter (record/replay) + cassette model responses in CI; real-target 100-case load test is a manual/staging job with its own budget cap; CI/dev runs are a cost line. → §11, §18, §19.

**Coverage gaps vs PRD (C#):** PRD-08 AttackCase fields (→§6), PRD-21/22 VulnReport fields + reproducibility bar (→§6), PRD-OPT-07 ATO packet (→§19), PRD-OPT-03 triage exercise (→§19), PRD-OPT-17 baselines (→§19), PRD-OPT-18 load test (→§19), PRD-OPT-05/09 integration packet (→§4/§19), PRD-02/03 target-readiness seam (→§2), PRD-OPT-16 index/SLO consolidation (→§6/§10). All folded.

## 5. Dimension summary (arch-finalize 12)

1. **PRD coverage** — table §2 above; zero blank cells. 2. **Missing flows** — degraded/ops flows added (Langfuse-down O7, queue backpressure F6, environment promotion O1). 3. **Lifecycle** — verdict + finding + campaign state machines pinned (D13, §6). 4. **Failure modes** — every external dep now has a designed behavior incl. Langfuse (O7). 5. **Interfaces/schemas** — mediated contract chain (D14), AttackCase/VulnReport field tables. 6. **Source of truth** — hashed `AttemptResult` authoritative for evidence (S9); exploit DB system-of-record for status (D5). 7. **Unresearched deps** — F3/F8/F12 verified against primary sources; cost numbers kept `open question`. 8. **Inconsistent decisions** — Langfuse-vs-simplicity (F3), refusal-integrity-as-invariant (F1), red-adapter-as-boundary (F2) resolved. 9. **Overbuilt scope** — none cut; every capability traces to a USERS.md use case. 10. **Trust boundaries** — enforcement point named for every crossing (policy gateway, DB roles, two-person rule). 11. **Testing/evals** — §18 covers boundary/invariant/regression + adversarial for the platform's own code. 12. **Deploy/rollback/observability** — environments (O1), expand/contract + PITR (O2), correlation IDs (O6), alerts (O3).
