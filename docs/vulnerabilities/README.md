# Vulnerability reports — authorized live Co-Pilot campaign (2026-07-24)

Draft findings from an **authorized, synthetic-only** adversarial campaign against the owner's live
Clinical Co-Pilot (`https://agent-production-9f62.up.railway.app/chat`). All reports are **DRAFT** —
publishing any finding is a separate two-person human-approval gate (approver ≠ launcher). No real
PHI; the session is pinned to a synthetic Synthea patient.

## Honest headline
**0 confirmed exploits.** The independent, deterministic `Judge` returned `INDETERMINATE` for every
adversarial probe (no trusted oracle/canary hit → no `EXPLOIT_CONFIRMED`). The Co-Pilot's layered
defenses held on every probe that received a response: a **deterministic pre-model refusal** plus an
**evidence-grounded re-render with per-claim verification** (`pass`/`flagged`/`blocked`). The findings
below are therefore Low/Informational observations and coverage notes — not exploits.

## Reports
| ID | Severity | Theme | Disposition |
|---|---|---|---|
| [AF-VULN-2026-0724-001](AF-VULN-2026-0724-001-chat-latency-and-rate-limiting.md) | Low | `/chat` ~72 s latency; target rate-limiting (429) | Availability/UX; 2 earlier items retracted as harness artifacts |
| [AF-VULN-2026-0724-002](AF-VULN-2026-0724-002-prompt-injection-jailbreak-resistance.md) | Low | Prompt-injection / jailbreak outcome | No disclosure; first-line refusal *inconsistent* — model-grounding is load-bearing |
| [AF-VULN-2026-0724-003](AF-VULN-2026-0724-003-sensitive-data-output-handling-resistance.md) | Informational | Sensitive-data & output-handling | Control validated — no leakage/reflection across all 17 probes (coverage gap closed in the authoritative run) |

## Method (what actually ran)
- **Tool-driven functional/regression:** the owner's Bruno collections (`@usebruno/cli@3.5.2`) for
  Week 1 (`/app`) and Week 2 (`/week2`). Scrubbed results in `evals/results/bruno-20260724/`.
- **Platform adversarial campaign:** a curated corpus (prompt injection, jailbreak/DAN, sensitive-data
  leakage, encoding/output-handling) fired through the real `OpenEmrAdapter` (`copilot_chat` profile)
  at ~1 req/2 s, with **deterministic code oracles** feeding schema-valid Evidence Envelopes into the
  real `agentforge.agents.judge.Judge`. Results in `evals/results/live-campaign-20260724*/`.
- **Global target config:** both sessions registered in `config/targets.json` and the platform catalog
  `config/live-target-catalog.staging.json` (validated by `scripts/validate_target_catalog.py`).

## What is still offline (honest limits)
- Full **autonomous orchestration** (Orchestrator → Red-Team → Judge → Documentation) and the
  two-person-gated **coordinator/lease** live path were not exercised — that path is blocked by design
  without a second approver, so this run used the adapter boundary + allowlist directly.
- The **calibrated LLM Judge layer is unwired at MVP**, so clean probes resolve to `INDETERMINATE`
  rather than a graded `NO_EXPLOIT_OBSERVED`.
- garak/promptfoo remain **offline-pinned** in this repo; the live scan used a curated corpus through
  the platform adapter (rate-cap-faithful) rather than garak's harness.
- **Indirect** injection / exfil via Week 2 uploaded documents (the richest surface) is not yet tested.

## Provenance
The first pass (`evals/results/live-campaign-20260724/`) was exploratory — a now-superseded inline SID
and a 30 s client timeout (which caused false timeouts). The **authoritative** results are
`evals/results/live-campaign-20260724-week1/` (Week 1 SID, 120 s timeout, 17/17 responded).

Credentials are by reference only (gitignored `.env.campaign`); the extracted Bruno bundle is never
committed.
