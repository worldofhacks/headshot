# AF-VULN-2026-0724-001 — `/chat` interactive latency & target rate-limiting

> **Status: DRAFT — not published.** Publishing is a separate two-person human-approval gate
> (approver ≠ launcher). Human-authored from the cited captures; no runtime Documentation-agent
> authorship is claimed.
> **Disposition: LOW (latency/UX). Two earlier "findings" were HARNESS ARTIFACTS and are retracted below.**

| Field | Value |
|---|---|
| Report ID | `AF-VULN-2026-0724-001` (unique) |
| Severity | **Low** (availability/UX) — the rate-limiting sub-observation is an *anecdotal* positive control |
| Category | Availability · latency · rate-limiting |
| OWASP LLM | `LLM10:2025` Unbounded Consumption (latency/resource) |
| OWASP Web | `A04:2021` Insecure Design (resource/rate-limit design; availability under CIA) |
| Target | Clinical Co-Pilot — `POST https://agent-production-9f62.up.railway.app/chat` (both sessions) |
| Evidence | Week 1 Bruno run + `evals/results/live-campaign-20260724*/` |

## What is actually true (measured)
1. **Interactive `/chat` latency is high: ~72 s** for a full RAG + LLM + per-claim-verification cycle.
   Measured directly by the authoritative Week 1 Bruno `chat` request: **72,208 ms** (health 217 ms,
   ready 9,643 ms, evidence-search 4,160 ms). The bundle's Bruno client sets a **180 s** timeout to
   accommodate this. For a point-of-care assistant, ~72 s per turn is a real usability concern even
   though the request completes correctly.
2. **Rate-limiting under concurrent pressure (HTTP 429) — ANECDOTAL, not captured.** During an
   uncaptured concurrent burst (a Week 2 `lab-upload` alongside a Week 1 `/chat` stream) the upload
   was observed returning **429 Too Many Requests**, noted only in prose in
   `evals/results/bruno-20260724/SUMMARY.md`; the suite was then re-run serially and every retained
   machine-readable capture (`week1-bruno.json`, `week2-bruno.json`) shows **HTTP 200**. Treat this
   as an *anecdotal* positive control and a testing-hygiene note (stay within the ≤ 3-worker ceiling),
   **not** a claim backed by a captured request/response.

## Retractions (harness artifacts — NOT target defects)
Two observations from the *first* exploratory pass (`evals/results/live-campaign-20260724/`) were
caused by the test harness, not the target, and are corrected here for honesty:

- **"41% request-timeout rate."** The first pass used a **30 s** client read-timeout. Because normal
  `/chat` latency is ~72 s, that timeout fired spuriously. It is a client misconfiguration, not a
  target availability defect. The conclusive re-run uses a 120 s timeout.
- **"~12-minute session lifetime."** The first pass authenticated with a **different, stale** inline
  SID (not the Week 1/Week 2 credentials in the bundle). The bundle's stated policy is a **72-hour**
  idle timeout with a durable session store surviving restarts and OAuth refresh. The single
  `HTTP 401 session expired` was seen only in that transient first pass and is **not preserved in the
  retained captures** (which show HTTP 200 throughout); it reflects the stale SID, not a short
  lifetime. (The adapter's fail-closed abort on 401 remains correct behavior.)

## Minimal reproduction
```bash
# Latency (authoritative):
(cd <bundle>/week1/bruno && npx --yes @usebruno/cli@3.5.2 run --env Runtime --bail)   # chat ~72s
# Rate-limiting: run an upload and a chat stream concurrently -> 429 on the second stream.
```

## Observed vs expected
| | |
|---|---|
| **Expected** | Interactive latency of a few seconds; predictable throughput under the authorized worker cap. |
| **Observed** | ~72 s per chat turn (completes correctly, captured); *anecdotally* 429 under an uncaptured concurrent burst (bounded-consumption control, not in the retained captures). |

## Recommended remediation / follow-up
1. **Reduce `/chat` tail latency** (RAG + LLM + per-claim verification, plus possible Railway cold
   starts): add response streaming, cache warm capacity, and surface a progress state so a ~72 s turn
   is not perceived as a hang.
2. Keep the **rate-limiter**; document its ceiling so authorized campaigns pace within it (this run
   caps at ≤ 3 workers and ~1 req/2 s per stream).
3. Fix the client harness default timeout to ≥ 120 s (done: `LC_TIMEOUT`).

## Current status & fix-validation
Status **open — Low**. Latency is measured and reproducible from the retained captures; the 429
rate-limiting observation is anecdotal (not captured); the two retracted items are corrected. No
exploit. Evidence: Week 1 Bruno `week1-bruno.json` + campaign `summary.json`.
