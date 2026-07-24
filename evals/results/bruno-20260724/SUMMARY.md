# Bruno functional/regression runs — 2026-07-24

Owner-supplied Bruno collections (`@usebruno/cli@3.5.2`, `--env Runtime --bail`) against the live
synthetic Clinical Co-Pilot. Credentials (SIDs) come from each collection's `Runtime.bru` (bearer
credentials, never committed); these scrubbed reports have the SID values replaced.

| Suite | Target | Requests | Tests | Result | Notable |
|---|---|---|---|---|---|
| Week 1 | `/app` (`WEEK1_SID`) | 4/4 | 16/16 | ✓ PASS | `chat` latency **72,208 ms** (full RAG+LLM+verification) |
| Week 2 | `/week2` (`WEEK2_SID`) | 11/11 | 24/24 | ✓ PASS | lab/intake upload, grounded-or-redacted extraction, private PNG preview, SHA-256 readback match, permanent dedup no-op; `chat` 75,884 ms |

## Positive controls confirmed by the collections
- Liveness/readiness carry a correlation id and cannot be served from a stale cache.
- Chat returns the verified serving envelope; **every served claim owns a machine-readable citation
  set**; `correlation_id` equals the `x-copilot-request-id` response header.
- Week 2 extraction **"exposes only grounded or redacted fields"**; page preview is **PNG and
  private**; source/artifact reads **match their SHA-256 digests**; re-uploading the same
  patient-scoped bytes is a **permanent no-op** (dedup).

## Honest note on a transient failure
An initial Week 2 run returned **HTTP 429** on `lab-upload` because a Week 1 adversarial `/chat`
stream was running **concurrently**. Re-run alone, Week 2 passed 24/24. The 429 is the target's
rate-limiter working (a positive control), not a defect — see `AF-VULN-2026-0724-001`.

Files: `week1-bruno.log` / `week1-bruno.json`, `week2-bruno.log` / `week2-bruno.json` (SID-scrubbed).
