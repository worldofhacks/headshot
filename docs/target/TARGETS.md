# Authorized live targets — Clinical Co-Pilot (synthetic)

Global, tracked target configuration for the two authorized synthetic-data Clinical Co-Pilot
sessions. This is the human-readable companion to the machine configs:

- `config/targets.json` — script-facing config used by `scripts/live_campaign.py` and the Bruno wrappers.
- `config/live-target-catalog.staging.json` — platform-native `AGENTFORGE_LIVE_TARGET_CATALOG_JSON`
  loaded by `agentforge.target.catalog.TrustedTargetCatalog.from_environment("staging")`
  (validate with `scripts/validate_target_catalog.py`).

> **Credentials are by reference only.** The Week 1 / Week 2 session SIDs are bearer credentials for
> synthetic patient data. They live in the **gitignored** `.env.campaign` as `WEEK1_SID` / `WEEK2_SID`
> and are **never** committed, printed, or logged. The extracted Bruno bundle is **never** committed.

## Authorization
- Ref: `authorization://agentforge/headshot-owner-synthetic-2026-07-24`
- Owner-authorized bounded adversarial + regression testing against the owner's own synthetic-data
  deployment. Synthetic patient data only — no real PHI.

## Shared facts (both targets)
| Property | Value |
|---|---|
| Host (allowlisted) | `agent-production-9f62.up.railway.app` (HTTPS only, redirects denied) |
| Chat endpoint | `POST /chat` |
| Request body | `{"session_id": "<SID by reference>", "message": "<prompt>"}` (auth: none header) |
| Response envelope | `brief`, `source` (`llm`\|`deterministic_fallback`\|`deterministic_refusal`), `degraded`, `verdicts[]`, `citations[]`, `claims[]?`, `correlation_id` |
| Integrity | `correlation_id` equals the `x-copilot-request-id` response header |
| Session expiry (typed) | HTTP 401 JSON `{"detail":"session expired …"}` → adapter aborts, no blind retry |
| Measured chat latency | ~72 s for a full RAG + LLM + per-claim verification cycle (Week 1 Bruno `chat`); Bruno client timeout is 180 s |

## Session policy (per the bundle README)
- Idle timeout: **72 hours** (259,200 s).
- Turn budget: **1,000 turns** per shared session.
- Sessions are shared (multiple callers per SID), **patient-pinned**, and survive agent restarts and
  OAuth access-token refresh (durable session store + encrypted delegated credential vault).

## Targets
| Target id | App URL | SID env | Uploads | Coverage |
|---|---|---|---|---|
| `copilot-week1` | `/app` | `WEEK1_SID` | no | liveness, readiness, anonymous guideline retrieval, authenticated patient-pinned cited chat |
| `copilot-week2` | `/week2` | `WEEK2_SID` | **yes (authorized synthetic docs)** | Week 1 plus synthetic lab upload, bounded processing polling, grounded extraction, PNG preview, digest verification, synthetic intake upload, permanent duplicate handling |

Both targets share the same host and `/chat` surface; they differ only by their patient-pinned session
(SID). In the platform catalog they are two `TargetDefinition`s (`copilot-week1`, `copilot-week2`),
each `auth_mode: session`, `payload_profile: copilot_chat`, credential by `secretref`.

## Testing rules (locked)
- Synthetic patient data only; no real PHI.
- No infrastructure changes, credential rotation, OAuth client registration, record deletion, or
  denial-of-service / load testing.
- ≤ 3 concurrent workers.
- Week 2's bundled synthetic document uploads are authorized.
- Live attacks are gated by `authorized-live-campaign` + the Policy Gateway; publishing any critical
  finding or remediation is a separate two-person human approval (approver ≠ launcher).

## Reproduce
```bash
# Bruno regression/functional suites (from the extracted bundle; SIDs from Runtime.bru):
(cd <bundle>/week1/bruno && npx --yes @usebruno/cli@3.5.2 run --env Runtime --bail)
(cd <bundle>/week2/bruno && npx --yes @usebruno/cli@3.5.2 run --env Runtime --bail)

# Platform adversarial campaign (SID by reference from .env.campaign):
set -a; . ./.env.campaign; set +a
LC_RUN_ID=live-campaign-YYYYMMDD-week1 LC_SID_ENV=WEEK1_SID LC_TIMEOUT=120 \
  .venv/bin/python scripts/live_campaign.py
```
