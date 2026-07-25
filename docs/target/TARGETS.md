# Authorized live targets — Clinical Co-Pilot (synthetic)

Global, tracked target configuration for the two authorized synthetic-data Clinical Co-Pilot
sessions (Week 1 and Week 2). This is the human-readable companion to the machine configs.

## Machine configs (tracked)
- `config/live-target-catalog.staging.json` — platform-native `AGENTFORGE_LIVE_TARGET_CATALOG_JSON`
  for `AGENTFORGE_ENVIRONMENT=staging` (loaded by `TrustedTargetCatalog.from_environment("staging")`).
- `config/live-target-catalog.production.json` — the identical catalog for
  `AGENTFORGE_ENVIRONMENT=production`; the only differences are each entry's `environment` and the
  `secretref://production/…` credential handles. Staging and production expose the **same** targets.
- `config/targets/clinical-copilot-20260724.json` — the `clinical-copilot-*` alias subset, kept
  byte-consistent with the canonical union above (referenced by tickets T-F05c/T-F05p and the
  final-submission manifest).
- `config/targets.json` — legacy/historical summary retained for artifact provenance and the Bruno
  wrappers. It is not live-execution authority; `scripts/live_campaign.py` now refuses.
- Validate all of it — network-free, no secrets — with `python scripts/validate_target_catalog.py`
  (loads **both** environment files through the real `TrustedTargetCatalog` code path).

> **Credentials are by reference only.** The Week 1 / Week 2 session SIDs are bearer credentials for
> synthetic patient data. They live in the **gitignored** `.env.campaign` (`WEEK1_SID` / `WEEK2_SID`)
> and in the **private Railway Runner** secret vars — **never** committed, printed, or logged. The
> extracted Bruno bundle is **never** committed. (The bundle README ships the raw SIDs in cleartext;
> treat the bundle itself as secret and keep it outside version control.)

## Target ids (both schemes resolve)
Two id schemes are registered as aliases for the same two synthetic sessions, so a campaign that
references either id resolves against the trusted catalog:

| Primary id | Alias id | App URL | SID env | Uploads |
|---|---|---|---|---|
| `copilot-week1` | `clinical-copilot-week1` | `/app` | `WEEK1_SID` | no |
| `copilot-week2` | `clinical-copilot-week2` | `/week2` | `WEEK2_SID` | yes (authorized synthetic docs) |

All four entries share host `agent-production-9f62.up.railway.app`, `auth_mode: session`,
`payload_profile: copilot_chat`, and credentials by `secretref`. The alias entries are consistent with
the primaries (same host, surfaces, caps, and authorization ref); they differ only in `target_id`,
`surface_id`s, and the `secretref` path.

## Environments (both behave identically)
`TrustedTargetCatalog.from_environment` requires each entry's `environment` to equal the selected
`AGENTFORGE_ENVIRONMENT` (`catalog.py:145` raises on a mismatch), so there is one catalog file per
environment. Loading is identical for both — proven by `scripts/validate_target_catalog.py`.

> **Enabling live sends is a deliberate operator step.** A live URL is only reachable when
> `AGENTFORGE_ENVIRONMENT=production`; at `staging` the targets load and preflight, but every live send
> is refused by the Policy Gateway's synthetic-data / live-URL guard. To run live: deploy the Runner
> with `AGENTFORGE_ENVIRONMENT=production` and inline `config/live-target-catalog.production.json`
> into `AGENTFORGE_LIVE_TARGET_CATALOG_JSON`. Per CLAUDE.md, staging and production keep separate
> bindings/secrets/authorization — production remains selected/planned until integration is verified.

## Authorization
- Ref: `authorization://agentforge/headshot-owner-synthetic-2026-07-24` (every entry's `ownership_authorization_ref`).
- Owner-authorized bounded adversarial + regression testing against the owner's own synthetic-data
  deployment. Synthetic patient data only — no real PHI.

## Shared facts (both targets)
| Property | Value |
|---|---|
| Host (allowlisted) | `agent-production-9f62.up.railway.app` (HTTPS only, redirects denied) |
| Chat endpoint | `POST /chat` |
| Evidence retrieval | `POST /evidence/search` (anonymous guideline retrieval) |
| Week 2 uploads | `POST /documents` (synthetic lab + intake); read-back via `GET /documents/{id}/…` |
| Request body | `{"session_id": "<SID by reference>", "message": "<prompt>"}` (SID in the body, not a header) |
| Response envelope | `brief`, `source` (`llm`\|`deterministic_fallback`\|`deterministic_refusal`), `degraded`, `verdicts[]`, `citations[]`, `claims[]?`, `correlation_id` |
| Integrity | `correlation_id` equals the `x-copilot-request-id` response header |
| Session expiry (typed) | HTTP 401 JSON `{"detail":"session expired …"}` → adapter aborts, no blind retry |
| Measured chat latency | ~72 s for a full RAG + LLM + per-claim verification cycle (Week 1 Bruno `chat`); Bruno client timeout 180 s |

## Session policy (per the bundle README)
- Idle timeout: **72 hours** (259,200 s).
- Turn budget: **1,000 turns** per shared session.
- Sessions are shared (multiple callers per SID), **patient-pinned**, and survive agent restarts and
  OAuth access-token refresh (durable session store + encrypted delegated credential vault).

## Credential provisioning (private Runner env vars — never committed)
The catalog binds credentials by `secretref`; the raw SIDs are resolved only at dispatch from private
Runner secret vars. Provision three groups on the **private Runner** (values below are placeholders —
real SIDs and digests are never placed in the repo):

1. Raw SIDs (the secret vars named on the right of the bindings map):
   - `OPENEMR_WEEK1_SMART_SESSION = <raw Week 1 SID>`
   - `OPENEMR_WEEK2_SMART_SESSION = <raw Week 2 SID>`
2. `AGENTFORGE_CREDENTIAL_BINDINGS_JSON` — maps each `secretref` to its secret-var name:
   ```json
   {
     "secretref://staging/copilot-week1/session/generation-20260724a": "OPENEMR_WEEK1_SMART_SESSION",
     "secretref://staging/copilot-week2/session/generation-20260724a": "OPENEMR_WEEK2_SMART_SESSION",
     "secretref://staging/clinical-copilot-week1/session/generation-20260724a": "OPENEMR_WEEK1_SMART_SESSION",
     "secretref://staging/clinical-copilot-week2/session/generation-20260724a": "OPENEMR_WEEK2_SMART_SESSION"
   }
   ```
   Use the `secretref://production/…` keys on the production Runner. Alias refs deliberately map to the
   same secret var as their primary (same physical session).
3. `AGENTFORGE_SESSION_LEASES_JSON` — one lease per `secretref`; `value_sha256` is re-verified against
   the revealed SID at dispatch (silent-rotation detection):
   ```json
   {
     "secretref://staging/copilot-week1/session/generation-20260724a": {
       "generation": "generation-20260724a",
       "expires_at": "<ISO-8601 UTC within the 72h idle window, e.g. 2026-07-27T13:00:00+00:00>",
       "value_sha256": "<64-hex SHA-256 of the raw Week 1 SID>",
       "expiry_source": "operator_conservative_lease"
     }
   }
   ```
   Week 2 and the `clinical-copilot-*` aliases follow the same shape; alias refs share their week's SID digest.

## Testing rules (locked)
- Synthetic patient data only; no real PHI.
- No infrastructure changes, credential rotation, OAuth client registration, record deletion, or
  denial-of-service / load testing.
- ≤ 3 concurrent workers. No catalog field encodes worker count directly; the bound is enforced
  structurally (the run's `HostedRunBinding` pins provider concurrency to 1, which is ≤ 3) and the
  no-DoS / no-load constraint is expressed through the per-target `safety_caps`
  (`target_requests_per_second: 0.5`, `physical_request_limit`, `max_attempts_per_run`,
  `target_retries_per_turn`).
- Week 2's bundled synthetic document uploads are authorized.
- Live attacks are gated by `authorized-live-campaign` + the Policy Gateway; publishing any
  finding/report regardless of severity, or performing remediation, is a separate human approval
  (and the finding approver must be distinct from the raiser).

## Reproduce
```bash
# Validate the tracked catalogs load (network-free, no secrets, both environments):
python scripts/validate_target_catalog.py

# Bruno regression/functional suites (from the extracted bundle; SIDs from Runtime.bru):
(cd <bundle>/week1/bruno && npx --yes @usebruno/cli@3.5.2 run --env Runtime --bail)
(cd <bundle>/week2/bruno && npx --yes @usebruno/cli@3.5.2 run --env Runtime --bail)

# Platform adversarial campaign:
# Use the authenticated Railway console/API to create the exact-scope authorization request,
# obtain a decision from a distinct approver, and launch the campaign. The private durable Runner
# is the only executor. Direct scripts intentionally exit before reading credentials or sending.
#
# After the authorized run completes, query the remote observations back:
python scripts/verify_langfuse_campaign.py \
  --campaign-run-id <completed-live-run-id> \
  --expected-environment production \
  --record-verification
```

Omit `--record-verification` only for a read-only query-back probe. The explicit flag atomically
changes every exact reconciled agent and physical target request from `queued` to `exported` and
records its first verification time; any exact-ID mismatch rolls back the entire verification
write. The required environment argument must exactly match the
production Runner configuration and every queried observation. Production and Staging must use
different Langfuse projects and distinct public/secret keypairs; a metadata label does not make shared
project credentials safe.
