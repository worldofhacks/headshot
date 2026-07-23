# Clinical Co-Pilot target and session readiness

Status: implementation and offline contract tests are complete; target-issued session lifetime and
rotation behavior remain unmeasured until an explicitly authorized, synthetic-only live campaign.
This document records facts and unknowns without making a live-readiness claim.

## Reviewed target contract

| Property | Current record | Evidence class |
|---|---|---|
| Transport | Exact allowlisted HTTPS host; redirects denied | Enforced by catalog, Runner, adapter, and Policy Gateway |
| Surface | `POST /chat` | Reviewed Bruno contract and offline adapter tests; not re-probed here |
| Request body | Exactly `{"session_id": <sealed session>, "message": <case message>}` | Offline contract test |
| Target authentication | Patient-pinned SMART session in `session_id`; no bearer header for this profile | Reviewed contract and offline test |
| Human authentication | Clerk session is accepted only by Web and is never forwarded to the target | Platform security contract |
| Data | Reviewed synthetic fixtures only; real PHI forbidden | Corpus validation and campaign gates |
| Session lifetime | Unknown until supplied by the target/session issuer | External measurement required |
| Target idle timeout / cookie requirements | Unknown | Authorized observation required |
| Conversation-history namespace | Unknown whether `session_id` also accumulates history across case messages | Authorized observation required |
| Session-expired response | Adapter recognizes HTTP 401 JSON whose detail begins `session expired` | Offline typed-error test; live wording still must be confirmed |
| Response limits | Catalog-defined timeout, content types, and byte ceiling | Enforced configuration; target maxima not yet measured |
| Rate limit | Authorization-bound target request rate | Enforced by gateway/Runner; target-provider ceiling not yet measured |
| Local target build | No target source is present in this repository | Deployed-target-only integration boundary |

The current adapter converts each authored case into one metered `/chat` request. A case with multiple
authored turns is joined into one message. “Persistent session” therefore means stable target identity,
HTTP cookie jar, and connection state across campaign cases; it does not mean issuing hidden internal
turns. Any future per-turn conversation support must route every physical request through Policy
Gateway accounting and requires a versioned adapter/contract change.

## Campaign session invariant

One campaign may use exactly one immutable session generation:

1. The approved target definition contains a versioned opaque reference such as
   `secretref://staging/openemr/session/generation-20260722a`. The operation hash binds that reference
   without storing its value.
2. Runner-only `AGENTFORGE_CREDENTIAL_BINDINGS_JSON` maps the reference to a sealed Railway variable.
3. Runner-only `AGENTFORGE_SESSION_LEASES_JSON` records the same generation, a timezone-aware expiry,
   and the SHA-256 of the sealed value. It contains no raw session.
4. Network-free preflight requires metadata expiry to extend beyond the campaign's usable window:
   `min(authorization expiry, Runner start + approved run timeout)`.
5. At the first verified dispatch boundary, Runner resolves the value once and verifies its digest.
   Later attempts receive the same in-memory `Secret`, even if process environment state changes.
6. One campaign-owned HTTP client is reused, retaining its cookie jar and connection pool. Each request
   still passes the pre-dispatch database revalidation and Policy Gateway limits.
7. Before each attempt, an expired or released lease fails closed. A target-confirmed expiry aborts
   after that single physical request. The campaign does not retry, refresh, or switch patient context.
8. Success, failure, or abort releases the lease reference, clears the adapter credential, and closes
   the owned client.

The generation/digest check prevents a Railway variable edit from silently changing identity under an
already approved reference. Python cannot guarantee byte-level zeroization of immutable strings, so
private process isolation, least-privilege Railway variables, short lease duration, cleanup, and no
logging remain required controls.

## Provisioning and rotation

The safe rotation unit is the full tuple of target version, credential reference generation, sealed
value, metadata, and human authorization—not just the secret value.

1. Select a new generation and register a new immutable target version/surface that references it.
2. Obtain a target session pinned to the reviewed synthetic patient fixture. Record the issuer's
   absolute expiry out of band; never infer a longer lifetime than the issuer supplies.
3. Provision the value only on private Runner and provision matching lifecycle metadata separately.
   Do not put either the value or a reversible encoding in the catalog, database, Web, chat, CI, or
   evidence.
4. Restart the private Runner, request the exact campaign authorization, and obtain a decision from a
   different Headshot Organization user.
5. Launch only if preflight shows the session covers the full bounded window. Otherwise allocate a new
   generation; never overwrite an approved generation.

After expiry, preserve already recorded evidence and launch a newly approved campaign. Never resume the
old run with a new session because that could alter patient scope and would invalidate its authorization
and evidence lineage.

## Readiness checklist

- [x] Request shape and credential placement have offline contract tests.
- [x] One credential generation is pinned across attempts and rejects silent replacement.
- [x] One real HTTP client is reused and closed after the campaign.
- [x] Local lease expiry and target-reported expiry are terminal typed aborts.
- [x] Every physical request remains independently policy-gated and accounted.
- [x] Session material is Runner-only and excluded from repr/log/config manifests.
- [ ] Target issuer's absolute and idle lifetimes are measured without recording the session value.
- [ ] Exact live expired-session status/body is confirmed against the reviewed adapter matcher.
- [ ] Target cookies or additional response-derived state are documented if observed.
- [ ] Cross-case conversation-history behavior is measured and either accepted as an explicit stateful campaign invariant or isolated through a newly reviewed target contract.
- [ ] Target rate, response-size, and timeout ceilings are measured under explicit authorization.
- [ ] One two-person-approved synthetic campaign completes without mid-run rotation.

Until all unchecked external items are complete, the live campaign remains blocked. Passive health
checks and Clerk authentication do not authorize a target request.
