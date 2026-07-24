# OpenEMR session-binding readiness — zero-call audit

**Verdict: BLOCKED. Do not provision or dispatch the session currently shared through chat.**

This audit was local and read-only except for this report. It made no Railway query or mutation,
opened no socket, contacted no target/provider, and incurred no spend. The chat-supplied session was
not repeated, read by a command, decoded, hashed, stored, or transmitted. Any session disclosed in
chat must be replaced with a fresh generation through the private Runner provisioning boundary.

## Exact `copilot_chat` value shape

The sealed Runner variable must contain **only the opaque session identifier value**. It must **not**
contain the cookie-style `sid=` key/value wrapper, a `Cookie:` header, or an entire cookie string.

Evidence:

- `OpenEmrAdapter._build_body()` places `credential.reveal()` directly into the JSON
  `session_id` field without parsing or stripping a prefix
  (`src/agentforge/target/openemr_adapter.py:353-376`).
- The frozen offline contract asserts the body is exactly
  `{"session_id": <injected identifier>, "message": <turn>}` and uses a bare fake identifier
  (`tests/test_openemr_adapter_chat.py:42-45,138-154`).
- `copilot_chat` sends neither an `Authorization` header nor bearer auth
  (`src/agentforge/target/openemr_adapter.py:336-351`;
  `tests/test_openemr_adapter_chat.py:183-196`).
- The sealed resolver returns the configured string verbatim
  (`src/agentforge/policy/scoped_credentials.py:219-228`). A cookie wrapper would therefore be sent
  verbatim as the JSON value and is not normalized into an identifier.

The repository contract is unambiguous. Parity with the currently deployed target remains an
external observation because target source is not in this repository.

## Findings

### SB-001 — Critical — lease metadata cannot enforce T-F05c

- **Location:** `src/agentforge/policy/scoped_credentials.py:34-49,181-211,230-267`;
  `tickets/T-F05c.md:23-32`.
- **Evidence:** `SessionLeaseMetadata` contains only `generation`, `expires_at`, and
  `value_sha256`. The environment parser rejects every other field. `session_ready()` checks only
  value presence, generation suffix, and expiry coverage.
- **Impact:** There is no not-before check, exact target/surface/patient-fixture binding, or
  server-owned maximum lease lifetime. The same reference could be reused by another catalog entry,
  a future-dated lease could be accepted, and an arbitrarily long expiry is structurally valid.
- **Fix:** Land a prerequisite lease-contract ticket before T-F05c. Extend the strict metadata and
  runtime lease with not-before, exact target binding, and bounded lifetime enforcement. Compare the
  same canonical metadata to the grant; do not introduce a second unenforced metadata mirror.
- **Mitigation:** Continue to block all live work.
- **False-positive note:** An external secret manager may carry such metadata, but no repository
  contract consumes or enforces it, and T-F05c explicitly requires it.

### SB-002 — High — wrong session shape is not rejected locally

- **Location:** `src/agentforge/target/openemr_adapter.py:366-376`;
  `src/agentforge/policy/scoped_credentials.py:219-228`;
  `.env.example:143-173`; `src/agentforge/target/preflight.py:134-153,253-267`.
- **Evidence:** The current path passes the sealed string unchanged. Legacy examples call the value
  a “session cookie,” expose `OPENEMR_SESSION_COOKIE`, and still show an `env:` credential reference,
  while the durable Runner requires a `secretref://` binding and the adapter requires a JSON
  identifier.
- **Impact:** An operator can provision a cookie wrapper or the obsolete variable/reference path;
  configuration appears non-empty but the first target call receives the wrong JSON value.
- **Fix:** Reject a leading cookie-name wrapper, cookie/header delimiters, and surrounding/control
  whitespace at a target-specific, secret-safe Runner validation boundary. Do not silently strip or
  rewrite the value. Remove or clearly deprecate the legacy cookie/`env:` examples.
- **Mitigation:** Provision only a fresh raw identifier under the reviewed
  `secretref://.../<generation>` path.
- **False-positive note:** The deployed target could accept both shapes, but that is not the reviewed
  contract and has not been established without a live call.

### SB-003 — Critical — required public zero-call gate does not exist

- **Location:** `tickets/T-F05c.md:1-43`.
- **Evidence:** `src/agentforge/campaign/live_preflight.py`,
  `scripts/preflight_live_campaign.py`, and `tests/test_live_campaign_preflight.py` are absent.
  T-F05c is backlog and depends on backlog T-F04h and T-F05a. Its current file scopes also exclude
  the resolver, Runner, lease tests, and deployment documentation needed to close SB-001.
- **Impact:** No command can prove grant/lease/target/caps agreement before secret resolution,
  mutation, adapter construction, calls, or spend. Implementing only T-F05c's current files would
  validate an artifact that the Runner itself does not enforce.
- **Fix:** Add a prerequisite scoped lease-contract task (resolver, Runner, lease tests, Runner
  tests, and runbook), complete T-F04h/T-F05a, then run T-F05c through independent
  test-review-freeze-implementation-code-review-security-review.
- **Mitigation:** Do not substitute `scripts/preflight_status.py` or
  `python -m agentforge.runner --check`; neither verifies the required campaign/session contract.
- **False-positive note:** Existing Runner preflight checks generation and expiry, but not the
  additive T-F05c contract.

### SB-004 — High — rotation can overlap differently configured Runner processes

- **Location:** `docs/deployment/RAILWAY.md:238-278`; `railway/runner.json:7-13`.
- **Evidence:** The runbook requires draining or aborting an old campaign before rotation and never
  overwriting an authorized generation. Railway Runner configuration permits a 30-second deployment
  overlap.
- **Impact:** A normal rolling deployment can leave old and new Runner processes alive with
  different catalog/session generations while jobs remain claimable.
- **Fix:** For credential rotation, stop new launches/scheduling, drain or hard-abort active work,
  stop the old Runner, activate the new immutable generation, and then start exactly one reviewed
  Runner generation. Do not rely on rolling overlap for this change.
- **Mitigation:** Queue and launch gates remain closed until one Runner generation is confirmed.
- **False-positive note:** An empty queue reduces exposure but is not a durable rotation control.

### SB-005 — Important — live lease assumptions remain unmeasured

- **Location:** `docs/target/READINESS.md:7-23,77-93`.
- **Evidence:** Issuer lifetime, idle timeout, cookie requirements, history namespace, exact
  expired-session response, and target ceilings remain open.
- **Impact:** A locally valid lease may still expire early, carry unexpected cross-case state, or
  fail with an unrecognized terminal response.
- **Fix:** Keep these as explicit unknowns and measure them only under a separately approved,
  synthetic-only observation. Never infer expiry from possession of an identifier.
- **Mitigation:** Short campaigns, terminal `401` handling, no in-run rotation, and preserved partial
  evidence remain required.

## Required lease schema and enforcement

The minimum closed metadata object for each versioned `secretref://` key should add:

```json
{
  "generation": "<immutable-generation>",
  "not_before": "<RFC3339 UTC>",
  "expires_at": "<RFC3339 UTC>",
  "value_sha256": "<digest produced inside the secret-provisioning boundary>",
  "target_binding": {
    "environment": "staging",
    "target_id": "<target-id>",
    "target_version": "<target-version>",
    "surface_id": "<surface-id>",
    "surface_version": "<surface-version>",
    "adapter_kind": "openemr",
    "scheme": "https",
    "host": "<exact-host>",
    "port": 443,
    "method": "POST",
    "relative_path": "chat",
    "auth_mode": "session",
    "credential_ref_sha256": "<digest of the opaque reference>",
    "synthetic_fixture_manifest_sha256": "<reviewed fixture-manifest digest>"
  }
}
```

Exact values must come from the reviewed catalog/scope and fixture artifacts, not caller-selected
defaults. Validation must:

1. reject unknown/missing fields and non-UTC or timezone-naive timestamps;
2. require the reference's final segment to equal `generation`;
3. require `not_before <= now < expires_at`, with only a documented bounded clock skew;
4. require expiry strictly beyond `min(grant expiry, Runner start + authorized timeout)`;
5. reject expiry beyond a server-owned issuer/lease maximum rather than accepting an operator-chosen
   far-future value;
6. compare every target-binding field and both derived hashes to the current catalog, authorization
   scope, fixture manifest, and campaign grant;
7. check not-before/expiry again before every attempt;
8. pin one value and one HTTP client for the campaign, then release both on success or abort; and
9. refuse replacement under the same generation/reference.

## Safe Runner-only Railway provisioning order

1. Land and independently review SB-001/SB-002 plus T-F05c; deploy one traceable release first.
2. Revoke or allow expiry of any session disclosed outside the secret manager. Obtain a fresh session
   for the reviewed synthetic patient through the target owner's secure flow.
3. Stop new launches and Scheduler enqueues; drain or hard-abort active work; stop the old Runner so
   deployment overlap cannot mix generations.
4. Create a new immutable generation, new `secretref://staging/.../<generation>` handle, and new
   target version/surface binding.
5. In Railway's private Runner service only, place the **raw identifier value** into a new sealed
   variable. Do not place it in Web, Scheduler, a command argument, shell history, repository file,
   ticket, log, screenshot, or evidence artifact.
6. Inside the same protected provisioning boundary, derive the digest without printing the value and
   write the non-secret binding/lease metadata. The catalog goes identically to Web and Runner; the
   binding map, lease metadata, and sealed value remain Runner-only.
7. Start one private Runner generation. Never overwrite an already authorized variable/reference.
8. Create the immutable campaign grant only after the deployed release, target observation,
   configuration projection, reviewed smoke, fixture, and lease metadata are final. A different
   Headshot Approver must approve it.
9. Run the zero-call gate below. Only a clean result permits consideration of T-F05b.

## Zero-call verification

Current offline evidence:

- The focused adapter/lease/Runner suite completed **25 passed** with bytecode and pytest cache writes
  disabled. It proves raw JSON placement, no bearer header, session-only profile selection,
  generation/digest pinning, expiry coverage, terminal expiry, cleanup, and no network in these tests.
- It does **not** prove not-before, exact lease target binding, maximum lifetime, deployed-variable
  correctness, target parity, or T-F05c.

Required before any target/provider call:

1. Add deterministic negatives for future not-before, expired/equal-boundary/overlong leases, every
   target-binding substitution, stale generation, reference-hash mismatch, cookie-wrapper shape,
   malformed/extra metadata, silent value replacement, and rolling-generation overlap.
2. Prove the public T-F05c path fails before database writes, resolver access, adapter/SDK
   construction, socket/DNS/HTTP, provider/target calls, and spend by patching each hook to raise.
3. Run the exact `tickets/T-F05c.md` `--check-only` command using only non-secret artifacts. Success
   may print only `CAMPAIGN_PREFLIGHT_OK <CAMPAIGN_AUTHORIZATION_SHA256>`; every mismatch exits 4.
4. Verify from Railway service metadata—not a raw variable listing—that the sealed variable,
   credential binding, and lease metadata are present only on the private Runner, and that Runner has
   no public domain.
5. Do not treat current `runner --check`, Web `/ready`, funding, possession of a session, or a passing
   target-free smoke as live authorization.

## Exact non-secret owner inputs still needed

- Approved staging target tuple: target ID/version, surface ID/version, adapter, exact HTTPS
  scheme/host/port, method/path, and allowlist hash.
- Reviewed synthetic patient/fixture IDs, hashes, attestation reference, and fixture-manifest hash.
- Fresh generation label, opaque credential-reference name, and Runner sealed-variable **name**
  (never its value).
- Issuer-attested absolute not-before, absolute expiry, idle-lifetime statement, and server-owned
  maximum accepted lease lifetime.
- Current reviewed release SHA plus deployment-manifest hash for Web/Runner/Scheduler.
- Secret-free target-contract/observation hash confirming the deployed `/chat` field contract.
- After deterministic prerequisites: complete campaign caps/nonce/expiry, Operator identity reference,
  and a distinct Approver identity/permission reference for `campaign.json`.

No secret value is an acceptable input to this report or to the T-F05c zero-call verifier.
