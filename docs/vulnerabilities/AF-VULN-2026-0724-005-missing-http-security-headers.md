# AF-VULN-2026-0724-005 — No HTTP security response headers on any captured Co-Pilot API response

> **Status: DRAFT — not published.** Publishing is a separate two-person human-approval gate
> (approver ≠ launcher). Drafted autonomously by the Documentation agent; **independently
> re-validated offline, twice**, against the retained captures only. No network call was made
> during either validation.
>
> **Disposition: LOW — control weakness (missing hardening baseline). Downgraded from the
> original MEDIUM.** The absence of the headers is certain. The impact is not.

| Field | Value |
|---|---|
| Report ID | `AF-VULN-2026-0724-005` (unique) |
| Classification | **control_weakness** — a missing control that raises risk; not itself exploitable as captured |
| Severity | **Low** (was Medium; see §3) |
| Category | Security misconfiguration · Transport-policy assertion · Output-handling defence-in-depth |
| OWASP Web | `A05:2021` Security Misconfiguration (CWE-693, CWE-16) — primary · `A02:2021` Cryptographic Failures — secondary, impact unconfirmed |
| OWASP LLM | `LLM05:2025` Improper Output Handling — inferred defence-in-depth only |
| Target | Clinical Co-Pilot, targets `copilot-week1` / `copilot-week2` (host by reference — see `config/live-target-catalog.*.json`; **no live URL is reproduced in this report**) |
| Evidence | 15 responses retained at `evals/results/bruno-20260724/{week1,week2}-bruno.json` |
| Judge verdict | **None.** No `Verdict` record exists for any header check — see §6 |

---

## 1. Summary

Every one of the 15 retained live responses — 4 from the week1 collection, 11 from week2, across
9 distinct route templates, all HTTP 200 — returns a response header union of **exactly 12 names**,
and **none of them is a security header**. The absence is uniform: there is no partially-hardened
route.

What is returned is `cache-control`, `connection`, either `content-length` or
`transfer-encoding`+`vary`, `content-type`, `date`, `server`, `x-copilot-request-id`,
`x-hikari-trace`, `x-railway-edge`, `x-railway-request-id`.

What is absent, at **0/15** each:

| Header | Count | Header | Count |
|---|---|---|---|
| `Strict-Transport-Security` | 0/15 | `Cross-Origin-Opener-Policy` | 0/15 |
| `Content-Security-Policy` (+ `-Report-Only`) | 0/15 | `Cross-Origin-Embedder-Policy` | 0/15 |
| `X-Content-Type-Options` | 0/15 | `Cross-Origin-Resource-Policy` | 0/15 |
| `X-Frame-Options` | 0/15 | `X-Permitted-Cross-Domain-Policies` | 0/15 |
| `Referrer-Policy` | 0/15 | `X-XSS-Protection` | 0/15 |
| `Permissions-Policy` | 0/15 | `Content-Disposition` | 0/15 |
| `Set-Cookie` | 0/15 | `Access-Control-*` (all) | 0/15 |

**But nothing in the retained corpus demonstrates an attacker turning that absence into impact.**
Every captured response is a machine-consumed API payload (14 `application/json`, 1 `image/png`),
each with an explicit `Content-Type`; there is no `text/html` document anywhere in the corpus; no
plaintext-HTTP request was ever issued; and the requests came from a CLI client with no browser
rendering context, no cookie jar and no `Origin` header. That is the definition of a control
weakness, not a vulnerability.

**The single most impactful confidentiality header for an API surface is correct.** `Cache-Control`
is `private, no-store` on all 11 data routes (including the private PNG preview) and
`no-store, no-cache, must-revalidate` on all 4 health/readiness probes — 15/15. Pin it as a
regression invariant; do not re-engineer it alongside the rest.

---

## 2. Offline reproduction (no network, no re-attack)

The original report's reproduction step was a live `curl` against the deployed origin. It is
replaced here: it embeds a live endpoint, it cannot run under the offline constraint, and executing
it would be an unauthorised re-attack outside the `authorized-live-campaign` gate.

```python
# Run from evals/results/bruno-20260724/ — reads retained files only, makes no network call.
import json
from collections import Counter

recs = [r for f in ("week1-bruno.json", "week2-bruno.json")
          for r in json.load(open(f))[0]["results"]]

print("RECORDS:", len(recs))                                           # 15
print("STATUSES:", Counter(r["response"]["status"] for r in recs))     # {200: 15}

hdrsets = [{k.lower() for k in r["response"]["headers"]} for r in recs]
print("HEADER UNION:", sorted(set().union(*hdrsets)))                  # 12 names

SEC = ["strict-transport-security", "content-security-policy", "x-content-type-options",
       "x-frame-options", "referrer-policy", "permissions-policy",
       "cross-origin-opener-policy", "cross-origin-embedder-policy",
       "cross-origin-resource-policy", "x-permitted-cross-domain-policies",
       "x-xss-protection", "content-disposition", "set-cookie",
       "access-control-allow-origin"]
for s in SEC:
    print(f"{s:38} {sum(s in h for h in hdrsets)}/{len(recs)}")        # every one -> 0/15

# Faithfulness: no redirect hop was followed and silently collapsed by the client.
print("url stable:", sum(r["request"]["url"] == r["response"]["url"] for r in recs))  # 15
```

**Derived results, re-obtained identically by two independent validators:**

- 15 records (4 week1 + 11 week2), matching each file's own `summary.totalRequests`.
- Statuses `{200: 15}`. Content types `{application/json: 14, image/png: 1}`.
- 9 route templates: `GET /health` ×2, `GET /ready` ×2, `POST /evidence/search` ×2,
  `POST /chat` ×2, `POST /documents` ×3, and one each of
  `GET /documents/{id}/status`, `/extraction-report`, `/pages/{n}`, `/readback-verification`.
- Header union = 12 names. Every one of **24** checked security headers = **0/15**.
- Header-count distribution `{11: 8, 10: 7}`; `content-length` on 7, `transfer-encoding` on 8,
  `vary: accept-encoding` on 8, intersection 0; `connection: close` on 15/15.
- `Cache-Control`: only two values, at counts 11 and 4, both correct.
- `request.url == response.url` on **15/15** — no redirect collapsed, so these are the origin's
  own final-response headers.

> **Parsing caveat for anyone re-running this.** The 3 `POST /documents` records store
> `request.data` as a Node `FormData` **object**, not a JSON string, so a bare
> `json.loads(r["request"]["data"])` raises `TypeError`. Type-check before parsing.

---

## 3. Why Low, and what would raise it

Each impact argument requires at least one precondition the corpus does not establish — and
several require preconditions the corpus **affirmatively contradicts**.

| Impact story | Precondition it needs | Status in the corpus |
|---|---|---|
| Clickjacking (`X-Frame-Options` / `frame-ancestors`) | An HTML surface on this origin | **0/15 `text/html`**; no request to either configured app path was ever made |
| XSS backstop (`CSP`) | An HTML surface **and** a prior regression in server-side sanitisation | Neither observed; CSP is the second line, not the control |
| Transport downgrade (`HSTS`) | The origin answers plaintext HTTP **and** the client would follow it | All 15 requests were `https`; no plaintext probe exists. The hosting **TLD is HSTS-preloaded at TLD level** in the browser preload list, which would force HTTPS for preload-honouring browsers regardless of the header |
| MIME sniffing (`nosniff`) | A client that sniffs away from an explicit `Content-Type` | All 15 carry an explicit `application/json` or `image/png`; modern browsers do not sniff those into HTML. Legacy-client defence-in-depth only |
| Cross-origin embed of the private PNG (`CORP`) | Possession of the artifact URL | The URL **is** the credential (`?session_id=…`), so an embedder already holds it. CORP grants an attacker nothing new |
| Cross-origin / UI-redress riding an authenticated session | An ambient-authority cookie | **`Set-Cookie` 0/15** and no `Cookie` header on any request — there is no ambient credential for a frame or embed to ride |
| `Referrer-Policy` compounding `…-004` | A browser rendering a credential-bearing URL | The 4 such requests came from a CLI client. Modern browsers default to `strict-origin-when-cross-origin`, which already strips path and query cross-origin |

> The HSTS preload point and the browser referrer-default are **external knowledge, not derived
> from any repo artifact.** They are flagged as such and must be confirmed against the published
> preload list before being relied on in front of a reviewer. They are stated because omitting them
> would leave the Low rating looking like a judgement call rather than a reasoned one.

**Preconditions an attacker actually needs for any of this to matter:** (a) an HTML surface served
from this origin; (b) an authenticated clinician's browser session on it; (c) for the transport
story, an active network-position attacker *and* a client that ignores the TLD preload; (d) for the
output-handling story, a prior failure of server-side sanitisation. None is evidenced.

**Raise to Medium if** an HTML console is confirmed on this origin, **or** the origin is confirmed
to answer on plaintext HTTP *and* the host is confirmed absent from the preload list.

**What is genuinely certain and depends on none of the above:** the `Strict-Transport-Security`
header is definitively *absent*, not merely unobserved. RFC 6797 requires a user agent to ignore an
STS header received over non-secure transport, so a correctly configured origin must emit it on
exactly the HTTPS 200 responses that were captured. It does not, on 15/15.

---

## 4. Sub-item: the headers that *are* present add fingerprinting surface

`Server: railway-hikari` and `X-Railway-Edge` (a single edge-region value on 15/15) disclose the
hosting stack and region. `X-Copilot-Request-Id` (15 distinct 32-hex values) and
`X-Railway-Request-Id` (15 distinct 22-char values) are per-response correlation identifiers and are
operationally justified.

`X-Hikari-Trace` deserves separate note: it carries only **2 distinct values across all 15
responses**, so it is a stable deploy/instance identifier rather than a per-request trace — a better
fingerprint than the original report's passing mention implies. This is an `A05` sub-item of the same
finding; only `x-copilot-request-id` (which the collections assert equals the body
`correlation_id`) has a retained operational purpose.

---

## 5. Observed vs expected

| | |
|---|---|
| **Expected** | One edge- or middleware-enforced hardening baseline on **every** response, including error responses and redirects: HSTS with long `max-age` + `includeSubDomains`; a CSP differentiated by surface (`default-src 'none'; frame-ancestors 'none'` for JSON, a nonce/hash script policy for any HTML); `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY`; `Referrer-Policy: no-referrer`; a restrictive `Permissions-Policy`; `Cross-Origin-Resource-Policy: same-origin` on private artifacts; `Content-Disposition` on the binary preview. Fingerprinting headers suppressed or genericised. |
| **Observed** | Response header union is 12 names across all 15 responses and contains **no security header of any kind**; 0/15 for all 24 checked. The absence is uniform — no partially-hardened route exists. `Cache-Control` is the sole correct control, at 15/15. |

---

## 6. Evidence limits — read before defending this finding

1. **Provenance and chain of custody.** The captures come from an owner-supplied **external**
   Bruno client (`@usebruno/cli@3.5.2`), not from the Headshot platform's scanner. They are
   **not byte-for-byte**: `SUMMARY.md:3-5` states the reports are scrubbed with SID values
   replaced, and both `.log` files record that the client actually wrote `week1-bruno-raw.json` /
   `week2-bruno-raw.json` to a path itself replaced by a placeholder. The raw originals are **not
   retained in this repository**, so the scrub cannot be independently re-verified. Record the
   scrub procedure and a digest of the raw artifact.
2. **Status-code scope.** All 15 captures are HTTP 200. `SUMMARY.md:21-23` notes a transient 429 on
   lab-upload whose capture was **not kept**, so header behaviour on 4xx/5xx paths is entirely
   unverified.
3. **No Judge verdict exists for this finding.** All recorded verdicts (17 + 17 in
   `live-campaign-*/verdicts.jsonl`, plus the `platform-live-run-20260724` cases) are
   `INDETERMINATE` and bound to `/chat` prompt-attack `attempt_id`s. The original report's
   `Judge verdict: INDETERMINATE` row is not attributable to any header check.
4. **Outside the platform's own harness.** Neither
   `evals/results/live-campaign-20260724*/responses.jsonl` nor `envelopes.jsonl` records **any**
   HTTP response header. This class of finding cannot currently be regression-tested by the
   platform that reported it.
5. **Not schema-renderable.** `src/agentforge/contracts/v1/vuln_report.json` requires 19 fields;
   this finding has no value for 6 of them — `finding_id`, `campaign_run_id`, `attempt_id`,
   `source_case_id`, `reproduction_sha256`, `evidence_references` — because it originates from an
   external run rather than a platform attempt.
6. **Multipart bodies unverifiable.** The 3 `POST /documents` records store `request.data` as a
   Node `FormData` object with `_streams` empty and `dataSize` 0, so credential carriage on those
   specific requests cannot be established offline.

---

## 7. Corrections applied to the original report

| # | Original claim | Correction |
|---|---|---|
| 1 | Header set is 10 names, "consistently limited" | It is **12** (`connection` and `content-length` omitted), and it is **not** uniform: 8 responses have 11 headers, 7 have 10. What *is* uniform is the absence of every security header |
| 2 | SID appears at `/app?sid=…` | **Fabricated.** No `/app` request, no `sid` parameter, anywhere in the corpus. The only URL-borne credential is `session_id`, on 4 week2 `GET /documents/{id}/…` routes. Report 004 itself concedes the UI form was not captured |
| 3 | `Referer` leaks the full URL to any third-party resource | Overstated. Requests came from a CLI client; modern browsers default to `strict-origin-when-cross-origin`, which strips path and query cross-origin |
| 4 | CSP/XFO protect "the console that renders model output" | No `text/html` response exists in the corpus. Plausible, unverifiable offline |
| 5 | HSTS absence exposes the session to downgrade | Header absence is **certain**; downgrade impact is **not established** — no plaintext probe, and the hosting TLD is preloaded |
| 6 | `Judge verdict: INDETERMINATE` | No `Verdict` record exists for any header check |
| 7 | Severity **Medium** | **Low** — see §3 |
| 8 | CWE-319 (cleartext transmission) | **Withdrawn** — all 15 requests and responses used HTTPS |
| 9 | CWE-1021 (clickjacking) | **Demoted to conditional** — it rests on the same missing HTML-surface premise as #4 |
| 10 | Live URL at report lines 14 and 46 | **Removed.** `src/agentforge/evals/validation.py:208` prohibits `https?://` in corpus content; `docs/vulnerabilities/README.md:3-4` has the same defect |
| 11 | Reproduction is a live `curl` | Replaced with the offline derivation in §2 |
| 12 | (omitted) | Additional absent headers named: all three `Cross-Origin-*`, `X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection`, `Content-Disposition`, `Set-Cookie`, all `Access-Control-*` |
| 13 | (omitted) | Scope, provenance, chain-of-custody, harness and schema limits — see §6 |
| 14 | (omitted) | `Set-Cookie` 0/15 means there is **no ambient-authority cookie session**, which structurally defeats the framing/CSRF/cross-origin-embed impact stories rather than merely leaving them unevidenced |
| 15 | (omitted) | The private artifact routes are **capability URLs**; missing `CORP` grants an embedder nothing it does not already hold |
| 16 | (omitted) | `X-Hikari-Trace` has only **2 distinct values** across 15 responses — a stable deploy identifier, not a per-request trace |
| 17 | (omitted) | `request.url == response.url` on 15/15 — proves no redirect hop was collapsed, closing the "HSTS lived on an unobserved hop" objection |

**Mappings declined as decorative.** `A01:2021 Broken Access Control` and
`LLM02:2025 Sensitive Information Disclosure` were considered and **dropped**. With no cookie
session and with capability-URL artifacts, the header absences add no access-control exposure of
their own; the URL-borne credential belongs to `AF-VULN-2026-0724-004` and the health/readiness
disclosure to `AF-VULN-2026-0724-006`. Claiming them here would inflate this report's apparent
surface.

**Cross-report note (affects 004, not this finding).** `config/targets.json` — the source of the
72-hour idle lifetime, 1,000-turn limit and `shared_sessions` figures that `AF-VULN-2026-0724-004`
relies on — is read by **no code**: `grep -rn "targets\.json" src/ scripts/ tests/` returns nothing,
and `docs/target/TARGETS.md:14-15` calls it "legacy/historical … not live-execution authority". The
live path reads `AGENTFORGE_LIVE_TARGET_CATALOG_JSON` from
`config/live-target-catalog.{staging,production}.json`, and `grep -c session_policy` returns **0**
for all three tracked catalog files. `TARGETS.md` attributes those figures to "the bundle README" —
owner-asserted, neither measured nor enforced. 004 should be re-validated on that point. Its
**core** claim is unaffected and remains the stronger finding of the pair: a sole-factor,
bearer-equivalent session identifier travelling in the URL query string is evidenced directly on 4
captured requests, with no `Authorization` header on any of the 15.

---

## 8. Recommended remediation

1. **One baseline, applied once.** Set HSTS (long `max-age` + `includeSubDomains`),
   `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
   and a restrictive `Permissions-Policy` at the edge or in a single response middleware, so they
   apply to every route **and every status code**.
2. **CSP, differentiated by surface.** `default-src 'none'; frame-ancestors 'none'` for JSON API
   responses; a nonce- or hash-based script policy with `frame-ancestors 'none'` for any HTML
   surface. **Confirm first** whether an HTML console is served from this origin — that premise is
   unverified and it is what caps the severity.
3. **Harden the binary preview.** `GET /documents/{id}/pages/{n}` returns `image/png` with neither
   `nosniff`, nor `Content-Disposition`, nor `Cross-Origin-Resource-Policy`. Add all three — but
   note the ordering: because that route authenticates by a query-string `session_id`, it is a
   capability URL, so **removing the credential from the URL is the load-bearing fix**, not CORP.
4. **Suppress the fingerprinting headers.** Genericise `Server`; drop `X-Railway-Edge`,
   `X-Hikari-Trace` and `X-Railway-Request-Id`; retain only `x-copilot-request-id`.
5. **Do not touch `Cache-Control`.** It is correct at 15/15. Pin it as a regression invariant.
6. **Jointly with `AF-VULN-2026-0724-004`, move the session identifier out of the URL.**
   `Referrer-Policy` mitigates a URL-borne credential; removing the credential retires the
   compounding argument *and* the CORP and capability-URL sub-items above.
7. **Settle the transport question properly.** Under the campaign gate, probe plaintext HTTP and
   record the host's preload status together. Both were unresolvable offline; both bear on severity.
8. **Platform-side.** Extend the Evidence Envelope and campaign response record to retain HTTP
   response headers — this finding class is currently invisible to the platform's own scanner.
9. **Then add a deterministic header oracle** to the regression corpus, and close the schema gap
   (`finding_id`, `campaign_run_id`, `attempt_id`, `source_case_id`, `reproduction_sha256`,
   `evidence_references`).
10. **Reporting hygiene.** Strip live endpoints from reports and from
    `docs/vulnerabilities/README.md`; record the capture scrub procedure and a raw-artifact digest;
    index 004, 005 and 006 in the reports table, which currently lists only 001–003.

---

## 9. Fix validation

**Status: `not_run`.** Do not mark this finding fixed on a header scan alone.

1. Re-run both Bruno collections against the remediated origin under the
   `authorized-live-campaign` gate; retain the new reports **plus** the scrub record and a digest
   of the pre-scrub raw file, alongside the 2026-07-24 baseline.
2. Re-run the §2 derivation and assert **15/15** (not 0/15) for `strict-transport-security`,
   `x-content-type-options`, `x-frame-options`, `referrer-policy` and `content-security-policy`,
   and that the header union grew by exactly the intended names and no others.
3. Assert the `image/png` preview now carries `nosniff`, `content-disposition` and
   `cross-origin-resource-policy` — **and** that its URL no longer carries `session_id`.
4. Assert `Cache-Control` has not regressed: still two values, still 15/15.
5. Assert the fingerprinting headers are gone or genericised, `x-hikari-trace` included.
6. Capture at least one 4xx and one 5xx (a malformed `POST /documents`; a rate-limited request) and
   assert the same header set applies to non-200 responses.
7. Assert `request.url == response.url` on every new record; if a redirect is now introduced,
   capture the redirect response itself and assert it carries HSTS.
8. Probe plaintext HTTP under the gate; assert a redirect to HTTPS. Record the preload-list status
   of the host in the same step.
9. Diff the old and new header unions and record the delta, so the fix is validated for the right
   reason rather than by a spot check.
10. **Only after** the Evidence Envelope retains response headers, promote these assertions into the
    regression corpus as a deterministic oracle, and confirm it **fails** against the retained
    2026-07-24 baseline and **passes** against the remediated capture.

---

## 10. Redaction status of the cited evidence

Independently swept. **No unmasked credential was found anywhere** under `evals/results/` or
`docs/vulnerabilities/`: no JWT-shaped string, no `Bearer <value>`, no `Set-Cookie` key, and zero
unmasked 24–40 character uppercase/digit/underscore tokens.

- **Already masked ✅** — the `session_id` value: 28 characters (19 uppercase, 6 asterisks, 2
  underscores, 1 digit), 2 distinct values, one per week. It occurs **6 times at the parsed-request
  level** (4 query + 2 body) and **10 times in the file text**, because the 4 query-borne values are
  mirrored into the matching `response.url` fields. Both counts are stated so a reviewer greps for
  the right number.
- **Cleartext but not credentials** — `x-copilot-request-id` (32-hex, 15 distinct; superficially
  resembles a session token and must not be mistaken for one during triage),
  `x-railway-request-id` (22-char, 15 distinct), the 40-hex build `sha` in `/health`
  (the subject of `…-006`), and the synthetic document UUIDs.
- **Newly flagged** — the full body of the `image/png` document-page preview (38,410 bytes) is
  retained **inline** in `week2-bruno.json`. It is a page image of a patient-scoped clinical
  document, acceptable **only** because the target carries a synthetic-data attestation in the live
  target catalog. That dependency must be stated in the evidence packet, not assumed, and this
  retention pattern must never be used for a target without such an attestation.
- **Scanner note** — a 31-character uppercase/underscore token in
  `evals/results/platform-live-run-20260724/` is the **published oracle canary name** already
  present in the tracked catalog's `canary_refs`, not a credential. It will trip a naive
  credential-shape scanner and should be allowlisted.
- **Removed in this rewrite** — the live `https://` endpoint that the original report embedded at
  its lines 14 and 46. `docs/vulnerabilities/README.md:3-4` still contains one and needs the same
  treatment.
