# AF-VULN-2026-0724-005 — No HTTP security response headers on any captured Co-Pilot API response

> **Status: DRAFT — not published.** Publishing is a separate two-person human-approval gate
> (approver ≠ launcher).
>
> **Authorship: hand-written.** The platform's Documentation agent did **not** draft this report and
> could not have — it rejects every verdict whose state is not `EXPLOIT_CONFIRMED`
> (`src/agentforge/agents/documentation/agent.py:172`), **no verdict record produced by any run in
> this repository has reached that state**. The only `EXPLOIT_CONFIRMED` states in the repo are 12
> authored `expected_verdict` labels in `evals/ground-truth/*.v1.json` — calibration fixtures whose
> own `campaign_run_id` is the literal `"ground-truth-unexecuted"`), and it emits schema-valid `VulnReport` JSON rather than Markdown. The finding was
> derived from an owner-supplied external Bruno capture and re-validated offline against the retained
> captures only. *(The "twice, independently, no network call" description of that re-validation is a
> process assertion — no repo artifact records it, and nothing here rests on it.)*
>
> **Disposition: severity `low` — control weakness (missing hardening baseline). Downgraded from the
> original `medium`.** The absence of the headers is certain. The impact is not.

| Field | Value |
|---|---|
| Report ID | `AF-VULN-2026-0724-005` (unique) |
| Classification | **control_weakness** — a missing control that raises risk; not itself exploitable as captured |
| Severity | **`low`** — the contract enum value (`src/agentforge/contracts/v1/vuln_report.json:37`); downgraded from `medium`, see §3 |
| Category | Security misconfiguration · Transport-policy assertion · Output-handling defence-in-depth |
| OWASP Web | `A05:2021` Security Misconfiguration (CWE-693, CWE-16) — primary · `A02:2021` Cryptographic Failures — secondary, impact unconfirmed |
| OWASP LLM | `LLM05:2025` Improper Output Handling — inferred defence-in-depth only |
| Target | Clinical Co-Pilot, targets `copilot-week1` / `copilot-week2` (host by reference — see `config/live-target-catalog.*.json`; **no live URL is reproduced in this report**) |
| Evidence | 15 responses retained at `evals/results/bruno-20260724/{week1,week2}-bruno.json` |
| Judge verdict | **None.** No `Verdict` record exists for any header check. Every verdict retained in the repo is `INDETERMINATE` and bound to a `POST /chat` prompt-attack `attempt_id` — separate evidence about a different surface, not an adjudication of this finding. See §6, limit 3 |

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
plaintext-HTTP request was ever issued; and the requests came from a CLI client
(`@usebruno/cli@3.5.2`, `SUMMARY.md:3`) whose recorded request-header set across all 15 exchanges is
exactly `{accept, content-type}` — no `Cookie` and no `Origin`. *(That is what the captures show. The
client's internal rendering or cookie-jar behaviour is not itself recorded and is not claimed here.)*
That is the definition of a control weakness, not a vulnerability.

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

recs = [
    r for f in ("week1-bruno.json", "week2-bruno.json") for r in json.load(open(f))[0]["results"]
]

print("RECORDS:", len(recs))  # 15
print("STATUSES:", Counter(r["response"]["status"] for r in recs))  # {200: 15}

hdrsets = [{k.lower() for k in r["response"]["headers"]} for r in recs]
print("HEADER UNION:", sorted(set().union(*hdrsets)))  # 12 names

SEC = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "x-permitted-cross-domain-policies",
    "x-xss-protection",
    "content-disposition",
    "set-cookie",
    "access-control-allow-origin",
]
for s in SEC:
    print(f"{s:38} {sum(s in h for h in hdrsets)}/{len(recs)}")  # every one -> 0/15

# Request/response URL equality — consistent with no client-followed redirect being collapsed.
print("url stable:", sum(r["request"]["url"] == r["response"]["url"] for r in recs))  # 15
```

**Derived results** (re-run the block above to reproduce every figure):

- 15 records (4 week1 + 11 week2), matching each file's own `summary.totalRequests`.
- Statuses `{200: 15}`. Content types `{application/json: 14, image/png: 1}`.
- 9 route templates: `GET /health` ×2, `GET /ready` ×2, `POST /evidence/search` ×2,
  `POST /chat` ×2, `POST /documents` ×3, and one each of
  `GET /documents/{id}/status`, `/extraction-report`, `/pages/{n}`, `/readback-verification`.
- Header union = 12 names. Every one of the **14** security headers checked by the script above =
  **0/15**. (The §1 table enumerates the same 14; an earlier draft said "24", which matches no list
  in this report and is withdrawn.)
- Header-count distribution `{11: 8, 10: 7}`; `content-length` on 7, `transfer-encoding` on 8,
  `vary: accept-encoding` on 8, intersection 0; `connection: close` on 15/15.
- `Cache-Control`: only two values, at counts 11 and 4, both correct.
- `request.url == response.url` on **15/15** — consistent with no client-followed redirect having
  been collapsed into these records. Note this does **not** establish that they are the origin's own
  headers: every response carries `server: railway-hikari` and `x-railway-edge`, so an edge hop is
  demonstrably present and is not separately observable in this corpus.

> **Parsing caveat for anyone re-running this.** The 3 `POST /documents` records store
> `request.data` as a Node `FormData` **object**, not a JSON string, so a bare
> `json.loads(r["request"]["data"])` raises `TypeError`. Type-check before parsing.

---

## 3. Why `low`, and what would raise it

Each impact argument requires at least one precondition the corpus does not establish — and
several require preconditions the corpus **affirmatively contradicts**.

The **Status** column below states only what the 15 captures show. Where an argument also depends on
external knowledge — a preload list, a browser default, an RFC — that dependency is named in the
column and is **not** treated as evidence.

| Impact story | Precondition it needs | Status in the corpus |
|---|---|---|
| Clickjacking (`X-Frame-Options` / `frame-ancestors`) | An HTML surface on this origin | **Unobserved.** 0/15 `text/html`; no request to any configured app/UI path was captured. Whether such a surface exists is **not established either way** — the corpus cannot show it does not |
| XSS backstop (`CSP`) | An HTML surface **and** a prior regression in server-side sanitisation | **Unobserved.** Neither appears in the corpus. CSP is a second line of defence, not the control; no claim is made about a console that was never captured |
| Transport downgrade (`HSTS`) | The origin answers plaintext HTTP **and** the client would follow it | All 15 requests were `https`; **no plaintext probe exists**, so downgrade impact is unestablished. *(An earlier draft asserted the hosting TLD is HSTS-preloaded. No repo artifact records any preload status, and this report does not name the host — the claim is withdrawn and must be confirmed against the published preload list before it is relied on.)* |
| MIME sniffing (`nosniff`) | A client that sniffs away from an explicit `Content-Type` | All 15 carry an explicit `application/json` or `image/png`. **No browser client appears in the corpus**, so sniffing behaviour is unevaluated here — not demonstrated defence-in-depth, and not demonstrated risk |
| Cross-origin embed of the private PNG (`CORP`) | Possession of the artifact URL | That route carries a query-string `session_id` and no other credential material on the wire, so it **behaves as** a capability URL and an embedder holding it already holds the credential. (No negative control was captured, so it is not established that the parameter is what authenticates — see `…-004` §5) |
| Cross-origin / UI-redress riding an authenticated session | An ambient-authority cookie | **`Set-Cookie` 0/15**, and no `Cookie` header on any of the 15 captured requests. No login or session-establishment flow was captured, so this shows **no ambient cookie credential on the captured API surface** — it does not prove none exists on the origin |
| `Referrer-Policy` compounding `…-004` | A browser rendering a credential-bearing URL | The 4 such requests came from a CLI client, so **no `Referer` behaviour was observed at all**. *(Browser referrer defaults are external knowledge, not derived from any repo artifact, and are not relied on here.)* |

> **The `low` rating rests on absence of evidence for impact, not on external mitigations.** An
> earlier draft leaned on two external-knowledge points — an HSTS TLD preload entry and modern
> browsers' `strict-origin-when-cross-origin` referrer default — to argue the rating down. Neither is
> derived from any repo artifact, so both have been removed from the reasoning above rather than
> merely footnoted. The rating stands on what the corpus does and does not contain.

**Preconditions an attacker actually needs for any of this to matter:** (a) an HTML surface served
from this origin; (b) an authenticated clinician's browser session on it; (c) for the transport
story, an active network-position attacker and an origin that answers plaintext HTTP; (d) for the
output-handling story, a prior failure of server-side sanitisation. **None is evidenced — and none is
excluded**, because the corpus contains no probe that would have shown it.

**Raise to `medium` if** an HTML console is confirmed on this origin, **or** the origin is confirmed
to answer on plaintext HTTP.

**What is genuinely certain and depends on none of the above:** `Strict-Transport-Security` is
absent on **15/15 HTTPS 200 responses** — precisely the class of response on which a correctly
configured origin would have to emit it, since a user agent ignores an STS header received over
non-secure transport. The measurement is 0/15; the "would have to emit it" step is external
standards knowledge (RFC 6797), not a repo artifact, and is flagged as such.

---

## 4. Sub-item: the headers that *are* present add fingerprinting surface

`Server: railway-hikari` and `X-Railway-Edge` (a single value, `ord1`, on 15/15) disclose the
hosting stack plus one opaque edge-location tag. What that tag denotes is not recorded in the
corpus; reading it as a geographic region is an inference. `X-Copilot-Request-Id` (15 distinct 32-hex values) and
`X-Railway-Request-Id` (15 distinct 22-char values) are per-response correlation identifiers and are
operationally justified.

`X-Hikari-Trace` deserves separate note: it carries only **2 distinct values across all 15
responses** (`…x8wt` ×8, `…zmv5` ×7), so it is **not** per-request. What it identifies is not
recorded anywhere in the corpus — "deploy/instance identifier" is an inference from cardinality
alone. What matters for this finding needs no such inference: a low-cardinality value is a better
fingerprint than a per-request one. This is an `A05` sub-item of the same finding.

Only `x-copilot-request-id` has a retained operational purpose. The collections assert it equals the
body `correlation_id`, and on the `/evidence/search` and `/chat` records it does (4 passing tests).
It does **not** match on the four `POST /documents` and job-status exchanges, where the body carries
the job's own id instead — so the equality is a property of some routes, not of all 15.

---

## 5. Observed vs expected

| | |
|---|---|
| **Expected** | One edge- or middleware-enforced hardening baseline on **every** response, including error responses and redirects: HSTS with long `max-age` + `includeSubDomains`; a CSP differentiated by surface (`default-src 'none'; frame-ancestors 'none'` for JSON, a nonce/hash script policy for any HTML); `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY`; `Referrer-Policy: no-referrer`; a restrictive `Permissions-Policy`; `Cross-Origin-Resource-Policy: same-origin` on private artifacts; `Content-Disposition` on the binary preview. Fingerprinting headers suppressed or genericised. |
| **Observed** | Response header union is 12 names across all 15 responses and contains **no security header of any kind**; 0/15 for all 14 headers checked in §2. The absence is uniform — no partially-hardened route exists. `Cache-Control` is the sole correct control, at 15/15. |

---

## 6. Evidence limits — read before defending this finding

1. **Provenance and chain of custody.** The captures come from an owner-supplied **external**
   Bruno client (`@usebruno/cli@3.5.2`), not from the Headshot platform's scanner. They are
   **not byte-for-byte**: `SUMMARY.md:3-5` states the reports are scrubbed with SID values replaced.
   The gap is worse than "the raw originals are missing": `SUMMARY.md:25` names companion
   `week1-bruno.log` / `week2-bruno.log` artifacts, and **no `.log` file is retained anywhere under
   `evals/results/`** — they match `.gitignore:20` (`*.log`). So neither the raw captures nor the
   client's own run logs are in this repository, and **the scrub cannot be independently re-verified
   here at all**. *(An earlier draft cited those `.log` files as evidence of the raw filenames; that
   citation is withdrawn — the files do not exist here.)* Record the scrub procedure and a digest of
   the raw artifact.
2. **Status-code scope.** All 15 captures are HTTP 200. `SUMMARY.md:21-23` notes a transient 429 on
   lab-upload whose capture was **not kept**, so header behaviour on 4xx/5xx paths is entirely
   unverified.
3. **No Judge verdict exists for this finding.** All 39 recorded verdicts — 17 in
   `live-campaign-20260724/verdicts.jsonl`, 17 in `-week1/`, and **5** under
   `platform-live-run-20260724/manifests/` (`AF-M11-DX-001`, `AF-M11-PI-003`, `AF-M11-TM-001..003`) —
   are `INDETERMINATE` and bound to `/chat` prompt-attack `attempt_id`s. They are **separate evidence
   about a different surface**, cited here only to establish that no header check was ever
   adjudicated. The original report's `Judge verdict: INDETERMINATE` row is not attributable to any
   header check and has been replaced with **None**.
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
| 2 | A UI request carrying the credential in its query string | **Dropped entirely.** No request to any app/UI path exists in the corpus and no such parameter appears anywhere in it. The only URL-borne credential is `session_id`, on 4 week2 `GET /documents/{id}/…` routes. What the corpus positively supports is stated in §1 and §3 instead |
| 3 | `Referer` leaks the full URL to any third-party resource | **Withdrawn.** All requests came from a CLI client, so no `Referer` behaviour was observed. Browser referrer defaults are external knowledge and are not relied on |
| 4 | CSP/XFO protect "the console that renders model output" | No `text/html` response exists in the corpus, and no request to any app/UI path was captured. Marked **unobserved** — not asserted, and not excluded |
| 5 | HSTS absence exposes the session to downgrade | Header absence is **certain** (0/15 on HTTPS 200s); downgrade impact is **not established** — no plaintext probe exists. *(The preload-list claim relied on here is withdrawn: no repo artifact records it.)* |
| 6 | `Judge verdict: INDETERMINATE` | No `Verdict` record exists for any header check; all 39 retained verdicts are `/chat` prompt-attack cases |
| 7 | Severity **Medium** | **`low`** — see §3 |
| 8 | CWE-319 (cleartext transmission) | **Withdrawn** — all 15 requests and responses used HTTPS |
| 9 | CWE-1021 (clickjacking) | **Demoted to conditional** — it rests on the same missing HTML-surface premise as #4 |
| 10 | Live URL embedded in the report body | **Removed** from this report. `src/agentforge/evals/validation.py:208` prohibits `https?://` in **corpus** content, so this is a house-style judgment here, not a validator violation. `docs/vulnerabilities/README.md` was scrubbed in the same rewrite and carries none; reports **001:14, 002:14 and 003:15 still do** and need the same treatment |
| 11 | Reproduction is a live `curl` | Replaced with the offline derivation in §2 |
| 12 | (omitted) | Additional absent headers named: all three `Cross-Origin-*`, `X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection`, `Content-Disposition`, `Set-Cookie`, all `Access-Control-*` |
| 13 | (omitted) | Scope, provenance, chain-of-custody, harness and schema limits — see §6 |
| 14 | (omitted) | `Set-Cookie` 0/15 and no `Cookie` header on any of the 15 captured requests: **no ambient cookie credential is observable on the captured API surface.** No login or session-establishment flow was captured, so this *weakens* the framing/CSRF/cross-origin-embed impact stories rather than structurally defeating them |
| 15 | (omitted) | The private artifact routes **behave as** capability URLs — a query-string `session_id` and no other credential material on the wire — so missing `CORP` grants an embedder nothing it does not already hold. (No negative control was captured; see `…-004` §5) |
| 16 | (omitted) | `X-Hikari-Trace` has only **2 distinct values** across 15 responses, so it is not per-request. What it identifies is not recorded in the corpus |
| 17 | (omitted) | `request.url == response.url` on 15/15 — **consistent with** no client-followed redirect having been collapsed. It does not close the "HSTS lived on an unobserved hop" objection: an edge hop is demonstrably present (`server: railway-hikari`, `x-railway-edge` 15/15) and is not separately observable |

**Mappings declined as decorative.** `A01:2021 Broken Access Control` and
`LLM02:2025 Sensitive Information Disclosure` were considered and **dropped**. On the captured
surface no cookie session is observable and the private artifacts behave as capability URLs, so the
header absences add no access-control exposure of their own; the URL-borne credential belongs to
`AF-VULN-2026-0724-004` and the health/readiness disclosure to `AF-VULN-2026-0724-006`. Claiming them
here would inflate this report's apparent surface.

**Cross-report note (affects 004, not this finding).** `config/targets.json` — the source of the
72-hour idle lifetime, 1,000-turn limit and `shared_sessions` figures that `AF-VULN-2026-0724-004`
cites — is read by **no code**: `grep -rn "targets\.json" src/ scripts/ tests/` returns nothing, and
`docs/target/TARGETS.md:15-16` calls it a "legacy/historical summary … not live-execution authority;
`scripts/live_campaign.py` now refuses". The live path reads `AGENTFORGE_LIVE_TARGET_CATALOG_JSON`
from `config/live-target-catalog.{staging,production}.json`, and `grep -c session_policy` returns
**0** for all three tracked catalog files. `TARGETS.md` attributes those figures to "the bundle
README" — owner-asserted, neither measured nor enforced. **004 already reflects this**: its §2.3
labels every 72-hour / shared-session / turn-budget statement *declared, not observed*, and demotes
CWE-613 to conditional. Its **core** claim is unaffected: a sole-factor, bearer-equivalent session
identifier travelling in the URL query string is evidenced directly on 4 captured requests, with no
`Authorization` header on any of the 15. (Whether the server *reads* that parameter is separately
unestablished — see 004 §3 and §5.)

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
   note the ordering: because that route carries a query-string `session_id` and no other credential
   material on the wire, it behaves as a capability URL, so **removing the credential from the URL is
   the load-bearing fix**, not CORP.
4. **Suppress the fingerprinting headers.** Genericise `Server`; drop `X-Railway-Edge`,
   `X-Hikari-Trace` and `X-Railway-Request-Id`; retain only `x-copilot-request-id`.
5. **Do not touch `Cache-Control`.** It is correct at 15/15. Pin it as a regression invariant.
6. **Jointly with `AF-VULN-2026-0724-004`, move the session identifier out of the URL.**
   `Referrer-Policy` mitigates a URL-borne credential; removing the credential retires the
   compounding argument *and* the CORP and capability-URL sub-items above.
7. **Settle the transport question properly.** Under the campaign gate, probe plaintext HTTP and
   record the host's HSTS preload-list status together. Both are unresolvable from this repository —
   no plaintext probe exists and no artifact records preload status — and both bear on severity.
8. **Platform-side.** Extend the Evidence Envelope and campaign response record to retain HTTP
   response headers — this finding class is currently invisible to the platform's own scanner.
9. **Then add a deterministic header oracle** to the regression corpus, and close the schema gap
   (`finding_id`, `campaign_run_id`, `attempt_id`, `source_case_id`, `reproduction_sha256`,
   `evidence_references`).
10. **Reporting hygiene.** Strip the live endpoint from reports **001, 002 and 003**, which still
    embed it (001:14, 002:14, 003:15); this report, 004, 006 and `docs/vulnerabilities/README.md`
    are already clean. Record the capture scrub procedure and a raw-artifact digest, and retain the
    client `.log` files that `SUMMARY.md:25` names but `.gitignore:20` currently excludes.
    *(The earlier item "index 004–006 in the reports table, which currently lists only 001–003" is
    withdrawn — `docs/vulnerabilities/README.md` already indexes all six.)*

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
`docs/vulnerabilities/`: no JWT-shaped string, no `Bearer <value>`, no `Set-Cookie` key, and no
credential-shaped 24–40 character uppercase/digit/underscore token. That token shape is not *zero*
matches — it matches exactly two strings, both benign and both identifiable by name: the published
oracle canary `SYNTH_CANARY_SYSTEM_PROMPT_4D2B` (31 chars, see the scanner note below) and the
environment-variable name `AGENTFORGE_LIVE_TARGET_CATALOG_JSON` (35 chars).

- **Already masked ✅** — the `session_id` value: 28 characters (19 uppercase, 6 asterisks, 2
  underscores, 1 digit), 2 distinct values, one per week. It occurs **6 times at the parsed-request
  level** (4 query + 2 body) and **10 times in the file text**, because the 4 query-borne values are
  mirrored into the matching `response.url` fields. Both counts are stated so a reviewer greps for
  the right number.
- **Cleartext but not credentials** — `x-copilot-request-id` (32-hex, 15 distinct; superficially
  resembles a session token and must not be mistaken for one during triage),
  `x-railway-request-id` (22-char, 15 distinct), the 40-hex build `sha` in `/health`
  (the subject of `…-006`), and the synthetic document UUIDs.
- **Newly flagged** — a copy of the `image/png` document-page preview body is retained **inline** in
  `week2-bruno.json`. Stated precisely, because an earlier draft got this wrong: **38,410 bytes is
  the response's declared `content-length`, not the size of what is retained.** The retained value is
  a *lossily text-decoded* string of 36,289 characters, of which **12,054 are U+FFFD replacement
  characters** — so the stored copy is corrupted and the original image cannot be reconstructed from
  it. By route and by the uploaded fixture it is a page rendering of a patient-scoped clinical
  document; the retained copy is too damaged to inspect. Retention is acceptable **only** because
  the target carries `synthetic_data_only: true` and a `synthetic_data_attestation_ref` in
  `config/live-target-catalog.{staging,production}.json`. That dependency must be stated in the
  evidence packet, not assumed, and this retention pattern must never be used for a target without
  such an attestation.
- **Scanner note** — a 31-character uppercase/underscore token in
  `evals/results/platform-live-run-20260724/` is the **published oracle canary name** already
  present in the tracked catalog's `canary_refs`, not a credential. It will trip a naive
  credential-shape scanner and should be allowlisted.
- **Removed in this rewrite** — the live `https://` endpoint the original report embedded in its
  header and reproduction sections. `docs/vulnerabilities/README.md` was scrubbed in the same
  rewrite and contains no URL at all. The endpoint **does** still appear in
  `AF-VULN-2026-0724-001:14`, `-002:14` and `-003:15`, which need the same treatment.
