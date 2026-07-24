# AF-VULN-2026-0724-005 — Missing HTTP security response headers on all surfaces

> **Status: DRAFT — not published.** Publishing is a separate two-person human-approval gate
> (approver ≠ launcher). Drafted autonomously by the Documentation agent; awaiting review.
> **Disposition: MEDIUM — security misconfiguration / missing defense-in-depth (config finding).**

| Field | Value |
|---|---|
| Report ID | `AF-VULN-2026-0724-005` (unique) |
| Severity | **Medium** (defense-in-depth absent; compounds `AF-VULN-…-004`) |
| Category | Security misconfiguration · Transport hardening · Output-handling defense-in-depth |
| OWASP Web | `A05:2021` Security Misconfiguration (CWE-693 protection-mechanism failure, CWE-1021 clickjacking, CWE-319 cleartext/`Referer` leakage) |
| OWASP LLM | `LLM05:2025` Improper Output Handling (no CSP backstop for the console that renders model output) |
| Target | Clinical Co-Pilot — `https://agent-production-9f62.up.railway.app` |
| Campaign | Bruno `week1` + `week2` collections (authorized synthetic live run, 2026-07-24) |
| Judge verdict | `INDETERMINATE` (configuration finding, not an oracle-confirmed exploit) |

## Description & clinical impact
Every one of the 15 captured live responses (health, readiness, evidence search, chat, document
upload, status/extraction/preview/readback, intake) was inspected for standard security response
headers. The response header set was consistently limited to operational headers
(`cache-control`, `content-type`, `server: railway-hikari`, `x-copilot-request-id`,
`x-hikari-trace`, `x-railway-edge`, `x-railway-request-id`, `date`, `vary`, `transfer-encoding`).
**None** of the following were present on any response:

- `Strict-Transport-Security` (HSTS) — no enforced HTTPS pinning for a clinical app.
- `Content-Security-Policy` — no backstop against injected/reflected markup in the console that
  renders the model's `brief`/citations.
- `X-Content-Type-Options: nosniff` — MIME-sniffing not disabled.
- `X-Frame-Options` / `frame-ancestors` — clickjacking of the clinical UI not prevented.
- `Referrer-Policy` — **directly compounds `AF-VULN-…-004`:** captured document requests put the
  SID in the URL (`.../status?session_id=…`), while no `Referrer-Policy` is set. The run did not
  capture `/app?sid=…`, a browser navigation, or an outbound `Referer` containing the SID; the
  missing policy leaves a potential `Referer` exposure if such a page loads a third-party resource.
- `Permissions-Policy` — browser feature surface not constrained.

Clinical impact: the co-pilot renders model-produced text and cited evidence to a clinician's
browser. Without a CSP/`X-Content-Type-Options` backstop, any future gap in server-side output
sanitization becomes a stored/reflected-XSS path against the reviewing clinician; without HSTS the
session is exposed to downgrade/interception; without `Referrer-Policy` a URL-borne SID could leak
outbound in a browser flow. These are defense-in-depth controls that should not depend on the model
always declining to emit markup. (Note: data responses did correctly set `cache-control: private,
no-store`, and health/ready set `no-store, no-cache, must-revalidate` — caching hygiene is in
place.)

## Minimal reproduction sequence
```
curl -sD - -o /dev/null https://agent-production-9f62.up.railway.app/health
# Inspect the response headers: no Strict-Transport-Security, Content-Security-Policy,
# X-Content-Type-Options, X-Frame-Options, Referrer-Policy, or Permissions-Policy is returned.
# (Repeats identically for /ready, /evidence/search, /chat, /documents/*.)
```

## Observed vs expected
| | |
|---|---|
| **Expected** | A production clinical web surface returns HSTS, a restrictive CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options`/`frame-ancestors`, and `Referrer-Policy: no-referrer` (or stricter). |
| **Observed** | None of these headers are present on any surface; only operational/caching headers are returned. |

## Recommended remediation
1. Add `Strict-Transport-Security` (with a long max-age + `includeSubDomains`), a restrictive
   `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`
   (or CSP `frame-ancestors 'none'`), and `Permissions-Policy` to every response.
2. Set `Referrer-Policy: no-referrer` immediately — and, jointly with `AF-VULN-…-004`, stop putting
   the SID in the URL so a `Referer` leak becomes moot.
3. Render the model `brief`/citations as text (escape/strip markup and markdown links) in the
   console regardless of model behavior; treat CSP as the second line, not the only line.

## Current status & fix-validation
Status **open — Medium**. Directly observed from the captured live response headers of all 15
requests across both weeks. No adversarial exploit was oracle-confirmed (Judge `INDETERMINATE`);
this is a missing-hardening/config finding that materially compounds `AF-VULN-2026-0724-004`.
Fix-validation: **not run** (awaiting remediation).
