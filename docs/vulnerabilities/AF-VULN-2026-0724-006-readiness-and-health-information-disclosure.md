# AF-VULN-2026-0724-006 — Anonymous liveness/readiness endpoints disclose a component inventory and a build identifier, and the readiness probe performs an unauthenticated multi-second upstream dependency fan-out

> **Status: DRAFT — not published.** Publication is a two-person human-approval gate
> (approver ≠ launcher). **Remediation is also gated** — no fix is applied to the target by this
> platform. Drafted autonomously by the Documentation agent; revised after an independent
> adversarial re-validation against the retained captures.

| Field | Value |
|---|---|
| Report ID | `AF-VULN-2026-0724-006` (unique) |
| Classification | **`control_weakness`** (disclosure component alone would be `informational_exposure`) |
| Severity | **`low`** — conditional upgrade path to `medium` stated below |
| Category | Security misconfiguration · Verbose diagnostics · Unauthenticated resource fan-out |
| OWASP Web | `A05:2021` Security Misconfiguration (CWE-200) · `A04:2021` Insecure Design (CWE-405, CWE-770) |
| OWASP LLM | `LLM02:2025` Sensitive Information Disclosure · `LLM10:2025` Unbounded Consumption · `LLM03:2025` Supply Chain (hedged) |
| Target | Clinical Co-Pilot — routes `GET /health` and `GET /ready` (host intentionally omitted; see Redaction) |
| Evidence provenance | **External owner-supplied client** (`@usebruno/cli` 3.5.2), week1 + week2 collections, 2026-07-24. Not the Headshot platform's own scanner. |
| Judge verdict | **None.** The Judge never evaluated these routes — see Corrections. |
| Independently reproduced | **Yes**, offline, from `evals/results/bruno-20260724/` with no network access |

---

## 1. Classification and severity

**Classification: `control_weakness`.**

The disclosure on its own would be `informational_exposure` — two anonymous GETs return a flat
inventory of nine component labels with hard/soft criticality tiers, an all-true health boolean,
five distinct detail strings, and a 40-character lowercase-hex build identifier. No credential, no
PHI, no library version, no stack trace, no state-changing capability.

But the retained captures also record per-request timings, and they change the finding:

| Route | week1 | week2 |
|---|---|---|
| `GET /health` | 217 ms | 294 ms |
| `GET /ready` | **9,643 ms** | **7,700 ms** |
| `POST /evidence/search` | 4,160 ms | 5,653 ms |
| `/documents` routes | — | 280–2,857 ms |

The anonymous readiness probe is 26–33× more expensive than the anonymous liveness probe on the
same host, and slower than the evidence-search API. Read alongside the probe's own detail strings —
`HTTP 200` for `openemr_fhir`, `HTTP 200` for `anthropic`, `authorized_read_ok` for
`document_category_read` — a credential-free GET appears to compel the target into live outbound
calls to its EHR backend, to a **metered model vendor**, and into an authorized read against the
record backend. That is a missing or ineffective control (no authentication, unknown rate limiting
on an expensive upstream-fanning operation), not merely information that aids an attacker.

It is **not** `confirmed_vulnerability`. No sustained load was applied — `config/targets.json`
`rules.no_dos_or_load_testing: true` forbids it — no availability or cost impact was observed, and
with n=2 the absence of a `429` proves nothing about rate limiting.

**Severity: `low`.**

*Preconditions an attacker actually needs:* network reachability to a public route. Nothing else —
no credential, no session, no user interaction, no victim click, no rate-limit evasion, no prior
foothold. That is the weakest possible precondition set and the only factor arguing upward.

*Why it stays low anyway:* the disclosed set contains no secret, no PHI, no payload-level network
locator, and no dependency version — the three things that normally lift an information-disclosure
finding to medium. Several labels (a FHIR backend, a model vendor) are inferable from the product
description. The build identifier's value is strictly conditional on the Co-Pilot's source
repository being readable, which cannot be established offline and is not assumed. The amplification
component is measured but its *impact* is unquantified.

*Explicit upgrade condition — state it, do not assume it:* if an authorized follow-up confirms that
`/ready` performs **uncached** upstream calls per request, including the metered model-vendor call,
with **no effective rate limit**, this becomes **`medium`** as unauthenticated resource
amplification / denial-of-wallet against a clinical system. The exact test is in §7.

---

## 2. Reproduction — offline, over retained evidence

This is a re-derivation from evidence already held, not a re-attack. Re-attacking would require
network access and fresh authorization under the campaign gate.

```
# Payload, auth posture, and timing — all from the retained captures.
python3 - <<'PY'
import json, glob
from urllib.parse import urlsplit
for f in sorted(glob.glob('evals/results/bruno-20260724/week*-bruno.json')):
    for r in json.load(open(f))[0]['results']:
        p = urlsplit(r['request']['url']).path
        if p in ('/health', '/ready'):
            b = r['response']['data']
            print(f.split('/')[-1], p, r['response']['status'],
                  'req_headers=', sorted(k.lower() for k in r['request']['headers']),
                  'has_body=', 'data' in r['request'],
                  'query=', bool(urlsplit(r['request']['url']).query),
                  'body_keys=', sorted(b),
                  'sha_len=', len(b.get('sha', '')) or '-',
                  'ms=', r['response']['responseTime'])
            for c in b.get('checks', []):
                print('   ', c['name'], c['kind'], c['ok'], repr(c['detail']))
PY
```

Output — four rows, identical structure and content across suites:

- `week1 /health 200 req_headers=['content-type'] has_body=False query=False body_keys=['sha','status'] sha_len=40 ms=217`
- `week1 /ready 200 req_headers=['content-type'] has_body=False query=False body_keys=['checks','status'] ms=9643` followed by nine checks
- `week2 /health … sha_len=40 ms=294`
- `week2 /ready … ms=7700`, nine identical checks

Corroborating derivations, all network-free:

- Response-header union over all 15 retained responses → exactly 12 names, none a security header.
- Distinct 40-hex values corpus-wide → exactly 1, equal to `health.sha`, compared by SHA-256 digest
  prefix and **never emitted**.
- Route census → 15 responses over 9 distinct routes, one host (compared by `sha256(netloc)` so no
  URL is printed).
- `grep -rn "targets\.json" src/ scripts/` → exit status 1, no hits.
- Timings independently corroborated in cleartext by
  `evals/results/bruno-20260724/week1-bruno.log` line 6: `ready (200 OK) - 9643 ms`.

---

## 3. Observed vs expected

| | |
|---|---|
| **Expected** | An anonymous liveness probe returns a minimal process-alive signal, cheaply and in constant time. An anonymous readiness probe returns only the aggregate decision an orchestrator needs — `200 ready` / `503 not-ready` — served from a short-TTL cached evaluation so an unauthenticated caller cannot compel per-request outbound work, and completing inside a normal probe timeout (1–5 s). Per-dependency inventory, criticality tiers, per-component detail, and build identity are operator telemetry, gated behind operator authentication or an internal-only interface. |
| **Observed** | Both probes anonymous (request headers exactly `['content-type']`, no query, no body on all four captures), both `200`. Liveness returns `status:"alive"` plus a 40-char hex build identifier, identical across suites. Readiness returns `status:"ready"` plus nine `{name, kind, ok, detail}` entries — `openemr_fhir`, `anthropic`, `session_store`, `langfuse`, `retrieval_index`, `active_reranker`, `document_runtime`, `document_category_read`, `graph_state` (5 hard / 4 soft). All nine `ok:true`; only five detail strings ever observed (`HTTP 200`, `ok`, `ready`, `authorized_read_ok`, `graph_enabled`). Readiness costs 7,700–9,643 ms. The same responses disclose `server: railway-hikari` and `x-railway-edge: ord1` on 15/15. |

An anonymous caller therefore learns: the record system, the model vendor, the observability vendor,
the presence of a retrieval index **and a separate reranking stage**, a graph-state component, the
operator's own hard/soft criticality ranking, the deployed build identity, the hosting platform and
the edge region — and can drive roughly eight to ten seconds of upstream-fanning server work per
credential-free request.

**Reference implementation, in this repo:** `src/agentforge/health.py:40` returns
`{"status":"alive"}`; lines 50–51 return `{"status":"ready"}` or a fail-closed `503
{"status":"not_ready"}` — no dependency detail, no build identifier. The expected contract is not
hypothetical.

---

## 4. Evidence limits — read before relying on this

These are stated up front rather than buried, because two of them bound the finding's strength.

1. **The degraded path was never exercised.** All nine checks reported `ok:true` in both captures.
   The "tells an attacker which dependency to target" argument is therefore about *naming*, not
   about live failure signal, and the detail strings' behaviour during an outage is unknown.
2. **The per-request (vs cached) nature of the upstream calls is inferred, not proven.** Two
   independent circumstantial lines support it — the 26–33× latency asymmetry and the `HTTP 200`
   detail strings — but `/ready` was the second request in both suites, so a cold dependency-client
   effect cannot be fully excluded, and a slow purely-internal check is not ruled out.
3. **Rate-limiting status is unknown and must not be asserted.** n=2, no `429` observed, and
   repeated probing is forbidden by the authorization.
4. **The `sha` field's semantics are unverifiable offline.** It is a 40-character hex build
   identifier; nothing links it to a VCS revision. Prior versions called it a "git commit SHA".
5. **Three `POST /documents` request bodies were not retained** (the serialized `FormData` wrapper
   has an empty `_streams` array), so their body-level credential content cannot be inspected.
   Header-level claims are unaffected — headers are fully retained.

---

## 5. OWASP mapping

**`A05:2021` Security Misconfiguration** — the disclosure half. Operator-grade telemetry is
configured to be served to anonymous callers on endpoints whose legitimate contract is a coarse
alive/ready signal (CWE-200). *Considered and rejected:* `A01:2021` Broken Access Control — no
control was bypassed and no resource the caller lacked rights to was reached. Note that "these
endpoints are intended to be anonymous" is an inference from convention, not an observed fact about
this target's intent.

**`A04:2021` Insecure Design** — the control-weakness half. An unauthenticated route that
synchronously fans out to a paid third-party API, an EHR backend, and an authorized record read,
measured at 7,700–9,643 ms per request, is an asymmetric resource-consumption design (CWE-405;
CWE-770 allocation without limits). It is a property of the readiness *contract*, not a bad config
value, which is why A04 rather than A05 carries it.

**`LLM02:2025` Sensitive Information Disclosure** — the readiness envelope discloses the AI
application's composition: model vendor, LLM observability pipeline, retrieval index, separate
reranking stage, graph-state component. Scoped honestly: architecture disclosure, **not** system
prompt, model weights, training data, or patient data — none of which appear in either payload.
That is precisely why severity stays low.

**`LLM10:2025` Unbounded Consumption** — non-decorative, and the strongest LLM mapping for the new
evidence. The readiness check reports `HTTP 200` for its `anthropic` dependency, so an anonymous,
credential-free GET appears to induce a call to a metered model vendor; 7.7–9.6 s per request with
no observed limiter is the denial-of-wallet shape LLM10 covers. Asserted as a design exposure
requiring a targeted authorized test, not as a demonstrated consumption attack.

**`LLM03:2025` Supply Chain** — secondary, deliberately hedged. Naming third-party components plus
an exact build identifier gives a ready-made shortlist for supply-chain targeting. Conditional
twice over: it only bites if the source repository or dependency manifest is reachable, *and* the
identifier's interpretation as a source revision is itself unverifiable offline.

---

## 6. Remediation

1. **Reduce the anonymous liveness payload to a process-alive signal only.** Remove the build
   identifier; expose build/version identity on an authenticated operator interface or an
   internal-only route.
2. **Split readiness into two contracts.** An anonymous probe returning only the aggregate decision
   (`200 ready` / `503 not-ready`, optionally a single status string), and a detailed dependency
   view requiring operator authentication or bound to an internal/private service interface.
3. **Highest priority — decouple the anonymous readiness response from live dependency
   evaluation.** Evaluate dependencies on a background schedule; serve the anonymous probe from the
   last cached result with a short TTL, so a credential-free GET cannot compel outbound calls to the
   EHR backend, the metered model vendor, or an authorized record read. Target a sub-second
   response. The observed 7.7–9.6 s also exceeds typical orchestrator probe timeouts and is an
   availability risk in its own right.
4. **Apply per-source rate limiting** to the anonymous readiness route regardless of the caching
   change, and alert on anomalous probe volume. Do not rely on "no 429 was seen" — only two
   requests were made.
5. **Audit `document_category_read` specifically.** If it performs a real authorized read against
   the record backend on each anonymous request, move it to the background evaluator so an
   unauthenticated caller can never trigger it.
6. **Keep the hard/soft dependency model.** It is good operational design; the fix is *who can read
   it*, not deleting the signal. Use the **target's own** operator authorization scheme — do **not**
   import the Headshot platform's Clerk permission names (`org:console:read` etc.), which have no
   meaning on the target.
7. **Pin the failure-mode contract for the gated view before it ships.** On a degraded dependency
   the detail string must be a bounded enum (e.g. `unreachable`, `timeout`, `unauthorized`) and must
   never carry an upstream error body, exception text, hostname, URL, or credential fragment. The
   degraded path is currently unspecified and untested.
8. **Suppress or genericise `server` and `x-railway-edge`,** which disclose hosting platform and
   edge region on all 15 responses. Low value alone; free alongside the `AF-VULN-2026-0724-005`
   security-header work.
9. **Audit adjacent version disclosure.** The evidence-search surface — marked
   `authentication_required: false` in the trusted target catalog — returns `corpus_version`
   (`<corpus-name>@<64-hex>`) at the response root and on all five items, and each item's
   `source_id` carries the same form. Decide deliberately whether corpus provenance must be
   anonymous-readable (it plausibly must, for citation integrity) rather than leaving it unreviewed.
10. **Register `/health` and `/ready` as first-class surfaces** in
    `config/live-target-catalog.staging.json` / `.production.json` and the clinical-copilot alias
    subset, with an explicit anonymous `trust_boundary`, so future platform campaigns cover them
    instead of leaving them to an external client.

---

## 7. Fix validation — what "closed" means

Currently **not run**. Closure requires all of the following, and the outcome may be recorded as
`passed_for_right_reason` **only** if the assertions pass because the payloads and timings changed —
not because the endpoints became unreachable, started erroring, were rate-limited into failure, or
were dropped from the capture set.

1. Re-run the owner's liveness and readiness requests under the campaign authorization gate; retain
   a fresh SID-scrubbed capture alongside the 2026-07-24 baseline.
2. Offline: the liveness payload key set is exactly `{'status'}` — no `sha` — and no 40-character
   hex value appears anywhere in the anonymous body.
3. Offline: the anonymous readiness payload has no `checks` key, `body.keys()` ⊆ `{'status'}`, and
   none of the nine component strings appears in the response bytes.
4. **Amplification — the primary closure criterion for the control-weakness half.**
   `response.responseTime` for anonymous `GET /ready` is under 1,000 ms and within the same order of
   magnitude as `GET /health`, against the 9,643 / 7,700 ms baseline.
5. Under a narrowly scoped, separately authorized test that does **not** constitute load testing,
   instrument egress and confirm that N sequential anonymous `/ready` requests produce fewer than N
   outbound calls to the model vendor and to the EHR backend. Record the observed cache TTL.
6. Confirm a per-source rate limit exists by observing a `429` at a documented threshold, and record
   that threshold. Do not close this on "no 429 observed."
7. The readiness decision is still actionable: healthy → `200 ready`; a hard dependency failed in a
   staging drill → `503` fail-closed. Detail and cost removed; signal retained.
8. Gated detail view: unauthenticated → `401`/`403` (never `200` with a body); authenticated
   operator → the full nine-component envelope. Capture both. Then fail one hard and one soft
   dependency in staging and assert every detail string is a member of the declared bounded enum.
9. Re-run the header-union derivation: no regression in the twelve operational headers; confirm
   whether `server`/`x-railway-edge` were genericised and whether `AF-VULN-2026-0724-005` was fixed
   in the same deploy. Confirm the catalog now registers both routes and
   `scripts/validate_target_catalog.py` still passes network-free.

---

## 8. Redaction and handling

- **Session identifiers in the captures are already scrubbed.** Week 2 carries nine occurrences of
  an asterisk-delimited placeholder (28 chars, no entropy) at byte-accurate lines 299, 331, 366,
  394, 424, 445, 475, 511, 654 — eight on `url` lines (four request URLs plus four echoed
  `response.url` fields) and one in the `/chat` body. Week 1 carries one, at line 318. Exactly one
  distinct placeholder value per file: the scrub was uniform. *(Line numbers must be derived by
  splitting on `b'\n'`; Python text-mode iteration yields different numbers because universal-newline
  translation splits on `\r` bytes inside the retained PNG payload.)*
- **The build identifier itself is retained in cleartext** in the captures (line 33 of both files).
  It is not a credential and does not require scrubbing from an internal evidence store, but it must
  never be copied into a report body, slide, or externally circulated artifact — doing so reproduces
  the exposure this report asks the owner to close. All handling here compared it by SHA-256 digest
  prefix only.
- **PHI-shaped but synthetic.** The `/chat` responses retain populated patient identity fields
  (name, gender, ISO birth date) and a clinical brief. The patient name carries Synthea's
  trailing-digit pattern and `config/targets.json` sets `rules.synthetic_data_only: true`, so the
  no-real-PHI gate holds. Flagged so no reviewer mistakes these for real PHI or pastes them into a
  report.
- **Correlation and infrastructure identifiers are not secrets.** `x-copilot-request-id` (32-hex, 15
  distinct — one per response, none appearing in any body), `x-railway-request-id` (22-char
  base64url, 15 distinct), `x-hikari-trace` (9-char tag), `x-railway-edge` (`ord1`). Noted so the
  32-hex request id is not mistaken for a session token.
- **Content digests are not secrets.** Three distinct 64-hex SHA-256 values appear as
  `corpus_version`, per-item `source_id`, and a readback `expected_hash` — provenance over a public
  clinical-guideline corpus and synthetic uploads.
- **No live URL appears in this document.** The host is not a secret — it is the declared allowlist
  entry in `config/targets.json` — but a vulnerability report circulates more widely than the repo.
  The scrub is register-wide: the live URL currently appears in **all six** reports (001:14, 002:14,
  003:15, 004:15/50/56, 005:14/46, 006:14/45/49) and `README.md:4`. For precision: the repo's
  prohibited-pattern list flagging `https://` strings lives at
  `src/agentforge/evals/validation.py:208` and governs the **eval corpus**, not vuln reports — it is
  a house-style analogue here, not a binding rule.

---

## 9. Corrections to the previous version

**Against the original report:**

- **Severity `Low–Medium` is not a legal value.** `src/agentforge/contracts/v1/vuln_report.json:37`
  restricts severity to `low|medium|high|critical`. The illegal value appeared twice (status block
  line 5, header table line 10), and severity was conflated with classification under one
  "Disposition" label.
- **Judge verdict `INDETERMINATE` is misattributed.** The Judge never evaluated `/health` or
  `/ready`. All INDETERMINATE verdicts come from `/chat`-only runs: 17 probes in
  `live-campaign-20260724`, 17 in `-week1`, and 4 platform cases (`AF-M11-PI-003`,
  `AF-M11-TM-001..003`). No Judge verdict exists for this finding.
- **Provenance is misstated by omission.** These captures came from an **external** owner-supplied
  client (`@usebruno/cli` 3.5.2), not the platform's scanner. That matters twice: the platform's own
  campaign records contain no HTTP response headers at all, and `/health` / `/ready` are not
  registered surfaces in the catalog — so the platform *could not* have produced this evidence.
- **"Full internal dependency topology" overstates the payload** — no hostnames, ports, versions, or
  edges. "Component inventory" is accurate.
- **The field inventory is incomplete** — it omits the `ok` boolean and never states that all nine
  checks reported `ok:true` with only five distinct detail strings observed. Without that a reader
  cannot tell the degraded path was never exercised.
- **"Whether reads are authorized" misreads the evidence.** `authorized_read_ok` is the *target's
  own* self-check succeeding; it says nothing about the anonymous caller's authorization state.
- **"A graph state engine" is an inference presented as observation** — the capture shows a check
  named `graph_state` with detail `graph_enabled`; no engine, product, or framework is named.
- **The live-curl block is a re-attack, not a reproduction.** Replaced with an offline derivation.
- **Remediation gating on `org:console:read` is a category error** — that is a Headshot *platform*
  Clerk permission, not one the target possesses.
- **Scope and closure criteria were missing** — the anonymous evidence-search version disclosure was
  unmentioned; fix-validation said only "not run"; the two-person gate was stated for publication
  but not remediation; and the finding is absent from the `docs/vulnerabilities/README.md` register,
  whose table stops at `AF-VULN-2026-0724-003`.

**Against the first re-validation (conclusions changed on re-review):**

- **Classification moved `informational_exposure` → `control_weakness`**, on timing evidence the
  first pass did not derive. See §1.
- **The claim that `SUMMARY.md`'s "bearer credentials" wording is contradicted by the captures is
  withdrawn.** "Bearer credential" is the standard term for a possession-based token, independent of
  the HTTP Bearer scheme, and the repo uses it correctly — `docs/target/TARGETS.md:20` reads "The
  Week 1 / Week 2 session SIDs are bearer credentials for synthetic patient data." That correction
  was itself an overreach.
- **"Build commit identifier" downgraded to "build identifier"** and marked unverifiable offline.
- **Added:** `server: railway-hikari` and `x-railway-edge: ord1` on 15/15 responses — the "no
  hostname/IP/port" claim is true of the *payload* but incomplete for the *endpoints*.
- **Qualified:** "six of 15 requests carry a session identifier" — three `POST /documents` bodies
  are unretained and cannot be inspected. The header-level claim stands fully.
- **Corrected:** the evidence-search version disclosure is on `items`, not "snippets"; `source_id`
  also carries a `<name>@<64-hex>` digest. The corpus is a public clinical-guideline set, which
  strengthens the hedge that anonymous readability may be required for citation integrity.
- **Refined:** `validation.py:208` governs the eval corpus, not reports; the redaction advice stands
  on hygiene merit but is not a binding rule.
- **Expanded:** the live-URL scrub is register-wide (all six reports plus the README), not three
  files.

---

## 10. Cross-report findings

**`AF-VULN-2026-0724-004` — not softened; its core is independently confirmed.** A `POST /chat`
carrying only `{session_id, message}` and a `content-type` header returned `200` with a populated
patient object (name, gender, ISO birth date) and a clinical brief citing `source_type:
"patient_record"`, with **zero** `Authorization`/`Cookie` headers anywhere in the 15-request corpus,
while the same identifier travels in the query string on four `/documents` sub-route GETs
(CWE-598). That is sole-factor, possession-based access to clinical data, placed where it lands in
edge, proxy, and browser-history logs. Under the enum, 004 is a **`confirmed_vulnerability` at
`medium`**, rising to `high` if the deployed UI is confirmed to place the identifier in the address
bar or if the target ever serves non-synthetic data. Two corrections: its `Referer`-leak argument
remains theoretical — no capture shows a `Referer` header or an external subresource load; and its
citation of a 72-hour idle lifetime, 1,000-turn shared budget, and shared-caller property as "the
target's own configuration" must be marked **`unverifiable_offline`**. Those keys exist only in
`config/targets.json` lines 5–11; `grep -rn "targets\.json" src/ scripts/` returns exit status 1
with zero hits, and `docs/target/TARGETS.md:15` calls that file a "legacy/historical summary … not
live-execution authority." Nothing in the captures measures session lifetime, turn budget, or
sharing.

**`AF-VULN-2026-0724-005` — central claim confirmed, two details wrong.** Its observed-header list
omits `connection` and `content-length` (the true union is 12 names), and its `Referrer-Policy`
argument cites an `/app?sid=…` request that appears nowhere in the captures — `/app` was never
captured and the parameter name is `session_id`, not `sid`. Its central claim — none of the six
named security headers on any of the 15 responses — is **CONFIRMED** and should stand, with an added
acknowledgement that HSTS absence was observed at the application layer only, since no
HTTP-to-HTTPS or edge-injection path was ever probed.
