# THREAT_MODEL.md — OpenEMR target + Headshot platform identity boundary

> **First-pass** target threat model produced by `/arch-draft` (the "AUDIT.md slot" per CLAUDE.md). The
> `threat-model` skill deepens it once the platform has probed the live target. Existing target defenses
> are marked **to-be-probed** where they are not yet observed — never assumed. The six numbered categories
> describe the **external target**. A separate section below now models the Headshot platform's human
> identity boundary. Clerk integration and authenticated Railway deployment are selected/planned, not
> claimed deployed. No real PHI is referenced anywhere in this repo.

## Summary (~500 words)

The target is a Clinical Co-Pilot chatbot embedded in OpenEMR that helps users retrieve chart
information, summarize notes, assist with intake, and support clinical operations. From the
platform's perspective it is a **maximally exposed LLM application**: it retrieves patient data
(RAG over clinical records), writes back to the record (drafts notes / assists with orders), invokes
tools/functions, and ingests uploaded content. Each of those four capabilities is an attack surface,
and their combination is what makes the target dangerous — an indirect injection delivered through an
uploaded document can reach a tool that writes to another patient's chart. The clinical setting
raises the blast radius from "wrong answer" to "wrong answer a clinician may act on," and from "data
leak" to "PHI disclosure across patients."

**Highest-risk categories, in priority order.** (1) **Indirect + multi-turn prompt injection**,
because the target ingests untrusted uploaded content and holds multi-turn context — the PRD already
reports "uploaded content appeared to influence future responses" and "multi-turn conversations
occasionally produced responses that ignored previous safeguards." (2) **PHI exfiltration /
cross-patient exposure / authorization bypass**, because RAG over patient data plus a broken access
boundary is a direct HIPAA-relevant disclosure. (3) **Tool misuse with write-back**, because
unintended invocation or parameter tampering can corrupt the record or place orders — the only
category here with autonomous *action* consequences. (4) **State corruption / context poisoning**,
because conversation history is a persistence layer an attacker can seed. (5) **DoS / cost
amplification**, because recursive tool calls and long chains already made "runtime cost and
performance difficult to predict." (6) **Identity / role exploitation**, because a co-pilot that
serves multiple roles is a privilege-escalation surface.

**How the platform prioritizes coverage.** The Orchestrator reads observability — cases-per-category,
pass/fail trend, open findings, regression risk — and directs the Red Team toward the highest-risk,
least-covered categories first, in the order above. Coverage is not "run everything once": it is a
standing loop that re-tests on every target version and escalates categories where partial successes
cluster (the Red Team mutates partials into variants). Every case is tagged **boundary | invariant |
regression** and mapped to **OWASP Web Top 10 + OWASP LLM Top 10**, so coverage is measured against a
recognized surface, not an ad-hoc list. Confirmed exploits are admitted to a deterministic regression
harness so a fixed vulnerability that reappears is caught on the next run.

**What is known vs. to-be-probed.** The target's *capabilities* are confirmed (RAG, write-back,
tools, uploads). Its *existing defenses* — input filtering, output guardrails, per-patient
authorization, rate limits, tool allowlists — are largely **unobserved** and are exactly what the
platform exists to establish empirically. This document therefore states each category's surface and
impact with confidence, and its existing-defenses column as a hypothesis the eval suite will confirm
or refute. The exact **external target** auth mode and API shape of the Co-Pilot are open questions pending inspection
(`PRESEARCH.md` OQ1–OQ3); they change *how* attacks are delivered, not *which* categories apply.

**Risk scoring** below is qualitative (Likelihood × Clinical Impact → Critical/High/Medium),
appropriate for a first pass; the MVP threat model attaches measured pass/fail evidence per category.

## OWASP taxonomy version (2021 anchor + 2025 crosswalk)

The **Web** `A0x` identifiers below are **OWASP Top 10:2021** — the set the PRD enumerates (it lists SSRF
as a standalone category, which exists only in 2021). **LLM** `LLM0x` identifiers are **OWASP LLM Top 10
(2025)**. Verified against owasp.org/Top10/2021 and owasp.org/Top10/2025 (2026-07-20). In the eval-case
schema each mapping is stored as a **structured tag `{framework, version, id, name}`** (e.g.
`{OWASP Web, 2021, A10, Server-Side Request Forgery}`), never a bare `A10` — because `A10` is *SSRF* in 2021
but *Mishandling of Exceptional Conditions* in 2025 (`DECISIONS.md` D15). **2021 → 2025 crosswalk** for the
categories used here: SSRF `A10:2021` → folded into `A01:2025` Broken Access Control · Injection `A03:2021`
→ `A05:2025` · `A08:2021` Software & Data Integrity Failures → `A08:2025` · `A07:2021` Identification & Auth
Failures → `A07:2025`. New in 2025 (forward-looking coverage candidates, not required by the PRD's 2021
anchor): `A03:2025` Software Supply Chain Failures, `A10:2025` Mishandling of Exceptional Conditions.

---

## Category 1 — Prompt Injection (direct · indirect · multi-turn)
- **Surface:** user chat input (direct); uploaded documents + RAG-retrieved record content (indirect);
  accumulated conversation context (multi-turn).
- **Impact:** the model executes attacker instructions — overriding safeguards, exfiltrating data, or
  triggering tools. Indirect injection is worst here because the payload rides in content a clinician
  legitimately uploaded or that RAG pulled from the record.
- **Exploit difficulty:** Low–Medium. The PRD already reports observed influence from uploaded content
  and multi-turn safeguard bypass.
- **Existing defenses:** *to-be-probed* (input sanitization? content/instruction separation?).
- **OWASP:** Web A03 Injection, A04 Insecure Design · LLM01 Prompt Injection, LLM04 Data/Model
  Poisoning (indirect via RAG/uploads).
- **Risk: Critical.**

## Category 2 — Data Exfiltration (PHI leakage · cross-patient · authorization bypass)
- **Surface:** RAG retrieval boundary; any response path that can echo retrieved records; the
  per-patient authorization check (if any).
- **Impact:** disclosure of PHI, or one patient's data surfacing in another's session — a direct
  regulatory and safety failure.
- **Exploit difficulty:** Medium. Depends on whether retrieval is scoped per authenticated
  patient/role or globally.
- **Existing defenses:** *to-be-probed* (row-level authz on retrieval? output PHI filtering?).
- **OWASP:** Web A01 Broken Access Control · LLM02 Sensitive Information Disclosure, LLM07 System
  Prompt Leakage, LLM08 Vector/Embedding Weaknesses (cross-tenant RAG bleed).
- **Risk: Critical.**

## Category 3 — State Corruption (conversation-history manipulation · context poisoning)
- **Surface:** persisted conversation state; any memory/summary the Co-Pilot carries forward; content
  written into the record that later re-enters context.
- **Impact:** an attacker seeds context so later, legitimate turns behave unsafely — a persistent,
  low-visibility compromise that survives across a session or is planted for a future user.
- **Exploit difficulty:** Medium. Requires understanding what the target persists.
- **Existing defenses:** *to-be-probed* (context trust separation? summary sanitization?).
- **OWASP:** Web A08 Software & Data Integrity Failures, A04 Insecure Design · LLM01 Prompt Injection,
  LLM04 Data/Model Poisoning.
- **Risk: High.**

## Category 4 — Tool Misuse (unintended invocation · parameter tampering · recursive calls)
- **Surface:** the tool/function-calling layer, especially any **write-back** tool (notes/orders) and
  any tool that takes free-form parameters.
- **Impact:** the highest-*action* category — corrupting the record, placing an unintended order, or
  driving recursive calls. Parameter tampering can redirect a legitimate tool to the wrong patient.
- **Exploit difficulty:** Medium–High (needs tool schema knowledge), but consequences are severe.
- **Existing defenses:** *to-be-probed* (tool allowlist? param validation? human confirm on write?).
- **OWASP:** Web A03 Injection, A01 Broken Access Control, A10 SSRF (if any tool fetches URLs) · LLM06
  Excessive Agency, LLM05 Improper Output Handling.
- **Risk: Critical.**

## Category 5 — Denial of Service (token exhaustion · infinite loops · cost amplification)
- **Surface:** unbounded generation, recursive tool chains, long multi-turn sessions, large uploads.
- **Impact:** cost blow-up and degraded availability — the PRD reports costs "increasing faster than
  expected" from recursive tool usage and long chains. In a clinical setting, unavailability is a
  safety issue.
- **Exploit difficulty:** Low–Medium.
- **Existing defenses:** *to-be-probed* (max tokens? loop/recursion caps? rate limits? upload caps?).
- **OWASP:** Web A04 Insecure Design · LLM10 Unbounded Consumption.
- **Risk: High.**

## Category 6 — Identity & Role Exploitation (privilege escalation · persona hijacking · trust-boundary violation)
- **Surface:** whatever distinguishes roles/permissions inside the Co-Pilot; any system-prompt-defined
  persona; the boundary between "user says" and "system authorizes."
- **Impact:** a lower-privileged user reaching higher-privileged data/actions, or the assistant being
  coerced into a persona that drops its safeguards.
- **Exploit difficulty:** Medium.
- **Existing defenses:** *to-be-probed* (role enforcement server-side vs prompt-only?).
- **OWASP:** Web A01 Broken Access Control, A07 Identification & Authentication Failures · LLM06
  Excessive Agency, LLM07 System Prompt Leakage.
- **Risk: High.**

## Platform identity boundary — Headshot console/API

This section models attacks against **AgentForge/Headshot itself**, not the external Co-Pilot. The
protected assets are target configuration, campaign controls, findings, hostile evidence, approval/audit
records, and event streams. The trust path is Browser → Clerk → public Railway Web → private Railway
services/Postgres. Clerk provides human identity; custom organization permissions provide application
RBAC; service identities and target-scoped credentials remain separate workload controls. All controls
below are required by the selected design and remain **planned until integration/deployment verification**.

| Platform identity threat | Abuse path and impact | Required control / failure behavior | OWASP Web Top 10:2021 |
|---|---|---|---|
| **1. Session-token theft** | A stolen bearer token lets an attacker act as a valid member until the token expires, exposing findings or campaign controls. | TLS; mandatory MFA for account access; short session lifetime; never persist a token in application storage unnecessarily; never log/token-trace it; revoke and investigate by immutable user/session ID. Sensitive operations still require custom permission and, where applicable, a different Approver. | **A07** Identification and Authentication Failures; **A02** Cryptographic Failures; **A09** Security Logging and Monitoring Failures |
| **2. XSS / token exposure** | Injected console content, especially hostile evidence, can execute in the Browser or leak a token through DOM, storage, telemetry, error reporting, or third-party scripts. | Escape/sanitize hostile content; strict CSP and dependency hygiene; never render raw evidence by default; no token in URL, Principal, error, log, trace, or client telemetry; keep frontend checks non-authoritative. | **A03** Injection; **A02** Cryptographic Failures |
| **3. Authorized-party misconfiguration** | A wildcard or incorrect `azp` allowlist lets a token minted for an unintended origin reach Headshot. | `CLERK_AUTHORIZED_PARTIES` is explicit per environment; wildcard rejected at config load; production entries require HTTPS; localhost allowed only locally; invalid config fails readiness and request-time failures return 503. | **A05** Security Misconfiguration; **A07** Identification and Authentication Failures |
| **4. Cross-origin / subdomain-cookie abuse** | An attacker-controlled origin or sibling subdomain induces authenticated requests, receives credentials, or abuses ambient cookies. | Exact CORS/authorized-party allowlists; secure cookie attributes where cookies are used; CSRF protection for ambient-cookie mutations; never trust all subdomains; no broad origin reflection; only the Web service is public. | **A01** Broken Access Control; **A05** Security Misconfiguration |
| **5. RBAC bypass** | Frontend role labels, Clerk system permissions, or client-supplied permission text are treated as authorization and unlock privileged actions. | Backend dependencies authorize only immutable custom organization permissions from the verified session claims. The role label is descriptive; client fields are ignored. Every handler defaults denied without its exact named permission. | **A01** Broken Access Control |
| **6. IDOR** | A permitted user changes a campaign, finding, evidence, target, or approval identifier to access a different object outside the authorized operation. | Permission checks are necessary but not sufficient: scope every lookup and mutation to the authorized organization/resource relationship; use server-derived identity; return non-enumerating denial; audit object and Principal IDs. | **A01** Broken Access Control |
| **7. Organization confusion** | A valid Clerk session with no organization, the wrong organization, or a production organization reused in staging is accepted. | Require the exact environment-specific `CLERK_REQUIRED_ORG_ID`; deny missing/wrong org with 403; personal accounts and user-created orgs disabled; staging config containing the production org ID fails load/readiness. | **A01** Broken Access Control; **A04** Insecure Design |
| **8. Approval identity spoofing** | The launcher supplies an approver ID, changes a role label, or replays their own session to satisfy a two-person gate. | Derive both identities only from verified immutable Principals and server-side workflow state; require `org:campaign:authorize`/`org:findings:approve`; enforce `approver.user_id != launcher_user_id`; bind action nonce; audit both user/session IDs. No solo/break-glass bypass. | **A01** Broken Access Control; **A07** Identification and Authentication Failures; **A04** Insecure Design |
| **9. Stale/revoked permission behavior** | A user removed from a role or organization continues using a still-valid signed session claim during its remaining lifetime. | Use short session lifetime and re-authentication for high-risk actions; revoke sessions and monitor audit events. **Residual:** networkless JWT verification deliberately accepts a valid signed claim until expiry, so permission revocation is not instantaneous. Never claim otherwise. | **A01** Broken Access Control; **A07** Identification and Authentication Failures |
| **10. Event-stream leakage** | An unauthenticated or under-authorized SSE/WebSocket subscriber receives findings, traces, costs, or hostile evidence; a token in a query string leaks via logs/referrers. | Authenticate and authorize before opening each stream; require the corresponding read permission and object scope; never place tokens in URLs; close/revalidate at token expiry; sanitize payloads; event routes are excluded from the public allowlist. | **A01** Broken Access Control; **A02** Cryptographic Failures; **A09** Security Logging and Monitoring Failures |
| **11. Authentication outage / fail-open** | Clerk, verifier, key, or configuration failure causes the service to bypass authentication so work can continue. | Networkless verification keeps valid signed sessions independent of a Clerk/JWKS request. Invalid config blocks readiness; unexpected verifier/SDK/config failure returns generic 503; no cached raw claim, frontend decision, anonymous fallback, or dynamic JWKS escape hatch is accepted. | **A04** Insecure Design; **A05** Security Misconfiguration; **A07** Identification and Authentication Failures |

**Priority.** RBAC/IDOR/organization confusion and approval spoofing are Critical because they can permit
live operations or expose hostile evidence; session/XSS/event-stream leakage is High because it can steal
the same authority; configuration, freshness, and outage behavior are High because a single fail-open
mistake collapses every route-level control. Authentication still does not authorize an attack: after
Clerk identity/RBAC and distinct-Approver checks, the Policy Gateway must independently enforce exact
target authorization, allowlist, scoped credentials, synthetic data, budget/rate, monitoring, and abort.

---

## Target coverage priority (feeds the Orchestrator)
`1 Prompt Injection (Critical)` → `2 Data Exfiltration (Critical)` → `4 Tool Misuse (Critical)` →
`3 State Corruption (High)` → `5 DoS/Cost (High)` → `6 Identity/Role (High)`. Priority is
re-evaluated each run from observability; a category with clustering partial-successes is escalated.
