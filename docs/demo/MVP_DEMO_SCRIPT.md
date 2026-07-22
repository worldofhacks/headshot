# Week 3 AgentForge MVP demo script

**Recording target:** 4–5 minutes

**Staging app:** https://web-staging-8e30.up.railway.app
**Login:** use the `godmode` demo credential supplied separately. Do not place the
password in the recording notes or repository.

## Before recording

1. Open the staging app, sign in, and leave **Live** selected.
2. Keep this script beside the browser.
3. Do not start a new live campaign during the recording unless a different human
   approver has already approved that exact target, scope, caps, budget, and nonce.
4. If a panel is still refreshing, continue to the next section and return once.

## 0:00–0:35 — Frame the product and prove it is live

**Click:** **Live**

> “AgentForge is a multi-agent adversarial evaluation platform continuously testing
> the live OpenEMR Clinical Co-Pilot. This is the deployed staging control plane—not
> a mock. The Web API, Postgres evidence store, private Runner, and Langfuse tracing
> connection are all operational.”

Point to the component statuses. Explain that the platform attacks the separate live
target over its deployed URL; no target source code lives in this repository.

## 0:35–1:10 — Target, authorization, and safety caps

**Click:** **Targets**

> “The target is the deployed Clinical Co-Pilot. Its exact origin is allowlisted, its
> credential is server-side, and the Runner fails closed on origin escape. Campaigns
> require explicit caps: nine attempts, one request per second, a fifteen-minute
> timeout, and a one-dollar maximum.”

Point to the configured target and surface. Mention that all fixtures are synthetic and
no real PHI is used.

## 1:10–1:50 — Real multi-agent campaign and evaluation coverage

**Click:** **Live**, then open campaign `bebb4d82…` if it is visible.

**Then click:** **Coverage**

> “This completed live campaign executed nine physical requests across prompt
> injection, data exfiltration, and tool misuse. Every evaluation is classified as a
> boundary, invariant, or regression and mapped to OWASP Web and OWASP LLM risks.
> The Red Team generates attacks, while the independent Judge evaluates evidence;
> it cannot turn an unverified result into an approved exploit.”

Point out the verified attempt count. If a verdict is indeterminate, say that this is
fail-closed behavior—not a failure hidden by the UI.

## 1:50–2:40 — Live DAST evidence and the publication gate

**Click:** **Findings**

> “A second real attack surface is represented here: an OWASP ZAP 2.17 passive
> baseline against the same deployed target. It produced three normalized findings:
> missing HSTS, missing X-Content-Type-Options, and cache-control review. They are
> Low, Low, and Informational—not confirmed exploits.”

Open one finding.

> “Every finding carries live-target provenance, tool version, configuration digest,
> run nonce, reproduction pointer, and the raw artifact SHA-256 beginning
> `89f10c94`. Publication remains blocked pending independent human validation.
> Even godmode cannot approve its own live campaign or bypass the publication gate.”

## 2:40–3:25 — Request-level observability, latency, and real cost

**Click:** **Traces**

> “Every physical target request receives a correlation trace, measured duration,
> status, and Langfuse export state. The Runner owns the tracing secret; the browser
> and Web tier never do.”

**Click:** **Costs**

> “Accounting is measured from persisted request records—not estimated as tokens
> multiplied by a constant. This campaign recorded nine requests, nine cents total,
> one cent per request, and approximately 321,485 milliseconds of end-to-end run
> latency.”

Point to `$0.09`, `9`, `$0.01`, and `321484.759 ms`.

## 3:25–4:10 — Human governance and reproducibility

**Click:** **Approvals**

> “Live execution and critical publication are human-gated. Authorization binds the
> target, surface, rate, attempt cap, timeout, dollar budget, and nonce. The operator
> who requests or runs a campaign cannot satisfy the distinct-human approval check
> for that same authorization.”

**Click:** **Configuration**

> “The control plane uses versioned typed contracts, deterministic tool adapters,
> durable Postgres state, migrations, bounded queues, audit history, and explicit
> error schemas. The repository also includes the threat model, architecture,
> persona documentation, reproducible eval fixtures, AI-use disclosure, and
> deployment evidence required by the Week 3 rubric.”

## 4:10–4:40 — Close

> “The defensible result is two real evaluation surfaces: a nine-case adversarial
> LLM campaign plus a live passive web baseline. We have three evidenced web
> hardening findings, no confirmed exploit, measured cost and latency, Langfuse
> request traces, and fail-closed human gates. The application, evidence contracts,
> and reproducible artifacts are deployed and reviewable.”

## Fast fallback

If campaign detail is slow, show **Coverage**, **Findings**, **Traces**, and **Costs** in
that order. These are authoritative server projections and contain the strongest MVP
proof. Never claim an exploit was confirmed; say “three publication-gated hardening
findings from a passive baseline.”
